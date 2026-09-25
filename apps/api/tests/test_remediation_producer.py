"""Step 13 -- the deterministic remediation PRODUCER.

WHY THIS FILE EXISTS
--------------------
`remediations` contained 0 rows after a scan that produced 698 findings. Nothing was broken
in the usual sense: the model, the migration and the report's read-side join all worked. The
table was empty because no code path ever wrote to it during a scan. The only writer was
`ai_service.generate_remediation` -- an on-demand HTTP endpoint, one call per vulnerability,
requiring a configured AI provider -- so every completed scan rendered "no remediation
available" for every finding.

`remediation_service.sync_remediation` closes that gap at the ingest boundary, next to the
risk, compliance and ATT&CK enrichments. These tests pin the eight properties the producer
has to hold, in the order the plan lists them:

  1. supported finding      -> a row with real, actionable content
  2. unsupported finding    -> NO row (never filler text)
  3. duplicate prevention   -> one row per vulnerability, enforced by the unique constraint
  4. idempotent rerun       -> re-running rewrites in place and never raises
  5. report consumption     -> what is stored is the shape reports/data.py reads
  6. canonical mapping      -> template id first, CWE as fallback
  7. persistence            -> the values survive a round trip
  8. transaction behaviour  -> the write participates in the caller's transaction

The catalogue itself is asserted for CONTENT quality too: guidance that degenerates into
"fix the vulnerability" would satisfy a row-count check while being worthless, which is the
failure mode this whole workstream exists to avoid.
"""

import asyncio
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.users.models import User
from apps.api.modules.vulnerabilities import remediation_catalog as CAT
from apps.api.modules.vulnerabilities.models import Vulnerability
from apps.api.modules.vulnerabilities.remediation_models import Remediation
from apps.api.modules.vulnerabilities.remediation_service import (
    CATALOG_VERSION,
    GENERATED_BY_CATALOG,
    _template_id,
    get_remediation_row,
    sync_remediation,
)
from apps.api.modules.workspaces.models import Workspace


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


def _run(coro):
    asyncio.run(coro)


async def _seed_vuln(s, *, fingerprint, category, severity="critical", title="Finding"):
    """One workspace/project/target/vulnerability chain, mirroring the seeding style of
    test_finding_asset_resolution."""
    user = User(email=f"rem-{uuid.uuid4()}@test.local", password_hash="x", full_name="Rem Tester")
    s.add(user)
    await s.flush()
    ws = Workspace(name=f"rem-ws-{uuid.uuid4().hex[:8]}", owner_user_id=user.id)
    s.add(ws)
    await s.flush()
    tenancy.bind_workspace(ws.id)
    project = Project(workspace_id=ws.id, name=f"rem-{uuid.uuid4().hex[:8]}", created_by=user.id)
    s.add(project)
    await s.flush()
    target = Target(project_id=project.id, type="domain", value="ex.test",
                    criticality="low", added_by=user.id)
    s.add(target)
    await s.flush()
    vuln = Vulnerability(
        project_id=project.id, fingerprint=fingerprint, title=title,
        category=category, severity=severity, status="open", ai_validated=False,
    )
    s.add(vuln)
    await s.flush()
    return vuln, ws.id


# --- 1: supported finding produces a row ------------------------------------------------------

def test_supported_finding_produces_a_remediation_row() -> None:
    """The headline case: a finding whose type has reviewed guidance gets a persisted row
    with a summary, ordered steps and the provenance that marks it catalogue-authored."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                vuln, wsid = await _seed_vuln(
                    s, fingerprint="sqli-error-based|status|https://h/a?id=1", category=None,
                )
                with tenancy.workspace_scope(wsid):
                    assert await sync_remediation(s, vuln.id, vuln.fingerprint, vuln.category) is True
                    row = await get_remediation_row(s, vuln.id)
                    assert row is not None
                    assert row.summary and row.summary.strip()
                    assert isinstance(row.steps, list) and len(row.steps) >= 3
                    assert row.generated_by == GENERATED_BY_CATALOG
                    assert row.prompt_version == CATALOG_VERSION
                    # Guidance for SQLi must actually say the thing that fixes SQLi.
                    assert "parameteris" in " ".join(row.steps).lower()
        finally:
            await engine.dispose()
    _run(scenario())


def test_critical_findings_with_no_cwe_still_get_guidance() -> None:
    """THE case that motivated keying on template id. On the reference scan all 166 critical
    SQL-injection findings had `category IS NULL`, because their nuclei templates report no
    CWE. A CWE-keyed producer would have left exactly the highest-severity population
    without guidance."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                for tid in ("sqli-error-based", "time-based-sqli"):
                    vuln, wsid = await _seed_vuln(
                        s, fingerprint=f"{tid}|status|https://h/a", category=None,
                    )
                    with tenancy.workspace_scope(wsid):
                        assert await sync_remediation(s, vuln.id, vuln.fingerprint, None) is True
                        assert await get_remediation_row(s, vuln.id) is not None
        finally:
            await engine.dispose()
    _run(scenario())


# --- 2: unsupported finding produces NOTHING ---------------------------------------------------

def test_unsupported_finding_produces_no_row() -> None:
    """Explicit policy: a type nobody has written guidance for gets NO row. Filler text would
    be indistinguishable from reviewed advice and would carry MBS's name."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                vuln, wsid = await _seed_vuln(
                    s, fingerprint="some-unreviewed-template|m|https://h/a",
                    category=None, severity="info",
                )
                with tenancy.workspace_scope(wsid):
                    assert await sync_remediation(s, vuln.id, vuln.fingerprint, None) is False
                    assert await get_remediation_row(s, vuln.id) is None
        finally:
            await engine.dispose()
    _run(scenario())


def test_finding_with_neither_template_nor_cwe_produces_no_row() -> None:
    """A non-nuclei finding with no CWE has no canonical identity to resolve, so it must fall
    through to "no guidance" rather than to a default."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                vuln, wsid = await _seed_vuln(s, fingerprint="opaque-fingerprint", category=None)
                with tenancy.workspace_scope(wsid):
                    assert await sync_remediation(s, vuln.id, vuln.fingerprint, None) is False
                    assert await get_remediation_row(s, vuln.id) is None
        finally:
            await engine.dispose()
    _run(scenario())


# --- 3 & 4: duplicate prevention and idempotent rerun ------------------------------------------

def test_rerunning_is_idempotent_and_creates_no_duplicate() -> None:
    """A re-scan re-ingests every recurring finding, so the producer runs again on rows that
    already have guidance. It must rewrite in place, not accumulate rows and not raise on the
    unique constraint."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                vuln, wsid = await _seed_vuln(
                    s, fingerprint="reflected-xss|body|https://h/s?q=1", category="cwe-79",
                    severity="medium",
                )
                with tenancy.workspace_scope(wsid):
                    for _ in range(3):
                        assert await sync_remediation(
                            s, vuln.id, vuln.fingerprint, vuln.category
                        ) is True
                    rows = (await s.scalars(
                        select(Remediation).where(Remediation.vulnerability_id == vuln.id)
                    )).all()
                    assert len(rows) == 1, f"expected exactly one row, got {len(rows)}"
        finally:
            await engine.dispose()
    _run(scenario())


def test_repeated_runs_produce_identical_content() -> None:
    """Determinism: the producer is a pure lookup, so two runs must store the same bytes.
    Content that drifted between runs would make a re-scan look like a change in guidance."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                vuln, wsid = await _seed_vuln(
                    s, fingerprint="unix-command-injection|status|https://h/x", category="cwe-78",
                    severity="high",
                )
                with tenancy.workspace_scope(wsid):
                    await sync_remediation(s, vuln.id, vuln.fingerprint, vuln.category)
                    first = await get_remediation_row(s, vuln.id)
                    snapshot = (first.summary, list(first.steps), list(first.reference_links))
                    s.expunge(first)
                    await sync_remediation(s, vuln.id, vuln.fingerprint, vuln.category)
                    second = await get_remediation_row(s, vuln.id)
                    assert (second.summary, list(second.steps), list(second.reference_links)) == snapshot
        finally:
            await engine.dispose()
    _run(scenario())


def test_human_authored_guidance_is_never_overwritten() -> None:
    """An analyst's edit outranks the catalogue. If a re-scan clobbered it, the producer would
    silently destroy reviewed work -- the one behaviour that would make it unsafe to run on
    every ingest."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                vuln, wsid = await _seed_vuln(
                    s, fingerprint="reflected-xss|body|https://h/s", category="cwe-79",
                    severity="medium",
                )
                with tenancy.workspace_scope(wsid):
                    s.add(Remediation(
                        vulnerability_id=vuln.id, summary="Analyst wrote this.",
                        steps=["Do the reviewed thing."], reference_links=[],
                        generated_by="human",
                    ))
                    await s.flush()
                    assert await sync_remediation(
                        s, vuln.id, vuln.fingerprint, vuln.category
                    ) is False
                    row = await get_remediation_row(s, vuln.id)
                    assert row.summary == "Analyst wrote this."
                    assert row.generated_by == "human"
        finally:
            await engine.dispose()
    _run(scenario())


def test_ai_authored_guidance_is_never_overwritten() -> None:
    """Same rule for the existing on-demand AI endpoint's output: the catalogue does not
    displace a generation a user explicitly requested."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                vuln, wsid = await _seed_vuln(
                    s, fingerprint="blind-ssrf|oast|https://h/f", category=None, severity="medium",
                )
                with tenancy.workspace_scope(wsid):
                    s.add(Remediation(
                        vulnerability_id=vuln.id, summary="AI wrote this.", steps=["step"],
                        reference_links=[], generated_by="ai", model_version="m1",
                    ))
                    await s.flush()
                    assert await sync_remediation(s, vuln.id, vuln.fingerprint, None) is False
                    row = await get_remediation_row(s, vuln.id)
                    assert row.summary == "AI wrote this."
                    assert row.generated_by == "ai"
        finally:
            await engine.dispose()
    _run(scenario())


def test_catalogue_refreshes_its_own_rows() -> None:
    """The converse of the two tests above: a row this producer owns MUST be refreshable, so
    a corrected catalogue entry reaches findings that already have guidance."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                vuln, wsid = await _seed_vuln(
                    s, fingerprint="reflected-xss|body|https://h/s", category="cwe-79",
                    severity="medium",
                )
                with tenancy.workspace_scope(wsid):
                    s.add(Remediation(
                        vulnerability_id=vuln.id, summary="stale", steps=[],
                        reference_links=[], generated_by=GENERATED_BY_CATALOG,
                    ))
                    await s.flush()
                    assert await sync_remediation(
                        s, vuln.id, vuln.fingerprint, vuln.category
                    ) is True
                    row = await get_remediation_row(s, vuln.id)
                    await s.refresh(row)
                    assert row.summary != "stale"
                    assert len(row.steps) >= 3
        finally:
            await engine.dispose()
    _run(scenario())


# --- 5 & 7: persistence and the shape the report reads ------------------------------------------

def test_stored_shape_is_what_the_report_reads() -> None:
    """reports/data.py reads `summary`, `steps` (a JSON list) and `reference_links`. A step
    list stored as a bare string is what used to crash the renderer, so the types matter as
    much as the presence of a row."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                vuln, wsid = await _seed_vuln(
                    s, fingerprint="http-missing-security-headers|h|https://h/", category="cwe-693",
                    severity="info",
                )
                with tenancy.workspace_scope(wsid):
                    await sync_remediation(s, vuln.id, vuln.fingerprint, vuln.category)
                    row = await get_remediation_row(s, vuln.id)
                    assert isinstance(row.summary, str)
                    assert isinstance(row.steps, list)
                    assert all(isinstance(step, str) and step.strip() for step in row.steps)
                    assert isinstance(row.reference_links, list)
                    for ref in row.reference_links:
                        assert set(ref) == {"title", "url"}
                        assert ref["url"].startswith("http")
        finally:
            await engine.dispose()
    _run(scenario())


# --- 8: transaction behaviour --------------------------------------------------------------------

def test_write_participates_in_the_callers_transaction() -> None:
    """The producer issues no commit of its own -- it runs inside the ingest transaction, so a
    rolled-back scan batch must not leave orphan guidance behind."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                vuln, wsid = await _seed_vuln(
                    s, fingerprint="reflected-xss|body|https://h/s", category="cwe-79",
                    severity="medium",
                )
                await s.commit()
                vuln_id = vuln.id
                with tenancy.workspace_scope(wsid):
                    await sync_remediation(s, vuln_id, "reflected-xss|body|https://h/s", "cwe-79")
                    assert await get_remediation_row(s, vuln_id) is not None
                    await s.rollback()
                    assert await get_remediation_row(s, vuln_id) is None, (
                        "guidance survived a rollback -- the producer committed on its own"
                    )
        finally:
            await engine.dispose()
    _run(scenario())


# --- 6: canonical mapping (pure, no DB) -----------------------------------------------------------

@pytest.mark.parametrize(
    "fingerprint,expected",
    [
        ("sqli-error-based|status|https://h/a", "sqli-error-based"),
        ("reflected-xss|body|https://h/s?q=1", "reflected-xss"),
        ("  spaced-template  |m|loc", "spaced-template"),
        ("no-delimiter", None),
        ("", None),
        (None, None),
        ("|m|loc", None),
    ],
)
def test_template_id_is_recovered_from_the_fingerprint(fingerprint, expected) -> None:
    assert _template_id(fingerprint) == expected


def test_template_id_takes_precedence_over_cwe() -> None:
    """Most-specific-first. A template with its own entry must not be answered by the broader
    CWE fallback, which would lose the template-specific advice."""
    by_template = CAT.guidance_for("time-based-sqli", "cwe-89")
    assert by_template is CAT.guidance_for("time-based-sqli", None)
    assert "timing" in " ".join(by_template.steps).lower()


def test_cwe_is_used_when_the_template_is_unknown() -> None:
    """The fallback tier: an unreviewed template with a known CWE still gets class guidance."""
    assert CAT.guidance_for("never-seen-template", "cwe-89") is not None
    assert CAT.guidance_for("never-seen-template", "CWE-89") is not None
    assert CAT.guidance_for("never-seen-template", "89") is not None


def test_lookup_normalises_case_and_whitespace() -> None:
    base = CAT.guidance_for("reflected-xss", None)
    for spelling in ("Reflected-XSS", "  reflected-xss  ", "REFLECTED-XSS"):
        assert CAT.guidance_for(spelling, None) is base


def test_unknown_identity_returns_none_with_no_fallback() -> None:
    for tid in ("stored-xss", "xss", "reflected-xss-extra", "something-opaque"):
        assert CAT.guidance_for(tid, None) is None
    assert CAT.guidance_for(None, "cwe-99999") is None
    assert CAT.guidance_for(None, None) is None


# --- catalogue content quality ---------------------------------------------------------------------

@pytest.mark.parametrize("template_id", sorted(CAT.catalogue_template_ids()))
def test_every_entry_is_substantive_and_actionable(template_id) -> None:
    """Guards against the failure mode the plan names explicitly: guidance that exists but
    says nothing. A row full of "fix the vulnerability" would pass a count check while being
    useless to the reader."""
    g = CAT.guidance_for(template_id, None)
    assert g.summary.strip() and len(g.summary) > 60, template_id
    assert len(g.steps) >= 3, f"{template_id} has too few steps to be actionable"
    for step in g.steps:
        assert step.strip() and len(step) > 30, f"{template_id} has a stub step: {step!r}"
    joined = (g.summary + " " + " ".join(g.steps)).lower()
    for empty in ("fix the vulnerability", "fix this issue", "todo", "tbd", "fixme",
                  "placeholder", "as appropriate", "consult your vendor"):
        assert empty not in joined, f"{template_id} contains empty guidance: {empty!r}"


@pytest.mark.parametrize("template_id", sorted(CAT.catalogue_template_ids()))
def test_entries_do_not_claim_exploitation_or_observation(template_id) -> None:
    """Entries are written without sight of a finding, so they cannot report an observation.
    Per-finding facts belong to the evidence."""
    g = CAT.guidance_for(template_id, None)
    text = (g.summary + " " + " ".join(g.steps)).lower()
    for claim in ("we exploited", "was exploited", "we confirmed", "we observed",
                  "the response contained", "successfully exploited"):
        assert claim not in text, f"{template_id} asserts an observation: {claim!r}"


@pytest.mark.parametrize("template_id", sorted(CAT.catalogue_template_ids()))
def test_references_are_well_formed(template_id) -> None:
    g = CAT.guidance_for(template_id, None)
    for ref in g.reference_dicts():
        assert set(ref) == {"title", "url"}
        assert ref["title"].strip()
        assert ref["url"].startswith("https://"), ref


def test_catalogue_keys_are_in_normal_form() -> None:
    """A key not already lowercase/stripped would be unreachable, since lookup normalises."""
    for key in CAT.catalogue_template_ids() + CAT.catalogue_cwes():
        assert key == key.strip().lower(), key
        assert key


def test_cwe_fallback_keys_are_canonical() -> None:
    """The fallback map is consulted with the output of `canonical_cwe`, so a key that is not
    already canonical could never match."""
    from apps.api.modules.vulnerabilities.taxonomy import canonical_cwe

    for key in CAT.catalogue_cwes():
        assert canonical_cwe(key) == key, key


def test_catalogue_module_is_pure() -> None:
    """No DB, no network, no scanner or report imports: it must stay a leaf module so it can
    be called from the ingest hot path."""
    import inspect

    source = inspect.getsource(CAT)
    for forbidden in ("import requests", "import httpx", "from sqlalchemy",
                      "from apps.api.modules.reports", "from apps.api.scanner_engine"):
        assert forbidden not in source, f"catalogue imports {forbidden!r}"
