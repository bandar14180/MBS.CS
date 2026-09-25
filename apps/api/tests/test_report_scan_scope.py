"""Phase 3.1 (R-03) -- reports must honour the requested `scan_ids` scope.

THE DEFECT THIS PINS
--------------------
`ReportCreate` accepted `scan_ids` and `service.create_report` stored them on the `Report` row,
but generation called `gather_report_data(db, project_id)` -- which had no scan parameter. So a
report requested for scans [A] silently covered the WHOLE project, and the stored `scan_ids`
misdescribed the document's actual scope.

THE CANONICAL RELATIONSHIP
--------------------------
`Vulnerability.last_seen_scan_id`. A vulnerability row is deduped per (project_id, fingerprint)
and OUTLIVES the scan that first saw it, so `first_detected_scan_id` names a historical event
rather than membership. `last_seen_scan_id` is written on EVERY ingest (new fingerprint and
re-detection alike) and is already what attack.service, remediation.verification, scans.service
and the orchestrator mean by "this scan's findings".

AUTHORIZATION
-------------
`scans` is tenancy-EXEMPT, so a client-supplied scan id is validated explicitly via
scans.service.get_scan (id AND workspace_id AND project_id, 404 otherwise) -- the existing
canonical helper, not a new access-control model.
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from apps.api.tests.test_remediation import (
    _auth,
    _register,
    _seed_findings,
    _workspace_project,
)


# --- fixtures -----------------------------------------------------------------------------

def _seed_scan(wid: str, pid: str, status: str = "completed") -> uuid.UUID:
    """A scan row in the given project. Mirrors test_remediation_verification._seed_scan."""
    import asyncio

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.modules.projects.models import Project, Target
    from apps.api.modules.scans.models import Scan

    async def _run() -> uuid.UUID:
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                with tenancy.workspace_scope(uuid.UUID(wid)):
                    project = await session.scalar(
                        select(Project).where(Project.id == uuid.UUID(pid))
                    )
                    target = Target(
                        project_id=uuid.UUID(pid), type="domain",
                        value=f"{uuid.uuid4()}.test", criticality="medium",
                        added_by=project.created_by,
                    )
                    session.add(target)
                    await session.flush()
                    scan = Scan(
                        workspace_id=uuid.UUID(wid), project_id=uuid.UUID(pid),
                        target_id=target.id, initiated_by=project.created_by,
                        scan_type="vuln", status=status, config={},
                    )
                    session.add(scan)
                    await session.commit()
                    return scan.id
        finally:
            await engine.dispose()

    return asyncio.run(_run())


def _link_findings_to_scan(wid: str, vuln_ids: list[uuid.UUID], scan_id: uuid.UUID) -> None:
    """Set `last_seen_scan_id` -- the canonical scan->finding link -- on the given findings.

    _seed_findings inserts rows without a scan linkage, which is exactly what an un-scoped
    legacy row looks like; this attaches them to a scan the way an ingest would."""
    import asyncio

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.modules.vulnerabilities.models import Vulnerability

    async def _run() -> None:
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                with tenancy.workspace_scope(uuid.UUID(wid)):
                    for vid in vuln_ids:
                        vuln = await session.scalar(
                            select(Vulnerability).where(Vulnerability.id == vid)
                        )
                        vuln.first_detected_scan_id = scan_id
                        vuln.last_seen_scan_id = scan_id
                    await session.commit()
        finally:
            await engine.dispose()

    asyncio.run(_run())


def _gather(wid: str, pid: str, scan_ids: list[uuid.UUID] | None = None):
    """Call the data layer directly -- the single place the scope is applied.

    Runs inside `tenancy.workspace_scope`, because `projects`/`vulnerabilities` are
    workspace-scoped and the tenancy guard rejects an unbound query. That is the same context
    the API request path establishes before reaching this function."""
    import asyncio

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.modules.reports.data import gather_report_data

    async def _run():
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                with tenancy.workspace_scope(uuid.UUID(wid)):
                    return await gather_report_data(session, uuid.UUID(pid), scan_ids)
        finally:
            await engine.dispose()

    return asyncio.run(_run())


def _finding(fingerprint: str, severity: str = "high", cvss: float = 7.5, **kw) -> dict:
    return {
        "fingerprint": fingerprint,
        "title": kw.get("title", fingerprint.split("|")[0]),
        "severity": severity,
        "status": kw.get("status", "open"),
        "category": kw.get("category", "cwe-79"),
        "cvss_score": cvss,
    }


@pytest.fixture()
def two_scan_project(client: TestClient):
    """A project with TWO scans, each owning its own findings.

    Scan A -> one CRITICAL finding.   Scan B -> one LOW finding.
    The severities differ materially so Case F can prove score isolation."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)

    scan_a = _seed_scan(wid, pid)
    scan_b = _seed_scan(wid, pid)

    ids_a = _seed_findings(wid, pid, [
        _finding("crit-template|param|https://a.test/x", "critical", 9.8),
    ])
    ids_b = _seed_findings(wid, pid, [
        _finding("low-template|param|https://b.test/y", "low", 2.1),
    ])
    _link_findings_to_scan(wid, ids_a, scan_a)
    _link_findings_to_scan(wid, ids_b, scan_b)

    return {
        "headers": headers, "wid": wid, "pid": pid,
        "scan_a": scan_a, "scan_b": scan_b,
        "vuln_a": ids_a[0], "vuln_b": ids_b[0],
    }


def _reports_url(wid: str, pid: str) -> str:
    return f"/api/v1/workspaces/{wid}/projects/{pid}/reports"


def _storage_available() -> bool:
    """Is the object store reachable? A successful POST /reports PERSISTS the PDF, so those
    tests need MinIO/S3; the scoping logic itself does not.

    The pre-existing `test_report_generate_list_download` has the same dependency and fails the
    same way on a workstation without the compose stack, so this is an ENVIRONMENT gate, not a
    concession about the feature. The authorization tests below deliberately do NOT use it:
    their requests are rejected (404) before any PDF is stored, so they run everywhere."""
    try:
        from apps.api.core.config import get_settings
        from apps.api.scanner_engine.storage_provider import get_storage_provider

        get_storage_provider(get_settings().s3_bucket_reports)._client()
        return True
    except Exception:
        return False


requires_storage = pytest.mark.skipif(
    not _storage_available(),
    reason="object storage (MinIO/S3) unreachable; POST /reports persists a PDF",
)


# --- CASE A: single scan ------------------------------------------------------------------

def test_case_a_single_scan_includes_only_its_findings(two_scan_project) -> None:
    ctx = two_scan_project
    data = _gather(ctx["wid"], ctx["pid"], [ctx["scan_a"]])

    assert data.total_vulns == 1
    assert [v.id for v in data.vulns] == [ctx["vuln_a"]]
    assert ctx["vuln_b"] not in [v.id for v in data.vulns]
    assert data.severity_counts.get("critical") == 1
    assert data.severity_counts.get("low", 0) == 0


def test_case_a_the_other_scan_sees_only_its_own(two_scan_project) -> None:
    ctx = two_scan_project
    data = _gather(ctx["wid"], ctx["pid"], [ctx["scan_b"]])

    assert data.total_vulns == 1
    assert [v.id for v in data.vulns] == [ctx["vuln_b"]]
    assert data.severity_counts.get("low") == 1


# --- CASE B: multiple scans ---------------------------------------------------------------

def test_case_b_multiple_scans_include_both(two_scan_project) -> None:
    ctx = two_scan_project
    data = _gather(ctx["wid"], ctx["pid"], [ctx["scan_a"], ctx["scan_b"]])

    assert data.total_vulns == 2
    assert {v.id for v in data.vulns} == {ctx["vuln_a"], ctx["vuln_b"]}


# --- CASE C: no explicit scope (the preserved contract) -----------------------------------

def test_case_c_no_scope_is_project_wide(two_scan_project) -> None:
    ctx = two_scan_project
    assert _gather(ctx["wid"], ctx["pid"], None).total_vulns == 2


def test_case_c_empty_list_is_project_wide_per_the_documented_contract(two_scan_project) -> None:
    """ReportCreate.scan_ids says verbatim: "Optional; empty = whole project"."""
    ctx = two_scan_project
    assert _gather(ctx["wid"], ctx["pid"], []).total_vulns == 2


def test_case_c_unscoped_report_reports_itself_as_project_wide(two_scan_project) -> None:
    ctx = two_scan_project
    data = _gather(ctx["wid"], ctx["pid"], [])
    assert data.is_scan_scoped() is False
    assert data.scope_scans == []


# --- CASE D: unknown scan must not fall back to project-wide ------------------------------

def test_case_d_unknown_scan_id_is_rejected_not_widened(client: TestClient, two_scan_project) -> None:
    """The critical safety property: a bad id must FAIL, never silently widen the population."""
    ctx = two_scan_project
    resp = client.post(
        _reports_url(ctx["wid"], ctx["pid"]),
        headers=ctx["headers"],
        json={"type": "technical", "scan_ids": [str(uuid.uuid4())]},
    )
    assert resp.status_code == 404, resp.text


def test_case_d_unknown_scan_in_the_data_layer_yields_nothing(two_scan_project) -> None:
    """Defence in depth: even called directly with an unvalidated id, the scoped query
    returns that scan's findings -- none -- rather than the whole project."""
    ctx = two_scan_project
    data = _gather(ctx["wid"], ctx["pid"], [uuid.uuid4()])
    assert data.total_vulns == 0
    assert data.vulns == []


# --- CASE E: cross-project / cross-workspace scan ------------------------------------------

def test_case_e_scan_from_another_project_is_rejected(client: TestClient, two_scan_project) -> None:
    ctx = two_scan_project
    other_pid = client.post(
        f"/api/v1/workspaces/{ctx['wid']}/projects",
        headers=ctx["headers"], json={"name": "Other"},
    ).json()["id"]
    foreign_scan = _seed_scan(ctx["wid"], other_pid)

    resp = client.post(
        _reports_url(ctx["wid"], ctx["pid"]),
        headers=ctx["headers"],
        json={"type": "technical", "scan_ids": [str(foreign_scan)]},
    )
    assert resp.status_code == 404, resp.text


def test_case_e_scan_from_another_workspace_is_rejected(client: TestClient, two_scan_project) -> None:
    """No cross-tenant leakage: a different tenant's scan id must 404, and must not be
    distinguishable from a merely unknown one."""
    ctx = two_scan_project
    stranger = _register(client, "Stranger")
    s_headers = _auth(stranger)
    s_wid, s_pid = _workspace_project(client, s_headers)
    foreign_scan = _seed_scan(s_wid, s_pid)

    resp = client.post(
        _reports_url(ctx["wid"], ctx["pid"]),
        headers=ctx["headers"],
        json={"type": "technical", "scan_ids": [str(foreign_scan)]},
    )
    assert resp.status_code == 404, resp.text


def test_case_e_cross_project_scan_leaks_no_findings_at_the_data_layer(two_scan_project, client) -> None:
    """Even if authorization were bypassed, the project_id predicate still fences the query."""
    ctx = two_scan_project
    stranger = _register(client, "Stranger2")
    s_headers = _auth(stranger)
    s_wid, s_pid = _workspace_project(client, s_headers)
    foreign_scan = _seed_scan(s_wid, s_pid)
    foreign_ids = _seed_findings(s_wid, s_pid, [
        _finding("secret-template|param|https://private.test/z", "critical", 10.0),
    ])
    _link_findings_to_scan(s_wid, foreign_ids, foreign_scan)

    data = _gather(ctx["wid"], ctx["pid"], [foreign_scan])
    assert data.total_vulns == 0
    assert data.vulns == []


# --- CASE F: score isolation ---------------------------------------------------------------

def test_case_f_score_is_computed_from_the_selected_scan_only(two_scan_project) -> None:
    """Scan A holds a CRITICAL, scan B holds a LOW. The scores must differ accordingly, and
    neither may equal the project-wide score."""
    ctx = two_scan_project
    score_a = _gather(ctx["wid"], ctx["pid"], [ctx["scan_a"]]).security_score
    score_b = _gather(ctx["wid"], ctx["pid"], [ctx["scan_b"]]).security_score
    score_all = _gather(ctx["wid"], ctx["pid"], []).security_score

    assert score_a < score_b, "a critical-only scope must score worse than a low-only scope"
    assert score_all < score_b, "the project-wide score carries both findings"
    assert score_a != score_all


def test_case_f_scope_is_applied_before_derived_semantics(two_scan_project) -> None:
    """The ordering requirement: scoping happens in the data layer, so every derived figure --
    not just the rendered text -- describes the scoped population."""
    ctx = two_scan_project
    data = _gather(ctx["wid"], ctx["pid"], [ctx["scan_b"]])

    assert data.total_vulns == 1
    assert data.active_vulns == 1
    assert data.total_issue_count() == 1
    assert data.active_issue_count() == 1
    assert data.scorable_issue_count() == 1
    assert data.severity_counts.get("critical", 0) == 0


# --- CASE G: section parity ----------------------------------------------------------------

def test_case_g_every_finding_derived_section_uses_the_scoped_population(two_scan_project) -> None:
    ctx = two_scan_project
    data = _gather(ctx["wid"], ctx["pid"], [ctx["scan_a"]])
    scoped_ids = {v.id for v in data.vulns}

    assert scoped_ids == {ctx["vuln_a"]}

    # Compliance (R-02 contract) draws only from scoped findings.
    contributing = {
        fid
        for _fw, controls in data.compliance_coverage()
        for _cid, _desc, ids in controls
        for fid in ids
    }
    assert contributing <= {v.finding_id for v in data.vulns}

    # MITRE, assets and the attack graph are all built from the same scoped rows.
    assert all(count <= len(scoped_ids) for *_x, count in data.attack_techniques)
    assert set(data.affected_assets()) <= {v.asset_value for v in data.vulns if v.asset_value}
    assert data.attack_graph.get("has_data") in (False, True)


def test_case_g_rendered_reports_agree_with_the_scoped_data(two_scan_project) -> None:
    import re

    from apps.api.modules.reports.render import render_executive, render_technical
    from apps.api.tests.test_report_layout import _pdf_text

    ctx = two_scan_project
    data = _gather(ctx["wid"], ctx["pid"], [ctx["scan_a"]])

    for pdf in (render_executive(data), render_technical(data)):
        text = re.sub(r"\s+", " ", _pdf_text(pdf))
        assert "1 selected scan(s)" in text
        # The excluded scan's finding title must not appear anywhere.
        assert "low-template" not in text


# --- scope metadata (auditability) ---------------------------------------------------------

def test_scope_metadata_names_the_selected_scans(two_scan_project) -> None:
    ctx = two_scan_project
    data = _gather(ctx["wid"], ctx["pid"], [ctx["scan_a"], ctx["scan_b"]])

    assert data.is_scan_scoped() is True
    assert {s["id"] for s in data.scope_scans} == {ctx["scan_a"], ctx["scan_b"]}
    assert all(s["status"] == "completed" for s in data.scope_scans)
    assert len(data.scope_targets()) == 2  # each scan got its own target


def test_scope_metadata_never_invents_a_window(two_scan_project) -> None:
    """These seeded scans have no started_at/completed_at, so the window must stay empty
    rather than being fabricated."""
    ctx = two_scan_project
    data = _gather(ctx["wid"], ctx["pid"], [ctx["scan_a"]])
    assert data.scope_window() == (None, None)


def test_scoped_report_renders_and_states_its_scope(two_scan_project) -> None:
    import re

    from apps.api.modules.reports.render import render_technical
    from apps.api.tests.test_report_layout import _pdf_text

    ctx = two_scan_project
    data = _gather(ctx["wid"], ctx["pid"], [ctx["scan_a"]])
    text = re.sub(r"\s+", " ", _pdf_text(render_technical(data)))
    assert "scoped to" in text
    assert "security score" in text.lower()


# --- API / PDF parity ----------------------------------------------------------------------

@requires_storage
def test_api_persists_the_same_scope_it_rendered(client: TestClient, two_scan_project) -> None:
    """The stored `scan_ids` must describe the document that was actually produced -- the
    misdescription R-03 was really about."""
    ctx = two_scan_project
    resp = client.post(
        _reports_url(ctx["wid"], ctx["pid"]),
        headers=ctx["headers"],
        json={"type": "technical", "scan_ids": [str(ctx["scan_a"])]},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert [str(s) for s in body["scan_ids"]] == [str(ctx["scan_a"])]
    assert body["storage_uri"]


@requires_storage
def test_unscoped_request_still_succeeds_and_stores_no_scope(client: TestClient, two_scan_project) -> None:
    ctx = two_scan_project
    resp = client.post(
        _reports_url(ctx["wid"], ctx["pid"]),
        headers=ctx["headers"],
        json={"type": "executive"},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["scan_ids"] == []


# --- incomplete scans: the existing gate is unchanged --------------------------------------

def test_existing_completed_scan_gate_is_preserved(client: TestClient) -> None:
    """A project whose only scan never completed still cannot produce a report -- Phase 3.1
    must not have altered that lifecycle contract."""
    owner = _register(client, "Owner2")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    _seed_scan(wid, pid, status="running")

    resp = client.post(
        _reports_url(wid, pid), headers=headers, json={"type": "technical"}
    )
    assert resp.status_code == 409, resp.text


def test_an_incomplete_scan_may_be_named_as_scope(client: TestClient) -> None:
    """The DELIBERATE boundary, asserted as behaviour.

    The completed-scan gate is a PROJECT-level precondition ("is there anything worth
    reporting on?"), while `scan_ids` selects WHICH findings to report. Phase 3.1 did not
    couple them: requiring every named scan to be completed would be a new lifecycle rule, and
    the brief forbids changing lifecycle semantics. So a project that HAS a completed scan may
    legitimately scope a report to a still-running one -- and gets that scan's findings, which
    for a scan still in flight is usually none."""
    owner = _register(client, "Owner3")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    _seed_scan(wid, pid, status="completed")        # satisfies the project-level gate
    running = _seed_scan(wid, pid, status="running")

    data = _gather(wid, pid, [running])
    assert data.total_vulns == 0
    assert [s["status"] for s in data.scope_scans] == ["running"]


# --- CASE H: Phase 2 behaviour intact -------------------------------------------------------

def test_case_h_r01_issue_counts_still_work_under_scope(two_scan_project) -> None:
    ctx = two_scan_project
    data = _gather(ctx["wid"], ctx["pid"], [ctx["scan_a"]])
    assert data.total_issue_count() == 1
    assert data.total_vulns == 1


def test_case_h_r02_compliance_population_still_scorable_only(two_scan_project) -> None:
    """R-02's invariant under scope: whatever contributes to compliance must be a SUBSET of the
    scoped, scorable findings.

    Subset rather than equality: these seeded rows carry no `compliance_mappings` (there is no
    ingest here to create them), so the contributing set is legitimately empty. The property
    that matters -- and the one R-02 fixed -- is that nothing outside the scoped scorable
    population can ever contribute."""
    ctx = two_scan_project
    from apps.api.modules.reports.scoring import is_scorable

    data = _gather(ctx["wid"], ctx["pid"], [ctx["scan_a"]])
    contributing = {
        fid
        for _fw, controls in data.compliance_coverage()
        for _cid, _desc, ids in controls
        for fid in ids
    }
    scoped_scorable = {v.finding_id for v in data.vulns if is_scorable(v)}
    assert contributing <= scoped_scorable
    # And the scoped population itself is the ONE selected scan's finding, not the project's two.
    assert scoped_scorable == {data.vulns[0].finding_id}
    assert len(data.vulns) == 1


def test_case_h_r04_score_band_still_resolves(two_scan_project) -> None:
    from apps.api.modules.reports import _branding as B
    from apps.api.modules.reports.render import _score_band

    ctx = two_scan_project
    data = _gather(ctx["wid"], ctx["pid"], [ctx["scan_a"]])
    assert B.score_band_color(_score_band(data.security_score)) != B.MUTED
