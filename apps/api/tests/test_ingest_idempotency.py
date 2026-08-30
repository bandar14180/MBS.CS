"""Duplicate-finding resilience across the ingest path.

A real full scan crashed like this: nuclei-dast emitted the same template match on the same
URL more than once (it re-hits a template while fuzzing a URL's parameters). Every finding in
one tool run shares that run's single evidence row, so the duplicates deduped to the SAME
vulnerability and then both tried to INSERT the same (vulnerability_id, evidence_id) PK. That
raised a 1062 IntegrityError, which left the scan's Session in PendingRollbackError state --
and the failure handler then crashed too, accessing `scan.id` on the poisoned session instead
of marking the scan failed, so it sat 'running' until the reaper recovered it hours later.

Three independent defences are asserted here:
  * the ingest link is idempotent (INSERT ... ON DUPLICATE KEY), so the duplicate never
    raises in the first place;
  * the nuclei parser (inherited by nuclei-dast) collapses duplicate fingerprints per run;
  * the run_scan failure handler rolls back before finalizing, so an ingest error still
    lands the scan in a clean 'failed' state.
"""
import asyncio
import uuid

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.users.models import User
from apps.api.modules.scans.models import Scan
from apps.api.modules.vulnerabilities.models import VulnerabilityEvidence
from apps.api.modules.vulnerabilities.service import ingest_finding
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.models import Evidence, ToolRun
from apps.api.scanner_engine.tool_runners.base import RawToolOutput, VulnerabilityFinding
from apps.api.scanner_engine.tool_runners.nuclei_dast_runner import NucleiDastRunner
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _seed_scan_and_evidence(s):
    """A project/scan/tool_run/evidence graph to hang vulnerability_evidence off of."""
    user = User(email=f"ing-{uuid.uuid4()}@test.local", password_hash="x", full_name="Ingest Tester")
    s.add(user)
    await s.flush()
    ws = Workspace(name="ing-ws", owner_user_id=user.id)
    s.add(ws)
    await s.flush()
    project = Project(workspace_id=ws.id, name="ing-proj", created_by=user.id)
    s.add(project)
    await s.flush()
    target = Target(project_id=project.id, type="domain", value="ex.test", criticality="low", added_by=user.id)
    s.add(target)
    await s.flush()
    scan = Scan(
        workspace_id=ws.id, project_id=project.id, target_id=target.id, initiated_by=user.id,
        scan_type="web", status="running", config={}, execution_token=uuid.uuid4(),
    )
    s.add(scan)
    await s.flush()
    tool_run = ToolRun(scan_id=scan.id, tool_name="nuclei-dast", tool_version="3", status="running", command_hash="")
    s.add(tool_run)
    await s.flush()
    evidence = Evidence(
        tool_run_id=tool_run.id, evidence_type="log", storage_uri="s3://x/y", checksum="0" * 64
    )
    s.add(evidence)
    await s.flush()
    return project.id, scan.id, tool_run.id, evidence.id, ws.id


def _finding(fp_suffix: str = "a") -> VulnerabilityFinding:
    return VulnerabilityFinding(
        fingerprint=f"tpl|matcher|https://ex.test/{fp_suffix}",
        title="Test finding",
        severity="high",
        category="CWE-79",
        description="d",
        matched_at="https://ex.test/",
    )


def test_linking_the_same_vuln_evidence_pair_twice_does_not_raise():
    """The exact crash: two findings in one run dedupe to the same vuln, then both link the
    same (vuln, evidence). ingest_finding must be idempotent, not raise a duplicate-key error."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                pid, sid, trid, eid, wsid = await _seed_scan_and_evidence(s)
                with tenancy.workspace_scope(wsid):
                    f = _finding()
                    v1 = await ingest_finding(s, project_id=pid, scan_id=sid, finding=f, tool_run_id=trid, evidence_id=eid)
                    # SAME fingerprint -> SAME vulnerability -> SAME (vuln, evidence) link.
                    v2 = await ingest_finding(s, project_id=pid, scan_id=sid, finding=f, tool_run_id=trid, evidence_id=eid)
                    await s.commit()
                    assert v1.id == v2.id
                    links = (await s.execute(
                        select(VulnerabilityEvidence).where(
                            VulnerabilityEvidence.vulnerability_id == v1.id,
                            VulnerabilityEvidence.evidence_id == eid,
                        )
                    )).scalars().all()
                    assert len(links) == 1, "the pair must be linked exactly once"
                    assert links[0].tool_run_id == trid, "tool_run_id must be preserved"
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_a_second_distinct_finding_still_creates_its_own_link():
    """Idempotency must not collapse genuinely different findings that share the evidence row."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                pid, sid, trid, eid, wsid = await _seed_scan_and_evidence(s)
                with tenancy.workspace_scope(wsid):
                    va = await ingest_finding(s, project_id=pid, scan_id=sid, finding=_finding("a"), tool_run_id=trid, evidence_id=eid)
                    vb = await ingest_finding(s, project_id=pid, scan_id=sid, finding=_finding("b"), tool_run_id=trid, evidence_id=eid)
                    await s.commit()
                    assert va.id != vb.id
                    total = (await s.execute(
                        select(VulnerabilityEvidence).where(VulnerabilityEvidence.evidence_id == eid)
                    )).scalars().all()
                    assert len(total) == 2
        finally:
            await engine.dispose()

    asyncio.run(scenario())


# --- parser-level dedup (no DB) ------------------------------------------------------------

def _dast_line(url: str, template="cve-2021-1", matcher="m1"):
    import json
    return json.dumps({
        "template-id": template, "matcher-name": matcher, "matched-at": url,
        "info": {"name": "X", "severity": "high"},
    })


def test_nuclei_parser_dedupes_identical_fingerprints_in_one_run():
    raw = RawToolOutput(
        command="nuclei",
        stdout="\n".join([
            _dast_line("https://ex.test/a"),
            _dast_line("https://ex.test/a"),   # exact duplicate fingerprint
            _dast_line("https://ex.test/b"),   # distinct
        ]),
        stderr="",
        exit_code=0,
    )
    findings = NucleiRunner().parse_vulnerabilities(raw)
    fps = [f.fingerprint for f in findings]
    assert len(fps) == len(set(fps)), "duplicate fingerprints were not collapsed"
    assert len(findings) == 2


def test_nuclei_dast_inherits_the_dedupe():
    """NucleiDastRunner uses NucleiRunner.parse_vulnerabilities -- the fix must apply to it."""
    assert NucleiDastRunner.parse_vulnerabilities is NucleiRunner.parse_vulnerabilities
    raw = RawToolOutput(
        command="nuclei -dast",
        stdout="\n".join([_dast_line("https://ex.test/x")] * 3),   # same template+url x3
        stderr="",
        exit_code=0,
    )
    findings = NucleiDastRunner().parse_vulnerabilities(raw)
    assert len(findings) == 1


def test_dedupe_does_not_change_the_fingerprint_format():
    raw = RawToolOutput(command="nuclei", stdout=_dast_line("https://ex.test/z", template="tpl", matcher="mm"), stderr="", exit_code=0)
    findings = NucleiRunner().parse_vulnerabilities(raw)
    assert findings[0].fingerprint == "tpl|mm|https://ex.test/z"


# --- P0: the failure handler recovers a poisoned session -----------------------------------

def test_finalize_after_poisoned_session_needs_rollback_first():
    """Reproduce the PendingRollbackError mechanism and prove rollback fixes it.

    A failed flush (here: a real duplicate-PK insert) leaves the Session poisoned -- the very
    next statement, and even a lazy `scan.id` load, re-raises PendingRollbackError. This is
    what crashed run_scan's failure handler before it could mark the scan failed. After
    db.rollback() (what the handler now does first), _finalize_status runs cleanly and the
    scan lands 'failed'."""
    from sqlalchemy.exc import IntegrityError, PendingRollbackError

    from apps.api.scanner_engine.orchestrator import _finalize_status, _load_scan

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                pid, sid, trid, eid, wsid = await _seed_scan_and_evidence(s)
                await s.commit()
                scan = await _load_scan(s, sid)
                token = scan.execution_token

                # Poison the session with the EXACT IntegrityError the real bug hit. First
                # ensure the pair exists (committed) via a raw insert -- committed and
                # order-independent, so pollution from another test cannot change the outcome.
                # Then add a NEW ORM VulnerabilityEvidence for the SAME PK: an ORM *flush*
                # failure is what leaves the session in PendingRollbackError (a raw execute
                # failure does not), which is precisely the state the real bug produced.
                v = await ingest_finding(
                    s, project_id=pid, scan_id=sid, finding=_finding(), tool_run_id=trid, evidence_id=eid
                )
                await s.commit()
                s.add(VulnerabilityEvidence(vulnerability_id=v.id, evidence_id=eid, tool_run_id=trid))
                raised = False
                try:
                    await s.flush()
                except IntegrityError:
                    raised = True
                assert raised, "expected the duplicate ORM insert to fail the flush"

                # Session is now poisoned: touching it re-raises until rollback.
                try:
                    await s.execute(text("SELECT 1"))
                    poisoned = False
                except PendingRollbackError:
                    poisoned = True
                assert poisoned, "session should be in PendingRollbackError state"

                # The fix: roll back first, THEN finalize. run_scan holds a live session and
                # its `scan` object across this; re-load after rollback to mirror that cleanly.
                await s.rollback()
                scan = await _load_scan(s, sid)
                won = await _finalize_status(s, scan, "failed", token)
                assert won is True

                final = (await s.execute(
                    text("SELECT status FROM scans WHERE id = :i"), {"i": str(sid)}
                )).scalar()
                assert final == "failed"
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_ownership_fence_still_blocks_finalize_after_rollback():
    """The rollback must not weaken the ownership fence: a WRONG token still cannot finalize."""
    from apps.api.scanner_engine.orchestrator import _finalize_status, _load_scan

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                _pid, sid, _trid, _eid, _wsid = await _seed_scan_and_evidence(s)
                await s.commit()
                await s.rollback()
                scan = await _load_scan(s, sid)
                won = await _finalize_status(s, scan, "failed", uuid.uuid4())  # not the owner
                assert won is False, "a non-owning token must not win the terminal write"
                still = (await s.execute(
                    text("SELECT status FROM scans WHERE id = :i"), {"i": str(sid)}
                )).scalar()
                assert still == "running", "the scan must stay running when the fence blocks"
        finally:
            await engine.dispose()

    asyncio.run(scenario())
