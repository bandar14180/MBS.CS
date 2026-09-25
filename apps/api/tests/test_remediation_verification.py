"""Verification, evidence, and the regression relink.

The central claim under test: a remediation item can reach `verified` ONLY through a real
retest, and the outcome is DERIVED from what that retest observed -- never asserted by a
caller, an AI response, an uploaded file, or a boolean.
"""
import uuid

from fastapi.testclient import TestClient

from apps.api.tests.test_remediation import (
    _auth,
    _make_item,
    _register,
    _rem_base,
    _seed_findings,
    _transition,
    _workspace_project,
)


def _seed_scan(wid: str, pid: str, status: str = "completed", *, with_detection_coverage: bool = True) -> uuid.UUID:
    """A completed scan row to hang a retest off.

    `scans` is tenancy-EXEMPT (the worker bootstraps from it before the workspace is known),
    so it needs a target + initiated_by but no workspace binding to insert.

    `with_detection_coverage=True` (the default) also seeds a completed `nuclei` ToolRun for
    this scan -- the real-world signal Prompt 13, Finding #3's coverage check
    (`_retest_had_usable_detection_coverage`) requires before `complete_verification` may
    report PASSED/FAILED rather than INCOMPLETE_COVERAGE. Every test in this file simulating a
    genuine retest wants this; pass False only to specifically exercise the no-coverage path."""
    import asyncio

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.modules.projects.models import Project, Target
    from apps.api.modules.scans.models import Scan
    from apps.api.scanner_engine.models import ToolRun

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
                    await session.flush()
                    if with_detection_coverage:
                        session.add(ToolRun(
                            scan_id=scan.id, tool_name="nuclei", tool_version="test",
                            status="completed", command_hash="",
                        ))
                    await session.commit()
                    return scan.id
        finally:
            await engine.dispose()

    return asyncio.run(_run())


def _set_last_seen(wid: str, vuln_ids, scan_id: uuid.UUID, status: str | None = None) -> None:
    """Point findings at a scan (and optionally change their status), simulating what a retest
    leaves behind."""
    import asyncio

    from sqlalchemy import update
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
                    values = {"last_seen_scan_id": scan_id}
                    if status is not None:
                        values["status"] = status
                    await session.execute(
                        update(Vulnerability)
                        .where(Vulnerability.id.in_(list(vuln_ids)))
                        .values(**values)
                    )
                    await session.commit()
        finally:
            await engine.dispose()

    asyncio.run(_run())


def _to_in_progress(client, headers, wid, pid, item):
    """proposed -> accepted -> in_progress: the state from which verification may be requested.

    Named for where it actually lands. Requesting verification is what moves an item to
    `awaiting_verification`, so a helper that stopped here but claimed otherwise would make
    every caller assert the wrong state."""
    item = _transition(client, headers, wid, pid, item, "accepted").json()
    return _transition(client, headers, wid, pid, item, "in_progress").json()


# =============================================================================================
# VERIFICATION (requirements 11, 20)
# =============================================================================================

def test_verification_requires_a_real_retest_scan(client: TestClient) -> None:
    """A request with NO linked scan cannot be completed. Without a retest there is nothing to
    derive an outcome from, and inventing one is exactly what this design forbids."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"noscan{uuid.uuid4().hex[:6]}")
    item = _to_in_progress(client, headers, wid, pid, item)

    req = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers, json={"version": item["version"]},
    )
    assert req.status_code == 201, req.text
    assert req.json()["status"] == "pending"
    assert req.json()["result"] is None

    resp = client.post(
        f"{_rem_base(wid, pid)}/verification/{req.json()['id']}/complete", headers=headers
    )
    assert resp.status_code == 409, resp.text
    assert "without a retest scan" in resp.json()["detail"]

    # And the item is still NOT verified.
    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert after["status"] == "awaiting_verification"
    assert after["verified_at"] is None


def test_verification_passes_when_the_retest_finds_the_issue_gone(client: TestClient) -> None:
    """PASSED is derived from the retest observing ZERO live locations for this issue."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    key = f"vpass{uuid.uuid4().hex[:6]}"
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": f"{key}|m|https://h/1", "title": "V", "severity": "high"},
    ])
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    item = _to_in_progress(client, headers, wid, pid, item)

    scan_id = _seed_scan(wid, pid)
    # The retest saw the finding and it is now FIXED -> not scorable -> zero live locations.
    _set_last_seen(wid, vuln_ids, scan_id, status="fixed")

    req = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers, json={"version": item["version"], "scan_id": str(scan_id)},
    ).json()
    resp = client.post(f"{_rem_base(wid, pid)}/verification/{req['id']}/complete", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["result"] == "passed"
    assert body["status"] == "completed"
    # The verdict carries its REPRODUCIBLE basis, not prose.
    assert body["detail"]["live_locations"] == 0
    assert body["detail"]["scan_id"] == str(scan_id)

    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert after["status"] == "verified"
    assert after["verified_at"] is not None


def test_verification_fails_and_reopens_the_work_when_the_issue_is_still_live(
    client: TestClient
) -> None:
    """FAILED sends the item back to in_progress -- a failed fix must reopen the work, not
    silently stall at awaiting_verification."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    key = f"vfail{uuid.uuid4().hex[:6]}"
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": f"{key}|m|https://h/1", "title": "V", "severity": "high"},
    ])
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    item = _to_in_progress(client, headers, wid, pid, item)

    scan_id = _seed_scan(wid, pid)
    # The retest re-detected it: still open, still scorable.
    _set_last_seen(wid, vuln_ids, scan_id, status="open")

    req = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers, json={"version": item["version"], "scan_id": str(scan_id)},
    ).json()
    resp = client.post(f"{_rem_base(wid, pid)}/verification/{req['id']}/complete", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["result"] == "failed"
    assert resp.json()["detail"]["live_locations"] == 1

    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert after["status"] == "in_progress"
    assert after["verified_at"] is None


def test_complete_verification_takes_no_result_argument() -> None:
    """STRUCTURAL guarantee for "AI cannot mark something verified": there is no parameter on
    the completion path through which any caller could assert an outcome."""
    import inspect

    from apps.api.modules.remediation.verification import complete_verification

    params = set(inspect.signature(complete_verification).parameters)
    for forbidden in ("passed", "result", "outcome", "verified", "success"):
        assert forbidden not in params, f"complete_verification accepts a caller-set '{forbidden}'"


def test_verification_completion_body_is_empty() -> None:
    """The HTTP surface matches the service signature: the completion endpoint accepts no
    request body, so there is nothing for a client to put a result in."""
    from apps.api.main import create_app

    spec = create_app().openapi()
    path = next(p for p in spec["paths"] if p.endswith("/verification/{request_id}/complete"))
    assert "requestBody" not in spec["paths"][path]["post"]


def test_atomic_claim_admits_exactly_one_worker(client: TestClient) -> None:
    """requirement 20: two workers, one request. The conditional UPDATE decides the winner."""
    import asyncio

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.modules.remediation.verification import claim_verification

    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"claim{uuid.uuid4().hex[:6]}")
    item = _to_in_progress(client, headers, wid, pid, item)
    req = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers, json={"version": item["version"]},
    ).json()

    async def _race() -> list[bool]:
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        results = []
        try:
            for _ in range(3):
                async with maker() as session:
                    with tenancy.workspace_scope(uuid.UUID(wid)):
                        results.append(
                            await claim_verification(session, uuid.UUID(req["id"]), uuid.uuid4())
                        )
        finally:
            await engine.dispose()
        return results

    outcomes = asyncio.run(_race())
    assert outcomes.count(True) == 1, f"expected exactly one winning claim, got {outcomes}"
    assert outcomes.count(False) == 2


def test_second_outstanding_verification_request_is_refused(client: TestClient) -> None:
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"dupreq{uuid.uuid4().hex[:6]}")
    item = _to_in_progress(client, headers, wid, pid, item)

    first = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers, json={"version": item["version"]},
    )
    assert first.status_code == 201, first.text

    reread = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    second = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers, json={"version": reread["version"]},
    )
    assert second.status_code == 409, second.text


def test_verification_rejects_a_scan_from_another_workspace(client: TestClient) -> None:
    """A body-supplied scan id is never trusted: one belonging to another tenant must 404."""
    owner_a = _register(client, "OwnerA")
    headers_a = _auth(owner_a)
    wid_a, pid_a = _workspace_project(client, headers_a)

    owner_b = _register(client, "OwnerB")
    headers_b = _auth(owner_b)
    wid_b, pid_b = _workspace_project(client, headers_b)
    foreign_scan = _seed_scan(wid_b, pid_b)

    item = _make_item(client, headers_a, wid_a, pid_a, f"xscan{uuid.uuid4().hex[:6]}")
    item = _to_in_progress(client, headers_a, wid_a, pid_a, item)

    resp = client.post(
        f"{_rem_base(wid_a, pid_a)}/{item['id']}/verification",
        headers=headers_a, json={"version": item["version"], "scan_id": str(foreign_scan)},
    )
    assert resp.status_code == 404, resp.text


def test_verification_cannot_be_requested_from_proposed(client: TestClient) -> None:
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"early{uuid.uuid4().hex[:6]}")

    resp = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers, json={"version": item["version"]},
    )
    assert resp.status_code == 409, resp.text


# =============================================================================================
# EVIDENCE (requirements 2, 18, and section 9)
# =============================================================================================

def test_remediation_evidence_upload_records_checksum_uploader_and_workspace_prefix(
    client: TestClient
) -> None:
    """Uploaded proof gets a SHA-256, an uploader, a workspace-prefixed key, and a NULL
    tool_run_id -- no fabricated tool run."""
    import base64
    import hashlib

    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"ev{uuid.uuid4().hex[:6]}")

    content = b"--- a/handler.py\n+++ b/handler.py\n- eval(user_input)\n+ safe_parse(user_input)\n"
    resp = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/evidence",
        headers=headers,
        json={
            "filename": "fix.patch",
            "content_type": "text/plain",
            "content_base64": base64.b64encode(content).decode(),
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()

    assert body["checksum"] == hashlib.sha256(content).hexdigest()
    assert body["evidence_type"] == "remediation_proof"
    assert body["uploaded_by"] is not None
    # NOT fabricated -- human proof has no tool run.
    assert body["tool_run_id"] is None
    # WORKSPACE-PREFIXED key (requirement 18).
    assert f"workspaces/{wid}/remediation/{item['id']}/" in body["storage_uri"]
    # The client-supplied filename never reaches the key.
    assert "fix.patch" not in body["storage_uri"]

    listing = client.get(f"{_rem_base(wid, pid)}/{item['id']}/evidence", headers=headers).json()
    assert [e["id"] for e in listing] == [body["id"]]


def test_uploading_evidence_does_not_verify_anything(client: TestClient) -> None:
    """An uploaded file is proof of WORK, never technical proof the vulnerability is gone."""
    import base64

    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"evnv{uuid.uuid4().hex[:6]}")
    item = _to_in_progress(client, headers, wid, pid, item)

    resp = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/evidence",
        headers=headers,
        json={"filename": "proof.txt", "content_base64": base64.b64encode(b"fixed, honest").decode()},
    )
    assert resp.status_code == 201, resp.text

    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    # Unmoved: uploading a file is not a transition, and certainly not a verification.
    assert after["status"] == "in_progress"
    assert after["verified_at"] is None


def test_evidence_is_not_readable_from_another_workspace(client: TestClient) -> None:
    """Evidence access is bounded by the authorized workspace/project, resolved through the
    item -- a guessed evidence id from another tenant reaches nothing."""
    import base64

    owner_a = _register(client, "OwnerA")
    headers_a = _auth(owner_a)
    wid_a, pid_a = _workspace_project(client, headers_a)
    item_a = _make_item(client, headers_a, wid_a, pid_a, f"evx{uuid.uuid4().hex[:6]}")
    client.post(
        f"{_rem_base(wid_a, pid_a)}/{item_a['id']}/evidence",
        headers=headers_a,
        json={"filename": "s.txt", "content_base64": base64.b64encode(b"secret").decode()},
    )

    owner_b = _register(client, "OwnerB")
    headers_b = _auth(owner_b)
    wid_b, pid_b = _workspace_project(client, headers_b)

    resp = client.get(f"{_rem_base(wid_b, pid_b)}/{item_a['id']}/evidence", headers=headers_b)
    assert resp.status_code == 404, resp.text


def test_malformed_base64_is_rejected_rather_than_silently_truncated(client: TestClient) -> None:
    """Strict decoding: a truncated artifact whose checksum then certifies the WRONG bytes is
    worse than a clear error."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"b64{uuid.uuid4().hex[:6]}")

    resp = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/evidence",
        headers=headers, json={"filename": "x.bin", "content_base64": "!!!not base64!!!"},
    )
    assert resp.status_code == 400, resp.text


def test_scanner_evidence_still_works_with_a_tool_run(client: TestClient) -> None:
    """The nullable widening must not break EXISTING scanner evidence, which still carries a
    tool_run_id and is still reachable through the scan API."""
    import asyncio

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.scanner_engine.models import Evidence, ToolRun

    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    scan_id = _seed_scan(wid, pid)

    async def _seed() -> tuple[uuid.UUID, uuid.UUID]:
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                with tenancy.workspace_scope(uuid.UUID(wid)):
                    run = ToolRun(
                        scan_id=scan_id, tool_name="nuclei", tool_version="3",
                        status="completed", command_hash="abc",
                    )
                    session.add(run)
                    await session.flush()
                    ev = Evidence(
                        tool_run_id=run.id, evidence_type="raw_output",
                        storage_uri=f"s3://bucket/tool-runs/{run.id}/raw-output.txt",
                        checksum="0" * 64,
                    )
                    session.add(ev)
                    await session.commit()
                    return run.id, ev.id
        finally:
            await engine.dispose()

    run_id, ev_id = asyncio.run(_seed())

    resp = client.get(
        f"/api/v1/workspaces/{wid}/projects/{pid}/scans/{scan_id}/tool-runs/{run_id}/evidence",
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    rows = resp.json()
    assert [r["id"] for r in rows] == [str(ev_id)]
    assert rows[0]["tool_run_id"] == str(run_id)


# =============================================================================================
# REGRESSION RELINK (requirement 34)
# =============================================================================================

def test_fixed_reopened_relinks_remediation_item(client: TestClient) -> None:
    """The regression path: a `fixed` finding that a re-scan re-detects flips to `reopened`,
    AND its remediation item follows -- it must not sit at verified/closed while the issue is
    demonstrably live again."""
    import asyncio

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.modules.vulnerabilities.models import Vulnerability
    from apps.api.modules.vulnerabilities.service import ingest_finding
    from apps.api.scanner_engine.models import Evidence, ToolRun
    from apps.api.scanner_engine.tool_runners.base import VulnerabilityFinding

    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    key = f"regress{uuid.uuid4().hex[:6]}"
    fingerprint = f"{key}|matcher|https://h/1"
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": fingerprint, "title": "Regression Issue", "severity": "high"},
    ])

    # A remediation item exists and has been driven to `closed`.
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    item = _to_in_progress(client, headers, wid, pid, item)
    scan_one = _seed_scan(wid, pid)
    _set_last_seen(wid, vuln_ids, scan_one, status="fixed")
    req = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers, json={"version": item["version"], "scan_id": str(scan_one)},
    ).json()
    client.post(f"{_rem_base(wid, pid)}/verification/{req['id']}/complete", headers=headers)
    verified = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert verified["status"] == "verified"
    closed = _transition(client, headers, wid, pid, verified, "closed").json()
    assert closed["status"] == "closed"

    # A LATER scan re-detects the same fingerprint -> the engine's regression path runs.
    scan_two = _seed_scan(wid, pid)

    async def _reingest() -> str:
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                with tenancy.workspace_scope(uuid.UUID(wid)):
                    run = ToolRun(
                        scan_id=scan_two, tool_name="nuclei", tool_version="3",
                        status="completed", command_hash="x",
                    )
                    session.add(run)
                    await session.flush()
                    ev = Evidence(
                        tool_run_id=run.id, evidence_type="raw_output",
                        storage_uri="s3://b/k", checksum="1" * 64,
                    )
                    session.add(ev)
                    await session.flush()

                    finding = VulnerabilityFinding(
                        fingerprint=fingerprint, title="Regression Issue",
                        severity="high", description="back again",
                    )
                    await ingest_finding(
                        session, uuid.UUID(pid), scan_two, finding, run.id, ev.id
                    )
                    await session.commit()

                    vuln = await session.scalar(
                        select(Vulnerability).where(Vulnerability.id == vuln_ids[0])
                    )
                    return vuln.status
        finally:
            await engine.dispose()

    assert asyncio.run(_reingest()) == "reopened", "the finding itself must flip fixed -> reopened"

    # THE POINT: the same remediation item followed, and no duplicate was created.
    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert after["status"] == "reopened"
    assert after["resolved_at"] is None
    assert after["verified_at"] is None

    all_items = client.get(_rem_base(wid, pid), headers=headers).json()
    matching = [i for i in all_items if i["issue_key"] == f"template:{key}"]
    assert len(matching) == 1, "a regression must reuse the existing item, never create a second"

    events = client.get(f"{_rem_base(wid, pid)}/{item['id']}/events", headers=headers).json()
    reopen_events = [e for e in events if e["to_status"] == "reopened"]
    assert reopen_events, "the regression must be recorded on the item timeline"
    # The ENGINE acted, not a person -- attributing it to a user would be a false actor.
    assert reopen_events[-1]["actor_user_id"] is None
