"""Regression coverage for Prompt 13, Finding #3: verification must be coverage-aware.

Before this change, `complete_verification` derived PASSED/FAILED purely from which locations
the retest scan happened to touch (`Vulnerability.last_seen_scan_id == scan_id`) -- a location
the retest never re-visited silently dropped out of the live-count instead of blocking the
verdict. A multi-location issue could report PASSED even though the retest only re-examined
some of its original locations, and a scan whose only detection tool FAILED could still report
PASSED (zero live locations found, because nothing was found at all).

This file exercises the two independent new invariants in
apps/api/modules/remediation/verification.py:
  * `_retest_had_usable_detection_coverage` -- the linked scan must have at least one
    completed/partial ToolRun for a vulnerability-detection tool (nuclei/nuclei-dast), or the
    result is INCOMPLETE_COVERAGE regardless of what the vulnerabilities table shows.
  * `baseline_locations` (captured at request_verification time) + the coverage gate together
    close the "retest touched fewer locations than the issue actually has" gap -- though the
    concrete signal this codebase can act on is TOOL-LEVEL completion (see the module docstring
    for why per-location proof-of-absence isn't available from these tools), so the requirement
    enforced end-to-end here is: no scan lacking a real, completed detection pass can ever
    produce PASSED or FAILED -- only INCOMPLETE_COVERAGE.
"""
import uuid

from fastapi.testclient import TestClient

from apps.api.tests.test_remediation import (
    _auth,
    _register,
    _rem_base,
    _seed_findings,
    _workspace_project,
)
from apps.api.tests.test_remediation_verification import (
    _seed_scan,
    _set_last_seen,
    _to_in_progress,
)


def _request_and_complete(client, headers, wid, pid, item, scan_id):
    req = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers, json={"version": item["version"], "scan_id": str(scan_id)},
    ).json()
    resp = client.post(f"{_rem_base(wid, pid)}/verification/{req['id']}/complete", headers=headers)
    return resp


# --- full coverage: real detection tool ran, issue gone -> PASS -----------------------------

def test_full_coverage_and_issue_gone_passes(client: TestClient) -> None:
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    key = f"covpass{uuid.uuid4().hex[:6]}"
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": f"{key}|m|https://h/1", "title": "V", "severity": "high"},
    ])
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    item = _to_in_progress(client, headers, wid, pid, item)

    scan_id = _seed_scan(wid, pid, with_detection_coverage=True)
    _set_last_seen(wid, vuln_ids, scan_id, status="fixed")

    resp = _request_and_complete(client, headers, wid, pid, item, scan_id)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["result"] == "passed"
    assert body["detail"]["coverage_ok"] is True
    assert body["detail"]["uncovered_locations"] == []

    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert after["status"] == "verified"


# --- zero coverage: no ToolRun at all for the retest scan -> INCOMPLETE_COVERAGE -------------

def test_zero_coverage_reports_incomplete_not_pass(client: TestClient) -> None:
    """The exact regression this finding closes: a scan with NO detection ToolRun (simulating
    a scan that never actually ran nuclei -- e.g. it only ran recon tools, or ToolRun rows were
    lost) must never be read as a clean PASS merely because nothing shows as still-live."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    key = f"covzero{uuid.uuid4().hex[:6]}"
    _seed_findings(wid, pid, [
        {"fingerprint": f"{key}|m|https://h/1", "title": "V", "severity": "high"},
    ])
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    item = _to_in_progress(client, headers, wid, pid, item)

    # No ToolRun seeded at all -- this scan demonstrates NOTHING about detection coverage,
    # even though nothing points last_seen_scan_id at it either (the naive old behavior would
    # have read this as "zero live locations" -> PASSED).
    scan_id = _seed_scan(wid, pid, with_detection_coverage=False)

    resp = _request_and_complete(client, headers, wid, pid, item, scan_id)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["result"] == "incomplete_coverage"
    assert body["detail"]["coverage_ok"] is False

    # The item must be left exactly where it was -- neither verified (no proof) nor bounced to
    # in_progress (no proof it's still broken either).
    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert after["status"] == "awaiting_verification"
    assert after["verified_at"] is None


def test_failed_tool_run_reports_incomplete_not_pass(client: TestClient) -> None:
    """A ToolRun that exists but is `failed` (the orchestrator's own signal that its output was
    discarded as untrustworthy) must be treated the same as no coverage at all -- not as a
    completed detection pass that happened to find nothing."""
    import asyncio

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.scanner_engine.models import ToolRun

    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    key = f"covfail{uuid.uuid4().hex[:6]}"
    _seed_findings(wid, pid, [
        {"fingerprint": f"{key}|m|https://h/1", "title": "V", "severity": "high"},
    ])
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    item = _to_in_progress(client, headers, wid, pid, item)

    scan_id = _seed_scan(wid, pid, with_detection_coverage=False)

    async def _seed_failed_run():
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                with tenancy.workspace_scope(uuid.UUID(wid)):
                    session.add(ToolRun(
                        scan_id=scan_id, tool_name="nuclei", tool_version="test",
                        status="failed", command_hash="", error_message="crashed",
                    ))
                    await session.commit()
        finally:
            await engine.dispose()

    asyncio.run(_seed_failed_run())

    resp = _request_and_complete(client, headers, wid, pid, item, scan_id)
    assert resp.status_code == 200, resp.text
    assert resp.json()["result"] == "incomplete_coverage"

    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert after["status"] == "awaiting_verification"


def test_partial_tool_run_still_counts_as_coverage(client: TestClient) -> None:
    """A `partial` ToolRun (usable output despite a non-benign exit) is real coverage -- the
    orchestrator's own distinction between 'discard entirely' (failed) and 'still usable'
    (partial) is respected here rather than collapsed."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    key = f"covpartial{uuid.uuid4().hex[:6]}"
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": f"{key}|m|https://h/1", "title": "V", "severity": "high"},
    ])
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    item = _to_in_progress(client, headers, wid, pid, item)

    import asyncio

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.scanner_engine.models import ToolRun

    scan_id = _seed_scan(wid, pid, with_detection_coverage=False)

    async def _seed_partial_run():
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                with tenancy.workspace_scope(uuid.UUID(wid)):
                    session.add(ToolRun(
                        scan_id=scan_id, tool_name="nuclei", tool_version="test",
                        status="partial", command_hash="",
                    ))
                    await session.commit()
        finally:
            await engine.dispose()

    asyncio.run(_seed_partial_run())
    _set_last_seen(wid, vuln_ids, scan_id, status="fixed")

    resp = _request_and_complete(client, headers, wid, pid, item, scan_id)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["result"] == "passed"
    assert body["detail"]["coverage_ok"] is True


def test_vulnerability_still_detected_with_full_coverage_fails(client: TestClient) -> None:
    """A real detection pass that STILL finds the issue must report FAILED, not
    INCOMPLETE_COVERAGE -- coverage and outcome are independent axes."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    key = f"covstillup{uuid.uuid4().hex[:6]}"
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": f"{key}|m|https://h/1", "title": "V", "severity": "high"},
    ])
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    item = _to_in_progress(client, headers, wid, pid, item)

    scan_id = _seed_scan(wid, pid, with_detection_coverage=True)
    _set_last_seen(wid, vuln_ids, scan_id, status="open")

    resp = _request_and_complete(client, headers, wid, pid, item, scan_id)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["result"] == "failed"
    assert body["detail"]["coverage_ok"] is True

    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert after["status"] == "in_progress"


# --- baseline_locations snapshot behavior ----------------------------------------------------

def test_baseline_locations_is_snapshotted_at_request_time(client: TestClient) -> None:
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    key = f"covbase{uuid.uuid4().hex[:6]}"
    _seed_findings(wid, pid, [
        {"fingerprint": f"{key}|m|https://h/1", "title": "V", "severity": "high"},
        {"fingerprint": f"{key}|m|https://h/2", "title": "V", "severity": "high"},
    ])
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    item = _to_in_progress(client, headers, wid, pid, item)

    scan_id = _seed_scan(wid, pid, with_detection_coverage=True)
    req = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers, json={"version": item["version"], "scan_id": str(scan_id)},
    ).json()

    assert sorted(req["baseline_locations"]) == ["https://h/1", "https://h/2"]


def test_multiple_locations_all_covered_and_gone_passes(client: TestClient) -> None:
    """The positive multi-location case: baseline has 2 locations, the retest (real ToolRun)
    finds neither live -> PASS. Confirms the coverage gate does not block a genuine full-clear."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    key = f"covmulti{uuid.uuid4().hex[:6]}"
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": f"{key}|m|https://h/1", "title": "V", "severity": "high"},
        {"fingerprint": f"{key}|m|https://h/2", "title": "V", "severity": "high"},
    ])
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    item = _to_in_progress(client, headers, wid, pid, item)

    scan_id = _seed_scan(wid, pid, with_detection_coverage=True)
    # Request verification WHILE both locations are still live -- this is what makes the
    # baseline snapshot non-empty (matches the real workflow: request, then retest, then
    # complete). Only AFTER the request is the retest simulated as having cleared them.
    req = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers, json={"version": item["version"], "scan_id": str(scan_id)},
    ).json()
    assert sorted(req["baseline_locations"]) == ["https://h/1", "https://h/2"]

    _set_last_seen(wid, vuln_ids, scan_id, status="fixed")
    resp = client.post(f"{_rem_base(wid, pid)}/verification/{req['id']}/complete", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["result"] == "passed"
    assert sorted(body["detail"]["baseline_locations"]) == ["https://h/1", "https://h/2"]
    assert body["detail"]["uncovered_locations"] == []


# --- tenancy isolation ------------------------------------------------------------------------

def test_coverage_check_is_scoped_to_the_linked_scans_own_tool_runs(client: TestClient) -> None:
    """A completed detection ToolRun belonging to a DIFFERENT scan must not count as coverage
    for this verification's linked scan -- the coverage query filters by this scan_id only."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    key = f"covscoped{uuid.uuid4().hex[:6]}"
    _seed_findings(wid, pid, [
        {"fingerprint": f"{key}|m|https://h/1", "title": "V", "severity": "high"},
    ])
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    item = _to_in_progress(client, headers, wid, pid, item)

    # A DIFFERENT scan has real coverage, but is not the one linked to this verification.
    _seed_scan(wid, pid, with_detection_coverage=True)
    scan_id = _seed_scan(wid, pid, with_detection_coverage=False)

    resp = _request_and_complete(client, headers, wid, pid, item, scan_id)
    assert resp.status_code == 200, resp.text
    assert resp.json()["result"] == "incomplete_coverage"


def test_a_foreign_workspaces_tool_run_cannot_satisfy_coverage(client: TestClient) -> None:
    """CROSS-TENANT: a fully-qualifying detection ToolRun owned by ANOTHER workspace must not
    satisfy this workspace's coverage requirement.

    The test above proves scan-level scoping within one tenant. This one raises the bar to a
    tenant boundary, which matters here because `_retest_had_usable_detection_coverage` queries
    `tool_runs` by `scan_id` ALONE, with no workspace predicate -- and both `tool_runs` and
    `scans` are tenancy-EXEMPT, so the ORM's automatic workspace filter does NOT constrain that
    query. The isolation therefore rests entirely on chain of custody: `scan_id` is read off a
    VerificationRequest that was itself loaded under a workspace predicate, and
    `request_verification` refuses to link a scan that `_require_project_scan` cannot find in
    this workspace+project. That is an argument, not an assertion, so it is asserted here.

    The foreign workspace is given the STRONGER position deliberately: its ToolRun is
    `completed` on a real `nuclei` run -- exactly what `with_detection_coverage=True` seeds for
    the passing cases -- while this workspace's linked scan has none. If tenant isolation were
    to leak, the foreign run would be the thing that wrongly turns this verdict into PASSED.
    """
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)

    # A separate tenant, owned by a different user, with genuine detection coverage.
    other_owner = _register(client, "OtherOwner")
    other_headers = _auth(other_owner)
    other_wid, other_pid = _workspace_project(client, other_headers)
    _seed_scan(other_wid, other_pid, with_detection_coverage=True)

    key = f"covforeign{uuid.uuid4().hex[:6]}"
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": f"{key}|m|https://h/1", "title": "V", "severity": "high"},
    ])
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    item = _to_in_progress(client, headers, wid, pid, item)

    # THIS workspace's retest has NO detection coverage of its own.
    scan_id = _seed_scan(wid, pid, with_detection_coverage=False)
    # Mark the finding fixed, so the ONLY thing standing between this verdict and a wrong
    # PASSED is the coverage gate refusing to borrow the foreign workspace's ToolRun.
    _set_last_seen(wid, vuln_ids, scan_id, status="fixed")

    resp = _request_and_complete(client, headers, wid, pid, item, scan_id)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["result"] == "incomplete_coverage"
    assert body["detail"]["coverage_ok"] is False

    # And the item was NOT verified off another tenant's evidence.
    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert after["status"] != "verified"
