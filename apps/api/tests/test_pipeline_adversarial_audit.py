"""Prompt 37 -- adversarial audit of the full pipeline.

Safe, controlled adversarial probes against the trust boundaries the pipeline actually has:

    Target -> Scope -> Discovery -> Detection -> Verification -> Correlation -> Evidence
    -> Finding -> Reporting

Each test states the ATTACK it models. Nothing here performs destructive exploitation, adds a
scanner runner, or sends traffic to a real target.

SCOPE NOTE (limitation, not omission): this codebase has NO TestPlan or Knowledge-Model/ASKG
subsystem -- see the batch report. Those pipeline stages therefore cannot be adversarially
tested here, and the prompt forbids inventing them. Everything downstream of Detection is
tested against the real implementation.
"""
import uuid

import pytest
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


def _request_verification(client, headers, wid, pid, item, scan_id, expect=None):
    resp = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers,
        json={"version": item["version"], "scan_id": str(scan_id)},
    )
    if expect is not None:
        assert resp.status_code == expect, resp.text
    return resp


def _complete(client, headers, wid, pid, request_id):
    return client.post(
        f"{_rem_base(wid, pid)}/verification/{request_id}/complete", headers=headers
    )


def _item_with_finding(client, headers, wid, pid, key_prefix="adv"):
    key = f"{key_prefix}{uuid.uuid4().hex[:6]}"
    vuln_ids = _seed_findings(
        wid, pid, [{"fingerprint": f"{key}|m|https://h/1", "title": "V", "severity": "high"}]
    )
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    return _to_in_progress(client, headers, wid, pid, item), vuln_ids


# =====================================================================================
# FALSE VERIFIED
# =====================================================================================


def test_caller_cannot_assert_a_verification_result(client: TestClient) -> None:
    """ATTACK: client declares its own fix verified by passing a result/passed flag.

    The defence is structural -- `complete_verification` takes no outcome argument -- so an
    injected field must be ignored rather than honoured."""
    headers = _auth(_register(client, "Owner"))
    wid, pid = _workspace_project(client, headers)
    item, vuln_ids = _item_with_finding(client, headers, wid, pid)

    scan_id = _seed_scan(wid, pid, with_detection_coverage=True)
    # The finding is STILL LIVE -- a truthful retest must report failed.
    _set_last_seen(wid, vuln_ids, scan_id)

    req = _request_verification(client, headers, wid, pid, item, scan_id).json()
    resp = client.post(
        f"{_rem_base(wid, pid)}/verification/{req['id']}/complete",
        headers=headers,
        json={"result": "passed", "passed": True, "status": "verified"},
    )
    assert resp.status_code == 200, resp.text
    # The injected assertion is ignored; the evidence decides.
    assert resp.json()["result"] == "failed"

    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert after["status"] != "verified"


def test_verification_without_a_retest_scan_is_refused(client: TestClient) -> None:
    """ATTACK: complete a verification with no retest at all, hoping for a default PASS."""
    headers = _auth(_register(client, "Owner"))
    wid, pid = _workspace_project(client, headers)
    item, _ = _item_with_finding(client, headers, wid, pid)

    req = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers,
        json={"version": item["version"]},
    ).json()
    resp = _complete(client, headers, wid, pid, req["id"])
    assert resp.status_code == 409
    assert "without a retest scan" in resp.text


def test_failed_detection_pass_cannot_yield_verified(client: TestClient) -> None:
    """ATTACK: link a retest whose detection tool never ran. Zero findings observed must mean
    'we did not look', not 'it is fixed'."""
    headers = _auth(_register(client, "Owner"))
    wid, pid = _workspace_project(client, headers)
    item, vuln_ids = _item_with_finding(client, headers, wid, pid)

    scan_id = _seed_scan(wid, pid, with_detection_coverage=False)
    _set_last_seen(wid, vuln_ids, scan_id, status="fixed")

    req = _request_verification(client, headers, wid, pid, item, scan_id).json()
    body = _complete(client, headers, wid, pid, req["id"]).json()
    assert body["result"] == "incomplete_coverage"
    assert body["detail"]["coverage_ok"] is False

    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert after["status"] != "verified"


def test_in_flight_retest_scan_cannot_verify(client: TestClient) -> None:
    """REGRESSION (Prompt 37, reproduced defect): a still-RUNNING scan must not verify.

    Before the fix, linking an in-flight scan whose first detection ToolRun had already
    completed satisfied the coverage gate, `_live_locations` counted only what had been
    ingested so far (zero), and the item was driven to `verified` -- a PASS from a retest
    that had not finished looking."""
    headers = _auth(_register(client, "Owner"))
    wid, pid = _workspace_project(client, headers)
    item, vuln_ids = _item_with_finding(client, headers, wid, pid)

    running_scan = _seed_scan(wid, pid, status="running", with_detection_coverage=True)
    _set_last_seen(wid, vuln_ids, running_scan, status="fixed")

    resp = _request_verification(client, headers, wid, pid, item, running_scan)
    assert resp.status_code == 409, resp.text
    assert "still in progress" in resp.text

    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert after["status"] != "verified"


@pytest.mark.parametrize("status", ["queued", "running"])
def test_no_unfinished_scan_status_can_verify(client: TestClient, status: str) -> None:
    """Every non-terminal lifecycle state must be refused, not just `running`."""
    headers = _auth(_register(client, "Owner"))
    wid, pid = _workspace_project(client, headers)
    item, _ = _item_with_finding(client, headers, wid, pid)

    scan_id = _seed_scan(wid, pid, status=status, with_detection_coverage=True)
    assert _request_verification(client, headers, wid, pid, item, scan_id).status_code == 409


def test_finished_but_failed_scan_is_linkable_and_reports_incomplete(client: TestClient) -> None:
    """A `failed` scan IS finished, so it must stay linkable: the coverage gate then gives the
    precise INCOMPLETE_COVERAGE outcome rather than a blunt refusal."""
    headers = _auth(_register(client, "Owner"))
    wid, pid = _workspace_project(client, headers)
    item, vuln_ids = _item_with_finding(client, headers, wid, pid)

    scan_id = _seed_scan(wid, pid, status="failed", with_detection_coverage=False)
    _set_last_seen(wid, vuln_ids, scan_id, status="fixed")

    req = _request_verification(client, headers, wid, pid, item, scan_id, expect=201).json()
    assert _complete(client, headers, wid, pid, req["id"]).json()["result"] == "incomplete_coverage"


# =====================================================================================
# CROSS-TENANT / EVIDENCE SUBSTITUTION
# =====================================================================================


def test_retest_scan_from_another_tenant_is_refused(client: TestClient) -> None:
    """ATTACK: substitute another workspace's clean scan as this item's retest evidence.

    This is the evidence-substitution path: if it worked, tenant A could mark its own issue
    verified using tenant B's unrelated scan."""
    owner_a = _auth(_register(client, "A"))
    owner_b = _auth(_register(client, "B"))
    wid_a, pid_a = _workspace_project(client, owner_a)
    wid_b, pid_b = _workspace_project(client, owner_b)

    item, _ = _item_with_finding(client, owner_a, wid_a, pid_a)
    foreign_scan = _seed_scan(wid_b, pid_b, with_detection_coverage=True)

    resp = _request_verification(client, owner_a, wid_a, pid_a, item, foreign_scan)
    assert resp.status_code == 404, resp.text
    assert "not found in this project" in resp.text.lower()


def test_scan_from_another_project_in_same_tenant_is_refused(client: TestClient) -> None:
    """ATTACK: same workspace, different project -- scope must hold inside a tenant too."""
    headers = _auth(_register(client, "Owner"))
    wid, pid = _workspace_project(client, headers)
    other_pid = client.post(
        f"/api/v1/workspaces/{wid}/projects",
        headers=headers,
        json={"name": f"other-{uuid.uuid4().hex[:6]}"},
    ).json()["id"]

    item, _ = _item_with_finding(client, headers, wid, pid)
    other_scan = _seed_scan(wid, other_pid, with_detection_coverage=True)

    resp = _request_verification(client, headers, wid, pid, item, other_scan)
    assert resp.status_code == 404, resp.text


def test_audit_trail_is_not_readable_across_tenants(client: TestClient) -> None:
    """ATTACK: read another tenant's audit trail to learn about their findings."""
    owner_a = _auth(_register(client, "A"))
    owner_b = _auth(_register(client, "B"))
    wid_a, _ = _workspace_project(client, owner_a)
    assert client.get(f"/api/v1/workspaces/{wid_a}/audit", headers=owner_b).status_code in (403, 404)


# =====================================================================================
# STATE MACHINE / REPLAY / CONCURRENCY
# =====================================================================================


def test_completion_is_idempotent_and_cannot_be_replayed(client: TestClient) -> None:
    """ATTACK: replay the completion call to re-apply a transition or flip an outcome."""
    headers = _auth(_register(client, "Owner"))
    wid, pid = _workspace_project(client, headers)
    item, vuln_ids = _item_with_finding(client, headers, wid, pid)

    scan_id = _seed_scan(wid, pid, with_detection_coverage=True)
    _set_last_seen(wid, vuln_ids, scan_id, status="fixed")

    req = _request_verification(client, headers, wid, pid, item, scan_id).json()
    first = _complete(client, headers, wid, pid, req["id"]).json()
    second = _complete(client, headers, wid, pid, req["id"]).json()

    assert first["result"] == second["result"] == "passed"
    assert first["completed_at"] == second["completed_at"], "replay must not re-time the outcome"


def test_stale_version_is_rejected_optimistic_lock(client: TestClient) -> None:
    """ATTACK: act on a remediation item using a stale version to clobber a concurrent edit."""
    headers = _auth(_register(client, "Owner"))
    wid, pid = _workspace_project(client, headers)
    item, _ = _item_with_finding(client, headers, wid, pid)

    stale_version = item["version"] - 1
    resp = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers,
        json={"version": stale_version},
    )
    assert resp.status_code in (409, 412, 422), resp.text


# =====================================================================================
# EVIDENCE LINEAGE / PROVENANCE
# =====================================================================================


def test_verification_detail_is_reproducible_structured_facts(client: TestClient) -> None:
    """A verdict must be re-derivable by an auditor, not justified by prose alone."""
    headers = _auth(_register(client, "Owner"))
    wid, pid = _workspace_project(client, headers)
    item, vuln_ids = _item_with_finding(client, headers, wid, pid)

    scan_id = _seed_scan(wid, pid, with_detection_coverage=True)
    _set_last_seen(wid, vuln_ids, scan_id, status="fixed")

    req = _request_verification(client, headers, wid, pid, item, scan_id).json()
    detail = _complete(client, headers, wid, pid, req["id"]).json()["detail"]

    assert detail["scan_id"] == str(scan_id)
    assert detail["issue_key"]
    assert detail["live_locations"] == 0
    assert detail["coverage_ok"] is True
    assert "baseline_locations" in detail


def test_inference_is_never_labelled_as_observation() -> None:
    """ATTACK on the epistemics: an INFERRED value must not be presentable as OBSERVED.

    Covers the two inference sites in the engine (auth-state classification and API intel)."""
    from apps.api.scanner_engine.api_intel import classify_api
    from apps.api.scanner_engine.auth_state import auth_metadata, classify_auth_state

    marked = auth_metadata(200, location=None, title=None)
    assert "auth_state" in marked["inferred_keys"], "a derived auth state must declare itself inferred"
    assert marked["auth_state"] == classify_auth_state(200, location=None, title=None)

    # A path-only API classification is INFERRED: no request was sent, so it must never sit
    # in the metadata namespace indistinguishable from a measured fact.
    intel = classify_api("https://h/api/v2/users").as_metadata()
    assert intel["is_api"] is True
    assert "is_api" in intel["inferred_keys"], "path-only classification must be marked inferred"


def test_source_findings_cannot_claim_runtime_verification() -> None:
    """ATTACK: use a static-analysis match as proof a runtime issue is exploitable."""
    from apps.api.scanner_engine.source_findings import (
        PROVENANCE_INFERRED,
        SourceRef,
        source_provenance,
    )

    prov = source_provenance(
        SourceRef(repository="r", commit="c" * 40, path="src/A.java", line=1),
        rule_id="rule",
        tool="semgrep",
    )
    assert prov["runtime_exploitability_provenance"] == PROVENANCE_INFERRED


# =====================================================================================
# UNCONTROLLED DISCOVERY EXPANSION / SCOPE
# =====================================================================================


def test_out_of_scope_host_is_not_accepted_as_a_finding() -> None:
    """ATTACK: attacker-controlled discovery output names a host outside the engagement,
    expanding the scan onto third-party infrastructure."""
    from apps.api.scanner_engine.scope_guard import host_in_scope

    assert host_in_scope("domain", "example.com", "app.example.com") is True
    # Classic scope-escape shapes, including the suffix-confusion payload.
    for hostile in ("evil.com", "example.com.evil.com", "notexample.com", "", None):
        assert host_in_scope("domain", "example.com", hostile) is False, hostile


def test_credential_testing_stays_unavailable_end_to_end() -> None:
    """ATTACK: reach credential testing through the readiness layer. It must fail closed."""
    from apps.api.scanner_engine.credential_testing_readiness import (
        CredentialTestingNotReady,
        CredentialTestingRequest,
        assert_credential_testing_allowed,
    )

    with pytest.raises(CredentialTestingNotReady):
        assert_credential_testing_allowed(
            CredentialTestingRequest(
                target_host="app.example.com",
                protocol="http-form",
                authorized=True,
                in_scope=True,
                exploitation_enabled=True,
                operator_approved=True,
            )
        )


# =====================================================================================
# REPORT-LAYER MANIPULATION
# =====================================================================================


def test_unknown_severity_cannot_be_laundered_into_info() -> None:
    """ATTACK: a tool emits a severity the report layer does not recognise, and the finding is
    silently downgraded to informational (the historical defect taxonomy.py documents)."""
    from apps.api.modules.vulnerabilities.taxonomy import (
        SEVERITIES,
        UNKNOWN_SEVERITY_FALLBACK,
        normalize_severity,
    )

    for hostile in ("CRITICAL ", "catastrophic", "\x00high", "sev:9"):
        result = normalize_severity(hostile)
        assert result in SEVERITIES
        assert result != "info", f"{hostile!r} must not be laundered into info"
    assert UNKNOWN_SEVERITY_FALLBACK != "info"


def test_cwe_is_never_fabricated() -> None:
    """ATTACK: an unmappable rule id is presented as a real CWE in the report."""
    from apps.api.modules.vulnerabilities.taxonomy import canonical_cwe

    for junk in ("not-a-cwe", "", None, "cwe-", "cwe-0", "OWASP-A1"):
        assert canonical_cwe(junk) is None, junk
    assert canonical_cwe("CWE-89") == "cwe-89"


def test_audit_detail_cannot_carry_a_credential_into_reports(client: TestClient) -> None:
    """ATTACK: smuggle a secret into the audit trail (which feeds exports/reports)."""
    from apps.api.modules.audit.service import scrub_detail

    scrubbed = scrub_detail("password=hunter2 while scanning")
    # `str | None` only because a falsy detail passes through; a non-empty input must not.
    assert scrubbed is not None
    assert "hunter2" not in scrubbed
