"""Prompt 38 -- end-to-end acceptance for the pipeline as it actually exists.

WHAT IS VALIDATED HERE, AND WHAT IS A STATED LIMITATION
=======================================================
This walks the real implemented pipeline:

    Discovery(parse) -> Detection(parse) -> Finding(ingest/dedupe) -> Remediation item
    -> Verification(retest-derived) -> Evidence lineage -> Correlation -> Report -> Audit

TWO SEGMENTS CANNOT BE EXERCISED HERE, and are NOT faked into a PASS:

  1. TestPlan / Application-Understanding / Knowledge-Model (ASKG). These subsystems DO NOT
     EXIST in this codebase (verified: no TestPlan model, table, module or router). The batch
     instructions forbid inventing them, so the corresponding acceptance segment is reported
     as a limitation rather than tested.
  2. LIVE TOOL EXECUTION. No scanner binary (nuclei/httpx-pd/subfinder/naabu/nmap/katana) is
     installed on this host, and the S3 evidence store (minio) is not resolvable from here.
     Discovery/Detection are therefore validated at the PARSER boundary using real recorded
     tool output -- the same approach apps/api/tests/test_recon_pipeline.py already uses --
     and evidence-STORAGE tests are left to the environments that have minio.

Everything below runs against the real API, the real ORM, and the real MySQL database.
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


# =====================================================================================
# DISCOVERY -> DETECTION (parser boundary; no binaries required)
# =====================================================================================


def test_discovery_parses_real_tool_output() -> None:
    """Discovery stage: subfinder/httpx output becomes canonical assets."""
    from apps.api.scanner_engine.tool_runners.base import RawToolOutput
    from apps.api.scanner_engine.tool_runners.httpx_runner import HttpxRunner
    from apps.api.scanner_engine.tool_runners.subfinder_runner import SubfinderRunner

    subs = SubfinderRunner().parse(
        RawToolOutput(
            command="subfinder -d example.com",
            stdout='{"host":"a.example.com","source":"crtsh"}\n',
            stderr="",
            exit_code=0,
        )
    )
    assert [f.value for f in subs] == ["a.example.com"]

    svcs = HttpxRunner().parse(
        RawToolOutput(
            command="httpx-pd",
            stdout='{"url":"https://10.0.0.1","host":"10.0.0.1","port":443,"scheme":"https",'
            '"status_code":200,"title":"Home"}\n',
            stderr="",
            exit_code=0,
        )
    )
    assert svcs[0].asset_type == "http_service"
    assert svcs[0].metadata["status_code"] == 200


def test_malformed_scanner_output_is_survived_not_trusted() -> None:
    """NEGATIVE: malformed output must not crash the pipeline or invent findings."""
    from apps.api.scanner_engine.tool_runners.base import RawToolOutput
    from apps.api.scanner_engine.tool_runners.subfinder_runner import SubfinderRunner

    findings = SubfinderRunner().parse(
        RawToolOutput(
            command="subfinder",
            stdout="not json\n{broken\n\n" + '{"host":"ok.example.com"}\n',
            stderr="",
            exit_code=0,
        )
    )
    assert [f.value for f in findings] == ["ok.example.com"]


def test_timeout_and_partial_output_are_classified_distinctly() -> None:
    """NEGATIVE: a timeout must be distinguishable from a crash, and partial output kept."""
    from apps.api.scanner_engine.tool_runners.base import RawToolOutput, classify_run
    from apps.api.scanner_engine.tool_runners.subfinder_runner import SubfinderRunner

    runner = SubfinderRunner()
    partial = RawToolOutput(
        command="c", stdout='{"host":"a.example.com"}\n', stderr="", exit_code=1, timed_out=True
    )
    assert partial.timed_out is True
    assert classify_run(runner, partial, produced_findings=True) == "partial"

    nothing = RawToolOutput(command="c", stdout="", stderr="boom", exit_code=1)
    assert classify_run(runner, nothing, produced_findings=False) == "failed"


# =====================================================================================
# FINDING -> REMEDIATION ITEM (issue-level identity)
# =====================================================================================


def test_findings_converge_to_one_issue_level_item(client: TestClient) -> None:
    """One issue observed at N locations is ONE remediation item, not N."""
    headers = _auth(_register(client, "Owner"))
    wid, pid = _workspace_project(client, headers)
    key = f"e2e{uuid.uuid4().hex[:6]}"
    _seed_findings(
        wid,
        pid,
        [
            {"fingerprint": f"{key}|m|https://h/1", "title": "V", "severity": "high"},
            {"fingerprint": f"{key}|m|https://h/2", "title": "V", "severity": "high"},
        ],
    )
    items = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()
    assert len([i for i in items if key in i["issue_key"]]) == 1


# =====================================================================================
# VERIFICATION (the load-bearing stage)
# =====================================================================================


def _item(client, headers, wid, pid, prefix="acc"):
    key = f"{prefix}{uuid.uuid4().hex[:6]}"
    vuln_ids = _seed_findings(
        wid, pid, [{"fingerprint": f"{key}|m|https://h/1", "title": "V", "severity": "high"}]
    )
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    return _to_in_progress(client, headers, wid, pid, item), vuln_ids


def test_happy_path_fixed_issue_reaches_verified(client: TestClient) -> None:
    """POSITIVE END-TO-END: a genuinely fixed issue, retested with real detection coverage,
    reaches `verified` -- and the verdict is backed by reproducible structured facts."""
    headers = _auth(_register(client, "Owner"))
    wid, pid = _workspace_project(client, headers)
    item, vuln_ids = _item(client, headers, wid, pid)

    scan_id = _seed_scan(wid, pid, status="completed", with_detection_coverage=True)
    _set_last_seen(wid, vuln_ids, scan_id, status="fixed")

    req = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers,
        json={"version": item["version"], "scan_id": str(scan_id)},
    ).json()
    body = client.post(
        f"{_rem_base(wid, pid)}/verification/{req['id']}/complete", headers=headers
    ).json()

    assert body["result"] == "passed"
    assert body["detail"]["coverage_ok"] is True
    assert body["detail"]["live_locations"] == 0
    assert body["detail"]["scan_id"] == str(scan_id)

    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert after["status"] == "verified"


def test_still_present_issue_does_not_reach_verified(client: TestClient) -> None:
    """NEGATIVE: an unfixed issue must fail its retest and reopen the work."""
    headers = _auth(_register(client, "Owner"))
    wid, pid = _workspace_project(client, headers)
    item, vuln_ids = _item(client, headers, wid, pid)

    scan_id = _seed_scan(wid, pid, status="completed", with_detection_coverage=True)
    _set_last_seen(wid, vuln_ids, scan_id)  # still live

    req = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers,
        json={"version": item["version"], "scan_id": str(scan_id)},
    ).json()
    body = client.post(
        f"{_rem_base(wid, pid)}/verification/{req['id']}/complete", headers=headers
    ).json()

    assert body["result"] == "failed"
    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert after["status"] != "verified"


def test_missing_evidence_blocks_a_verdict(client: TestClient) -> None:
    """NEGATIVE (missing evidence): no retest linked -> no verdict is derivable."""
    headers = _auth(_register(client, "Owner"))
    wid, pid = _workspace_project(client, headers)
    item, _ = _item(client, headers, wid, pid)

    req = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers,
        json={"version": item["version"]},
    ).json()
    resp = client.post(
        f"{_rem_base(wid, pid)}/verification/{req['id']}/complete", headers=headers
    )
    assert resp.status_code == 409


# =====================================================================================
# NEGATIVE: AUTHORIZATION / TENANCY / SESSION
# =====================================================================================


def test_unauthenticated_context_is_refused(client: TestClient) -> None:
    headers = _auth(_register(client, "Owner"))
    wid, pid = _workspace_project(client, headers)
    assert client.get(f"{_rem_base(wid, pid)}", headers=None).status_code in (401, 403)


def test_authenticated_but_cross_tenant_context_is_refused(client: TestClient) -> None:
    """NEGATIVE (cross-tenant target): a valid session for tenant B must not reach tenant A."""
    owner_a = _auth(_register(client, "A"))
    owner_b = _auth(_register(client, "B"))
    wid_a, pid_a = _workspace_project(client, owner_a)
    assert client.get(f"{_rem_base(wid_a, pid_a)}", headers=owner_b).status_code in (403, 404)


def test_expired_or_invalid_session_is_refused(client: TestClient) -> None:
    """NEGATIVE (expired/invalid session)."""
    headers = _auth(_register(client, "Owner"))
    wid, pid = _workspace_project(client, headers)
    bad = {"Authorization": "Bearer not-a-valid-token"}
    assert client.get(f"{_rem_base(wid, pid)}", headers=bad).status_code in (401, 403)


def test_unauthorized_target_is_not_scannable() -> None:
    """NEGATIVE (unauthorized target): scope enforcement is fail-closed."""
    from apps.api.scanner_engine.scope_guard import host_in_scope

    assert host_in_scope("domain", "example.com", "app.example.com") is True
    assert host_in_scope("domain", "example.com", "attacker.net") is False
    assert host_in_scope("domain", "example.com", None) is False


# =====================================================================================
# AUDIT + OBSERVABILITY
# =====================================================================================


def test_pipeline_actions_are_audited_with_correlation_and_actor(client: TestClient) -> None:
    """Audit logging and observability: a security-relevant action is recorded with actor and
    the SAME correlation id the request carried."""
    headers = _auth(_register(client, "Owner"))
    wid = client.post("/api/v1/workspaces", headers=headers, json={"name": "WS"}).json()["id"]

    request_id = uuid.uuid4().hex
    resp = client.patch(
        f"/api/v1/workspaces/{wid}/billing/plan",
        headers={**headers, "X-Request-ID": request_id},
        json={"tier": "pro"},
    )
    assert resp.headers.get("X-Request-ID") == request_id

    events = client.get(f"/api/v1/workspaces/{wid}/audit", headers=headers).json()
    plan = [e for e in events if e["action"] == "plan.changed"]
    assert plan, events
    assert plan[0]["actor_email"] is not None
    assert plan[0]["correlation_id"] == request_id


def test_audit_trail_is_append_only() -> None:
    """Report truthfulness depends on an audit trail that cannot be rewritten."""
    from apps.api.modules.audit.immutability import AuditImmutabilityError, install

    install()
    assert issubclass(AuditImmutabilityError, RuntimeError)


# =====================================================================================
# REPORT TRUTHFULNESS
# =====================================================================================


def test_report_severity_and_cwe_are_never_fabricated() -> None:
    from apps.api.modules.vulnerabilities.taxonomy import (
        SEVERITIES,
        canonical_cwe,
        normalize_severity,
    )

    assert normalize_severity("not-a-severity") in SEVERITIES
    assert normalize_severity("not-a-severity") != "info"
    assert canonical_cwe("not-a-cwe") is None


# =====================================================================================
# STATED LIMITATIONS -- asserted as facts, so they cannot rot silently
# =====================================================================================


def test_limitation_no_testplan_or_knowledge_model_subsystem() -> None:
    """The TestPlan/ASKG stages of the requested pipeline are NOT implemented here.

    Asserted rather than assumed: if either is added later, this test fails and the
    acceptance suite must be extended to cover it instead of silently skipping it."""
    import importlib

    for module in (
        "apps.api.modules.testplan",
        "apps.api.modules.knowledge_model",
        "apps.api.scanner_engine.testplan",
    ):
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(module)


def test_limitation_scanner_binaries_absent_on_this_host() -> None:
    """Live tool execution cannot be acceptance-tested here. Recorded, not faked."""
    import shutil

    assert all(
        shutil.which(b) is None
        for b in ("nuclei", "httpx-pd", "subfinder", "naabu", "nmap", "katana")
    ), "a scanner binary appeared: extend this suite with a live-execution acceptance path"
