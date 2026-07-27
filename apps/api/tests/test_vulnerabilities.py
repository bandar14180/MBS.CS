import uuid

from fastapi.testclient import TestClient

from apps.api.scanner_engine.tool_runners.base import RawToolOutput
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner

# `client` fixture (session-scoped TestClient) lives in conftest.py.


# --- Nuclei parse (pure unit) ---

def test_nuclei_parse() -> None:
    raw = RawToolOutput(
        command="nuclei",
        stdout=(
            '{"template-id":"http-missing-security-headers","matcher-name":"strict-transport-security",'
            '"matched-at":"http://10.0.0.1","type":"http",'
            '"info":{"name":"HTTP Missing Security Headers","severity":"info",'
            '"description":"desc","tags":["misconfig"],'
            '"classification":{"cwe-id":["CWE-693"],"cvss-score":0.0}}}\n'
            "not-json\n"
            '{"template-id":"tech-detect","matched-at":"http://10.0.0.1",'
            '"info":{"name":"Nginx","severity":"info"}}\n'
        ),
        stderr="",
        exit_code=0,
    )
    findings = NucleiRunner().parse_vulnerabilities(raw)
    assert len(findings) == 2
    f = findings[0]
    assert f.title == "HTTP Missing Security Headers"
    assert f.severity == "info"
    assert f.category == "CWE-693"
    assert f.matched_at == "http://10.0.0.1"
    # fingerprint is stable + location-specific
    assert f.fingerprint == "http-missing-security-headers|strict-transport-security|http://10.0.0.1"
    # regular parse() emits no assets for a vuln scanner
    assert NucleiRunner().parse(raw) == []


def test_nuclei_requires_active_testing_flag() -> None:
    assert NucleiRunner().requires_active_testing is True


# --- vulnerability engine CVSS floor (pure) ---

def test_cvss_score_falls_back_to_severity_floor() -> None:
    from apps.api.modules.vulnerabilities.service import _score_for
    from apps.api.scanner_engine.tool_runners.base import VulnerabilityFinding

    # tool-reported score wins
    assert _score_for(VulnerabilityFinding(fingerprint="f", title="t", severity="low", cvss_score=8.1)) == 8.1
    # else severity floor
    assert _score_for(VulnerabilityFinding(fingerprint="f", title="t", severity="high")) == 7.5
    assert _score_for(VulnerabilityFinding(fingerprint="f", title="t", severity="info")) == 0.0
    # unknown severity -> None (no invented score)
    assert _score_for(VulnerabilityFinding(fingerprint="f", title="t", severity="weird")) is None


# --- helpers for API tests ---

def _register(client: TestClient, name: str) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct horse battery staple", "full_name": name},
    )
    assert resp.status_code == 201, resp.text
    return {"email": email, **resp.json()}


def _auth(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _target(client: TestClient, headers: dict) -> tuple[str, str, str]:
    wid = client.post("/api/v1/workspaces", headers=headers, json={"name": "WS"}).json()["id"]
    pid = client.post(f"/api/v1/workspaces/{wid}/projects", headers=headers, json={"name": "P"}).json()["id"]
    tid = client.post(
        f"/api/v1/workspaces/{wid}/projects/{pid}/targets",
        headers=headers,
        json={"type": "domain", "value": f"{uuid.uuid4()}.test"},
    ).json()["id"]
    return wid, pid, tid


def _verify(client: TestClient, headers: dict, wid: str, pid: str, tid: str, active: bool) -> None:
    base = f"/api/v1/workspaces/{wid}/projects/{pid}/targets/{tid}/authorization-scope"
    client.post(base, headers=headers, json={"proof_type": "dns_txt", "proof_reference": "x"})
    client.post(f"{base}/verify", headers=headers, json={"active_testing_allowed": active})


# --- active-testing gate at scan creation ---

def test_active_tool_blocked_without_active_testing(client: TestClient) -> None:
    owner = _register(client, "Owner")
    wid, pid, tid = _target(client, _auth(owner))
    _verify(client, _auth(owner), wid, pid, tid, active=False)  # verified but NOT active-allowed

    resp = client.post(
        f"/api/v1/workspaces/{wid}/projects/{pid}/scans",
        headers=_auth(owner),
        json={"target_id": tid, "scan_type": "web", "requested_modules": ["nuclei"]},
    )
    assert resp.status_code == 403


def test_passive_tool_allowed_without_active_testing(client: TestClient, monkeypatch) -> None:
    from apps.api.celery_app.tasks import scan_tasks

    class _R:
        id = "t"

    monkeypatch.setattr(scan_tasks.run_scan_task, "delay", lambda *a, **k: _R())

    owner = _register(client, "Owner")
    wid, pid, tid = _target(client, _auth(owner))
    _verify(client, _auth(owner), wid, pid, tid, active=False)

    resp = client.post(
        f"/api/v1/workspaces/{wid}/projects/{pid}/scans",
        headers=_auth(owner),
        json={"target_id": tid, "scan_type": "network", "requested_modules": ["naabu"]},
    )
    assert resp.status_code == 202


def test_active_tool_allowed_when_active_testing_enabled(client: TestClient, monkeypatch) -> None:
    from apps.api.celery_app.tasks import scan_tasks

    class _R:
        id = "t"

    monkeypatch.setattr(scan_tasks.run_scan_task, "delay", lambda *a, **k: _R())

    owner = _register(client, "Owner")
    wid, pid, tid = _target(client, _auth(owner))
    _verify(client, _auth(owner), wid, pid, tid, active=True)

    resp = client.post(
        f"/api/v1/workspaces/{wid}/projects/{pid}/scans",
        headers=_auth(owner),
        json={"target_id": tid, "scan_type": "web", "requested_modules": ["nuclei"]},
    )
    assert resp.status_code == 202


# --- vulnerability status PATCH (auditable decision) ---

def test_vulnerability_status_requires_justification(client: TestClient) -> None:
    owner = _register(client, "Owner")
    wid, pid, _ = _target(client, _auth(owner))
    # No vuln exists; we only assert the schema rejects an empty justification (422)
    # against a random id -- validation happens before the row lookup.
    resp = client.patch(
        f"/api/v1/workspaces/{wid}/projects/{pid}/vulnerabilities/{uuid.uuid4()}/status",
        headers=_auth(owner),
        json={"status": "false_positive", "justification": ""},
    )
    assert resp.status_code == 422


def test_member_cannot_change_vuln_status(client: TestClient) -> None:
    owner = _register(client, "Owner")
    member = _register(client, "Member")
    wid, pid, _ = _target(client, _auth(owner))
    client.post(
        f"/api/v1/workspaces/{wid}/members/invite",
        headers=_auth(owner),
        json={"email": member["email"], "role_name": "member"},
    )
    # member has vulnerability:read but not vulnerability:manage
    resp = client.patch(
        f"/api/v1/workspaces/{wid}/projects/{pid}/vulnerabilities/{uuid.uuid4()}/status",
        headers=_auth(member),
        json={"status": "false_positive", "justification": "looks benign"},
    )
    assert resp.status_code == 403
