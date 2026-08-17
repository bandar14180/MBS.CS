import uuid

from fastapi.testclient import TestClient

from apps.api.scanner_engine.tool_runners.base import RawToolOutput
from apps.api.scanner_engine.tool_runners.naabu_runner import NaabuRunner

# `client` fixture (session-scoped TestClient) lives in conftest.py.


def _register(client: TestClient, full_name: str) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct horse battery staple", "full_name": full_name},
    )
    assert resp.status_code == 201, resp.text
    return {"email": email, **resp.json()}


def _auth(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def test_scan_capabilities_endpoint(client: TestClient) -> None:
    owner = _register(client, "Owner")
    resp = client.get("/api/v1/scan-capabilities", headers=_auth(owner))
    assert resp.status_code == 200
    caps = resp.json()
    assert caps["domain"]["supported"] is True
    assert caps["repo"]["supported"] is False
    assert "subfinder" in caps["domain"]["scanners"]


def test_private_ip_target_rejected_at_creation(client: TestClient) -> None:
    # SSRF guard wired into target creation: a private CIDR is refused with 400.
    owner = _register(client, "Owner")
    headers = _auth(owner)
    ws = client.post("/api/v1/workspaces", headers=headers, json={"name": "WS"}).json()["id"]
    proj = client.post(f"/api/v1/workspaces/{ws}/projects", headers=headers, json={"name": "P"}).json()["id"]
    resp = client.post(
        f"/api/v1/workspaces/{ws}/projects/{proj}/targets",
        headers=headers,
        json={"type": "ip_range", "value": "10.0.0.0/24"},
    )
    assert resp.status_code == 400
    assert "SSRF" in resp.json()["detail"] or "not permitted" in resp.json()["detail"]


def test_unsupported_target_type_scan_is_rejected(client: TestClient, no_celery_dispatch) -> None:
    # A repo/api/cloud_account target has no scanner engine yet -> creating a scan
    # must fail clearly at creation, never "complete" having assessed nothing.
    owner = _register(client, "Owner")
    headers = _auth(owner)
    ws = client.post("/api/v1/workspaces", headers=headers, json={"name": "WS"}).json()["id"]
    proj = client.post(f"/api/v1/workspaces/{ws}/projects", headers=headers, json={"name": "P"}).json()["id"]
    tgt = client.post(
        f"/api/v1/workspaces/{ws}/projects/{proj}/targets",
        headers=headers,
        json={"type": "repo", "value": "github.com/example/repo"},
    ).json()["id"]
    resp = client.post(
        f"/api/v1/workspaces/{ws}/projects/{proj}/scans",
        headers=headers,
        json={"target_id": tgt, "scan_type": "web", "requested_modules": ["nmap"]},
    )
    assert resp.status_code == 400
    assert "not supported" in resp.json()["detail"]


def _make_target(client: TestClient, headers: dict) -> tuple[str, str, str]:
    ws = client.post("/api/v1/workspaces", headers=headers, json={"name": "Scan WS"})
    workspace_id = ws.json()["id"]
    project = client.post(
        f"/api/v1/workspaces/{workspace_id}/projects", headers=headers, json={"name": "P"}
    )
    project_id = project.json()["id"]
    target = client.post(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/targets",
        headers=headers,
        json={"type": "domain", "value": f"{uuid.uuid4()}.test"},
    )
    return workspace_id, project_id, target.json()["id"]


def _verify_target(client: TestClient, headers: dict, workspace_id: str, project_id: str, target_id: str) -> None:
    base = f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/targets/{target_id}/authorization-scope"
    client.post(base, headers=headers, json={"proof_type": "dns_txt", "proof_reference": "x"})
    client.post(f"{base}/verify", headers=headers, json={"active_testing_allowed": False})


def test_naabu_parse_extracts_ports() -> None:
    raw = RawToolOutput(
        command="naabu -host 10.0.0.1",
        stdout='{"ip":"10.0.0.1","port":80,"protocol":"tcp"}\n'
        'garbage line that is not json\n'
        '{"ip":"10.0.0.1","port":443,"protocol":"tcp"}\n',
        stderr="",
        exit_code=0,
    )
    findings = NaabuRunner().parse(raw)
    assert len(findings) == 2
    assert findings[0].asset_type == "port"
    assert findings[0].value == "10.0.0.1:80"
    assert findings[0].metadata["port"] == 80
    assert findings[1].value == "10.0.0.1:443"


def test_scan_blocked_on_unverified_target(client: TestClient, no_celery_dispatch) -> None:
    owner = _register(client, "Owner")
    workspace_id, project_id, target_id = _make_target(client, _auth(owner))

    resp = client.post(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/scans",
        headers=_auth(owner),
        json={"target_id": target_id, "scan_type": "network", "requested_modules": ["naabu"]},
    )
    assert resp.status_code == 403


def test_scan_rejects_unknown_module(client: TestClient, no_celery_dispatch) -> None:
    owner = _register(client, "Owner")
    workspace_id, project_id, target_id = _make_target(client, _auth(owner))
    _verify_target(client, _auth(owner), workspace_id, project_id, target_id)

    resp = client.post(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/scans",
        headers=_auth(owner),
        json={"target_id": target_id, "scan_type": "network", "requested_modules": ["definitely-not-a-tool"]},
    )
    assert resp.status_code == 400


def test_scan_created_when_target_verified(client: TestClient, no_celery_dispatch) -> None:
    owner = _register(client, "Owner")
    workspace_id, project_id, target_id = _make_target(client, _auth(owner))
    _verify_target(client, _auth(owner), workspace_id, project_id, target_id)

    resp = client.post(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/scans",
        headers=_auth(owner),
        json={"target_id": target_id, "scan_type": "network", "requested_modules": ["naabu"]},
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "queued"
    assert body["config"]["requested_modules"] == ["naabu"]
    # default: AI planning off
    assert body["config"]["use_ai_planner"] is False

    listed = client.get(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/scans", headers=_auth(owner)
    )
    assert listed.status_code == 200
    assert any(s["id"] == body["id"] for s in listed.json())


def test_use_ai_planner_flag_persisted_to_config(client: TestClient, no_celery_dispatch, monkeypatch) -> None:
    # Regression: the use_ai_planner flag must reach scan.config, or the
    # orchestrator's AI-planning branch is unreachable (dead code).
    # AI planning now requires a configured key for the active provider at
    # creation time, so provide a dummy one (the scan is never dispatched here, so
    # the provider is never actually called). Default provider is openrouter.
    from apps.api.core.config import get_settings

    # Pin the provider so the test is deterministic regardless of the dev's .env.
    monkeypatch.setattr(get_settings(), "ai_provider", "openrouter")
    monkeypatch.setattr(get_settings(), "openrouter_api_key", "sk-test-dummy")

    owner = _register(client, "Owner")
    workspace_id, project_id, target_id = _make_target(client, _auth(owner))
    _verify_target(client, _auth(owner), workspace_id, project_id, target_id)

    resp = client.post(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/scans",
        headers=_auth(owner),
        json={
            "target_id": target_id,
            "scan_type": "network",
            "requested_modules": ["naabu"],
            "use_ai_planner": True,
        },
    )
    assert resp.status_code == 202, resp.text
    assert resp.json()["config"]["use_ai_planner"] is True


def test_use_ai_planner_without_key_is_rejected(client: TestClient, no_celery_dispatch, monkeypatch) -> None:
    # With no API key for the active provider, requesting the AI planner must be
    # rejected at creation (clear 400) rather than creating a scan that instantly
    # fail-fasts. Default provider is openrouter.
    from apps.api.core.config import get_settings

    # Pin the provider so the test is deterministic regardless of the dev's .env
    # (AI_PROVIDER=local is key-less-but-enabled and would not reject).
    monkeypatch.setattr(get_settings(), "ai_provider", "openrouter")
    monkeypatch.setattr(get_settings(), "openrouter_api_key", "")
    monkeypatch.setattr(get_settings(), "anthropic_api_key", "")

    owner = _register(client, "Owner")
    workspace_id, project_id, target_id = _make_target(client, _auth(owner))
    _verify_target(client, _auth(owner), workspace_id, project_id, target_id)

    resp = client.post(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/scans",
        headers=_auth(owner),
        json={
            "target_id": target_id,
            "scan_type": "network",
            "requested_modules": ["naabu"],
            "use_ai_planner": True,
        },
    )
    assert resp.status_code == 400
    assert "AI planner requires" in resp.json()["detail"]


def test_outsider_cannot_read_scans(client: TestClient, no_celery_dispatch) -> None:
    owner = _register(client, "Owner")
    outsider = _register(client, "Outsider")
    workspace_id, project_id, target_id = _make_target(client, _auth(owner))
    _verify_target(client, _auth(owner), workspace_id, project_id, target_id)
    client.post(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/scans",
        headers=_auth(owner),
        json={"target_id": target_id, "scan_type": "network", "requested_modules": ["naabu"]},
    )

    resp = client.get(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/scans", headers=_auth(outsider)
    )
    assert resp.status_code == 403
