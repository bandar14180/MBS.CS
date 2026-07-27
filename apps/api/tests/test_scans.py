import uuid

import pytest
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


@pytest.fixture
def no_celery_dispatch(monkeypatch):
    """Stops create_scan from actually queueing to Celery/Redis -- we only want
    to test the API/gate/persistence layer here, not tool execution (that's
    verified live against the worker + naabu). Returns a fake AsyncResult."""
    from apps.api.celery_app.tasks import scan_tasks

    class _FakeResult:
        id = "fake-task-id"

    monkeypatch.setattr(scan_tasks.run_scan_task, "delay", lambda *a, **k: _FakeResult())


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


def test_use_ai_planner_flag_persisted_to_config(client: TestClient, no_celery_dispatch) -> None:
    # Regression: the use_ai_planner flag must reach scan.config, or the
    # orchestrator's AI-planning branch is unreachable (dead code).
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
