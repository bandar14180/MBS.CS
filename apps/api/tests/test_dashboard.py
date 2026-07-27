import uuid

from fastapi.testclient import TestClient

# Shared session-scoped `client` fixture lives in conftest.py.


def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct horse battery staple", "full_name": "Dash User"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _headers(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def test_dashboard_summary_empty_and_seeded(client: TestClient) -> None:
    headers = _headers(_register(client))

    ws = client.post("/api/v1/workspaces", headers=headers, json={"name": "Dash WS"})
    workspace_id = ws.json()["id"]

    # Empty workspace -> everything zeroed, no recent scans.
    empty = client.get(f"/api/v1/workspaces/{workspace_id}/dashboard/summary", headers=headers)
    assert empty.status_code == 200, empty.text
    body = empty.json()
    assert body["projects"] == 0
    assert body["targets"] == 0
    assert body["scans"]["total"] == 0
    assert body["vulnerabilities"]["total"] == 0
    assert body["vulnerabilities"]["by_severity"]["critical"] == 0
    assert body["recent_scans"] == []

    # Seed a project + a target.
    project = client.post(
        f"/api/v1/workspaces/{workspace_id}/projects", headers=headers, json={"name": "P1"}
    )
    project_id = project.json()["id"]
    client.post(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/targets",
        headers=headers,
        json={"type": "domain", "value": "dash.example.test"},
    )

    seeded = client.get(f"/api/v1/workspaces/{workspace_id}/dashboard/summary", headers=headers)
    assert seeded.status_code == 200
    body = seeded.json()
    assert body["projects"] == 1
    assert body["targets"] == 1


def test_dashboard_summary_isolated_per_workspace(client: TestClient) -> None:
    # A member of workspace A must not see workspace B's counts (RLS + explicit filter).
    a = _headers(_register(client))
    b = _headers(_register(client))

    ws_a = client.post("/api/v1/workspaces", headers=a, json={"name": "A"}).json()["id"]
    ws_b = client.post("/api/v1/workspaces", headers=b, json={"name": "B"}).json()["id"]

    # Two projects in B, none in A.
    client.post(f"/api/v1/workspaces/{ws_b}/projects", headers=b, json={"name": "B1"})
    client.post(f"/api/v1/workspaces/{ws_b}/projects", headers=b, json={"name": "B2"})

    summary_a = client.get(f"/api/v1/workspaces/{ws_a}/dashboard/summary", headers=a).json()
    assert summary_a["projects"] == 0

    summary_b = client.get(f"/api/v1/workspaces/{ws_b}/dashboard/summary", headers=b).json()
    assert summary_b["projects"] == 2

    # A non-member of B is rejected outright.
    denied = client.get(f"/api/v1/workspaces/{ws_b}/dashboard/summary", headers=a)
    assert denied.status_code == 403
