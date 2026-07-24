import uuid

from fastapi.testclient import TestClient

# `client` fixture (session-scoped TestClient) lives in conftest.py -- see
# that file for why it must be shared across every test module.


def _register(client: TestClient, full_name: str = "Test User") -> dict:
    email = f"{uuid.uuid4()}@example.com"
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct horse battery staple", "full_name": full_name},
    )
    assert resp.status_code == 201, resp.text
    tokens = resp.json()
    return {"email": email, **tokens}


def _auth_headers(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def test_register_and_me(client: TestClient) -> None:
    tokens = _register(client)
    resp = client.get("/api/v1/users/me", headers=_auth_headers(tokens))
    assert resp.status_code == 200
    assert resp.json()["email"] == tokens["email"]


def test_workspace_project_target_lifecycle(client: TestClient) -> None:
    owner = _register(client, "Owner")
    headers = _auth_headers(owner)

    ws = client.post("/api/v1/workspaces", headers=headers, json={"name": "Test Workspace"})
    assert ws.status_code == 201, ws.text
    workspace_id = ws.json()["id"]

    members = client.get(f"/api/v1/workspaces/{workspace_id}/members", headers=headers)
    assert members.status_code == 200
    assert len(members.json()) == 1
    assert members.json()[0]["role_name"] == "owner"

    project = client.post(
        f"/api/v1/workspaces/{workspace_id}/projects",
        headers=headers,
        json={"name": "Test Project"},
    )
    assert project.status_code == 201, project.text
    project_id = project.json()["id"]

    target = client.post(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/targets",
        headers=headers,
        json={"type": "domain", "value": "example.test"},
    )
    assert target.status_code == 201, target.text

    targets = client.get(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/targets", headers=headers
    )
    assert targets.status_code == 200
    assert len(targets.json()) == 1
    assert targets.json()[0]["value"] == "example.test"


def test_non_member_is_denied(client: TestClient) -> None:
    owner = _register(client, "Owner2")
    outsider = _register(client, "Outsider")

    ws = client.post("/api/v1/workspaces", headers=_auth_headers(owner), json={"name": "Private Workspace"})
    workspace_id = ws.json()["id"]

    resp = client.get(f"/api/v1/workspaces/{workspace_id}/members", headers=_auth_headers(outsider))
    assert resp.status_code == 403


def test_member_role_cannot_manage_workspace(client: TestClient) -> None:
    owner = _register(client, "Owner3")
    member = _register(client, "Member3")

    ws = client.post("/api/v1/workspaces", headers=_auth_headers(owner), json={"name": "RBAC Workspace"})
    workspace_id = ws.json()["id"]

    invite = client.post(
        f"/api/v1/workspaces/{workspace_id}/members/invite",
        headers=_auth_headers(owner),
        json={"email": member["email"], "role_name": "member"},
    )
    assert invite.status_code == 201, invite.text

    project = client.post(
        f"/api/v1/workspaces/{workspace_id}/projects",
        headers=_auth_headers(member),
        json={"name": "Member project"},
    )
    assert project.status_code == 201
    project_id = project.json()["id"]

    delete_resp = client.delete(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}", headers=_auth_headers(member)
    )
    assert delete_resp.status_code == 403

    invite_resp = client.post(
        f"/api/v1/workspaces/{workspace_id}/members/invite",
        headers=_auth_headers(member),
        json={"email": "another@example.com", "role_name": "member"},
    )
    assert invite_resp.status_code == 403


def test_refresh_token_rotation_invalidates_old_token(client: TestClient) -> None:
    tokens = _register(client, "Refresher")

    refreshed = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 200

    stale = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert stale.status_code == 401


def test_unauthenticated_request_rejected(client: TestClient) -> None:
    resp = client.get("/api/v1/workspaces")
    assert resp.status_code == 401
