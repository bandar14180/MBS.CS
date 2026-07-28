import uuid

from fastapi.testclient import TestClient


def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct horse battery staple", "full_name": "Note User"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _auth(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _ws(client: TestClient, headers: dict) -> str:
    return client.post("/api/v1/workspaces", headers=headers, json={"name": "Note WS"}).json()["id"]


def test_notifications_empty_state(client: TestClient) -> None:
    headers = _auth(_register(client))
    ws = _ws(client, headers)
    assert client.get(f"/api/v1/workspaces/{ws}/notifications", headers=headers).json() == []
    assert client.get(f"/api/v1/workspaces/{ws}/notifications/unread-count", headers=headers).json()["count"] == 0


def test_mark_all_read_ok(client: TestClient) -> None:
    headers = _auth(_register(client))
    ws = _ws(client, headers)
    resp = client.post(f"/api/v1/workspaces/{ws}/notifications/read-all", headers=headers)
    assert resp.status_code == 204


def test_notifications_require_membership(client: TestClient) -> None:
    owner = _auth(_register(client))
    outsider = _auth(_register(client))
    ws = _ws(client, owner)
    resp = client.get(f"/api/v1/workspaces/{ws}/notifications", headers=outsider)
    assert resp.status_code == 403
