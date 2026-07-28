import uuid

from fastapi.testclient import TestClient


def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct horse battery staple", "full_name": "Key User"},
    )
    assert resp.status_code == 201, resp.text
    return {"email": email, **resp.json()}


def _auth(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _key_auth(secret: str) -> dict:
    return {"Authorization": f"Bearer {secret}"}


def test_api_key_lifecycle(client: TestClient) -> None:
    owner = _register(client)
    jwt = _auth(owner)
    ws = client.post("/api/v1/workspaces", headers=jwt, json={"name": "KeyWS"}).json()["id"]
    client.post(f"/api/v1/workspaces/{ws}/projects", headers=jwt, json={"name": "P"})

    created = client.post(f"/api/v1/workspaces/{ws}/api-keys", headers=jwt, json={"name": "CI"})
    assert created.status_code == 201, created.text
    secret = created.json()["secret"]
    assert secret.startswith("mbsk_")

    # authenticate with the key
    r = client.get(f"/api/v1/workspaces/{ws}/projects", headers=_key_auth(secret))
    assert r.status_code == 200 and len(r.json()) == 1

    # the list never leaks the secret
    listed = client.get(f"/api/v1/workspaces/{ws}/api-keys", headers=jwt).json()
    assert len(listed) == 1 and "secret" not in listed[0]

    # revoke -> key stops working
    assert client.delete(f"/api/v1/workspaces/{ws}/api-keys/{created.json()['id']}", headers=jwt).status_code == 204
    assert client.get(f"/api/v1/workspaces/{ws}/projects", headers=_key_auth(secret)).status_code == 401


def test_api_key_is_workspace_bound(client: TestClient) -> None:
    owner = _register(client)
    jwt = _auth(owner)
    ws = client.post("/api/v1/workspaces", headers=jwt, json={"name": "A"}).json()["id"]
    other = client.post("/api/v1/workspaces", headers=jwt, json={"name": "B"}).json()["id"]
    secret = client.post(f"/api/v1/workspaces/{ws}/api-keys", headers=jwt, json={"name": "k"}).json()["secret"]
    # valid for ws, rejected for other
    assert client.get(f"/api/v1/workspaces/{ws}/projects", headers=_key_auth(secret)).status_code == 200
    assert client.get(f"/api/v1/workspaces/{other}/projects", headers=_key_auth(secret)).status_code == 403


def test_bogus_key_rejected(client: TestClient) -> None:
    owner = _register(client)
    ws = client.post("/api/v1/workspaces", headers=_auth(owner), json={"name": "A"}).json()["id"]
    assert client.get(f"/api/v1/workspaces/{ws}/projects", headers=_key_auth("mbsk_not_a_real_key")).status_code == 401


def test_only_manager_can_create_key(client: TestClient) -> None:
    owner = _register(client)
    member = _register(client)
    jwt = _auth(owner)
    ws = client.post("/api/v1/workspaces", headers=jwt, json={"name": "A"}).json()["id"]
    client.post(
        f"/api/v1/workspaces/{ws}/members/invite",
        headers=jwt,
        json={"email": member["email"], "role_name": "member"},
    )
    resp = client.post(f"/api/v1/workspaces/{ws}/api-keys", headers=_auth(member), json={"name": "x"})
    assert resp.status_code == 403
