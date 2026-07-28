import uuid

from fastapi.testclient import TestClient


def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct horse battery staple", "full_name": "Before"},
    )
    assert resp.status_code == 201, resp.text
    return {"email": email, **resp.json()}


def _auth(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def test_update_profile_name(client: TestClient) -> None:
    headers = _auth(_register(client))
    resp = client.patch("/api/v1/users/me", headers=headers, json={"full_name": "After"})
    assert resp.status_code == 200
    assert resp.json()["full_name"] == "After"
    assert client.get("/api/v1/users/me", headers=headers).json()["full_name"] == "After"


def test_change_password_flow(client: TestClient) -> None:
    tokens = _register(client)
    headers = _auth(tokens)
    # wrong current password -> 400
    bad = client.post(
        "/api/v1/users/me/change-password",
        headers=headers,
        json={"current_password": "nope", "new_password": "brand-new-pass-123"},
    )
    assert bad.status_code == 400

    # correct current password -> 204, and the new password works to log in
    ok = client.post(
        "/api/v1/users/me/change-password",
        headers=headers,
        json={"current_password": "correct horse battery staple", "new_password": "brand-new-pass-123"},
    )
    assert ok.status_code == 204

    relogin = client.post("/api/v1/auth/login", json={"email": tokens["email"], "password": "brand-new-pass-123"})
    assert relogin.status_code == 200
