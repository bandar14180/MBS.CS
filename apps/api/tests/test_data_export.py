"""Data Privacy Hardening -- GET /users/me/export (GDPR access/portability).

Verifies the export includes profile, memberships, API-key metadata, and an activity
summary, and that it NEVER leaks a secret or hash.
"""
import json
import uuid

from fastapi.testclient import TestClient

_PW = "correct horse battery staple"


def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": _PW, "full_name": "Export Me"},
    )
    assert r.status_code == 201, r.text
    return {"email": email, **r.json()}


def _auth(t: dict) -> dict:
    return {"Authorization": f"Bearer {t['access_token']}"}


def test_export_requires_auth(client: TestClient) -> None:
    assert client.get("/api/v1/users/me/export").status_code == 401


def test_export_contains_personal_data(client: TestClient) -> None:
    u = _register(client)
    h = _auth(u)
    ws = client.post("/api/v1/workspaces", headers=h, json={"name": "Acme"}).json()["id"]
    client.post(f"/api/v1/workspaces/{ws}/api-keys", headers=h, json={"name": "ci-key"})

    r = client.get("/api/v1/users/me/export", headers=h)
    assert r.status_code == 200, r.text
    data = r.json()

    assert data["profile"]["email"] == u["email"]
    assert data["profile"]["full_name"] == "Export Me"
    assert data["profile"]["status"] == "active"

    assert len(data["workspaces"]) == 1
    assert data["workspaces"][0]["workspace_name"] == "Acme"
    assert data["workspaces"][0]["role_name"] == "owner"

    assert len(data["api_keys"]) == 1
    assert data["api_keys"][0]["name"] == "ci-key"
    assert data["api_keys"][0]["prefix"].startswith("mbsk_")

    summary = data["activity_summary"]
    assert summary["workspace_count"] == 1
    assert summary["api_key_count"] == 1
    assert summary["active_api_key_count"] == 1


def test_export_never_leaks_secrets_or_hashes(client: TestClient) -> None:
    u = _register(client)
    h = _auth(u)
    ws = client.post("/api/v1/workspaces", headers=h, json={"name": "Acme"}).json()["id"]
    client.post(f"/api/v1/workspaces/{ws}/api-keys", headers=h, json={"name": "ci-key"})

    blob = json.dumps(client.get("/api/v1/users/me/export", headers=h).json()).lower()
    for forbidden in ("password_hash", "key_hash", "token_hash", "mfa_secret", "secret", "\"hash\""):
        assert forbidden not in blob, f"export leaked '{forbidden}'"
