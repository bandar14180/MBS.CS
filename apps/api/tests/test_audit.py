import uuid

from fastapi.testclient import TestClient


def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct horse battery staple", "full_name": "Audit User"},
    )
    assert resp.status_code == 201, resp.text
    return {"email": email, **resp.json()}


def _auth(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def test_audit_empty_for_new_workspace(client: TestClient) -> None:
    headers = _auth(_register(client))
    ws = client.post("/api/v1/workspaces", headers=headers, json={"name": "Audit WS"}).json()["id"]
    assert client.get(f"/api/v1/workspaces/{ws}/audit", headers=headers).json() == []


def test_plan_change_is_audited(client: TestClient) -> None:
    headers = _auth(_register(client))
    ws = client.post("/api/v1/workspaces", headers=headers, json={"name": "Audit WS"}).json()["id"]
    client.patch(f"/api/v1/workspaces/{ws}/billing/plan", headers=headers, json={"tier": "pro"})

    events = client.get(f"/api/v1/workspaces/{ws}/audit", headers=headers).json()
    assert any(e["action"] == "plan.changed" and "pro" in (e["detail"] or "") for e in events)
    assert events[0]["actor_email"] is not None  # actor is denormalized


def test_audit_is_manager_only(client: TestClient) -> None:
    owner = _auth(_register(client))
    member = _register(client)
    ws = client.post("/api/v1/workspaces", headers=owner, json={"name": "Audit WS"}).json()["id"]
    client.post(
        f"/api/v1/workspaces/{ws}/members/invite",
        headers=owner,
        json={"email": member["email"], "role_name": "member"},
    )
    # a plain member lacks workspace:manage -> 403 on the audit log
    resp = client.get(f"/api/v1/workspaces/{ws}/audit", headers=_auth(member))
    assert resp.status_code == 403
