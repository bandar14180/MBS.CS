"""Data Privacy Hardening -- DELETE /users/me (GDPR erasure via anonymization).

Verifies: password-confirmed, irreversible, blocks all further auth, scrubs the user
row, revokes API keys, and anonymizes the denormalized audit_events.actor_email while
preserving the audit row (actor_user_id stays -> trail integrity).
"""
import asyncio
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core.config import get_settings

_PW = "correct horse battery staple"


def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": _PW, "full_name": "Erase Me"},
    )
    assert r.status_code == 201, r.text
    tokens = r.json()
    me = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 200, me.text
    return {"email": email, "id": me.json()["id"], **tokens}


def _auth(t: dict) -> dict:
    return {"Authorization": f"Bearer {t['access_token']}"}


def _create_workspace(client: TestClient, headers: dict) -> str:
    r = client.post("/api/v1/workspaces", headers=headers, json={"name": "WS"})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _insert_audit_event(workspace_id: str, user_id: str, email: str) -> None:
    eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    try:
        async with eng.begin() as c:
            await c.execute(
                text("SELECT set_config('app.current_workspace_id', :wid, true)"),
                {"wid": workspace_id},
            )
            await c.execute(
                text(
                    "INSERT INTO audit_events "
                    "(id, workspace_id, actor_user_id, actor_email, action, resource_type, created_at) "
                    "VALUES (:id, :wid, :uid, :email, 'test.action', 'test', now())"
                ),
                {"id": str(uuid.uuid4()), "wid": workspace_id, "uid": user_id, "email": email},
            )
    finally:
        await eng.dispose()


async def _read_actor_emails(user_id: str) -> list:
    eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    try:
        async with eng.connect() as c:
            rows = (
                await c.execute(
                    text("SELECT actor_email FROM audit_events WHERE actor_user_id = :uid"),
                    {"uid": user_id},
                )
            ).all()
            return [r[0] for r in rows]
    finally:
        await eng.dispose()


async def _read_user(user_id: str):
    eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    try:
        async with eng.connect() as c:
            return (
                await c.execute(
                    text("SELECT email, full_name, status, mfa_enabled FROM users WHERE id = :id"),
                    {"id": user_id},
                )
            ).first()
    finally:
        await eng.dispose()


def test_delete_requires_correct_password(client: TestClient) -> None:
    u = _register(client)
    h = _auth(u)
    bad = client.request("DELETE", "/api/v1/users/me", headers=h, json={"password": "wrong"})
    assert bad.status_code == 401
    # Account is untouched and still usable.
    assert client.get("/api/v1/users/me", headers=h).status_code == 200


def test_delete_erases_pii_and_blocks_auth(client: TestClient) -> None:
    u = _register(client)
    h = _auth(u)
    ws = _create_workspace(client, h)
    asyncio.run(_insert_audit_event(ws, u["id"], u["email"]))

    ok = client.request("DELETE", "/api/v1/users/me", headers=h, json={"password": _PW})
    assert ok.status_code == 204

    # 1) The old access token can no longer be used (status != active).
    assert client.get("/api/v1/users/me", headers=h).status_code == 401
    # 2) Login with the original credentials fails (email was tombstoned).
    relogin = client.post("/api/v1/auth/login", json={"email": u["email"], "password": _PW})
    assert relogin.status_code == 401

    # 3) The user row is scrubbed.
    row = asyncio.run(_read_user(u["id"]))
    assert row is not None  # row preserved (referential integrity), but anonymized
    email, full_name, status_, mfa_enabled = row
    assert email.startswith("deleted+") and email.endswith("@deleted.invalid")
    assert full_name == "Deleted User"
    assert status_ == "deleted"
    assert mfa_enabled is False

    # 4) The denormalized audit PII is anonymized; the audit row itself survives.
    emails = asyncio.run(_read_actor_emails(u["id"]))
    assert emails, "audit event should still exist (trail preserved)"
    assert all(e == "[deleted]" for e in emails)
    assert u["email"] not in emails


def test_delete_revokes_api_keys(client: TestClient) -> None:
    u = _register(client)
    h = _auth(u)
    ws = _create_workspace(client, h)
    created = client.post(f"/api/v1/workspaces/{ws}/api-keys", headers=h, json={"name": "k"})
    assert created.status_code == 201, created.text
    raw_key = created.json()["secret"]

    # Key works before erasure.
    key_hdr = {"Authorization": f"Bearer {raw_key}"}
    assert client.get("/api/v1/users/me", headers=key_hdr).status_code == 200

    ok = client.request("DELETE", "/api/v1/users/me", headers=h, json={"password": _PW})
    assert ok.status_code == 204

    # Key is revoked -> authentication via the key now fails.
    assert client.get("/api/v1/users/me", headers=key_hdr).status_code == 401
