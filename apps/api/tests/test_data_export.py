"""Data Privacy Hardening -- GET /users/me/export (GDPR access/portability).

Verifies the export includes profile, memberships, API-key metadata, activity summary, and
(GDPR export expansion) the user's own scans / reports / actor audit events -- metadata only,
tenant-isolated, never leaking secrets or internal storage paths, and audited via account.exported.
"""
import asyncio
import json
import logging
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
        json={"email": email, "password": _PW, "full_name": "Export Me"},
    )
    assert r.status_code == 201, r.text
    tokens = r.json()
    me = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 200, me.text
    return {"email": email, "id": me.json()["id"], **tokens}


def _auth(t: dict) -> dict:
    return {"Authorization": f"Bearer {t['access_token']}"}


def _workspace(client: TestClient, headers: dict, name: str = "Acme") -> str:
    return client.post("/api/v1/workspaces", headers=headers, json={"name": name}).json()["id"]


# A report is seeded with a real storage_uri + a scan with config, to prove neither leaks.
_SECRET_STORAGE_URI = "s3://mbs-reports/internal/secret-path.pdf"


async def _seed_activity(workspace_id: str, user_id: str) -> dict:
    """Insert a project -> target -> scan, plus a report and an audit event owned by the user.
    Direct SQL keeps the test hermetic (no full scan pipeline). Runs under the workspace GUC so
    it works whether or not the DB role bypasses RLS."""
    eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    ids = {k: str(uuid.uuid4()) for k in ("project", "target", "scan", "report", "audit")}
    try:
        async with eng.begin() as c:
            await c.execute(
                text("SELECT set_config('app.current_workspace_id', :w, true)"), {"w": workspace_id}
            )
            await c.execute(
                text("INSERT INTO projects (id, workspace_id, name, status, created_by, created_at) "
                     "VALUES (:id,:w,'Proj','active',:u, now())"),
                {"id": ids["project"], "w": workspace_id, "u": user_id},
            )
            await c.execute(
                text("INSERT INTO targets (id, project_id, type, value, criticality, added_by, created_at) "
                     "VALUES (:id,:p,'domain','example.com','medium',:u, now())"),
                {"id": ids["target"], "p": ids["project"], "u": user_id},
            )
            await c.execute(
                text("INSERT INTO scans (id, workspace_id, project_id, target_id, initiated_by, "
                     "scan_type, status, config, created_at) "
                     "VALUES (:id,:w,:p,:t,:u,'recon','completed','{}'::jsonb, now())"),
                {"id": ids["scan"], "w": workspace_id, "p": ids["project"], "t": ids["target"], "u": user_id},
            )
            await c.execute(
                text("INSERT INTO reports (id, project_id, type, format, storage_uri, scan_ids, "
                     "generated_by, generated_at) "
                     "VALUES (:id,:p,'technical','pdf',:uri,'[]'::jsonb,:u, now())"),
                {"id": ids["report"], "p": ids["project"], "uri": _SECRET_STORAGE_URI, "u": user_id},
            )
            await c.execute(
                text("INSERT INTO audit_events (id, workspace_id, actor_user_id, actor_email, action, "
                     "resource_type, resource_id, created_at) "
                     "VALUES (:id,:w,:u,:e,'scan.created','scan',:s, now())"),
                {"id": ids["audit"], "w": workspace_id, "u": user_id, "e": "seed@example.com", "s": ids["scan"]},
            )
    finally:
        await eng.dispose()
    return ids


# --- existing coverage ---------------------------------------------------------------------

def test_export_requires_auth(client: TestClient) -> None:
    assert client.get("/api/v1/users/me/export").status_code == 401


def test_export_contains_personal_data(client: TestClient) -> None:
    u = _register(client)
    h = _auth(u)
    ws = _workspace(client, h)
    client.post(f"/api/v1/workspaces/{ws}/api-keys", headers=h, json={"name": "ci-key"})

    data = client.get("/api/v1/users/me/export", headers=h).json()
    assert data["profile"]["email"] == u["email"]
    assert data["workspaces"][0]["workspace_name"] == "Acme"
    assert data["workspaces"][0]["role_name"] == "owner"
    assert data["api_keys"][0]["name"] == "ci-key"
    assert data["api_keys"][0]["prefix"].startswith("mbsk_")
    assert data["activity_summary"]["workspace_count"] == 1
    assert data["activity_summary"]["api_key_count"] == 1


def test_export_never_leaks_secrets_or_hashes(client: TestClient) -> None:
    u = _register(client)
    h = _auth(u)
    ws = _workspace(client, h)
    client.post(f"/api/v1/workspaces/{ws}/api-keys", headers=h, json={"name": "ci-key"})

    blob = json.dumps(client.get("/api/v1/users/me/export", headers=h).json()).lower()
    for forbidden in ("password_hash", "key_hash", "token_hash", "mfa_secret", "secret", "\"hash\""):
        assert forbidden not in blob, f"export leaked '{forbidden}'"


# --- GDPR export expansion: scans / reports / audit ----------------------------------------

def test_export_includes_user_scans_reports_and_audit(client: TestClient) -> None:
    u = _register(client)
    h = _auth(u)
    ws = _workspace(client, h)
    ids = asyncio.run(_seed_activity(ws, u["id"]))

    data = client.get("/api/v1/users/me/export", headers=h).json()
    assert ids["scan"] in {s["id"] for s in data["scans"]}
    assert ids["report"] in {r["id"] for r in data["reports"]}
    assert ids["audit"] in {a["id"] for a in data["audit_events"]}

    summary = data["activity_summary"]
    assert summary["scan_count"] >= 1
    assert summary["report_count"] >= 1
    assert summary["audit_event_count"] >= 1


def test_export_is_metadata_only(client: TestClient) -> None:
    u = _register(client)
    h = _auth(u)
    ws = _workspace(client, h)
    asyncio.run(_seed_activity(ws, u["id"]))
    data = client.get("/api/v1/users/me/export", headers=h).json()

    # exact metadata surface -- no scan config/evidence, no report storage path
    assert set(data["scans"][0]) == {
        "id", "workspace_id", "scan_type", "status", "created_at", "started_at", "completed_at",
    }
    assert set(data["reports"][0]) == {
        "id", "project_id", "type", "format", "scan_ids", "generated_at",
    }
    assert set(data["audit_events"][0]) == {
        "id", "workspace_id", "action", "resource_type", "resource_id", "created_at",
    }
    blob = json.dumps(data).lower()
    assert "s3://" not in blob and "storage_uri" not in blob and "secret-path" not in blob


def test_export_is_tenant_isolated_between_users(client: TestClient) -> None:
    a = _register(client)
    ws_a = _workspace(client, _auth(a), "A-space")
    asyncio.run(_seed_activity(ws_a, a["id"]))

    b = _register(client)
    ws_b = _workspace(client, _auth(b), "B-space")
    ids_b = asyncio.run(_seed_activity(ws_b, b["id"]))

    # A's export must contain NONE of B's scans/reports/audit (filtered by ownership + RLS).
    data = client.get("/api/v1/users/me/export", headers=_auth(a)).json()
    assert ids_b["scan"] not in {s["id"] for s in data["scans"]}
    assert ids_b["report"] not in {r["id"] for r in data["reports"]}
    assert ids_b["audit"] not in {ev["id"] for ev in data["audit_events"]}
    # and every workspace_id present belongs to A
    assert all(s["workspace_id"] == ws_a for s in data["scans"])


def test_export_emits_account_exported_event(client: TestClient, caplog) -> None:
    u = _register(client)
    h = _auth(u)
    ws = _workspace(client, h)
    asyncio.run(_seed_activity(ws, u["id"]))
    with caplog.at_level(logging.INFO, logger="mbs.security"):
        assert client.get("/api/v1/users/me/export", headers=h).status_code == 200
    assert "account.exported" in {r.getMessage() for r in caplog.records}
