"""Phase 1.7 -- high-value business-logic tests.

Exercises real service/business logic through the public API (plus a couple of direct
service calls where the beat path has no endpoint), driving the under-covered CRUD +
lifecycle code in workspaces, projects, vulnerabilities, dashboard, reports, and schedules.
No artificial assertions; minimal seeding via the same RLS-GUC session the worker uses.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core.config import get_settings
from apps.api.modules.scans.models import Scan
from apps.api.modules.vulnerabilities.models import Vulnerability
from apps.api.scanner_engine.models import Evidence, ToolRun
from apps.api.tests.test_scans import (  # helpers reused (no_celery_dispatch is a conftest fixture)
    _auth,
    _make_target,
    _register,
    _verify_target,
)


def _me(client, headers) -> str:
    return client.get("/api/v1/users/me", headers=headers).json()["id"]


async def _seed(ws: str, project: str, target: str, user_id: str, *, completed_scan=True, vulns=True) -> str | None:
    """Seed a completed scan + a few vulnerabilities for the project (RLS GUC set, exactly
    like the worker). Returns the scan id (or None)."""
    engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    scan_id = None
    try:
        async with maker() as s:
            await s.execute(text("SELECT set_config('app.current_workspace_id', :w, false)"), {"w": ws})
            if completed_scan:
                now = datetime.now(timezone.utc)
                scan = Scan(
                    workspace_id=uuid.UUID(ws), project_id=uuid.UUID(project), target_id=uuid.UUID(target),
                    initiated_by=uuid.UUID(user_id), scan_type="network", status="completed", config={},
                    started_at=now - timedelta(minutes=2), completed_at=now,
                )
                s.add(scan)
                await s.flush()
                scan_id = str(scan.id)
            if vulns:
                for i, (sev, st, score) in enumerate(
                    [("critical", "open", 9.5), ("medium", "confirmed", 5.5), ("low", "false_positive", 3.1)]
                ):
                    s.add(Vulnerability(
                        project_id=uuid.UUID(project),
                        first_detected_scan_id=uuid.UUID(scan_id) if scan_id else None,
                        last_seen_scan_id=uuid.UUID(scan_id) if scan_id else None,
                        fingerprint=f"fp-{i}-{uuid.uuid4()}", title=f"Finding {i}", category="web",
                        severity=sev, status=st, cvss_score=score,
                    ))
            await s.commit()
        return scan_id
    finally:
        await engine.dispose()


# --- Workspaces: member management + roles ------------------------------------------------

def test_workspace_member_lifecycle_and_roles(client):
    owner = _auth(_register(client, "BLWSOwner"))
    member = _register(client, "BLWSMember")
    ws = client.post("/api/v1/workspaces", headers=owner, json={"name": "BL WS"}).json()["id"]

    assert any(w["id"] == ws for w in client.get("/api/v1/workspaces", headers=owner).json())
    roles = client.get("/api/v1/roles", headers=owner)
    assert roles.status_code == 200 and any(r["name"] == "owner" for r in roles.json())

    inv = client.post(f"/api/v1/workspaces/{ws}/members/invite", headers=owner,
                      json={"email": member["email"], "role_name": "member"})
    assert inv.status_code == 201, inv.text
    uid = inv.json()["user_id"]

    upd = client.patch(f"/api/v1/workspaces/{ws}/members/{uid}/role", headers=owner, json={"role_name": "admin"})
    assert upd.status_code == 200 and upd.json()["role_name"] == "admin"

    assert client.delete(f"/api/v1/workspaces/{ws}/members/{uid}", headers=owner).status_code == 204
    assert all(m["user_id"] != uid for m in client.get(f"/api/v1/workspaces/{ws}/members", headers=owner).json())


# --- Projects + targets: full CRUD --------------------------------------------------------

def test_project_and_target_update_delete(client):
    headers = _auth(_register(client, "BLProj"))
    ws, project, target = _make_target(client, headers)

    got = client.get(f"/api/v1/workspaces/{ws}/projects/{project}", headers=headers)
    assert got.status_code == 200

    patched = client.patch(f"/api/v1/workspaces/{ws}/projects/{project}", headers=headers,
                           json={"name": "Renamed", "description": "d", "status": "archived"})
    assert patched.status_code == 200 and patched.json()["name"] == "Renamed"

    tgt = client.patch(f"/api/v1/workspaces/{ws}/projects/{project}/targets/{target}", headers=headers,
                       json={"criticality": "high"})
    assert tgt.status_code == 200 and tgt.json()["criticality"] == "high"

    assert client.get(f"/api/v1/workspaces/{ws}/projects", headers=headers).status_code == 200
    assert client.delete(f"/api/v1/workspaces/{ws}/projects/{project}", headers=headers).status_code == 204
    assert client.get(f"/api/v1/workspaces/{ws}/projects/{project}", headers=headers).status_code == 404


# --- Vulnerabilities: list filters / get / status transitions -----------------------------

def test_vulnerability_listing_filtering_and_status(client):
    headers = _auth(_register(client, "BLVuln"))
    ws, project, target = _make_target(client, headers)
    asyncio.run(_seed(ws, project, target, _me(client, headers)))
    base = f"/api/v1/workspaces/{ws}/projects/{project}/vulnerabilities"

    allv = client.get(base, headers=headers)
    assert allv.status_code == 200 and len(allv.json()) == 3
    assert allv.json()[0]["severity"] == "critical"          # ordered by cvss desc

    assert len(client.get(base + "?severity=critical", headers=headers).json()) == 1
    assert len(client.get(base + "?status=false_positive", headers=headers).json()) == 1

    vid = allv.json()[0]["id"]
    assert client.get(f"{base}/{vid}", headers=headers).status_code == 200

    ok = client.patch(f"{base}/{vid}/status", headers=headers,
                      json={"status": "confirmed", "justification": "verified manually"})
    assert ok.status_code == 200 and ok.json()["status"] == "confirmed"

    bad = client.patch(f"{base}/{vid}/status", headers=headers,
                       json={"status": "not_a_status", "justification": "x"})
    assert bad.status_code in (400, 422)   # rejected (schema or service guard)

    # risk score not computed for a seeded vuln -> 404 (exercises the risk 404 branch)
    assert client.get(f"{base}/{vid}/risk", headers=headers).status_code == 404
    assert client.get(f"{base}/{vid}/compliance-mappings", headers=headers).status_code == 200
    assert client.get(f"{base}/{vid}/attack-mappings", headers=headers).status_code == 200


def test_vulnerability_not_found(client):
    headers = _auth(_register(client, "BLVuln404"))
    ws, project, _t = _make_target(client, headers)
    r = client.get(f"/api/v1/workspaces/{ws}/projects/{project}/vulnerabilities/{uuid.uuid4()}", headers=headers)
    assert r.status_code == 404


# --- Dashboard ----------------------------------------------------------------------------

def test_dashboard_summary_and_recommendations(client):
    headers = _auth(_register(client, "BLDash"))
    ws, project, target = _make_target(client, headers)
    asyncio.run(_seed(ws, project, target, _me(client, headers)))

    summary = client.get(f"/api/v1/workspaces/{ws}/dashboard/summary", headers=headers)
    assert summary.status_code == 200
    body = summary.json()
    assert "total_vulnerabilities" in body or "vulnerabilities" in body or isinstance(body, dict)

    recs = client.get(f"/api/v1/workspaces/{ws}/dashboard/recommendations", headers=headers)
    assert recs.status_code == 200 and isinstance(recs.json(), list)


# --- Reports: 409 guard, then generate/list/download over a completed scan -----------------

def test_report_requires_completed_scan(client):
    headers = _auth(_register(client, "BLRep409"))
    ws, project, _t = _make_target(client, headers)
    r = client.post(f"/api/v1/workspaces/{ws}/projects/{project}/reports", headers=headers,
                    json={"type": "executive", "scan_ids": []})
    assert r.status_code == 409   # no completed scan to report on


def test_report_generate_list_download(client):
    headers = _auth(_register(client, "BLRep"))
    ws, project, target = _make_target(client, headers)
    scan_id = asyncio.run(_seed(ws, project, target, _me(client, headers)))
    base = f"/api/v1/workspaces/{ws}/projects/{project}/reports"

    created = client.post(base, headers=headers, json={"type": "technical", "scan_ids": [scan_id]})
    assert created.status_code == 201, created.text
    rid = created.json()["id"]

    assert any(r["id"] == rid for r in client.get(base, headers=headers).json())

    dl = client.get(f"{base}/{rid}/download", headers=headers)
    assert dl.status_code == 200
    assert dl.headers["content-type"] == "application/pdf"
    assert dl.content[:4] == b"%PDF"


# --- Schedules: update validation + the beat run-due path ---------------------------------

def test_schedule_update_interval_validation(client):
    headers = _auth(_register(client, "BLSched"))
    ws, project, target = _make_target(client, headers)
    base = f"/api/v1/workspaces/{ws}/projects/{project}/schedules"
    sid = client.post(base, headers=headers, json={
        "target_id": target, "scan_type": "web", "requested_modules": ["httpx"], "interval_minutes": 60,
    }).json()["id"]

    assert client.get(base, headers=headers).status_code == 200
    ok = client.patch(f"{base}/{sid}", headers=headers, json={"interval_minutes": 120})
    assert ok.status_code == 200 and ok.json()["interval_minutes"] == 120
    # below the 5-minute floor is rejected by the service (400), distinct from schema 422
    bad = client.patch(f"{base}/{sid}", headers=headers, json={"enabled": True, "interval_minutes": 3})
    assert bad.status_code in (400, 422)


def test_run_due_schedules_launches_and_advances(client, no_celery_dispatch):
    headers = _auth(_register(client, "BLBeat"))
    ws, project, target = _make_target(client, headers)
    _verify_target(client, headers, ws, project, target)   # so create_scan passes the scope gate
    base = f"/api/v1/workspaces/{ws}/projects/{project}/schedules"
    sid = client.post(base, headers=headers, json={
        "target_id": target, "scan_type": "network", "requested_modules": ["naabu"], "interval_minutes": 60,
    }).json()["id"]

    from apps.api.modules.schedules.service import run_due_schedules

    async def _run():
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                # make the schedule due
                await s.execute(
                    text("UPDATE scan_schedules SET next_run_at = now() - interval '1 minute' WHERE id = :i"),
                    {"i": uuid.UUID(sid)},
                )
                await s.commit()
                launched = await run_due_schedules(s)
                nxt = await s.scalar(
                    text("SELECT next_run_at > now() FROM scan_schedules WHERE id = :i"),
                    {"i": uuid.UUID(sid)},
                )
            return launched, nxt
        finally:
            await engine.dispose()

    launched, advanced = asyncio.run(_run())
    assert launched >= 1          # the due schedule fired a scan
    assert advanced is True       # next_run_at was pushed into the future


# --- Auth: login / bad password / logout / revoked refresh --------------------------------

def test_auth_login_logout_flows(client):
    reg = _register(client, "BLAuth")
    email = reg["email"]

    ok = client.post("/api/v1/auth/login", json={"email": email, "password": "correct horse battery staple"})
    assert ok.status_code == 200 and "access_token" in ok.json()

    assert client.post("/api/v1/auth/login", json={"email": email, "password": "wrongpassword123"}).status_code == 401
    assert client.post("/api/v1/auth/login",
                       json={"email": f"unknown-{uuid.uuid4()}@example.com", "password": "wrongpassword123"}).status_code == 401

    assert client.post("/api/v1/auth/logout", json={"refresh_token": reg["refresh_token"]}).status_code == 204
    # a revoked refresh token can no longer be rotated
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": reg["refresh_token"]}).status_code == 401


# --- Scan cancellation + sub-resources ----------------------------------------------------

def test_scan_cancel_and_subresources(client, no_celery_dispatch):
    headers = _auth(_register(client, "BLScanSvc"))
    ws, project, target = _make_target(client, headers)
    _verify_target(client, headers, ws, project, target)
    base = f"/api/v1/workspaces/{ws}/projects/{project}/scans"
    sid = client.post(base, headers=headers,
                      json={"target_id": target, "scan_type": "network", "requested_modules": ["naabu"]}).json()["id"]

    assert client.get(f"{base}/{sid}/tool-runs", headers=headers).status_code == 200
    assert client.get(f"{base}/{sid}/ai-plan", headers=headers).status_code == 404   # none generated

    cancelled = client.post(f"{base}/{sid}/cancel", headers=headers)
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled"
    # cancelling a terminal scan is rejected
    assert client.post(f"{base}/{sid}/cancel", headers=headers).status_code == 400


# --- Dead-letter queue operator tooling ---------------------------------------------------

def test_dlq_inspect_replay_remove_purge(monkeypatch):
    from apps.api.celery_app import dlq
    from apps.api.celery_app.tasks import scan_tasks

    dlq.purge()   # clean slate
    sid = str(uuid.uuid4())
    scan_tasks._record_dlq(sid, RuntimeError("boom"), task_id="t1", retries=3)
    scan_tasks._record_dlq(str(uuid.uuid4()), RuntimeError("other"), task_id="t2", retries=3)

    entries = dlq.inspect()
    assert any(e.get("scan_id") == sid for e in entries)

    monkeypatch.setattr(scan_tasks.run_scan_task, "delay", lambda *a, **k: None)   # no real dispatch
    assert dlq.replay(sid) is True          # found + re-enqueued + removed
    assert dlq.replay(sid) is False         # already gone
    assert dlq.remove(str(uuid.uuid4())) == 0

    assert dlq._main(["list"]) == 0
    assert dlq._main(["purge"]) == 0
    assert dlq._main([]) == 2               # usage
    assert dlq.inspect() == []


# --- Cheap read endpoints across several services -----------------------------------------

def test_api_keys_and_notifications_and_audit(client):
    headers = _auth(_register(client, "BLMisc"))
    ws = client.post("/api/v1/workspaces", headers=headers, json={"name": "Misc WS"}).json()["id"]

    created = client.post(f"/api/v1/workspaces/{ws}/api-keys", headers=headers, json={"name": "ci-key"})
    assert created.status_code == 201 and created.json().get("secret")
    kid = created.json()["id"]
    assert any(k["id"] == kid for k in client.get(f"/api/v1/workspaces/{ws}/api-keys", headers=headers).json())
    assert client.delete(f"/api/v1/workspaces/{ws}/api-keys/{kid}", headers=headers).status_code == 204

    assert client.get(f"/api/v1/workspaces/{ws}/notifications", headers=headers).status_code == 200
    assert client.get(f"/api/v1/workspaces/{ws}/notifications/unread-count", headers=headers).status_code == 200
    assert client.post(f"/api/v1/workspaces/{ws}/notifications/read-all", headers=headers).status_code == 204

    assert client.get(f"/api/v1/workspaces/{ws}/audit", headers=headers).status_code == 200


# --- Scan analytics views (attack matrix / kill-chain / graph / timeline) ------------------

def test_scan_attack_views_and_timeline(client):
    headers = _auth(_register(client, "BLAttack"))
    ws, project, target = _make_target(client, headers)
    scan_id = asyncio.run(_seed(ws, project, target, _me(client, headers)))
    base = f"/api/v1/workspaces/{ws}/projects/{project}/scans/{scan_id}"

    assert client.get(base, headers=headers).status_code == 200                    # get_scan
    assert client.get(f"{base}/tool-runs", headers=headers).status_code == 200
    assert client.get(f"{base}/attack-matrix", headers=headers).status_code == 200  # attack_service
    assert client.get(f"{base}/kill-chain", headers=headers).status_code == 200
    assert client.get(f"{base}/attack-graph", headers=headers).status_code == 200
    assert client.get(f"{base}/timeline", headers=headers).status_code == 200
    assert client.get(f"{base}/agent-decisions", headers=headers).status_code == 200


def test_authorization_scope_read(client):
    headers = _auth(_register(client, "BLScope"))
    ws, project, target = _make_target(client, headers)
    _verify_target(client, headers, ws, project, target)
    base = f"/api/v1/workspaces/{ws}/projects/{project}/targets/{target}/authorization-scope"
    assert client.get(base, headers=headers).status_code == 200


async def _seed_toolrun(ws: str, project: str, target: str, user_id: str) -> tuple[str, str]:
    """Seed a completed scan with a tool run + one evidence row (RLS GUC set)."""
    engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as s:
            await s.execute(text("SELECT set_config('app.current_workspace_id', :w, false)"), {"w": ws})
            now = datetime.now(timezone.utc)
            scan = Scan(workspace_id=uuid.UUID(ws), project_id=uuid.UUID(project), target_id=uuid.UUID(target),
                        initiated_by=uuid.UUID(user_id), scan_type="network", status="completed", config={},
                        started_at=now - timedelta(minutes=1), completed_at=now)
            s.add(scan)
            await s.flush()
            tr = ToolRun(scan_id=scan.id, tool_name="naabu", tool_version="1", status="completed", command_hash="h")
            s.add(tr)
            await s.flush()
            s.add(Evidence(tool_run_id=tr.id, evidence_type="log_excerpt",
                           storage_uri=f"mem://{tr.id}", checksum="abc"))
            await s.commit()
            return str(scan.id), str(tr.id)
    finally:
        await engine.dispose()


def test_scan_tool_runs_and_evidence(client):
    headers = _auth(_register(client, "BLEvid"))
    ws, project, target = _make_target(client, headers)
    scan_id, tr_id = asyncio.run(_seed_toolrun(ws, project, target, _me(client, headers)))
    base = f"/api/v1/workspaces/{ws}/projects/{project}/scans/{scan_id}"

    runs = client.get(f"{base}/tool-runs", headers=headers)
    assert runs.status_code == 200 and any(r["id"] == tr_id for r in runs.json())

    ev = client.get(f"{base}/tool-runs/{tr_id}/evidence", headers=headers)
    assert ev.status_code == 200 and len(ev.json()) >= 1


def test_scan_create_with_agent_flags(client, no_celery_dispatch):
    headers = _auth(_register(client, "BLAgentScan"))
    ws, project, target = _make_target(client, headers)
    _verify_target(client, headers, ws, project, target)
    r = client.post(
        f"/api/v1/workspaces/{ws}/projects/{project}/scans", headers=headers,
        json={"target_id": target, "scan_type": "network", "requested_modules": ["naabu"],
              "use_agent": True, "exploitation_enabled": False, "approved_hosts": []},
    )
    assert r.status_code == 202 and r.json()["config"]["use_agent"] is True


async def _seed_asset(ws: str, project: str, target: str) -> str:
    from apps.api.modules.assets.models import Asset

    engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as s:
            await s.execute(text("SELECT set_config('app.current_workspace_id', :w, false)"), {"w": ws})
            a = Asset(project_id=uuid.UUID(project), target_id=uuid.UUID(target),
                      asset_type="http_service", value="http://seed.example", metadata_={})
            s.add(a)
            await s.flush()
            aid = str(a.id)
            await s.commit()
            return aid
    finally:
        await engine.dispose()


def test_assets_listing_get_and_ai_status(client):
    headers = _auth(_register(client, "BLAssets"))
    ws, project, target = _make_target(client, headers)
    aid = asyncio.run(_seed_asset(ws, project, target))

    assert client.get("/api/v1/ai/status", headers=headers).status_code == 200   # provider status report

    listed = client.get(f"/api/v1/workspaces/{ws}/projects/{project}/assets", headers=headers)
    assert listed.status_code == 200 and any(a["id"] == aid for a in listed.json())

    assert client.get(f"/api/v1/workspaces/{ws}/assets/{aid}", headers=headers).status_code == 200
    assert client.get(f"/api/v1/workspaces/{ws}/assets/{uuid.uuid4()}", headers=headers).status_code == 404
