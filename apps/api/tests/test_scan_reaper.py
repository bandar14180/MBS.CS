"""Phase 1.2 -- orphan scan recovery (reaper). Verifies that scans stuck in 'running'
past the timeout are safely marked 'failed', while recent/terminal scans are untouched,
tenant selectivity holds, and a recovered scan can never be double-executed.

Real Postgres via a self-managed session (scans is RLS-exempt, like the worker path).
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core.config import get_settings
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.orchestrator import _claim_scan, _finalize_status, reap_orphaned_scans

TIMEOUT = 7200  # 2h
OLD = datetime.now(timezone.utc) - timedelta(hours=3)      # past the timeout -> orphan
RECENT = datetime.now(timezone.utc) - timedelta(seconds=5)  # well within the timeout


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _seed_scan(session, status, started_at):
    user = User(email=f"reap-{uuid.uuid4()}@test.local", password_hash="x", full_name="Reap Tester")
    session.add(user)
    await session.flush()
    ws = Workspace(name="reap-ws", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    project = Project(workspace_id=ws.id, name="reap-proj", created_by=user.id)
    session.add(project)
    await session.flush()
    target = Target(project_id=project.id, type="ip_range", value="203.0.113.50", criticality="low", added_by=user.id)
    session.add(target)
    await session.flush()
    scan = Scan(
        workspace_id=ws.id, project_id=project.id, target_id=target.id, initiated_by=user.id,
        scan_type="network", status=status, config={}, started_at=started_at,
    )
    session.add(scan)
    await session.commit()
    return ws.id, scan.id


async def _status(session, scan_id):
    return await session.scalar(select(Scan.status).where(Scan.id == scan_id))


async def _config(session, scan_id):
    return await session.scalar(select(Scan.config).where(Scan.id == scan_id))


# --- 1 & 2: old running recovered; recent running untouched (deterministic together) ---

def test_reaper_recovers_old_and_spares_recent():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                _wa, old_id = await _seed_scan(s, "running", OLD)
                _wb, recent_id = await _seed_scan(s, "running", RECENT)
                reaped = await reap_orphaned_scans(s, TIMEOUT)
                old = await _status(s, old_id)
                recent = await _status(s, recent_id)
                completed = await s.scalar(select(Scan.completed_at).where(Scan.id == old_id))
            return reaped, old, recent, completed
        finally:
            await engine.dispose()

    reaped, old, recent, completed = asyncio.run(scenario())
    assert reaped >= 1                       # at least our orphan was recovered
    assert old == "failed" and completed is not None   # (1) old running -> failed
    assert recent == "running"               # (2) recent running left alone


# --- 3 & 4: completed / FAILED / cancelled scans are never touched ---

def test_reaper_ignores_terminal_scans():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                ids = {}
                # includes 'failed' (scenario 4): an already-failed scan stays failed.
                for st in ("completed", "failed", "cancelled", "completed_with_errors"):
                    _w, sid = await _seed_scan(s, st, OLD)  # OLD but not 'running'
                    ids[st] = sid
                await reap_orphaned_scans(s, TIMEOUT)
                out = {st: await _status(s, sid) for st, sid in ids.items()}
            return out
        finally:
            await engine.dispose()

    out = asyncio.run(scenario())
    assert out == {
        "completed": "completed", "failed": "failed",
        "cancelled": "cancelled", "completed_with_errors": "completed_with_errors",
    }


# --- 7: the orphaned scan gets a clear, persisted failure reason ---

def test_reaper_persists_failure_reason():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                _w, sid = await _seed_scan(s, "running", OLD)
                await reap_orphaned_scans(s, TIMEOUT)
                return await _status(s, sid), await _config(s, sid)
        finally:
            await engine.dispose()

    status, config = asyncio.run(scenario())
    assert status == "failed"
    recovery = (config or {}).get("recovery")
    assert recovery, "failure reason (config.recovery) was not persisted"
    assert "orphaned" in recovery["reason"].lower()
    assert recovery["running_timeout_seconds"] == TIMEOUT
    assert recovery.get("recovered_at")


# --- 5: running the reaper twice is safe (idempotent) for a given scan ---

def test_reaper_is_idempotent_across_runs():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                _w, sid = await _seed_scan(s, "running", OLD)
                first = await reap_orphaned_scans(s, TIMEOUT)          # recovers our orphan
                status1, config1 = await _status(s, sid), await _config(s, sid)
                await reap_orphaned_scans(s, TIMEOUT)                  # our scan no longer 'running'
                status2, config2 = await _status(s, sid), await _config(s, sid)
            return first, status1, status2, config1, config2
        finally:
            await engine.dispose()

    first, status1, status2, config1, config2 = asyncio.run(scenario())
    assert first >= 1
    assert status1 == status2 == "failed"                 # 2nd run does not re-touch it
    assert config1["recovery"] == config2["recovery"]     # reason not rewritten/corrupted


# --- 6: a scan that completes first (race) is NOT overwritten by the reaper ---

def test_reaper_does_not_overwrite_a_completing_scan():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                _w, sid = await _seed_scan(s, "running", OLD)   # old enough to be a reap candidate
                scan = await s.get(Scan, sid)
                # the worker finishes FIRST: running -> completed (atomic conditional write)
                won = await _finalize_status(s, scan, "completed")
                # the reaper then runs -- it must NOT clobber the just-completed scan
                await reap_orphaned_scans(s, TIMEOUT)
                return won, await _status(s, sid), await _config(s, sid)
        finally:
            await engine.dispose()

    won, status, config = asyncio.run(scenario())
    assert won is True
    assert status == "completed"                    # reaper left the completed scan alone
    assert "recovery" not in (config or {})         # no orphan reason falsely attached


# --- 4: a recovered scan cannot be double-executed ---

def test_reaped_scan_cannot_be_double_executed():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                _w, sid = await _seed_scan(s, "running", OLD)
                await reap_orphaned_scans(s, TIMEOUT)     # -> 'failed' (reclaimable)
                status_after = await _status(s, sid)
                # Two workers now attempt to claim the recovered scan: exactly one wins.
                first = await _claim_scan(s, sid)
                second = await _claim_scan(s, sid)
            return status_after, first, second
        finally:
            await engine.dispose()

    status_after, first, second = asyncio.run(scenario())
    assert status_after == "failed"                 # recovered, reclaimable
    assert (first, second).count(True) == 1         # atomic claim -> no duplicate execution


# --- 5: tenant selectivity (system reaper acts per-scan, not cross-tenant leakage) ---

def test_reaper_is_tenant_selective():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                ws_a, a_id = await _seed_scan(s, "running", OLD)      # tenant A: orphan
                ws_b, b_id = await _seed_scan(s, "running", RECENT)   # tenant B: healthy/recent
                await reap_orphaned_scans(s, TIMEOUT)
                a = await _status(s, a_id)
                b = await _status(s, b_id)
                # tenant B's project/target rows are untouched by the reaper.
                b_proj = await s.scalar(select(Scan.project_id).where(Scan.id == b_id))
                proj_ok = await s.scalar(select(Project.id).where(Project.id == b_proj))
            return ws_a, ws_b, a, b, proj_ok
        finally:
            await engine.dispose()

    ws_a, ws_b, a, b, proj_ok = asyncio.run(scenario())
    assert ws_a != ws_b
    assert a == "failed"        # A's orphan recovered
    assert b == "running"       # B untouched (recent) -> no cross-tenant side effect
    assert proj_ok is not None  # tenant data intact


# --- disable switch: reaper is a no-op when recovery is turned off ---

def test_reaper_respects_disable_flag(monkeypatch):
    from apps.api.celery_app.tasks import scan_tasks

    monkeypatch.setattr(get_settings(), "scan_orphan_recovery_enabled", False)

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                _w, sid = await _seed_scan(s, "running", OLD)
            reaped = await scan_tasks._reap()          # disabled -> no DB work
            async with maker() as v:
                status = await _status(v, sid)
            return reaped, status
        finally:
            await engine.dispose()

    reaped, status = asyncio.run(scenario())
    assert reaped == 0 and status == "running"     # untouched when disabled
