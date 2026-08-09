"""Queued-scan relay: scans durably committed 'queued' but never delivered to Celery
(celery_task_id IS NULL) past the threshold are re-dispatched; a relay + a late original
message cannot double-execute (atomic scan claim); a relay dispatch failure leaves the scan
recoverable; and the relay never touches running/terminal or freshly-queued scans.
"""
import asyncio
import uuid

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core.config import get_settings
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.orchestrator import _claim_scan

RELAY_OLD = 600  # seconds; older than the default 300s relay threshold


class _FakeResult:
    def __init__(self):
        self.id = f"task-{uuid.uuid4()}"


def _patch_delay(monkeypatch):
    from apps.api.celery_app.tasks import scan_tasks

    calls: list[str] = []
    monkeypatch.setattr(scan_tasks.run_scan_task, "delay", lambda sid: (calls.append(sid), _FakeResult())[1])
    return calls


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _seed_scan(status="queued", *, task_id=None, age_seconds=0) -> uuid.UUID:
    engine = _engine()
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as s:
            user = User(email=f"relay-{uuid.uuid4()}@test.local", password_hash="x", full_name="Relay")
            s.add(user)
            await s.flush()
            ws = Workspace(name="relay-ws", owner_user_id=user.id)
            s.add(ws)
            await s.flush()
            project = Project(workspace_id=ws.id, name="relay-proj", created_by=user.id)
            s.add(project)
            await s.flush()
            target = Target(project_id=project.id, type="ip_range", value="203.0.113.60", criticality="low", added_by=user.id)
            s.add(target)
            await s.flush()
            scan = Scan(workspace_id=ws.id, project_id=project.id, target_id=target.id, initiated_by=user.id,
                        scan_type="network", status=status, config={}, celery_task_id=task_id)
            s.add(scan)
            await s.flush()
            if age_seconds:
                await s.execute(text("UPDATE scans SET created_at = now() - make_interval(secs => :a) WHERE id = :i"),
                                {"a": age_seconds, "i": scan.id})
            await s.commit()
            return scan.id
    finally:
        await engine.dispose()


async def _scan_field(scan_id, field):
    engine = _engine()
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as s:
            return (await s.execute(text(f"SELECT {field} FROM scans WHERE id = :i"), {"i": scan_id})).scalar()
    finally:
        await engine.dispose()


# --- 5: a stale, never-delivered queued scan is re-dispatched ---

def test_relay_redispatches_stale_undelivered_scan(monkeypatch):
    from apps.api.celery_app.tasks import scan_tasks

    calls = _patch_delay(monkeypatch)
    scan_id = asyncio.run(_seed_scan("queued", task_id=None, age_seconds=RELAY_OLD))

    relayed = asyncio.run(scan_tasks._relay_queued())
    assert relayed >= 1
    assert str(scan_id) in calls                                   # re-dispatched
    assert asyncio.run(_scan_field(scan_id, "celery_task_id")) is not None   # marked, won't relay again


# --- 6: relay message + late original message cannot both execute (atomic claim) ---

def test_relay_plus_late_original_cannot_double_execute():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                # a queued scan (as if relayed AND the original message is also in the broker)
                scan_id = await _seed_scan_inline(s, "queued")
                first = await _claim_scan(s, scan_id)     # one worker (e.g. relay msg) claims
                second = await _claim_scan(s, scan_id)    # the other (late original) cannot
            return first, second
        finally:
            await engine.dispose()

    first, second = asyncio.run(scenario())
    assert (first, second).count(True) == 1   # atomic claim -> exactly one execution


async def _seed_scan_inline(session, status):
    user = User(email=f"relay2-{uuid.uuid4()}@test.local", password_hash="x", full_name="Relay2")
    session.add(user)
    await session.flush()
    ws = Workspace(name="relay2-ws", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    project = Project(workspace_id=ws.id, name="relay2-proj", created_by=user.id)
    session.add(project)
    await session.flush()
    target = Target(project_id=project.id, type="ip_range", value="203.0.113.61", criticality="low", added_by=user.id)
    session.add(target)
    await session.flush()
    scan = Scan(workspace_id=ws.id, project_id=project.id, target_id=target.id, initiated_by=user.id,
                scan_type="network", status=status, config={})
    session.add(scan)
    await session.commit()
    return scan.id


# --- 7: a relay dispatch failure leaves the scan recoverable for a later relay ---

def test_relay_dispatch_failure_leaves_scan_recoverable(monkeypatch):
    from apps.api.celery_app.tasks import scan_tasks

    scan_id = asyncio.run(_seed_scan("queued", task_id=None, age_seconds=RELAY_OLD))

    def _boom(_sid):
        raise RuntimeError("broker down")

    monkeypatch.setattr(scan_tasks.run_scan_task, "delay", _boom)
    relayed = asyncio.run(scan_tasks._relay_queued())
    assert relayed == 0                                              # nothing dispatched
    assert asyncio.run(_scan_field(scan_id, "status")) == "queued"   # untouched
    assert asyncio.run(_scan_field(scan_id, "celery_task_id")) is None  # still eligible

    # broker recovers -> a later relay picks it up
    calls = _patch_delay(monkeypatch)
    relayed2 = asyncio.run(scan_tasks._relay_queued())
    assert relayed2 >= 1 and str(scan_id) in calls


# --- 8: the relay ignores running/terminal and freshly-queued scans ---

def test_relay_ignores_non_eligible_scans(monkeypatch):
    from apps.api.celery_app.tasks import scan_tasks

    calls = _patch_delay(monkeypatch)
    running = asyncio.run(_seed_scan("running", task_id=None, age_seconds=RELAY_OLD))
    completed = asyncio.run(_seed_scan("completed", task_id=None, age_seconds=RELAY_OLD))
    dispatched = asyncio.run(_seed_scan("queued", task_id="already-has-a-task", age_seconds=RELAY_OLD))
    fresh = asyncio.run(_seed_scan("queued", task_id=None, age_seconds=0))  # too new

    asyncio.run(scan_tasks._relay_queued())

    for sid in (running, completed, dispatched, fresh):
        assert str(sid) not in calls                                # none re-dispatched
    assert asyncio.run(_scan_field(running, "status")) == "running"  # orphan-reaper's job, not the relay's
