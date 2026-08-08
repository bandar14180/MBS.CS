"""Atomic schedule-dispatch claim: a due schedule is dispatched by exactly one runner even
under overlapping beat ticks / acks_late redelivery, next_run_at advances exactly once, and
disabled/not-due schedules are skipped. Real Postgres via self-managed sessions.
"""
import asyncio
import uuid

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core.config import get_settings
from apps.api.modules.scans.models import Scan
from apps.api.modules.schedules.service import run_due_schedules
from apps.api.tests.test_scans import _auth, _make_target, _register, _verify_target


class _FakeResult:
    def __init__(self):
        self.id = f"task-{uuid.uuid4()}"


def _patch_delay(monkeypatch):
    """Stop create_scan from touching real Celery/Redis; record dispatched scan ids."""
    from apps.api.celery_app.tasks import scan_tasks

    calls: list[str] = []
    monkeypatch.setattr(scan_tasks.run_scan_task, "delay", lambda sid: (calls.append(sid), _FakeResult())[1])
    return calls


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


def _setup_schedule(client, headers):
    ws, project, target = _make_target(client, headers)
    _verify_target(client, headers, ws, project, target)
    base = f"/api/v1/workspaces/{ws}/projects/{project}/schedules"
    sid = client.post(base, headers=headers, json={
        "target_id": target, "scan_type": "network", "requested_modules": ["naabu"], "interval_minutes": 60,
    }).json()["id"]
    return ws, project, target, sid


async def _exec(query: str, **params):
    """Run a statement that returns no rows (UPDATE/DDL) and commit."""
    engine = _engine()
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as s:
            await s.execute(text(query), params)
            await s.commit()
    finally:
        await engine.dispose()


async def _fetchone(query: str, **params):
    engine = _engine()
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as s:
            return (await s.execute(text(query), params)).first()
    finally:
        await engine.dispose()


async def _run_due() -> int:
    engine = _engine()
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as s:
            return await run_due_schedules(s)
    finally:
        await engine.dispose()


async def _scan_count(project_id: str) -> int:
    engine = _engine()
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as s:
            return await s.scalar(select(func.count()).select_from(Scan).where(Scan.project_id == uuid.UUID(project_id)))
    finally:
        await engine.dispose()


def _make_due(sid: str):
    asyncio.run(_exec("UPDATE scan_schedules SET next_run_at = now() - interval '1 minute' WHERE id = :i",
                     i=uuid.UUID(sid)))


# --- 1: back-to-back/overlapping runs dispatch a due schedule EXACTLY once ---

def test_due_schedule_dispatched_exactly_once(client, monkeypatch):
    _patch_delay(monkeypatch)
    headers = _auth(_register(client, "SchedClaim1"))
    ws, project, target, sid = _setup_schedule(client, headers)
    _make_due(sid)

    asyncio.run(_run_due())      # first runner claims + dispatches
    asyncio.run(_run_due())      # second runner: not due (claimed) -> skips

    # exactly ONE scan row for this schedule's project -> no duplicate dispatch
    assert asyncio.run(_scan_count(project)) == 1


# --- 2: next_run_at advances exactly once ---

def test_next_run_at_advances_exactly_once(client, monkeypatch):
    _patch_delay(monkeypatch)
    headers = _auth(_register(client, "SchedClaim2"))
    ws, project, target, sid = _setup_schedule(client, headers)
    _make_due(sid)

    asyncio.run(_run_due())
    after1 = asyncio.run(_fetchone("SELECT next_run_at FROM scan_schedules WHERE id = :i", i=uuid.UUID(sid)))[0]
    asyncio.run(_run_due())      # not due now -> must not advance again
    after2 = asyncio.run(_fetchone("SELECT next_run_at FROM scan_schedules WHERE id = :i", i=uuid.UUID(sid)))[0]

    assert after1 == after2                      # advanced exactly once
    now_row = asyncio.run(_fetchone("SELECT now()"))[0]
    assert after1 > now_row                       # into the future


# --- 3: a single due schedule launches one scan and records last_scan_id ---

def test_single_due_schedule_launches_one_scan(client, monkeypatch):
    _patch_delay(monkeypatch)
    headers = _auth(_register(client, "SchedClaim3"))
    ws, project, target, sid = _setup_schedule(client, headers)
    _make_due(sid)

    asyncio.run(_run_due())
    assert asyncio.run(_scan_count(project)) == 1
    last_scan_id = asyncio.run(_fetchone("SELECT last_scan_id FROM scan_schedules WHERE id = :i", i=uuid.UUID(sid)))[0]
    assert last_scan_id is not None


# --- 4: disabled or not-due schedules are skipped (no dispatch) ---

def test_disabled_and_not_due_are_skipped(client, monkeypatch):
    _patch_delay(monkeypatch)
    headers = _auth(_register(client, "SchedClaim4"))
    ws, project, target, sid = _setup_schedule(client, headers)

    # freshly created -> next_run_at is in the future (not due)
    asyncio.run(_run_due())
    assert asyncio.run(_scan_count(project)) == 0

    # disabled AND due -> still skipped (enabled filter)
    asyncio.run(_exec("UPDATE scan_schedules SET enabled = false, next_run_at = now() - interval '1 minute' WHERE id = :i",
                     i=uuid.UUID(sid)))
    asyncio.run(_run_due())
    assert asyncio.run(_scan_count(project)) == 0
