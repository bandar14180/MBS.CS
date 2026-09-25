"""Liveness-based orphan recovery: long scans live, dead scans are recovered.

The scanner previously died on the clock. `scans.run_scan` inherited Celery's global
soft/hard limits (1h/65min), so ANY scan past an hour was killed and marked 'failed' purely
for elapsed time -- while the orphan reaper independently failed anything 'running' for 2h.
Both decided from total runtime, which cannot distinguish a healthy 5-hour nuclei/ffuf run
on a large scope (normal) from a scan whose worker was SIGKILLed (dead).

The replacement is a heartbeat: the executor stamps `scans.last_heartbeat_at` roughly every
30s for as long as a tool is running, and the reaper keys on SILENCE instead of runtime.
These tests pin both halves of that contract -- the healthy long scan that must survive, and
the dead one that must still be recovered -- against a real MySQL, since the behavior is a
property of the SQL predicate and the column, not of Python.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core.config import get_settings
from apps.api.core import tenancy
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.orchestrator import reap_orphaned_scans

AGE_TIMEOUT = 7200      # the no-heartbeat fallback
STALE = 900             # scan_stale_heartbeat_seconds


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


def _ago(seconds: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=seconds)


async def _seed(session, *, started_at, last_heartbeat_at, status="running"):
    user = User(email=f"hb-{uuid.uuid4()}@test.local", password_hash="x", full_name="HB Tester")
    session.add(user)
    await session.flush()
    ws = Workspace(name="hb-ws", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    # Bind the just-created workspace before inserting rows into it -- the same step
    # production takes in workspaces.service.create_workspace, and required by the INSERT
    # guard in core/tenancy.py (an ORM flush INSERT bypasses the SELECT/UPDATE/DELETE
    # filter, so tenant-scoped writes are validated separately and fail closed).
    tenancy.bind_workspace(ws.id)
    project = Project(workspace_id=ws.id, name="hb-proj", created_by=user.id)
    session.add(project)
    await session.flush()
    target = Target(project_id=project.id, type="ip_range", value="203.0.113.51",
                    criticality="low", added_by=user.id)
    session.add(target)
    await session.flush()
    scan = Scan(
        workspace_id=ws.id, project_id=project.id, target_id=target.id, initiated_by=user.id,
        scan_type="network", status=status, config={},
        started_at=started_at, last_heartbeat_at=last_heartbeat_at,
        execution_token=uuid.uuid4(),
    )
    session.add(scan)
    await session.commit()
    return scan.id


async def _status(session, scan_id):
    return await session.scalar(select(Scan.status).where(Scan.id == scan_id))


def _run(coro_factory):
    async def _outer():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                return await coro_factory(s)
        finally:
            await engine.dispose()

    return asyncio.run(_outer())


# --- the behaviour this whole change exists to deliver ------------------------------------

@pytest.mark.parametrize("hours", [3, 5, 12])
def test_a_healthy_long_running_scan_is_never_reaped_however_long_it_runs(hours):
    """THE HEADLINE GUARANTEE. Started `hours` ago -- far past both the old 1h Celery limit
    and the old 2h reaper -- but heartbeating right now, so it is alive and must be left
    completely alone. This must hold at ANY runtime, hence the escalating parametrisation."""
    async def scenario(s):
        scan_id = await _seed(s, started_at=_ago(hours * 3600), last_heartbeat_at=_ago(5))
        reaped = await reap_orphaned_scans(s, AGE_TIMEOUT, STALE)
        return reaped, await _status(s, scan_id)

    _reaped, status = _run(scenario)
    assert status == "running", (
        f"a live scan running for {hours}h was reaped -- runtime must not decide liveness"
    )


def test_a_dead_executor_is_still_recovered_even_though_it_started_recently():
    """The other half: heartbeat went silent past the staleness window. The scan started only
    minutes ago (so the OLD age-based rule would have spared it for another ~2h), but its
    worker is gone -- recovery must not wait on total runtime either."""
    async def scenario(s):
        scan_id = await _seed(s, started_at=_ago(600), last_heartbeat_at=_ago(STALE + 120))
        reaped = await reap_orphaned_scans(s, AGE_TIMEOUT, STALE)
        return reaped, await _status(s, scan_id)

    reaped, status = _run(scenario)
    assert reaped >= 1 and status == "failed"


def test_a_briefly_silent_scan_is_not_reaped():
    """Missing a few beats (slow heartbeat write, GC pause, DB contention) must not reap a
    live scan -- the window is ~30 beats wide precisely to absorb that."""
    async def scenario(s):
        scan_id = await _seed(s, started_at=_ago(4 * 3600), last_heartbeat_at=_ago(STALE // 3))
        await reap_orphaned_scans(s, AGE_TIMEOUT, STALE)
        return await _status(s, scan_id)

    assert _run(scenario) == "running"


def test_a_scan_that_never_heartbeat_falls_back_to_the_age_rule():
    """NULL heartbeat (died before its first tick, or a pre-heartbeat build) must not make a
    scan immortal -- the COALESCE fallback still recovers it on the old age rule."""
    async def scenario(s):
        old = await _seed(s, started_at=_ago(AGE_TIMEOUT + 600), last_heartbeat_at=None)
        recent = await _seed(s, started_at=_ago(300), last_heartbeat_at=None)
        await reap_orphaned_scans(s, AGE_TIMEOUT, STALE)
        return await _status(s, old), await _status(s, recent)

    old_status, recent_status = _run(scenario)
    assert old_status == "failed", "a never-heartbeat scan past the age limit must be recoverable"
    assert recent_status == "running", "a recently started scan must not be reaped"


def test_reaper_records_why_it_recovered_the_scan():
    """The recovery reason stays queryable in config.recovery, now including the staleness
    threshold that actually made the decision."""
    async def scenario(s):
        scan_id = await _seed(s, started_at=_ago(3600), last_heartbeat_at=_ago(STALE + 300))
        await reap_orphaned_scans(s, AGE_TIMEOUT, STALE)
        return await s.scalar(select(Scan.config).where(Scan.id == scan_id))

    cfg = _run(scenario)
    recovery = cfg["recovery"]
    assert recovery["stale_heartbeat_seconds"] == STALE
    assert "heartbeat" in recovery["reason"]


def test_terminal_scans_are_never_touched_by_the_reaper():
    """Unchanged safety property: only 'running' rows are eligible."""
    async def scenario(s):
        ids = {}
        for st in ("completed", "failed", "cancelled", "queued"):
            ids[st] = await _seed(
                s, started_at=_ago(AGE_TIMEOUT * 2), last_heartbeat_at=_ago(STALE * 2), status=st
            )
        await reap_orphaned_scans(s, AGE_TIMEOUT, STALE)
        return {st: await _status(s, i) for st, i in ids.items()}

    assert _run(scenario) == {
        "completed": "completed", "failed": "failed",
        "cancelled": "cancelled", "queued": "queued",
    }


# --- heartbeat writer -----------------------------------------------------------------

def test_heartbeat_is_fenced_on_the_execution_token():
    """A superseded executor (graceful-shutdown requeue, then re-claim) must not keep a scan
    looking alive on the new owner's behalf -- same fencing every other ownership-sensitive
    write in the orchestrator uses."""
    from apps.api.scanner_engine.orchestrator import _stamp_heartbeat

    async def scenario(s):
        scan_id = await _seed(s, started_at=_ago(60), last_heartbeat_at=None)
        await _stamp_heartbeat(s, scan_id, uuid.uuid4())   # WRONG token
        wrong = await s.scalar(select(Scan.last_heartbeat_at).where(Scan.id == scan_id))
        real = await s.scalar(select(Scan.execution_token).where(Scan.id == scan_id))
        await _stamp_heartbeat(s, scan_id, real)           # correct token
        right = await s.scalar(select(Scan.last_heartbeat_at).where(Scan.id == scan_id))
        return wrong, right

    wrong, right = _run(scenario)
    assert wrong is None, "a superseded executor must not be able to stamp liveness"
    assert right is not None, "the owning executor must be able to stamp liveness"


def test_a_failing_heartbeat_never_breaks_the_scan():
    """Liveness reporting is best-effort: a DB blip must not fail an otherwise healthy scan."""
    from apps.api.scanner_engine import orchestrator

    async def scenario():
        class Boom:
            async def execute(self, *a, **k):
                raise RuntimeError("db is down")

            async def commit(self):
                pass

        await orchestrator._stamp_heartbeat(Boom(), uuid.uuid4(), uuid.uuid4())

    asyncio.run(scenario())   # must not raise


def test_heartbeat_loop_ticks_while_a_real_subprocess_is_running():
    """The property the whole design rests on: the progress loop does NOT await the
    subprocess, so heartbeats keep landing for a tool's entire lifetime. Uses a REAL
    subprocess -- a mock cannot demonstrate this."""
    import sys

    from apps.api.scanner_engine import orchestrator

    beats: list[int] = []

    class _Runner:
        name = "fake-long-tool"

        async def run(self, *_a, **_k):
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-c", "import time; time.sleep(3)",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            return "done"

    class _Scan:
        id = uuid.uuid4()

    async def scenario(monkey_interval=0.4):
        orig_interval = orchestrator.TOOL_PROGRESS_INTERVAL_SECONDS
        orig_stamp = orchestrator._stamp_heartbeat
        orchestrator.TOOL_PROGRESS_INTERVAL_SECONDS = monkey_interval

        async def _fake_stamp(_db, _scan_id, _tok):
            beats.append(1)

        orchestrator._stamp_heartbeat = _fake_stamp
        try:
            return await orchestrator._run_with_progress(
                _Runner(), _Scan(), "t", {}, [], 0.0, db=object(), execution_token=uuid.uuid4()
            )
        finally:
            orchestrator.TOOL_PROGRESS_INTERVAL_SECONDS = orig_interval
            orchestrator._stamp_heartbeat = orig_stamp

    result = asyncio.run(scenario())
    assert result == "done"
    assert len(beats) >= 4, (
        f"only {len(beats)} heartbeats landed while a real subprocess ran -- the progress "
        "loop is not independent of the tool"
    )


# --- configuration invariants ------------------------------------------------------------

def test_scan_task_has_no_wall_clock_limit_but_other_tasks_do():
    """The exemption must be scoped to scans.run_scan alone."""
    from apps.api.celery_app import worker as worker_mod
    from apps.api.celery_app.tasks import scan_tasks  # noqa: F401 -- registers the task

    conf = worker_mod.celery_app.conf
    scan_task = worker_mod.celery_app.tasks["scans.run_scan"]
    assert scan_task.soft_time_limit is None, "scans.run_scan must not have a soft time limit"
    assert scan_task.time_limit is None, "scans.run_scan must not have a hard time limit"
    # Everything else keeps its bounds.
    assert conf.task_soft_time_limit == get_settings().celery_task_soft_time_limit_seconds
    assert conf.task_time_limit > conf.task_soft_time_limit


def test_visibility_timeout_covers_a_five_hour_scan_and_is_not_derived_from_a_scan_limit():
    """acks_late redelivery safety. This used to be derived from the hard task limit; with
    scans exempt that derivation would collapse to the 4200s floor and redeliver every scan
    past ~70 minutes, so it is now explicit and must comfortably exceed 5 hours."""
    from apps.api.celery_app.worker import celery_app

    vt = (celery_app.conf.broker_transport_options or {}).get("visibility_timeout")
    assert vt is not None
    assert vt >= 5 * 3600, f"visibility_timeout {vt}s cannot cover a 5-hour scan"


def test_resource_protections_are_preserved():
    """Removing the wall-clock limits must not have removed any resource control."""
    from apps.api.celery_app.worker import celery_app
    from apps.api.scanner_engine.tool_runners import arjun_runner, ffuf_runner

    conf = celery_app.conf
    assert conf.worker_prefetch_multiplier == 1
    assert conf.worker_max_tasks_per_child == get_settings().celery_worker_max_tasks_per_child
    assert ffuf_runner.MAX_CONCURRENT_TARGETS >= 1
    assert arjun_runner.MAX_CONCURRENT_TARGETS >= 1
