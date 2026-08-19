"""Phase 1.5 -- graceful shutdown & worker reliability.

Covers: soft-timeout handling (scan marked failed, reclaimable), cancellation-race
prevention (a cancelled scan is never clobbered by a terminal write), terminal-state
protection + no-duplicate-execution (atomic running->terminal), Docker graceful-shutdown
configuration, and Celery worker config loading.

Real Postgres via a self-managed session (scans is RLS-exempt, like the worker path).
"""
import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core.config import get_settings
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.orchestrator import _claim_scan, _execution_stop_reason, _finalize_status

NOW = datetime.now(timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[3]


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _seed_scan(session, status, execution_token=None):
    """Seed a scan. A 'running' scan is seeded WITH an execution_token, because in production
    a scan is only ever 'running' as the result of a claim, and the claim always stamps an
    owner -- terminal writes are fenced on it (P1-1 P3)."""
    user = User(email=f"sd-{uuid.uuid4()}@test.local", password_hash="x", full_name="Shutdown Tester")
    session.add(user)
    await session.flush()
    ws = Workspace(name="sd-ws", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    project = Project(workspace_id=ws.id, name="sd-proj", created_by=user.id)
    session.add(project)
    await session.flush()
    target = Target(project_id=project.id, type="ip_range", value="203.0.113.77", criticality="low", added_by=user.id)
    session.add(target)
    await session.flush()
    scan = Scan(
        workspace_id=ws.id, project_id=project.id, target_id=target.id, initiated_by=user.id,
        scan_type="network", status=status, config={}, started_at=NOW,
        execution_token=execution_token or (uuid.uuid4() if status == "running" else None),
    )
    session.add(scan)
    await session.commit()
    return scan


async def _status(session, scan_id):
    return await session.scalar(select(Scan.status).where(Scan.id == scan_id))


# --- terminal-state protection + cancellation-race prevention -----------------------------

def test_finalize_wins_on_running_and_never_clobbers_cancelled():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                running = await _seed_scan(s, "running")
                won = await _finalize_status(s, running, "completed", running.execution_token)
                running_after = await _status(s, running.id)

                cancelled = await _seed_scan(s, "cancelled")
                lost = await _finalize_status(s, cancelled, "completed", uuid.uuid4())
                cancelled_after = await _status(s, cancelled.id)
            return won, running_after, lost, cancelled_after
        finally:
            await engine.dispose()

    won, running_after, lost, cancelled_after = asyncio.run(scenario())
    assert won is True and running_after == "completed"          # normal terminal write
    assert lost is False and cancelled_after == "cancelled"      # cancel race: not clobbered


def test_finalize_is_atomic_no_duplicate_terminal_write():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_scan(s, "running")
                token = scan.execution_token
                first = await _finalize_status(s, scan, "completed", token)
                second = await _finalize_status(s, scan, "failed", token)   # already terminal
                # A terminal scan is not re-claimable -> no duplicate execution.
                reclaim = await _claim_scan(s, scan.id, uuid.uuid4())
                final = await _status(s, scan.id)
            return first, second, reclaim, final
        finally:
            await engine.dispose()

    first, second, reclaim, final = asyncio.run(scenario())
    assert (first, second) == (True, False)     # exactly one terminal write wins
    assert reclaim is False                     # completed scan cannot be re-claimed
    assert final == "completed"                 # status not flipped to failed


def test_cancellation_probe_still_stops_a_running_scan():
    """The cooperative-cancellation probe (formerly `_is_cancelled`, now folded into
    `_execution_stop_reason`): a cancel is still detected between tools, unchanged."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                running = await _seed_scan(s, "running")
                cancelled = await _seed_scan(s, "cancelled")
                return (
                    await _execution_stop_reason(s, running.id, running.execution_token),
                    await _execution_stop_reason(s, cancelled.id, uuid.uuid4()),
                )
        finally:
            await engine.dispose()

    running_reason, cancelled_reason = asyncio.run(scenario())
    assert running_reason is None            # owned + running -> keep going
    assert cancelled_reason == "cancelled"   # cancel still wins, ahead of any ownership check


# --- soft-timeout behavior ----------------------------------------------------------------

def test_fail_scan_marks_running_failed_but_spares_cancelled():
    from apps.api.celery_app.tasks import scan_tasks

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                running = await _seed_scan(s, "running")
                cancelled = await _seed_scan(s, "cancelled")
            await scan_tasks._fail_scan(str(running.id), "soft_time_limit_exceeded", 0.0, running.execution_token)
            await scan_tasks._fail_scan(str(cancelled.id), "soft_time_limit_exceeded", 0.0, uuid.uuid4())
            async with maker() as v:
                return await _status(v, running.id), await _status(v, cancelled.id)
        finally:
            await engine.dispose()

    running_after, cancelled_after = asyncio.run(scenario())
    assert running_after == "failed"        # soft timeout -> failed (reclaimable)
    assert cancelled_after == "cancelled"   # never clobbers a cancelled scan


def test_fail_scan_integrates_failure_metric():
    """Soft-timeout recovery reuses the existing failure metric (no observability change)."""
    from apps.api.celery_app.tasks import scan_tasks
    from apps.api.core import observability as obs

    if not obs._PROM:
        pytest.skip("prometheus_client not installed; metric is a no-op")

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                running = await _seed_scan(s, "running")
            before = obs.SCAN_FAILED._value.get()
            await scan_tasks._fail_scan(str(running.id), "soft_time_limit_exceeded", 12.5, running.execution_token)
            return before, obs.SCAN_FAILED._value.get()
        finally:
            await engine.dispose()

    before, after = asyncio.run(scenario())
    assert after == before + 1


def test_hard_time_limit_is_final_safety_net_not_soft_handled():
    """The HARD limit is the last resort: its exception is distinct from the soft one, so
    the task's soft handler cannot catch it -- a hard timeout is left to the reaper backstop
    and is never silently acked as success. Also verifies hard strictly exceeds soft."""
    from billiard.exceptions import TimeLimitExceeded

    from apps.api.celery_app.worker import celery_app

    assert not issubclass(TimeLimitExceeded, SoftTimeLimitExceeded)   # soft handler won't catch hard
    assert celery_app.conf.task_time_limit > celery_app.conf.task_soft_time_limit


def test_backward_compatible_task_routing_and_disable_semantics():
    """New Phase 1.5 knobs are additive: existing task routing/queues and reliability
    settings are untouched, and a 0 value disables a limit (maps to None = prior behavior)."""
    from apps.api.celery_app.worker import celery_app

    conf = celery_app.conf
    # Unchanged routing / queues (pre-1.5 behavior).
    assert conf.task_default_queue == "default"
    assert conf.task_routes["scans.run_scan"] == {"queue": "scans"}
    # Unchanged task identity / DLQ.
    from apps.api.celery_app.tasks.scan_tasks import DLQ_KEY

    assert DLQ_KEY == "dlq:scans.run_scan"
    # Disable semantics: 0 -> None (no limit), i.e. exactly the pre-1.5 "unbounded" default.
    assert (0 or None) is None


def test_soft_time_limit_task_marks_failed_and_does_not_retry(monkeypatch):
    """The task-level SoftTimeLimitExceeded handler marks the scan failed and returns
    normally (acks the task) instead of autoretrying into another guaranteed timeout."""
    from apps.api.celery_app.tasks import scan_tasks

    # Each asyncio.run gets its own engine (a StaticPool connection is pinned to the loop
    # that opened it; the task's own asyncio.run runs between these two).
    async def _prep():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_scan(s, "running")
                return scan.id
        finally:
            await engine.dispose()

    scan_id = asyncio.run(_prep())

    async def _boom(_scan_id, execution_token=None):
        # Model what the real `_run` does before it times out: the atomic claim stamps THIS
        # execution as the owner (P1-1 P3). The soft-timeout handler's terminal write is
        # fenced on that token, so the row must actually carry it for this to be realistic.
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                await s.execute(
                    text("UPDATE scans SET execution_token = :t WHERE id = :i"),
                    {"t": str(execution_token), "i": str(_scan_id)},
                )
                await s.commit()
        finally:
            await engine.dispose()
        raise SoftTimeLimitExceeded()

    monkeypatch.setattr(scan_tasks, "_run", _boom)
    monkeypatch.setattr(scan_tasks, "_record_dlq", lambda *a, **k: None)  # skip Redis

    result = scan_tasks.run_scan_task.apply(args=[str(scan_id)])

    async def _check():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as v:
                return await _status(v, scan_id)
        finally:
            await engine.dispose()

    assert result.successful()             # returned normally, no retry/raise
    assert result.result == str(scan_id)
    assert asyncio.run(_check()) == "failed"


# --- Celery worker config loading ---------------------------------------------------------

def test_worker_config_time_limits_and_recycling():
    from apps.api.celery_app.worker import celery_app

    conf = celery_app.conf
    settings = get_settings()
    # Soft strictly before hard (invariant enforced at wiring time).
    assert conf.task_soft_time_limit == settings.celery_task_soft_time_limit_seconds
    assert conf.task_time_limit > conf.task_soft_time_limit
    # Worker recycling wired from settings.
    assert conf.worker_max_tasks_per_child == settings.celery_worker_max_tasks_per_child
    # Phase 1.2/inspection invariants preserved (must NOT be changed).
    assert conf.task_acks_late is True
    assert conf.task_reject_on_worker_lost is True
    assert conf.worker_prefetch_multiplier == 1


def test_time_limits_stay_below_orphan_timeout():
    # A self-terminated (soft/hard) scan must never have to wait on the reaper.
    s = get_settings()
    assert s.celery_task_soft_time_limit_seconds < s.celery_task_time_limit_seconds
    assert s.celery_task_time_limit_seconds <= s.scan_orphan_timeout_seconds


# --- Docker graceful-shutdown configuration -----------------------------------------------

def _need_infra():
    if not (REPO_ROOT / "infra").is_dir():
        pytest.skip("infra/ not bind-mounted in this environment")


def test_compose_declares_stop_grace_periods():
    _need_infra()
    compose = (REPO_ROOT / "infra" / "docker-compose.yml").read_text(encoding="utf-8")
    # Every long-lived service that must drain on shutdown declares a grace window.
    assert compose.count("stop_grace_period") >= 3   # api, worker, beat


def test_api_dockerfile_uses_exec_for_sigterm():
    _need_infra()
    dockerfile = (REPO_ROOT / "infra" / "docker" / "Dockerfile.api").read_text(encoding="utf-8")
    # uvicorn must become PID 1 (exec) so it receives SIGTERM directly.
    assert "exec uvicorn" in dockerfile


def test_worker_and_beat_keep_exec_form_pid1():
    _need_infra()
    compose = (REPO_ROOT / "infra" / "docker-compose.yml").read_text(encoding="utf-8")
    # exec (JSON array) form keeps celery as PID 1 so SIGTERM = warm shutdown.
    assert '["celery", "-A", "apps.api.celery_app.worker.celery_app", "worker"' in compose
    assert '["celery", "-A", "apps.api.celery_app.worker.celery_app", "beat"' in compose


# =========================================================================================
# P1-1 -- interrupted-scan requeue on graceful worker shutdown.
#
# Context: acks_late + reject_on_worker_lost mean the broker REDELIVERS a scan whose worker
# died mid-execution. But the redelivered task is useless on its own: `_claim_scan` accepts
# only 'queued'/'failed', so a row left at 'running' by the dead worker is not claimable and
# the redelivered task exits without executing -- ACKing (and destroying) the only message
# that could have restarted the scan. E-1 pins that behavior; the shutdown hook then makes
# the row claimable again so the redelivery it already gets can actually do its job.
# =========================================================================================

async def _seed_running_scan_with_task(session, task_id="celery-task-abc123"):
    """A scan exactly as a killed worker leaves it: claimed ('running'), started_at set,
    and stamped with the celery task id of the message that is about to be redelivered."""
    scan = await _seed_scan(session, "running")
    scan.celery_task_id = task_id
    await session.commit()
    return scan


# --- E-1: characterization -- redelivery of a 'running' scan is DISCARDED ------------------

def test_running_scan_redelivery_is_discarded_not_reexecuted(monkeypatch):
    """CHARACTERIZATION (pre-fix behavior of P1-1).

    A redelivered task for a scan still marked 'running' must be shown to:
      1. fail the atomic claim (`_claim_scan` -> False),
      2. never reach the executor (the post-claim scope gate is never called),
      3. exit SUCCESSFULLY with no retry -- i.e. the broker message is ACKed and gone,
      4. leave the scan stranded in 'running' (recoverable only by the 2h orphan reaper).

    This test asserts the CURRENT behavior deliberately. It must keep passing after the fix:
    the fix does not make 'running' claimable, it makes the row stop being 'running'.
    """
    from apps.api.celery_app.tasks import scan_tasks
    from apps.api.scanner_engine import orchestrator

    async def _prep():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_running_scan_with_task(s)
                # The claim itself must refuse a 'running' row (the root of P1-1).
                claimed = await _claim_scan(s, scan.id, uuid.uuid4())
                return scan.id, claimed
        finally:
            await engine.dispose()

    scan_id, claimed_while_running = asyncio.run(_prep())
    assert claimed_while_running is False, "'running' must never be claimable"

    # Spy on the first thing run_scan does AFTER a successful claim. If the executor were
    # entered, this would be called; it must not be.
    executor_calls = []

    async def _spy_scope(*a, **k):
        executor_calls.append(a)
        raise AssertionError("executor must not run for an unclaimable scan")

    monkeypatch.setattr(orchestrator, "require_verified_target", _spy_scope)
    monkeypatch.setattr(scan_tasks, "_record_dlq", lambda *a, **k: None)  # no Redis in tests

    # The redelivery: Celery re-runs the SAME task with the SAME scan id.
    result = scan_tasks.run_scan_task.apply(args=[str(scan_id)])

    async def _check():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as v:
                row = (await v.execute(
                    text("SELECT status, celery_task_id, started_at FROM scans WHERE id = :i"),
                    {"i": str(scan_id)},
                )).first()
                return row
        finally:
            await engine.dispose()

    status, task_id, started_at = asyncio.run(_check())

    assert executor_calls == []            # (2) executor never invoked
    assert result.successful()             # (3) task returned normally -> message ACKed
    assert result.state == "SUCCESS"       #     ...not RETRY / FAILURE
    assert result.result == str(scan_id)
    assert status == "running"             # (4) scan stranded: redelivery accomplished nothing
    assert task_id == "celery-task-abc123"
    assert started_at is not None


# --- E-2: the shutdown requeue transition -------------------------------------------------

def test_shutdown_requeues_inflight_scan():
    """running -> queued, with the execution stamps cleared, and the row claimable again.

    Clearing celery_task_id is load-bearing twice over: it is what the existing queued-relay
    keys on (status='queued' AND celery_task_id IS NULL) if the broker redelivery is itself
    lost, and it stops a stale task id from pointing at a message that no longer exists.
    """
    from apps.api.celery_app import shutdown

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_running_scan_with_task(s)
            requeued = await shutdown.requeue_scan(str(scan.id))
            async with maker() as v:
                row = (await v.execute(
                    text("SELECT status, started_at, celery_task_id FROM scans WHERE id = :i"),
                    {"i": str(scan.id)},
                )).first()
                # The EXISTING claim must now accept it -- the fix works by changing the row,
                # never by loosening _claim_scan.
                claimable = await _claim_scan(v, scan.id, uuid.uuid4())
            return requeued, row, claimable
        finally:
            await engine.dispose()

    requeued, (status, started_at, task_id), claimable = asyncio.run(scenario())
    assert requeued is True
    assert status == "queued"          # running -> queued
    assert started_at is None          # execution stamp cleared
    assert task_id is None             # stale task id cleared (also enables the relay backstop)
    assert claimable is True           # claimable again by the UNCHANGED _claim_scan


def test_shutdown_requeue_never_touches_cancelled_or_terminal_scans():
    """The conditional UPDATE is the only guard needed: anything not 'running' is left alone,
    so a shutdown racing a user cancellation or a just-finished scan cannot resurrect it."""
    from apps.api.celery_app import shutdown

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        results = {}
        try:
            for state in ("cancelled", "completed", "failed", "completed_with_errors"):
                async with maker() as s:
                    scan = await _seed_scan(s, state)
                requeued = await shutdown.requeue_scan(str(scan.id))
                async with maker() as v:
                    after = await _status(v, scan.id)
                results[state] = (requeued, after)
            return results
        finally:
            await engine.dispose()

    for state, (requeued, after) in asyncio.run(scenario()).items():
        assert requeued is False, f"{state} must not be requeued"
        assert after == state, f"{state} must be left untouched (got {after})"


def test_shutdown_requeue_loses_race_against_concurrent_cancellation():
    """RACE: a cancel that commits between the watchdog's poll and its write must win.
    The requeue is conditional on status='running', so the late shutdown write finds no row."""
    from apps.api.celery_app import shutdown

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_running_scan_with_task(s)
                # The API cancels while the worker is draining...
                await s.execute(
                    text("UPDATE scans SET status = 'cancelled' WHERE id = :i"), {"i": str(scan.id)}
                )
                await s.commit()
            # ...and only now does the shutdown watchdog attempt its write.
            requeued = await shutdown.requeue_scan(str(scan.id))
            async with maker() as v:
                after = await _status(v, scan.id)
                reclaimable = await _claim_scan(v, scan.id, uuid.uuid4())
            return requeued, after, reclaimable
        finally:
            await engine.dispose()

    requeued, after, reclaimable = asyncio.run(scenario())
    assert requeued is False        # shutdown lost the race, as it must
    assert after == "cancelled"     # cancellation preserved
    assert reclaimable is False     # and a cancelled scan is never re-executed


# --- the watchdog: only requeue what did NOT drain -----------------------------------------

def test_watchdog_does_not_requeue_a_scan_that_finished_in_the_grace_window(monkeypatch):
    """NO-REGRESSION GUARD. A scan that completes inside stop_grace_period must be left
    entirely alone -- requeueing it would strand it 'queued' (its terminal write requires
    'running') and the relay would later re-run a finished scan: duplicate ACTIVE scanning."""
    from apps.api.celery_app import shutdown

    async def _prep():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_running_scan_with_task(s)
                return scan.id
        finally:
            await engine.dispose()

    scan_id = asyncio.run(_prep())

    # First poll: still running. Second poll: drained (the task finished normally).
    polls = [[str(scan_id)], []]
    monkeypatch.setattr(shutdown, "inflight_scan_ids", lambda: polls.pop(0) if polls else [])

    requeued = shutdown.drain_and_requeue(deadline=30.0, poll=0.01)

    async def _check():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as v:
                return (await v.execute(
                    text("SELECT status, celery_task_id FROM scans WHERE id = :i"),
                    {"i": str(scan_id)},
                )).first()
        finally:
            await engine.dispose()

    status, task_id = asyncio.run(_check())
    assert requeued == []                       # clean drain -> no write at all
    assert status == "running"                  # row untouched by the watchdog
    assert task_id == "celery-task-abc123"


def test_watchdog_requeues_a_scan_still_running_at_the_deadline(monkeypatch):
    from apps.api.celery_app import shutdown

    async def _prep():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_running_scan_with_task(s)
                return scan.id
        finally:
            await engine.dispose()

    scan_id = asyncio.run(_prep())
    monkeypatch.setattr(shutdown, "inflight_scan_ids", lambda: [str(scan_id)])  # never drains

    requeued = shutdown.drain_and_requeue(deadline=0.0, poll=0.01)

    async def _check():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as v:
                return await _status(v, scan_id)
        finally:
            await engine.dispose()

    assert requeued == [str(scan_id)]
    assert asyncio.run(_check()) == "queued"


def test_shutdown_signal_is_wired_and_celery_reliability_config_intact():
    """The hook is connected to worker_shutting_down, and the settings the fix DEPENDS on
    (redelivery) are unchanged -- the fix is worthless without them."""
    from celery.signals import worker_shutting_down

    from apps.api.celery_app.worker import celery_app

    receivers = [r[1]() if callable(r[1]) else r[1] for r in worker_shutting_down.receivers]
    names = {getattr(r, "__name__", "") for r in receivers if r is not None}
    assert "_requeue_inflight_scans" in names

    conf = celery_app.conf
    assert conf.task_acks_late is True             # redelivery on worker loss
    assert conf.task_reject_on_worker_lost is True
    assert conf.worker_prefetch_multiplier == 1
    assert conf.task_routes["scans.run_scan"] == {"queue": "scans"}   # routing untouched


# --- STEP 4: the complete shutdown -> requeue -> redelivery -> claim -> execute path -------

def test_full_recovery_path_requeued_scan_is_redelivered_claimed_and_executed(monkeypatch):
    """END-TO-END proof that P1-1 is actually closed.

    Not just 'the UPDATE works': the SAME redelivered task that E-1 shows is discarded must,
    after the shutdown requeue, pass the UNCHANGED _claim_scan and enter the executor.

      1. scan is 'running' (worker killed mid-scan)
      2. shutdown watchdog requeues it -> 'queued'
      3. Celery redelivers the task (same scan id)
      4. _claim_scan claims it -> 'running'
      5. execution begins (post-claim scope gate reached, row observed as 'running')
    """
    from apps.api.celery_app import shutdown
    from apps.api.celery_app.tasks import scan_tasks
    from apps.api.scanner_engine import orchestrator

    async def _prep():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_running_scan_with_task(s)
                return scan.id
        finally:
            await engine.dispose()

    scan_id = asyncio.run(_prep())                                    # (1)

    monkeypatch.setattr(shutdown, "inflight_scan_ids", lambda: [str(scan_id)])
    assert shutdown.drain_and_requeue(deadline=0.0, poll=0.01) == [str(scan_id)]   # (2)

    # (5) Spy at the first post-claim step. It receives the live session, so it can prove the
    # row really was claimed to 'running' by THIS execution before the executor proceeded.
    observed = {}

    async def _spy_scope(db, *a, **k):
        observed["status_at_execution"] = (await db.execute(
            text("SELECT status FROM scans WHERE id = :i"), {"i": str(scan_id)}
        )).scalar()
        raise ValueError("stop here -- execution demonstrably began")

    monkeypatch.setattr(orchestrator, "require_verified_target", _spy_scope)
    monkeypatch.setattr(scan_tasks, "_record_dlq", lambda *a, **k: None)

    result = scan_tasks.run_scan_task.apply(args=[str(scan_id)])      # (3) redelivery

    assert observed.get("status_at_execution") == "running"           # (4)+(5) claimed & executing
    assert result.failed()          # only because the spy aborted the run, not because of a skip
    assert isinstance(result.result, ValueError)


def test_requeued_scan_can_be_claimed_by_exactly_one_executor():
    """Redelivery + relay can both race for a requeued scan. The unchanged atomic claim
    still guarantees at-most-one executor -- the fix adds no second execution path."""
    from apps.api.celery_app import shutdown

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_running_scan_with_task(s)
            await shutdown.requeue_scan(str(scan.id))
            # Two independent sessions = two workers racing on the redelivered scan.
            async with maker() as a, maker() as b:
                first = await _claim_scan(a, scan.id, uuid.uuid4())
                second = await _claim_scan(b, scan.id, uuid.uuid4())
            async with maker() as v:
                return first, second, await _status(v, scan.id)
        finally:
            await engine.dispose()

    first, second, final = asyncio.run(scenario())
    assert [first, second].count(True) == 1     # exactly one executor wins
    assert final == "running"


def test_requeue_is_idempotent_across_repeated_shutdowns():
    """A second shutdown pass over an already-requeued scan is a no-op (not 'running')."""
    from apps.api.celery_app import shutdown

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_running_scan_with_task(s)
            first = await shutdown.requeue_scan(str(scan.id))
            second = await shutdown.requeue_scan(str(scan.id))
            async with maker() as v:
                return first, second, await _status(v, scan.id)
        finally:
            await engine.dispose()

    first, second, final = asyncio.run(scenario())
    assert (first, second) == (True, False)
    assert final == "queued"


# =========================================================================================
# P1-1 / P3 -- EXECUTION OWNERSHIP FENCING.
#
# The real prefork+SIGTERM probe proved the original requeue had a race: the shutdown
# watchdog flipped running->queued at the deadline while the executor was STILL running.
# The executor then finished, its terminal write (`WHERE status='running'`) matched 0 rows,
# and the outcome was silently discarded -- leaving a row that the queued relay would
# redispatch, i.e. a completed scan re-run against a live customer target.
#
# The fix adds `scans.execution_token`: the atomic claim stamps WHICH execution owns the
# scan, the requeue clears it (revocation), and every terminal write is fenced on it. These
# tests pin that a revoked executor can neither finalize nor be mistaken for the new owner.
# =========================================================================================

async def _seed_owned_running_scan(session, token, task_id="celery-task-p3"):
    """A scan as a live executor holds it: claimed, running, stamped with ITS token."""
    scan = await _seed_scan(session, "queued")
    claimed = await _claim_scan(session, scan.id, token)
    assert claimed is True
    await session.execute(
        text("UPDATE scans SET celery_task_id = :t WHERE id = :i"),
        {"t": task_id, "i": str(scan.id)},
    )
    await session.commit()
    return scan


async def _row(session, scan_id):
    return (await session.execute(
        text("SELECT status, started_at, celery_task_id, execution_token FROM scans WHERE id = :i"),
        {"i": str(scan_id)},
    )).first()


# --- the fence itself ---------------------------------------------------------------------

def test_claim_stamps_an_execution_token_and_finalize_clears_it():
    """Ownership is recorded on claim and released on the terminal write."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            token = uuid.uuid4()
            async with maker() as s:
                scan = await _seed_owned_running_scan(s, token)
                after_claim = await _row(s, scan.id)
                won = await _finalize_status(s, scan, "completed", token)
                after_final = await _row(s, scan.id)
            return after_claim, won, after_final
        finally:
            await engine.dispose()

    (status, _, _, tok), won, (fstatus, _, _, ftok) = asyncio.run(scenario())
    assert status == "running" and tok is not None      # claim installed an owner
    assert won is True
    assert fstatus == "completed"
    assert ftok is None                                  # terminal scan is owned by nobody


def test_requeue_revokes_the_execution_token():
    """The shutdown requeue is what REVOKES ownership -- that is what makes the fence bite."""
    from apps.api.celery_app import shutdown

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            token = uuid.uuid4()
            async with maker() as s:
                scan = await _seed_owned_running_scan(s, token)
            requeued = await shutdown.requeue_scan(str(scan.id))
            async with maker() as v:
                return requeued, await _row(v, scan.id)
        finally:
            await engine.dispose()

    requeued, (status, started_at, task_id, token) = asyncio.run(scenario())
    assert requeued is True
    assert (status, started_at, task_id, token) == ("queued", None, None, None)


def test_p3_revoked_executor_cannot_finalize_completed_or_failed():
    """THE P3 DEFECT, at the write level.

    requeue -> old executor still running -> old executor attempts its terminal write.
    Both flavours (completed AND failed) must be refused, and the row must stay exactly as
    the requeue left it -- claimable by a fresh executor, not silently terminal."""
    from apps.api.celery_app import shutdown

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        results = {}
        try:
            for flavour in ("completed", "failed", "completed_with_errors"):
                token = uuid.uuid4()
                async with maker() as s:
                    scan = await _seed_owned_running_scan(s, token)
                await shutdown.requeue_scan(str(scan.id))
                async with maker() as s2:
                    scan2 = await s2.get(Scan, scan.id)
                    won = await _finalize_status(s2, scan2, flavour, token)
                    row = await _row(s2, scan.id)
                    # ...and the row is still recoverable by the UNCHANGED claim.
                    claimable = await _claim_scan(s2, scan.id, uuid.uuid4())
                results[flavour] = (won, row, claimable)
            return results
        finally:
            await engine.dispose()

    for flavour, (won, (status, _, _, _), claimable) in asyncio.run(scenario()).items():
        assert won is False, f"revoked executor must not write {flavour}"
        assert status == "queued", f"row must stay queued, got {status} after {flavour}"
        assert claimable is True


def test_old_executor_cannot_clobber_the_new_owner_after_reclaim():
    """OWNERSHIP: old executor vs new executor.

    requeue -> a NEW executor claims (fresh token) -> the OLD executor finally finishes.
    The old executor's write must NOT land: without the fence it would satisfy
    `status='running'` and terminate the NEW executor's live scan with a stale outcome."""
    from apps.api.celery_app import shutdown

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            old_token, new_token = uuid.uuid4(), uuid.uuid4()
            async with maker() as s:
                scan = await _seed_owned_running_scan(s, old_token)
            await shutdown.requeue_scan(str(scan.id))
            async with maker() as s2:
                reclaimed = await _claim_scan(s2, scan.id, new_token)      # new executor
                scan2 = await s2.get(Scan, scan.id)
                stale = await _finalize_status(s2, scan2, "completed", old_token)  # old one
                row = await _row(s2, scan.id)
                # the new owner can still finalize normally
                scan3 = await s2.get(Scan, scan.id)
                new_won = await _finalize_status(s2, scan3, "completed", new_token)
                final = await _row(s2, scan.id)
            return reclaimed, stale, row, new_won, final, new_token
        finally:
            await engine.dispose()

    reclaimed, stale, (status, _, _, tok), new_won, (fstatus, _, _, _), new_token = asyncio.run(scenario())
    assert reclaimed is True
    assert stale is False                    # stale executor refused
    assert status == "running"               # new owner's scan untouched by the old executor
    assert str(tok) == str(new_token)        # ...and still owned by the NEW executor
    assert new_won is True                   # the real owner still finalizes normally
    assert fstatus == "completed"


def test_soft_timeout_finalize_is_fenced_to_its_own_execution():
    """The soft-timeout path (`_fail_scan`) is a terminal write too, and runs OUTSIDE
    run_scan -- it must be fenced on the same token, or a timeout firing after a requeue +
    re-claim would mark the NEW executor's running scan as failed."""
    from apps.api.celery_app import shutdown
    from apps.api.celery_app.tasks.scan_tasks import _fail_scan

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            old_token, new_token = uuid.uuid4(), uuid.uuid4()
            async with maker() as s:
                scan = await _seed_owned_running_scan(s, old_token)
            await shutdown.requeue_scan(str(scan.id))
            async with maker() as s2:
                await _claim_scan(s2, scan.id, new_token)     # new executor owns it now
            await _fail_scan(str(scan.id), "soft_time_limit_exceeded", 1.0, old_token)
            async with maker() as v:
                return await _row(v, scan.id)
        finally:
            await engine.dispose()

    status, _, _, tok = asyncio.run(scenario())
    assert status == "running", "a stale soft-timeout must not fail the new owner's scan"
    assert tok is not None


def test_stop_reason_classifies_owned_cancelled_and_revoked():
    """The between-tools probe: what makes an executor stop, and why."""
    from apps.api.celery_app import shutdown
    from apps.api.scanner_engine.orchestrator import _execution_stop_reason

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            out = {}
            token = uuid.uuid4()
            async with maker() as s:
                owned = await _seed_owned_running_scan(s, token)
                out["owned"] = await _execution_stop_reason(s, owned.id, token)

                cancelled = await _seed_owned_running_scan(s, token)
                await s.execute(text("UPDATE scans SET status='cancelled' WHERE id=:i"),
                                {"i": str(cancelled.id)})
                await s.commit()
                out["cancelled"] = await _execution_stop_reason(s, cancelled.id, token)

                revoked = await _seed_owned_running_scan(s, token)
            await shutdown.requeue_scan(str(revoked.id))
            async with maker() as s2:
                out["revoked"] = await _execution_stop_reason(s2, revoked.id, token)
                # a DIFFERENT executor now owns it -> also revoked for us
                await _claim_scan(s2, revoked.id, uuid.uuid4())
                out["reclaimed_by_other"] = await _execution_stop_reason(s2, revoked.id, token)
            return out
        finally:
            await engine.dispose()

    out = asyncio.run(scenario())
    assert out["owned"] is None                    # keep going
    assert out["cancelled"] == "cancelled"         # pre-existing cooperative cancellation
    assert out["revoked"] == "revoked"
    assert out["reclaimed_by_other"] == "revoked"


# --- the P3 ordering, driven through the REAL run_scan ------------------------------------

def _patch_scan_prelude(monkeypatch):
    """Let run_scan past the scope + SSRF gates without running any tool or touching a
    network: the scan then has NO requested modules, so it goes straight to its terminal
    write -- which is exactly the moment P3 is about."""
    from apps.api.scanner_engine import net_guard, orchestrator

    class _Scope:
        active_testing_allowed = False

    async def _scope(*a, **k):
        return _Scope()

    monkeypatch.setattr(orchestrator, "require_verified_target", _scope)
    monkeypatch.setattr(net_guard, "resolve_and_validate", lambda *a, **k: None)


def test_p3_ordering_executor_finishing_after_requeue_publishes_no_result(monkeypatch):
    """THE EXACT P3 ORDERING, end to end through run_scan (success flavour).

        shutdown requeue  ->  old executor still executing  ->  old executor finalizes

    Proves the old executor cannot silently turn this into a normal `completed` result,
    cannot emit a ScanCompleted event or a lifecycle metric for a scan it no longer owns,
    and leaves a row that is claimable by exactly the fresh executor that should run it."""
    from apps.api.celery_app import shutdown
    from apps.api.scanner_engine import orchestrator

    _patch_scan_prelude(monkeypatch)

    published, metrics = [], []
    monkeypatch.setattr(orchestrator, "_publish_scan_completed",
                        lambda *a, **k: published.append(a) or _noop_coro())
    monkeypatch.setattr(orchestrator, "record_scan_result",
                        lambda *a, **k: metrics.append(a))

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_scan(s, "queued")
                await s.execute(text("UPDATE scans SET started_at = NULL WHERE id = :i"),
                                {"i": str(scan.id)})
                await s.commit()
                scan_id = scan.id

            # The requeue lands mid-execution, at the last seam before the terminal write.
            async def _requeue_midrun(db, sc):
                await shutdown.requeue_scan(str(sc.id))

            monkeypatch.setattr(orchestrator, "_synthesize_attack_narrative", _requeue_midrun)

            async with maker() as run_session:
                await orchestrator.run_scan(run_session, scan_id)   # must NOT raise

            async with maker() as v:
                row = await _row(v, scan_id)
                claimable = await _claim_scan(v, scan_id, uuid.uuid4())
            return row, claimable
        finally:
            await engine.dispose()

    (status, started_at, task_id, token), claimable = asyncio.run(scenario())
    assert status == "queued"          # NOT silently completed
    assert started_at is None and task_id is None and token is None
    assert published == []             # no ScanCompleted for a scan we no longer own
    assert metrics == []               # no false lifecycle metric
    assert claimable is True           # the fresh executor can take it


def _noop_coro():
    async def _c():
        return None
    return _c()


def test_p3_ordering_failure_flavour_is_not_recorded_as_a_failed_scan(monkeypatch):
    """Same P3 ordering, but the executor ends by RAISING (the shape the live SIGTERM probe
    reproduced). It must not record `failed`, must not publish, and must not re-raise into
    the retry/dead-letter machinery -- the requeued row is the recovery path."""
    from apps.api.celery_app import shutdown
    from apps.api.scanner_engine import orchestrator

    published, metrics = [], []
    monkeypatch.setattr(orchestrator, "_publish_scan_completed",
                        lambda *a, **k: published.append(a) or _noop_coro())
    monkeypatch.setattr(orchestrator, "record_scan_result", lambda *a, **k: metrics.append(a))

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_scan(s, "queued")
                await s.execute(text("UPDATE scans SET started_at = NULL WHERE id = :i"),
                                {"i": str(scan.id)})
                await s.commit()
                scan_id = scan.id

            async def _requeue_then_fail(db, *a, **k):
                await shutdown.requeue_scan(str(scan_id))
                raise ValueError("probe: executor ran on past its revocation")

            monkeypatch.setattr(orchestrator, "require_verified_target", _requeue_then_fail)

            async with maker() as run_session:
                await orchestrator.run_scan(run_session, scan_id)   # must NOT raise

            async with maker() as v:
                return await _row(v, scan_id)
        finally:
            await engine.dispose()

    status, _, _, token = asyncio.run(scenario())
    assert status == "queued"      # not 'failed'
    assert token is None
    assert published == []
    assert metrics == []


def test_revoked_executor_stops_before_launching_another_tool(monkeypatch):
    """COOPERATIVE STOP: once revoked, the executor must abandon the run BEFORE the next
    tool -- this is what keeps it from overlapping with the executor that takes over."""
    from apps.api.celery_app import shutdown
    from apps.api.scanner_engine import orchestrator

    _patch_scan_prelude(monkeypatch)
    launched = []

    # Stub registry so the test does not depend on which real tools apply to which target
    # type -- three runners that all apply, so the loop WOULD launch three without the fix.
    stub_registry = {
        name: type(
            f"_Stub{i}", (),
            {"name": name, "version": "0", "phase": i,
             "applicable_target_types": None, "requires_active_testing": False},
        )
        for i, name in enumerate(("stub_a", "stub_b", "stub_c"))
    }
    monkeypatch.setattr(orchestrator, "TOOL_REGISTRY", stub_registry)

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_scan(s, "queued")
                await s.execute(
                    text("UPDATE scans SET started_at = NULL, config = :c ::jsonb WHERE id = :i"),
                    {"c": '{"requested_modules": ["stub_a", "stub_b", "stub_c"]}', "i": str(scan.id)},
                )
                await s.commit()
                scan_id = scan.id

            # Revoke as soon as the FIRST tool has run: the stop-check before tool #2 must fire.
            async def _tool_then_revoke(db, scan, runner, *a, **k):
                launched.append(runner.name)
                await shutdown.requeue_scan(str(scan_id))
                return [], "success"

            monkeypatch.setattr(orchestrator, "_run_single_tool", _tool_then_revoke)

            async with maker() as run_session:
                await orchestrator.run_scan(run_session, scan_id)
            async with maker() as v:
                return await _row(v, scan_id)
        finally:
            await engine.dispose()

    status, _, _, _ = asyncio.run(scenario())
    assert len(launched) == 1, f"must stop after the revocation, launched={launched}"
    assert status == "queued"


# --- multiple in-flight scans + the timing invariant ---------------------------------------

def test_watchdog_requeues_every_inflight_scan_and_revokes_each(monkeypatch):
    """A worker runs several scans concurrently (prefork children); ALL of them must be
    requeued and revoked, independently."""
    from apps.api.celery_app import shutdown

    async def _prep():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                return [(await _seed_owned_running_scan(s, uuid.uuid4())).id for _ in range(3)]
        finally:
            await engine.dispose()

    ids = asyncio.run(_prep())
    monkeypatch.setattr(shutdown, "inflight_scan_ids", lambda: [str(i) for i in ids])
    requeued = shutdown.drain_and_requeue(deadline=0.0, poll=0.01)

    async def _check():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as v:
                return [await _row(v, i) for i in ids]
        finally:
            await engine.dispose()

    assert sorted(requeued) == sorted(str(i) for i in ids)
    for status, started_at, task_id, token in asyncio.run(_check()):
        assert (status, started_at, task_id, token) == ("queued", None, None, None)


def test_shutdown_timing_invariant_keeps_redispatch_after_the_worker_is_gone():
    """NON-OVERLAP INVARIANT (config-level), stated in terms of the REAL relay clock.

    The relay ages a queued scan off `queued_at`, which the requeue refreshes. So the
    earliest a replacement executor can be dispatched is:

        requeue deadline  +  scan_queued_relay_seconds

    and the old worker is dead (SIGKILL) at `stop_grace_period`. The invariant that actually
    matters is therefore:

        requeue deadline  <  stop_grace_period  <  requeue deadline + relay interval

    NOTE this is deliberately NOT `stop_grace_period < relay interval`: that older form was
    misleading, because when the relay aged rows off `created_at` a requeued scan was ALREADY
    past any threshold and could be redispatched inside the grace window.

    Uses the env-AWARE accessors, so a deployment that tunes either value via environment
    (rather than editing the defaults) is still checked."""
    import re

    from apps.api.celery_app.shutdown import deadline_seconds
    from apps.api.core.config import get_settings

    compose = (REPO_ROOT / "infra" / "docker-compose.yml").read_text(encoding="utf-8")
    worker_block = compose.split("  worker:", 1)[1]
    grace = int(re.search(r"stop_grace_period:\s*(\d+)s", worker_block).group(1))

    deadline = deadline_seconds()
    relay = get_settings().scan_queued_relay_seconds

    assert deadline < grace, (
        f"requeue deadline {deadline}s must land before SIGKILL at {grace}s, or the scan is "
        "never requeued at all"
    )
    assert grace < deadline + relay, (
        f"the old worker is SIGKILLed at {grace}s but the relay could redispatch at "
        f"{deadline}+{relay}s -- a replacement executor could start while it is still alive"
    )


def test_relay_ages_a_requeued_scan_off_the_requeue_not_its_creation():
    """THE FIX for the misleading invariant.

    A scan created long ago and requeued at the shutdown deadline must NOT be immediately
    relay-eligible -- otherwise the relay redispatches it inside the grace window, while the
    old executor is still running. Ageing off `queued_at` gives the old worker its full
    grace period to die first."""
    from apps.api.celery_app import shutdown

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        relay_secs = get_settings().scan_queued_relay_seconds
        try:
            async with maker() as s:
                scan = await _seed_owned_running_scan(s, uuid.uuid4())
                # Created LONG ago -- under the old created_at rule this alone made it eligible.
                await s.execute(
                    text("UPDATE scans SET created_at = now() - make_interval(secs => :a) WHERE id = :i"),
                    {"a": relay_secs * 10, "i": str(scan.id)},
                )
                await s.commit()
            await shutdown.requeue_scan(str(scan.id))

            def _eligible_sql():
                return text(
                    "SELECT count(*) FROM scans WHERE id = :i AND status = 'queued' "
                    "AND celery_task_id IS NULL "
                    "AND coalesce(queued_at, created_at) < now() - make_interval(secs => :secs)"
                )

            async with maker() as v:
                just_requeued = await v.scalar(_eligible_sql(), {"i": str(scan.id), "secs": relay_secs})
                # ...and once the relay interval has elapsed since the REQUEUE, it is eligible.
                await v.execute(
                    text("UPDATE scans SET queued_at = now() - make_interval(secs => :a) WHERE id = :i"),
                    {"a": relay_secs + 60, "i": str(scan.id)},
                )
                await v.commit()
                after_interval = await v.scalar(_eligible_sql(), {"i": str(scan.id), "secs": relay_secs})
            return just_requeued, after_interval
        finally:
            await engine.dispose()

    just_requeued, after_interval = asyncio.run(scenario())
    assert just_requeued == 0, "a freshly requeued scan must not be relay-eligible yet"
    assert after_interval == 1, "it must become relay-eligible once the interval elapses"


def test_relay_still_recovers_a_never_dispatched_queued_scan():
    """NO REGRESSION to the relay's original purpose: a scan that was committed 'queued' but
    never got a task id is still recovered once it ages past the interval."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        relay_secs = get_settings().scan_queued_relay_seconds
        try:
            async with maker() as s:
                scan = await _seed_scan(s, "queued")
                await s.execute(
                    text("UPDATE scans SET celery_task_id = NULL, started_at = NULL, "
                         "queued_at = now() - make_interval(secs => :a) WHERE id = :i"),
                    {"a": relay_secs + 60, "i": str(scan.id)},
                )
                await s.commit()
                fresh = await s.scalar(
                    text("SELECT count(*) FROM scans WHERE id = :i AND status = 'queued' "
                         "AND celery_task_id IS NULL "
                         "AND coalesce(queued_at, created_at) < now() - make_interval(secs => :secs)"),
                    {"i": str(scan.id), "secs": relay_secs},
                )
                # legacy rows (queued_at NULL, pre-migration) must still fall back to created_at
                await s.execute(
                    text("UPDATE scans SET queued_at = NULL, "
                         "created_at = now() - make_interval(secs => :a) WHERE id = :i"),
                    {"a": relay_secs + 60, "i": str(scan.id)},
                )
                await s.commit()
                legacy = await s.scalar(
                    text("SELECT count(*) FROM scans WHERE id = :i AND status = 'queued' "
                         "AND celery_task_id IS NULL "
                         "AND coalesce(queued_at, created_at) < now() - make_interval(secs => :secs)"),
                    {"i": str(scan.id), "secs": relay_secs},
                )
            return fresh, legacy
        finally:
            await engine.dispose()

    fresh, legacy = asyncio.run(scenario())
    assert fresh == 1      # normal undelivered queued scan still recovered
    assert legacy == 1     # pre-migration rows (queued_at NULL) keep the created_at behaviour


# --- P1-1 follow-ups: launch gate, relay timing, broker visibility -------------------------

def test_revocation_between_the_check_and_the_launch_still_blocks_the_tool(monkeypatch):
    """THE READ-THEN-LAUNCH RACE.

    Ordering under test:
        executor: _execution_stop_reason() -> None   (still owns it)
        shutdown: requeue -> token revoked
        executor: about to launch the next tool

    The between-tools check has already passed, so only the last-moment gate inside
    `_run_single_tool` can stop this. It must: no tool process may be spawned once a
    revocation is visible, and the abandoned attempt must be auditable rather than left
    as a 'running' ToolRun row."""
    from apps.api.celery_app import shutdown
    from apps.api.scanner_engine import orchestrator

    _patch_scan_prelude(monkeypatch)

    launched = []
    stub_registry = {
        name: type(
            f"_Gate{i}", (),
            {"name": name, "version": "0", "phase": i,
             "applicable_target_types": None, "requires_active_testing": False},
        )
        for i, name in enumerate(("gate_a", "gate_b"))
    }
    monkeypatch.setattr(orchestrator, "TOOL_REGISTRY", stub_registry)

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_scan(s, "queued")
                await s.execute(
                    text("UPDATE scans SET started_at = NULL, config = :c ::jsonb WHERE id = :i"),
                    {"c": '{"requested_modules": ["gate_a", "gate_b"]}', "i": str(scan.id)},
                )
                await s.commit()
                scan_id = scan.id

            # Revoke AFTER the loop's stop-check has passed: patch the check to report
            # "still yours", then revoke, so only the launch-time gate can catch it.
            real_stop_reason = orchestrator._execution_stop_reason
            calls = {"n": 0}

            async def _stale_then_revoke(db, sid, token):
                calls["n"] += 1
                if calls["n"] == 1:
                    # the between-tools check: report healthy, THEN revoke behind its back
                    await shutdown.requeue_scan(str(scan_id))
                    return None
                return await real_stop_reason(db, sid, token)

            monkeypatch.setattr(orchestrator, "_execution_stop_reason", _stale_then_revoke)

            async def _spy_run(self, *a, **k):
                launched.append(self.name)
                raise AssertionError("a revoked executor must never spawn a tool")

            for cls in stub_registry.values():
                cls.run = _spy_run

            async with maker() as run_session:
                await orchestrator.run_scan(run_session, scan_id)

            async with maker() as v:
                row = await _row(v, scan_id)
                runs = (await v.execute(
                    text("SELECT tool_name, status FROM tool_runs WHERE scan_id = :i"),
                    {"i": str(scan_id)},
                )).fetchall()
            return row, runs
        finally:
            await engine.dispose()

    (status, _, _, token), runs = asyncio.run(scenario())
    assert launched == [], "no tool process may start after the revocation is visible"
    assert status == "queued" and token is None          # left for the new owner
    assert [r[1] for r in runs] == ["abandoned_revoked"]  # the attempt is auditable


def test_revoked_executor_publishes_no_duplicate_event_or_metric(monkeypatch):
    """A revoked executor must emit NO ScanCompleted and NO lifecycle metric, so a
    redispatched run cannot produce two completion signals for one scan."""
    from apps.api.celery_app import shutdown
    from apps.api.scanner_engine import orchestrator

    _patch_scan_prelude(monkeypatch)
    published, metrics = [], []
    monkeypatch.setattr(orchestrator, "_publish_scan_completed",
                        lambda *a, **k: published.append(a) or _noop_coro())
    monkeypatch.setattr(orchestrator, "record_scan_result", lambda *a, **k: metrics.append(a))

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_scan(s, "queued")
                await s.execute(text("UPDATE scans SET started_at = NULL WHERE id = :i"),
                                {"i": str(scan.id)})
                await s.commit()
                scan_id = scan.id

            async def _requeue_midrun(db, sc):
                await shutdown.requeue_scan(str(sc.id))

            monkeypatch.setattr(orchestrator, "_synthesize_attack_narrative", _requeue_midrun)
            async with maker() as run_session:
                await orchestrator.run_scan(run_session, scan_id)

            # the replacement executor then runs it for real and DOES publish exactly once
            async def _noop_narrative(db, sc):
                return None

            monkeypatch.setattr(orchestrator, "_synthesize_attack_narrative", _noop_narrative)
            async with maker() as run2:
                await orchestrator.run_scan(run2, scan_id)
            async with maker() as v:
                return await _row(v, scan_id)
        finally:
            await engine.dispose()

    status, _, _, token = asyncio.run(scenario())
    assert status == "completed"      # the NEW owner's result
    assert token is None              # terminal scan is owned by nobody
    assert len(published) == 1        # exactly one ScanCompleted for the whole saga
    assert len(metrics) == 1          # ...and exactly one lifecycle metric


def test_broker_visibility_timeout_exceeds_the_hard_task_time_limit():
    """acks_late means an in-flight scan's message sits in the broker's unacked set. If the
    Redis visibility timeout is BELOW the hard task time limit, that message is restored and
    redelivered while the original worker is still executing the scan -- the atomic claim
    stops it running twice, but it acks away the scan's only redelivery safety net.

    Asserted against the LIVE config so the value cannot silently drift back under."""
    from apps.api.celery_app.worker import celery_app

    vt = (celery_app.conf.broker_transport_options or {}).get("visibility_timeout")
    hard = celery_app.conf.task_time_limit
    assert vt is not None, "visibility_timeout must be set explicitly, not left to kombu's 3600s"
    assert hard is not None
    assert vt > hard, (
        f"visibility_timeout {vt}s must exceed the hard task time limit {hard}s, or a "
        "long scan is redelivered while its own worker is still running it"
    )
    # the reliability settings this all rests on are unchanged
    assert celery_app.conf.task_acks_late is True
    assert celery_app.conf.task_reject_on_worker_lost is True
    assert celery_app.conf.worker_prefetch_multiplier == 1
    assert celery_app.conf.task_routes["scans.run_scan"] == {"queue": "scans"}


def test_ownership_writes_cannot_be_called_without_a_token():
    """The fence has no off switch: `_claim_scan` and `_finalize_status` REQUIRE a token, so
    no caller can silently perform an unowned claim or terminal write."""
    import inspect

    from apps.api.celery_app.tasks.scan_tasks import _fail_scan
    from apps.api.scanner_engine.orchestrator import _claim_scan, _finalize_status

    for fn, param in ((_claim_scan, "execution_token"),
                      (_finalize_status, "execution_token"),
                      (_fail_scan, "execution_token")):
        sig = inspect.signature(fn)
        assert param in sig.parameters, f"{fn.__name__} lost its {param} parameter"
        assert sig.parameters[param].default is inspect.Parameter.empty, (
            f"{fn.__name__}.{param} must be REQUIRED -- a default silently disables the fence"
        )


# --- P1-1 corrections: migration backfill + reaper revocation ------------------------------

def test_queued_at_migration_backfills_instead_of_resetting_queue_age():
    """MIGRATION SEMANTICS (regression for the `DEFAULT now()` backfill trap).

    Adding `queued_at` directly as `DEFAULT now()` does NOT leave existing rows NULL: on
    PostgreSQL 11+ the default is applied to every pre-existing row, which would reset the
    relay clock of everything already sitting in the queue. The migration therefore does it
    in three steps, and this test pins each of them:

      1. ADD COLUMN with NO default  -> existing rows stay NULL (not stamped with now())
      2. UPDATE ... = created_at     -> the real queue age is preserved
      3. ALTER ... SET DEFAULT now() -> future inserts get the current time

    Steps run against a TEMPORARY table so the real schema is untouched and no second
    database is needed. LIMITATION: this pins the SQL semantics of the migration, not the
    Alembic wiring; the assertions at the end check that the wiring actually landed on the
    live (already-migrated) test database.
    """
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                await s.execute(text(
                    "CREATE TEMPORARY TABLE _mig_probe ("
                    "  id serial PRIMARY KEY, created_at timestamptz NOT NULL) ON COMMIT DROP"
                ))
                await s.execute(text(
                    "INSERT INTO _mig_probe (created_at) VALUES (now() - interval '2 hours')"
                ))
                # Step 1 -- exactly what the migration does first.
                await s.execute(text("ALTER TABLE _mig_probe ADD COLUMN queued_at timestamptz"))
                step1_null = await s.scalar(text("SELECT queued_at IS NULL FROM _mig_probe"))
                # Step 2 -- the backfill.
                await s.execute(text(
                    "UPDATE _mig_probe SET queued_at = created_at WHERE queued_at IS NULL"
                ))
                step2 = (await s.execute(text(
                    "SELECT queued_at = created_at, age(now(), queued_at) > interval '1 hour' "
                    "FROM _mig_probe"
                ))).first()
                # Step 3 -- the default for future rows.
                await s.execute(text(
                    "ALTER TABLE _mig_probe ALTER COLUMN queued_at SET DEFAULT now()"
                ))
                await s.execute(text("INSERT INTO _mig_probe (created_at) VALUES (now())"))
                step3_current = await s.scalar(text(
                    "SELECT age(now(), queued_at) < interval '1 minute' "
                    "FROM _mig_probe ORDER BY id DESC LIMIT 1"
                ))
                # ...and the counter-example this whole design exists to avoid.
                await s.execute(text(
                    "CREATE TEMPORARY TABLE _mig_trap (id serial PRIMARY KEY) ON COMMIT DROP"
                ))
                await s.execute(text("INSERT INTO _mig_trap DEFAULT VALUES"))
                await s.execute(text(
                    "ALTER TABLE _mig_trap ADD COLUMN queued_at timestamptz DEFAULT now()"
                ))
                trap_null = await s.scalar(text("SELECT queued_at IS NULL FROM _mig_trap"))
                await s.rollback()
            return step1_null, step2, step3_current, trap_null
        finally:
            await engine.dispose()

    step1_null, (backfilled, age_preserved), step3_current, trap_null = asyncio.run(scenario())
    assert step1_null is True, "step 1 must NOT stamp existing rows"
    assert backfilled is True, "step 2 must set queued_at = created_at"
    assert age_preserved is True, "the row's real 2h queue age must survive the migration"
    assert step3_current is True, "step 3 must give new rows now()"
    assert trap_null is False, (
        "counter-example: ADD COLUMN ... DEFAULT now() backfills existing rows -- which is "
        "exactly why the migration must not do that"
    )


def test_queued_at_schema_default_and_new_scan_timestamp():
    """The three-step migration actually landed on the live schema: the DB default is now(),
    the column stays nullable, and a freshly created scan gets a current queued_at."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                col = (await s.execute(text(
                    "SELECT column_default, is_nullable FROM information_schema.columns "
                    "WHERE table_name = 'scans' AND column_name = 'queued_at'"
                ))).first()
                scan = await _seed_scan(s, "queued")
                fresh = (await s.execute(text(
                    "SELECT queued_at IS NOT NULL, age(now(), queued_at) < interval '1 minute' "
                    "FROM scans WHERE id = :i"
                ), {"i": str(scan.id)})).first()
            return col, fresh
        finally:
            await engine.dispose()

    (default, nullable), (has_value, is_current) = asyncio.run(scenario())
    assert default is not None and "now()" in default   # step 3 present in the real schema
    assert nullable == "YES"                            # never made NOT NULL
    assert has_value is True and is_current is True     # new scans are stamped on insert


def test_reaper_revokes_ownership_so_a_stale_executor_stays_silent(monkeypatch):
    """REAPER -> STALE EXECUTOR (regression for the duplicate terminal signals).

    The orphan reaper marks a presumed-dead scan 'failed'. If it left `execution_token`
    intact, the still-alive executor's terminal write would fail on status alone, its
    ownership check would say the row is STILL ours, and it would fall through into
    `record_scan_result('failed')` + ScanCompleted + a re-raise that dead-letters the task --
    duplicate lifecycle signals for a scan the reaper already terminalized.

    The reaper now clears the token in the SAME atomic statement, so the executor recognises
    it lost ownership and stays completely silent. Drives the real task, the real reaper and
    the real ownership fence -- nothing about the ownership logic is mocked.
    """
    from apps.api.celery_app.tasks import scan_tasks
    from apps.api.scanner_engine import orchestrator

    published, metrics, dlq = [], [], []
    monkeypatch.setattr(orchestrator, "_publish_scan_completed",
                        lambda *a, **k: published.append(a) or _noop_coro())
    monkeypatch.setattr(orchestrator, "record_scan_result", lambda *a, **k: metrics.append(a))
    monkeypatch.setattr(scan_tasks, "_record_dlq", lambda *a, **k: dlq.append(a))

    async def _prep():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_scan(s, "queued")
                await s.execute(text("UPDATE scans SET started_at = NULL WHERE id = :i"),
                                {"i": str(scan.id)})
                await s.commit()
                return scan.id
        finally:
            await engine.dispose()

    scan_id = asyncio.run(_prep())

    # Mid-execution: the scan looks orphaned and the REAL reaper terminalizes it, then this
    # executor keeps going and finally errors -- the exact ordering that used to double-report.
    async def _reap_then_fail(db, *a, **k):
        await db.execute(
            text("UPDATE scans SET started_at = now() - interval '3 hours' WHERE id = :i"),
            {"i": str(scan_id)},
        )
        await db.commit()
        reaped = await orchestrator.reap_orphaned_scans(db, 7200)
        assert reaped >= 1
        raise ValueError("probe: executor still running after the reaper terminalized it")

    monkeypatch.setattr(orchestrator, "require_verified_target", _reap_then_fail)

    result = scan_tasks.run_scan_task.apply(args=[str(scan_id)])

    async def _check():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as v:
                return await _row(v, scan_id)
        finally:
            await engine.dispose()

    status, _, _, token = asyncio.run(_check())
    assert status == "failed"          # the REAPER's result stands...
    assert token is None               # ...and the reaper revoked ownership
    assert published == []             # no duplicate ScanCompleted
    assert metrics == []               # no duplicate terminal lifecycle metric
    assert dlq == []                   # no dead-letter caused by the stale executor
    assert result.successful()         # the task acked instead of failing


def test_reaper_cannot_revoke_a_freshly_reclaimed_scan():
    """The reaper's `started_at` predicate is what protects a REPLACEMENT owner: a scan that
    was just re-claimed has a current started_at, so a reaper pass cannot clear its token."""
    from apps.api.celery_app import shutdown
    from apps.api.scanner_engine.orchestrator import reap_orphaned_scans

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_scan(s, "queued")
                old_token = uuid.uuid4()
                await _claim_scan(s, scan.id, old_token)
                await s.execute(
                    text("UPDATE scans SET started_at = now() - interval '3 hours' WHERE id = :i"),
                    {"i": str(scan.id)},
                )
                await s.commit()
                await shutdown.requeue_scan(str(scan.id))
                new_token = uuid.uuid4()
                await _claim_scan(s, scan.id, new_token)      # replacement owner, started_at=now()
                await reap_orphaned_scans(s, 7200)
                row = await _row(s, scan.id)
            return row, new_token
        finally:
            await engine.dispose()

    (status, _, _, token), new_token = asyncio.run(scenario())
    assert status == "running"                    # replacement owner untouched
    assert str(token) == str(new_token)           # its token was NOT cleared by the reaper
