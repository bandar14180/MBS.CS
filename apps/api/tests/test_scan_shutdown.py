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
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core.config import get_settings
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.orchestrator import _claim_scan, _finalize_status, _is_cancelled

NOW = datetime.now(timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[3]


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _seed_scan(session, status):
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
                won = await _finalize_status(s, running, "completed")     # running -> terminal
                running_after = await _status(s, running.id)

                cancelled = await _seed_scan(s, "cancelled")
                lost = await _finalize_status(s, cancelled, "completed")  # must NOT overwrite
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
                first = await _finalize_status(s, scan, "completed")
                second = await _finalize_status(s, scan, "failed")   # already terminal
                # A terminal scan is not re-claimable -> no duplicate execution.
                reclaim = await _claim_scan(s, scan.id)
                final = await _status(s, scan.id)
            return first, second, reclaim, final
        finally:
            await engine.dispose()

    first, second, reclaim, final = asyncio.run(scenario())
    assert (first, second) == (True, False)     # exactly one terminal write wins
    assert reclaim is False                     # completed scan cannot be re-claimed
    assert final == "completed"                 # status not flipped to failed


def test_is_cancelled_probe():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                running = await _seed_scan(s, "running")
                cancelled = await _seed_scan(s, "cancelled")
                return (
                    await _is_cancelled(s, running.id),
                    await _is_cancelled(s, cancelled.id),
                )
        finally:
            await engine.dispose()

    running_flag, cancelled_flag = asyncio.run(scenario())
    assert running_flag is False and cancelled_flag is True


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
            await scan_tasks._fail_scan(str(running.id), "soft_time_limit_exceeded")
            await scan_tasks._fail_scan(str(cancelled.id), "soft_time_limit_exceeded")
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
            await scan_tasks._fail_scan(str(running.id), "soft_time_limit_exceeded", 12.5)
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

    async def _boom(_scan_id):
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
