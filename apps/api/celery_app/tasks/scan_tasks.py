import asyncio
import uuid

from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.celery_app.worker import celery_app
from apps.api.core.config import get_settings
from apps.api.scanner_engine.orchestrator import run_scan


async def _run(scan_id: str) -> None:
    # A fresh engine bound to THIS task's event loop. Reusing the API's
    # module-level engine here fails with "Future attached to a different loop"
    # because Celery runs each task under a new asyncio.run() loop while the
    # pooled asyncpg connections belong to whichever loop first opened them.
    #
    # StaticPool pins the whole task to ONE physical connection. The
    # orchestrator sets the workspace RLS GUC once (session-level,
    # is_local=false) and then commits several times; with a normal pool each
    # commit returns the connection and the next op could check out a
    # different one WITHOUT the GUC set -- FORCE RLS would then block the
    # worker's own writes to tool_runs/evidence/assets. One persistent
    # connection keeps the GUC alive across those commits.
    settings = get_settings()
    # Honor enterprise proxy / custom-CA settings for the scanner tools + AI calls
    # made during the scan (mirrors them into the process env). Idempotent.
    from apps.api.core.config import configure_networking

    configure_networking(settings)
    engine = create_async_engine(settings.database_url, poolclass=StaticPool)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_maker() as session:  # -> AsyncSession (inferred)
            await run_scan(session, uuid.UUID(scan_id))
    finally:
        await engine.dispose()


async def _fail_scan(scan_id: str, reason: str, duration_s: float = 0.0) -> None:
    """Mark a scan 'failed' from the TASK level (Phase 1.5), used when the Celery soft
    time limit fires. The signal surfaces out of asyncio.run (outside the orchestrator's
    own try/except), so without this the scan would stay 'running' until the reaper.

    REUSES the orchestrator's atomic `_finalize_status` (running -> terminal ONLY) rather
    than duplicating the transition, so it can never clobber a cancelled/terminal scan and
    'failed' stays reclaimable via the atomic claim. Integrates the EXISTING failure metric
    (record_scan_result -- no observability change) and emits one structured log line.
    Own short-lived engine (StaticPool), like _run; scans is RLS-exempt so no GUC needed."""
    import logging

    from apps.api.core.observability import record_scan_result
    from apps.api.modules.scans.models import Scan
    from apps.api.scanner_engine.orchestrator import _finalize_status

    settings = get_settings()
    engine = create_async_engine(settings.database_url, poolclass=StaticPool)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_maker() as session:  # -> AsyncSession (inferred)
            scan = await session.get(Scan, uuid.UUID(scan_id))
            recovered = scan is not None and await _finalize_status(session, scan, "failed")
        if recovered:
            # Reuse the existing lifecycle metric (SCAN_FAILED + duration + outcomes).
            record_scan_result("failed", duration_s)
        logging.getLogger("mbs.scan").warning(
            "scan.soft_timeout scan=%s reason=%s duration=%.2fs timeout=%ss reclaimable=%s",
            scan_id, reason, duration_s, settings.celery_task_soft_time_limit_seconds, recovered,
            extra={
                "event": "scan.soft_timeout",
                "scan_id": scan_id,
                "reason": reason,
                "duration_s": round(duration_s, 2),
                "timeout_s": settings.celery_task_soft_time_limit_seconds,
                "shutdown_reason": "soft_time_limit",
                "reclaimable": recovered,
            },
        )
    finally:
        await engine.dispose()


DLQ_KEY = "dlq:scans.run_scan"


def _record_dlq(scan_id: str, exc: BaseException, *, task_id: str | None = None, retries: int = 0) -> None:
    """Push an exhausted scan task onto a Redis dead-letter list for inspection /
    replay. Best-effort: a DLQ write must never mask the original failure. See
    apps.api.celery_app.dlq for inspect/replay/remove tooling."""
    import json
    import time as _time

    try:
        import redis

        client = redis.from_url(get_settings().redis_url)
        client.rpush(
            DLQ_KEY,
            json.dumps(
                {
                    "task_name": "scans.run_scan",
                    "task_id": task_id,
                    "scan_id": scan_id,          # workspace is derivable via the scan row
                    "retries": retries,
                    "error": f"{type(exc).__name__}: {exc}"[:1000],
                    "ts": _time.time(),
                }
            ),
        )
        client.ltrim(DLQ_KEY, -1000, -1)  # cap the list
    except Exception:  # noqa: BLE001
        pass

    # E4: a dead-lettered scan is a reliability failure -> best-effort email alert (never raises,
    # gated OFF unless email is enabled; no scan/evidence detail in the message).
    try:
        from apps.api.modules.notifications.alerts import email_system_alert

        email_system_alert(
            "reliability_dlq", "Scan permanently failed (dead-lettered)",
            "A scan task exhausted its retries and was dead-lettered. Inspect via "
            "`python -m apps.api.celery_app.dlq list`.",
        )
    except Exception:  # noqa: BLE001
        pass


def _transient_error_types() -> tuple[type[BaseException], ...]:
    """Infrastructure faults a retry can plausibly recover from -- transient DB / broker /
    network blips. EVERYTHING ELSE (bad config, disallowed target, parser/programming bugs) is
    PERMANENT: retrying just repeats the failure and its side effects, so those are dead-lettered
    without retry (F2). Import-guarded so a missing optional dep can never break task import."""
    types: list[type[BaseException]] = [ConnectionError, TimeoutError]  # builtin network / timeout
    try:
        from sqlalchemy.exc import InterfaceError, OperationalError  # DB connection / transient

        types += [OperationalError, InterfaceError]
    except Exception:  # noqa: BLE001
        pass
    try:
        from redis.exceptions import ConnectionError as RedisConnectionError  # broker / DLQ / relay
        from redis.exceptions import TimeoutError as RedisTimeoutError

        types += [RedisConnectionError, RedisTimeoutError]
    except Exception:  # noqa: BLE001
        pass
    return tuple(types)


# F2: retry ONLY these transient infra faults; permanent failures go straight to the DLQ.
TRANSIENT_ERRORS = _transient_error_types()


@celery_app.task(
    bind=True,
    name="scans.run_scan",
    acks_late=True,
    autoretry_for=TRANSIENT_ERRORS,   # F2: transient infra faults only -- NOT permanent errors
    retry_backoff=True,       # exponential backoff between retries
    retry_backoff_max=300,
    retry_jitter=True,
    max_retries=3,
)
def run_scan_task(self, scan_id: str, correlation_id: str | None = None) -> str:
    """Execute a scan. Retries with exponential backoff ONLY on transient infra faults
    (TRANSIENT_ERRORS -- DB/broker/network); when those retries are exhausted the task is
    dead-lettered. A PERMANENT failure (bad config, disallowed target, parser bug) is NOT
    retried -- it is dead-lettered immediately (F2). The scan itself is idempotent -- the
    orchestrator skips a scan that already reached a terminal state -- so acks_late redelivery
    after a worker crash is safe.

    correlation_id (Phase 4.1): the originating API request's id, propagated so worker/scan
    logs can be joined to the request that created the scan. Optional/back-compatible -- a
    missing id (relay/redelivery/older callers) gets a freshly generated one so worker logs
    remain correlatable within this execution."""
    import time as _time

    from apps.api.core.observability import new_correlation_id, set_correlation_id

    set_correlation_id(correlation_id or new_correlation_id())
    _started = _time.monotonic()
    try:
        asyncio.run(_run(scan_id))
    except SoftTimeLimitExceeded as exc:
        # The soft time limit fired (Phase 1.5): the scan ran too long. Mark it 'failed'
        # cleanly so it is reclaimable (not stuck 'running' waiting on the reaper), record
        # it to the DLQ for inspection, and do NOT autoretry into another guaranteed
        # timeout -- returning normally acks the task and stops the retry chain. The HARD
        # limit (billiard TimeLimitExceeded / SIGKILL) is deliberately NOT caught here: it
        # is the final safety net, left to the orphan reaper.
        asyncio.run(_fail_scan(scan_id, "soft_time_limit_exceeded", _time.monotonic() - _started))
        _record_dlq(scan_id, exc, task_id=self.request.id, retries=self.request.retries)
        return scan_id
    except TRANSIENT_ERRORS as exc:
        # Transient infra fault (F2): autoretry_for drives the exponential-backoff retry. Only
        # dead-letter once the retries are exhausted, then let the failure propagate.
        if self.request.retries >= self.max_retries:
            _record_dlq(scan_id, exc, task_id=self.request.id, retries=self.request.retries)
        raise
    except Exception as exc:
        # PERMANENT / deterministic failure (F2): retrying would only repeat the failure and its
        # side effects, so do NOT retry -- dead-letter immediately for inspection/replay and fail.
        _record_dlq(scan_id, exc, task_id=self.request.id, retries=self.request.retries)
        raise
    return scan_id


async def _reap() -> int:
    """Recover orphaned 'running' scans (Phase 1.2). Own short-lived engine (StaticPool),
    like _run. Fully best-effort at the outer task level."""
    import logging

    from apps.api.core.observability import record_scan_reaped
    from apps.api.scanner_engine.orchestrator import reap_orphaned_scans

    settings = get_settings()
    if not settings.scan_orphan_recovery_enabled:
        return 0
    engine = create_async_engine(settings.database_url, poolclass=StaticPool)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_maker() as session:  # -> AsyncSession (inferred)
            reaped = await reap_orphaned_scans(session, settings.scan_orphan_timeout_seconds)
        if reaped:
            record_scan_reaped(reaped, reason="timeout")
            logging.getLogger("mbs.scan").warning(
                "scan.reaper recovered %d orphaned running scan(s) older than %ds",
                reaped, settings.scan_orphan_timeout_seconds,
            )
        return reaped
    finally:
        await engine.dispose()


async def _relay_queued() -> int:
    """Queued-scan RELAY: re-dispatch scans that were durably committed as 'queued' but
    never got a celery_task_id (their Celery dispatch failed -- the DB+Redis dual-write's
    Redis side) and have sat past scan_queued_relay_seconds.

    Conservative: `celery_task_id IS NULL` targets ONLY undelivered scans -- a scan already
    in flight has a task id and is never touched. It NEVER creates a second scan row; it just
    re-enqueues the existing scan_id, and the atomic scan claim (queued/failed -> running)
    guarantees a relay message + any late original message cannot both execute. If the relay
    .delay() itself fails (broker still down), celery_task_id stays NULL -> recoverable on a
    later tick. Own short-lived engine (StaticPool); scans is RLS-exempt so no GUC needed."""
    import logging

    settings = get_settings()
    if not settings.scan_queued_relay_enabled:
        return 0
    engine = create_async_engine(settings.database_url, poolclass=StaticPool)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    relayed = 0
    try:
        async with session_maker() as session:  # -> AsyncSession (inferred)
            rows = await session.execute(
                text(
                    "SELECT id FROM scans WHERE status = 'queued' AND celery_task_id IS NULL "
                    "AND created_at < now() - make_interval(secs => :secs)"
                ),
                {"secs": int(settings.scan_queued_relay_seconds)},
            )
            ids = [r[0] for r in rows.fetchall()]

            for sid in ids:
                try:
                    result = run_scan_task.delay(str(sid))
                except Exception:  # noqa: BLE001 -- broker still down; leave queued+null, retry next tick
                    logging.getLogger("mbs.scan").warning(
                        "scan.relay_dispatch_failed scan=%s (left recoverable)", sid, exc_info=True
                    )
                    continue
                # Mark dispatched so it isn't relayed again -- conditional on still being the
                # undelivered row (a racing claim/dispatch must win instead).
                await session.execute(
                    text(
                        "UPDATE scans SET celery_task_id = :tid "
                        "WHERE id = :id AND status = 'queued' AND celery_task_id IS NULL"
                    ),
                    {"tid": result.id, "id": sid},
                )
                await session.commit()
                relayed += 1

        if relayed:
            from apps.api.core.observability import record_scan_relayed

            record_scan_relayed(relayed)
            logging.getLogger("mbs.scan").warning(
                "scan.relay redispatched %d undelivered queued scan(s) older than %ds",
                relayed, settings.scan_queued_relay_seconds,
            )
        return relayed
    finally:
        await engine.dispose()


@celery_app.task(name="scans.reap_orphans")
def reap_orphaned_scans_task() -> int:
    """Beat-scheduled recovery: (1) orphan reaper -- 'running' scans past the timeout become
    'failed'; (2) queued relay -- 'queued' scans never delivered to Celery are re-dispatched.
    Both are idempotent + safe to run concurrently (atomic UPDATE / atomic scan claim), and
    neither creates duplicate work. Returns the orphan-reaped count (unchanged contract)."""
    async def _both() -> int:
        reaped = await _reap()
        await _relay_queued()
        return reaped

    return asyncio.run(_both())
