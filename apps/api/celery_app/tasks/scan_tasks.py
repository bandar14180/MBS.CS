import asyncio
import uuid

from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
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
        async with session_maker() as session:  # type: AsyncSession
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
        async with session_maker() as session:  # type: AsyncSession
            scan = await session.get(Scan, uuid.UUID(scan_id))
            recovered = bool(scan) and await _finalize_status(session, scan, "failed")
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


def _record_dlq(scan_id: str, exc: Exception, *, task_id: str | None = None, retries: int = 0) -> None:
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


@celery_app.task(
    bind=True,
    name="scans.run_scan",
    acks_late=True,
    autoretry_for=(Exception,),
    retry_backoff=True,       # exponential backoff between retries
    retry_backoff_max=300,
    retry_jitter=True,
    max_retries=3,
)
def run_scan_task(self, scan_id: str) -> str:
    """Execute a scan. Retries with exponential backoff on failure (transient DB /
    storage / network issues recover); after retries are exhausted the task is
    dead-lettered for inspection. The scan itself is idempotent -- the orchestrator
    skips a scan that already reached a terminal state -- so acks_late redelivery
    after a worker crash is safe."""
    import time as _time

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
    except Exception as exc:
        if self.request.retries >= self.max_retries:
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
        async with session_maker() as session:  # type: AsyncSession
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


@celery_app.task(name="scans.reap_orphans")
def reap_orphaned_scans_task() -> int:
    """Beat-scheduled orphan-scan reaper. Idempotent + safe to run concurrently: the
    recovery is a single atomic UPDATE, and it never re-dispatches work."""
    return asyncio.run(_reap())
