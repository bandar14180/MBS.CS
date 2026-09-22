import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone

from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.scanner_engine.scan_routing import queue_for_scan
from apps.api.celery_app.worker import celery_app
from apps.api.core.config import get_settings
from apps.api.core.db import make_worker_engine
# P8-F COLD-START ANCHOR -- IMPORTED AT MODULE SCOPE ON PURPOSE. THIS LINE IS THE FIX.
#
# `platform_uptime` captures `_PROCESS_START_MONOTONIC` at import, and the whole gate is
# only meaningful if that happens ONCE, in the worker MainProcess, BEFORE prefork forks its
# children -- they then inherit the one anchor and every sweep measures from the same
# origin.
#
# It was previously imported lazily inside `reap_stale_workers()`. Celery's `include=` list
# is what the MainProcess loads at boot, and it loads THIS module -- but the lazy import
# meant `platform_uptime` was first touched inside a forked CHILD, on that child's first
# sweep. Each child therefore started its own anchor at its own first execution, so every
# sweep reported `uptime=0.0s` and the 600s grace could never expire. Verified live on
# 2026-09-17: `ForkPoolWorker-1` and `ForkPoolWorker-8` both logged `uptime=0.0s
# grace=600.0s`, 300s apart -- stale detection was effectively disabled.
#
# Importing here fixes it because this module IS in `include=`, so the import runs during
# MainProcess boot (verified: `loader.import_default_modules()` loads scan_tasks). Child
# recycling cannot reset it either: a replacement child is forked from that same parent and
# inherits the parent's already-initialised module, rather than re-executing it.
#
# `noqa: F401` -- imported for the side effect of initialising the anchor, not for a name.
from apps.api.core import platform_uptime  # noqa: F401
from apps.api.scanner_engine.orchestrator import run_scan


async def _run(scan_id: str, execution_token: uuid.UUID | None = None) -> None:
    # A fresh engine bound to THIS task's event loop. Reusing the API's
    # module-level engine here fails with "Future attached to a different loop"
    # because Celery runs each task under a new asyncio.run() loop while the
    # pooled DB-API connections (aiomysql) belong to whichever loop first opened them.
    #
    # StaticPool pins the whole task to ONE physical connection. Historically
    # (Postgres/RLS) this mattered because the workspace GUC was session-level
    # and a normal pool could hand a later commit a different connection
    # without it set. Under the Phase 0 MySQL cutover, tenant scoping is a
    # per-asyncio-task ContextVar (apps.api.core.tenancy), not a DB-session
    # GUC, so that specific hazard no longer applies -- but StaticPool is kept
    # anyway: it's still the simplest way to give a Celery task (its own
    # asyncio.run() loop) a short-lived, single-connection engine that can't
    # collide with the API process's pooled connections across event loops.
    settings = get_settings()
    # Honor enterprise proxy / custom-CA settings for the scanner tools + AI calls
    # made during the scan (mirrors them into the process env). Idempotent.
    from apps.api.core.config import configure_networking

    configure_networking(settings)
    engine = make_worker_engine(settings.database_url)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_maker() as session:  # -> AsyncSession (inferred)
            await run_scan(session, uuid.UUID(scan_id), execution_token=execution_token)
    finally:
        await engine.dispose()


async def _fail_scan(
    scan_id: str, reason: str, duration_s: float, execution_token: uuid.UUID
) -> None:
    """Mark a scan 'failed' from the TASK level (Phase 1.5), used when the Celery soft
    time limit fires. The signal surfaces out of asyncio.run (outside the orchestrator's
    own try/except), so without this the scan would stay 'running' until the reaper.

    REUSES the orchestrator's atomic `_finalize_status` (running -> terminal ONLY) rather
    than duplicating the transition, so it can never clobber a cancelled/terminal scan and
    'failed' stays reclaimable via the atomic claim. Integrates the EXISTING failure metric
    (record_scan_result -- no observability change) and emits one structured log line.
    Own short-lived engine (StaticPool), like _run; scans is EXEMPT so no binding needed."""
    import logging

    from apps.api.core.observability import record_scan_result
    from apps.api.modules.scans.models import Scan
    from apps.api.scanner_engine.orchestrator import _finalize_status

    settings = get_settings()
    engine = make_worker_engine(settings.database_url)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_maker() as session:  # -> AsyncSession (inferred)
            scan = await session.get(Scan, uuid.UUID(scan_id))
            # Fenced on THIS execution's token (P1-1 P3): if the scan was requeued on
            # shutdown and re-claimed by a new executor, the row is 'running' again -- an
            # unfenced write here would clobber the NEW owner's scan with our timeout.
            recovered = scan is not None and await _finalize_status(
                session, scan, "failed", execution_token
            )
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
    # One ownership token for this whole execution (P1-1 P3). Generated HERE, not inside
    # run_scan, so the soft-timeout handler below can fence its terminal write on the same
    # token -- otherwise a timeout firing after a shutdown requeue + re-claim would mark the
    # NEW executor's running scan as failed.
    execution_token = uuid.uuid4()
    try:
        asyncio.run(_run(scan_id, execution_token))
    except SoftTimeLimitExceeded as exc:
        # The soft time limit fired (Phase 1.5): the scan ran too long. Mark it 'failed'
        # cleanly so it is reclaimable (not stuck 'running' waiting on the reaper), record
        # it to the DLQ for inspection, and do NOT autoretry into another guaranteed
        # timeout -- returning normally acks the task and stops the retry chain. The HARD
        # limit (billiard TimeLimitExceeded / SIGKILL) is deliberately NOT caught here: it
        # is the final safety net, left to the orphan reaper.
        asyncio.run(_fail_scan(
            scan_id, "soft_time_limit_exceeded", _time.monotonic() - _started, execution_token
        ))
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
    engine = make_worker_engine(settings.database_url)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_maker() as session:  # -> AsyncSession (inferred)
            reaped = await reap_orphaned_scans(
                session,
                settings.scan_orphan_timeout_seconds,
                settings.scan_stale_heartbeat_seconds,
            )
        if reaped:
            record_scan_reaped(reaped, reason="timeout")
            logging.getLogger("mbs.scan").warning(
                "scan.reaper recovered %d orphaned running scan(s) older than %ds",
                reaped, settings.scan_orphan_timeout_seconds,
            )
        return reaped
    finally:
        await engine.dispose()


async def _reconcile_tool_runs() -> int:
    """Repair tool_runs stuck 'running' under an already-terminal scan. Own short-lived
    engine, exactly like _reap, and best-effort at the outer task level.

    Runs AFTER _reap in the same beat tick deliberately: _reap is what moves a dead scan to
    'failed', and this sweep only considers scans that are already terminal. Running it
    second means a scan reaped in this tick has its orphaned tool runs reconciled in the
    NEXT one, once the grace period has also elapsed -- never in the same instant the scan
    became terminal, which is precisely the race the grace period exists to avoid."""
    import logging

    from apps.api.scanner_engine.orchestrator import reconcile_orphaned_tool_runs

    settings = get_settings()
    if not settings.toolrun_reconcile_enabled:
        return 0
    engine = make_worker_engine(settings.database_url)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_maker() as session:
            reconciled = await reconcile_orphaned_tool_runs(
                session, settings.toolrun_reconcile_grace_seconds
            )
        if reconciled:
            logging.getLogger("mbs.scan").warning(
                "toolrun.reconciler repaired %d tool run(s) left 'running' under a "
                "terminal scan (grace %ds)",
                reconciled, settings.toolrun_reconcile_grace_seconds,
            )
        return reconciled
    finally:
        await engine.dispose()


async def _relay_queued() -> int:
    """Queued-scan RELAY: re-dispatch scans that were durably committed as 'queued' but
    never got a celery_task_id (their Celery dispatch failed -- the DB+Redis dual-write's
    Redis side) and have sat past scan_queued_relay_seconds.

    Ages rows off `queued_at` (when the scan ENTERED the queue), NOT `created_at`. A scan
    returned to the queue by the graceful-shutdown hook was created long before it ran, so
    ageing off `created_at` made it eligible IMMEDIATELY on requeue -- the relay could
    redispatch it inside the container's stop_grace_period while the old executor was still
    running, producing two live executions against the same target. Rows that predate the
    `queued_at` column were explicitly backfilled from `created_at` by its migration, so they
    keep their real queue age; `coalesce(queued_at, created_at)` is a defensive fallback for
    an unexpected NULL, not the mechanism that preserves that behaviour.

    Conservative: `celery_task_id IS NULL` targets ONLY undelivered scans -- a scan already
    in flight has a task id and is never touched. It NEVER creates a second scan row; it just
    re-enqueues the existing scan_id, and the atomic scan claim (queued/failed -> running)
    guarantees a relay message + any late original message cannot both execute. If the relay
    .delay() itself fails (broker still down), celery_task_id stays NULL -> recoverable on a
    later tick. Own short-lived engine (StaticPool); `scans` is in tenancy.EXEMPT_TABLES (this
    is a beat-scheduled sweep across ALL workspaces' queued scans, not a single-workspace
    request, so there's no single workspace_id to bind).

    Phase 0 MySQL cutover: MySQL has no `make_interval()`. The cutoff timestamp is computed
    in Python instead and bound as a plain parameter -- see orchestrator.reap_orphaned_scans
    for the same pattern. `coalesce()` itself needs no change; MySQL supports it natively."""
    import logging

    settings = get_settings()
    if not settings.scan_queued_relay_enabled:
        return 0
    # DISPATCH-MODEL GUARD. The relay only makes sense where Celery is what dispatches a
    # scan. Under the LEASE model `create_scan` deliberately leaves `celery_task_id` NULL
    # (the scan row IS the queue, claimed via POST /v1/lease), so EVERY queued scan matches
    # this sweep's predicate -- and relaying them would enqueue messages onto
    # `scans.public`, which nothing consumes. That would recreate the exact undelivered
    # backlog this dispatch split exists to remove, and would additionally stamp
    # `celery_task_id`, disqualifying those scans from any future relay.
    #
    # So: when Celery is not the dispatcher, there is nothing to re-dispatch and a queued
    # scan is recovered by a worker leasing it, not by this task. Returning 0 here is not
    # "the relay is broken" -- it is the relay correctly declining to act on a queue it does
    # not own.
    if not settings.celery_scan_dispatch_enabled:
        return 0
    engine = make_worker_engine(settings.database_url)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    relayed = 0
    try:
        async with session_maker() as session:  # -> AsyncSession (inferred)
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=int(settings.scan_queued_relay_seconds))
            # Explicit deleting-workspace guard: never re-dispatch a scan whose workspace is being
            # torn down. This is the PRIMARY protection against resurrecting a deleting tenant's
            # scan; the FK cascade (a dispatch into a gone workspace fails) remains a backstop.
            # MBS.SC: `config` is selected too so the relay can re-derive the scan's QUEUE.
            # This sweep is deliberately cross-tenant (it relays every workspace's stranded
            # scans), which is why it uses raw SQL with an explicit workspace JOIN rather
            # than the ORM auto-filter -- see the tenancy note on this task.
            rows = await session.execute(
                text(
                    "SELECT s.id, s.config FROM scans s JOIN workspaces w ON w.id = s.workspace_id "
                    "WHERE s.status = 'queued' AND s.celery_task_id IS NULL "
                    "AND w.status <> 'deleting' "
                    "AND coalesce(s.queued_at, s.created_at) < :cutoff"
                ),
                {"cutoff": cutoff},
            )
            ids = [(r[0], r[1]) for r in rows.fetchall()]

            for sid, raw_config in ids:
                try:
                    # MBS.SC Phase 5: relay to the scan's OWN queue. `.delay()` would use the
                    # default route (`scans.public`), which would hand a stranded PRIVATE
                    # scan to a public worker -- one with internet egress and no tunnel, and
                    # no authorization for that customer's network.
                    cfg = raw_config if isinstance(raw_config, dict) else json.loads(raw_config or "{}")
                    relay_queue = queue_for_scan(
                        network_zone=cfg.get("network_zone") or "public",
                        site_id=cfg.get("site_id"),
                    )
                    result = run_scan_task.apply_async(args=[str(sid)], queue=relay_queue)
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
    'failed'; (2) TOOL-RUN reconciliation -- tool_runs left 'running' under an already-
    terminal scan are repaired; (3) queued relay -- 'queued' scans never delivered to Celery
    are re-dispatched. All three are idempotent + safe to run concurrently (atomic UPDATE /
    atomic scan claim), and none creates duplicate work. Returns the orphan-reaped count
    (unchanged contract -- the reconciler's count is logged, not returned, so existing
    callers and metrics keep their meaning)."""
    async def _all() -> int:
        reaped = await _reap()
        # Each step owns its failure: a reconciliation problem must not stop the relay from
        # re-dispatching undelivered scans, which is the more user-visible of the two.
        try:
            await _reconcile_tool_runs()
        except Exception:  # noqa: BLE001 -- best-effort sweep, logged with its traceback
            import logging

            logging.getLogger("mbs.scan").exception(
                "toolrun.reconciler failed; scan reaping and queued relay are unaffected"
            )
        await _relay_queued()
        return reaped

    return asyncio.run(_all())


# ---------------------------------------------------------------------------------------
# Worker-level stale reaper (MBS.SC PHASE 8 -- P8-F)
# ---------------------------------------------------------------------------------------

async def _reap_stale_workers() -> int:
    """Suspend workers that have stopped heartbeating. Own short-lived engine, like _reap.

    Deliberately SEPARATE from `_reap` (the SCAN reaper) rather than folded into it: they
    answer different questions -- "is this scan's executor dead?" versus "should this worker
    still be given NEW work?" -- and a failure in one must not suppress the other. They share
    a cadence, not a code path.

    Cross-tenant by design (it sweeps every workspace's workers), and it needs no tenancy
    bypass because it is a single raw UPDATE over `scanner_workers`, which is infrastructure
    rather than tenant-scoped data.

    COLD-START GRACE. This is the caller that opts into the P8-F startup gate, because it is
    the one whose process lifetime actually tracks the platform's: the task runs on the
    `default` queue in `worker-default`, so "this process has been up for N seconds" means
    "the control plane has been able to receive heartbeats for N seconds". The grace REUSES
    `worker_stale_after_seconds` rather than adding a second knob -- one window of silence is
    already the agreed definition of "too long", so a platform that has not yet been up that
    long simply cannot have observed a full window of it.
    """
    import logging

    from apps.api.modules.scanner_workers.service import reap_stale_workers

    settings = get_settings()
    engine = make_worker_engine(settings.database_url)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_maker() as session:
            suspended = await reap_stale_workers(
                session, settings.worker_stale_after_seconds,
                startup_grace_seconds=float(settings.worker_stale_after_seconds),
            )
        if suspended:
            logging.getLogger("mbs.scan").warning(
                "scanner_worker.reaper suspended %d worker(s) silent for more than %ds",
                suspended, settings.worker_stale_after_seconds,
            )
        return suspended
    finally:
        await engine.dispose()


@celery_app.task(name="workers.reap_stale")
def reap_stale_workers_task() -> int:
    """Beat-scheduled worker liveness sweep (P8-F).

    Returns how many workers were suspended. Idempotent and safe to run concurrently with
    itself or with the scan reaper: the underlying statement is one atomic conditional
    UPDATE whose source state is 'active', so a second pass matches nothing.

    Runs on the DEFAULT queue (never `scans`), like every other beat task here, so it cannot
    compete with scan execution for a worker slot.
    """
    return asyncio.run(_reap_stale_workers())
