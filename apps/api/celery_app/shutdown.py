"""P1-1 -- return an interrupted scan to the queue on graceful worker shutdown.

THE DEFECT
----------
``task_acks_late`` + ``task_reject_on_worker_lost`` already make the broker REDELIVER a scan
whose worker died mid-execution. That redelivery is currently wasted: the dead worker left the
row at ``status='running'``, and the atomic claim (``orchestrator._claim_scan``) accepts only
``queued``/``failed``. The redelivered task therefore fails the claim, logs
``scan.skip_not_claimable``, returns normally -- and ACKs the one message that could have
restarted the scan. The scan then sits ``running`` until the orphan reaper marks it terminally
``failed`` (up to ``scan_orphan_timeout_seconds`` + one reaper interval), and is never re-run.

THE FIX
-------
Do not touch the claim. Instead, stop the row from being ``running`` before the worker dies:
transition it back to ``queued`` and clear the execution stamps, so the redelivery the broker
*already performs* lands on a row the EXISTING claim accepts. The recovery path becomes:

    SIGTERM -> worker_shutting_down -> running->queued -> worker dies
            -> Celery redelivery -> _claim_scan (queued->running) -> scan executes

WHY THIS DOES NOT REQUEUE IMMEDIATELY
-------------------------------------
``worker_shutting_down`` fires the instant SIGTERM arrives -- while the in-flight scan is still
running and may well finish inside the grace window. Requeueing right then would be a REGRESSION:
the task's terminal write (``_finalize_status``, conditional on ``status='running'``) would fail,
the row would stay ``queued`` with a NULL ``celery_task_id``, and the queued-relay would later
re-dispatch a scan that had actually completed -- duplicate ACTIVE scanning of a customer target.

So the handler writes nothing up front. It starts a watchdog that polls the worker's own
active-request set and requeues only what is STILL executing as the grace window closes:

  * scan finishes inside the window  -> active set empties -> watchdog exits, NO write, the
    task's own terminal status stands (unchanged behavior);
  * scan is still running at the deadline -> requeue, moments before Docker's SIGKILL.

The deadline must sit inside the container's ``stop_grace_period`` (120s for the scan worker);
it is env-tunable so a deployment with a different grace can align it.
"""
import logging
import os
import threading
import time

logger = logging.getLogger("mbs.shutdown")

SCAN_TASK_NAME = "scans.run_scan"

# Requeue this many seconds after SIGTERM if the scan is still running. Must be < the
# service's stop_grace_period (infra/docker-compose.yml: 120s for `worker`) so the write
# lands before SIGKILL, with margin for the UPDATE itself.
DEFAULT_DEADLINE_SECONDS = 90.0
DEFAULT_POLL_SECONDS = 2.0


def _env_float(name: str, default: float) -> float:
    try:
        val = float(os.environ.get(name, "") or default)
        return val if val > 0 else default
    except (TypeError, ValueError):
        return default


def deadline_seconds() -> float:
    return _env_float("MBS_SHUTDOWN_REQUEUE_DEADLINE_SECONDS", DEFAULT_DEADLINE_SECONDS)


def poll_seconds() -> float:
    return _env_float("MBS_SHUTDOWN_REQUEUE_POLL_SECONDS", DEFAULT_POLL_SECONDS)


# --- the atomic transition ----------------------------------------------------------------

async def requeue_scan(scan_id: str) -> bool:
    """Atomically return ONE interrupted scan to the queue: ``running`` -> ``queued``,
    clearing ``started_at``, ``celery_task_id`` and ``execution_token``.

    Clearing ``execution_token`` is the REVOCATION (P1-1 P3): it is what tells the executor
    that may still be running that it no longer owns this scan. Without it the old executor
    would finish, find ``status`` no longer ``running``, silently discard its outcome and
    leave a redispatchable row -- a completed scan re-run against a live target. With it the
    executor's fenced terminal write provably cannot land, and its next ownership check stops
    it before it can start another tool.

    Refreshing ``queued_at`` is what stops the relay redispatching this scan while the old
    worker is still draining. The relay ages rows off ``queued_at``; without this the row
    kept its original (long past) ``created_at`` and became relay-eligible the instant it was
    requeued -- i.e. inside the container's stop_grace_period, with the old executor still
    running. Now the earliest redispatch is requeue + ``scan_queued_relay_seconds``, which is
    comfortably after SIGKILL.

    CONDITIONAL on the row still being ``running`` (mirrors ``_claim_scan`` /
    ``_finalize_status``), so it can never clobber a scan that was cancelled or reached a
    terminal state concurrently -- those keep their status and this returns False. Returns
    True iff THIS caller performed the write.

    Clearing ``celery_task_id`` is what also makes the row recoverable by the existing
    queued-relay if the broker redelivery is itself lost (relay targets
    ``status='queued' AND celery_task_id IS NULL``), giving the fix a second safety net.

    Own short-lived engine (StaticPool), like the other worker-side entry points; `scans`
    is in tenancy.EXEMPT_TABLES, so no workspace binding is needed.
    """
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from apps.api.core.config import get_settings
    from apps.api.core.db import make_worker_engine

    engine = make_worker_engine(get_settings().database_url)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_maker() as session:
            # Phase 0 MySQL cutover: RETURNING replaced with rowcount (MySQL has none);
            # exact here because of CLIENT_FOUND_ROWS (core/db.py's _mysql_connect_args).
            result = await session.execute(
                text(
                    "UPDATE scans SET status = 'queued', started_at = NULL, "
                    "celery_task_id = NULL, execution_token = NULL, queued_at = now() "
                    "WHERE id = :id AND status = 'running'"
                ),
                {"id": str(scan_id)},
            )
            requeued = result.rowcount == 1
            await session.commit()
        return requeued
    finally:
        await engine.dispose()


def requeue_scan_sync(scan_id: str) -> bool:
    """Blocking wrapper -- the shutdown watchdog runs in a plain thread, not an event loop."""
    import asyncio

    return asyncio.run(requeue_scan(scan_id))


# --- what is this worker still executing? -------------------------------------------------

def inflight_scan_ids() -> list[str]:
    """Scan ids this worker is still executing, read from Celery's own active-request set.

    ``celery.worker.state.active_requests`` is maintained in the MainProcess (where the
    shutdown signals fire), so it is visible even though prefork runs tasks in children.
    Best-effort: any unexpected shape is skipped rather than raised -- shutdown must never
    crash on observability of its own state.
    """
    try:
        from celery.worker import state as worker_state
    except Exception:  # noqa: BLE001 -- not running under a worker (e.g. imported in the API)
        return []

    ids: list[str] = []
    try:
        for request in list(getattr(worker_state, "active_requests", ()) or ()):
            if getattr(request, "name", None) != SCAN_TASK_NAME:
                continue
            args = getattr(request, "args", None) or ()
            if args:
                ids.append(str(args[0]))
    except Exception:  # noqa: BLE001
        logger.warning("shutdown.inflight_scan_lookup_failed", exc_info=True)
    return ids


# --- the watchdog -------------------------------------------------------------------------

def drain_and_requeue(deadline: float | None = None, poll: float | None = None) -> list[str]:
    """Wait for this worker's scans to drain; requeue whatever is still running at the deadline.

    Returns the scan ids actually requeued (empty on a clean drain -- the normal, desired case).
    Never raises: a shutdown hook must not be able to prevent the worker from exiting.
    """
    deadline = deadline_seconds() if deadline is None else deadline
    poll = poll_seconds() if poll is None else poll
    started = time.monotonic()

    try:
        while True:
            pending = inflight_scan_ids()
            if not pending:
                logger.info(
                    "shutdown.drained_cleanly -- no scan required requeueing",
                    extra={"event": "shutdown.drained_cleanly"},
                )
                return []
            if time.monotonic() - started >= deadline:
                break
            time.sleep(poll)

        requeued: list[str] = []
        for scan_id in inflight_scan_ids():
            try:
                if requeue_scan_sync(scan_id):
                    requeued.append(scan_id)
                    logger.warning(
                        "shutdown.scan_requeued scan=%s -- running->queued for redelivery", scan_id,
                        extra={
                            "event": "shutdown.scan_requeued",
                            "scan_id": scan_id,
                            "shutdown_reason": "worker_shutting_down",
                            "deadline_s": deadline,
                        },
                    )
                else:
                    # Reached a terminal/cancelled state between the poll and the write --
                    # correct outcome, nothing to recover.
                    logger.info(
                        "shutdown.scan_not_requeued scan=%s -- no longer running", scan_id,
                        extra={"event": "shutdown.scan_not_requeued", "scan_id": scan_id},
                    )
            except Exception:  # noqa: BLE001 -- one failure must not strand the others
                logger.warning(
                    "shutdown.requeue_failed scan=%s -- falls back to the orphan reaper", scan_id,
                    extra={"event": "shutdown.requeue_failed", "scan_id": scan_id},
                    exc_info=True,
                )
        return requeued
    except Exception:  # noqa: BLE001
        logger.warning("shutdown.watchdog_failed", exc_info=True)
        return []


def on_worker_shutting_down(**_kwargs) -> threading.Thread | None:
    """``worker_shutting_down`` handler. Starts the watchdog on a daemon thread so the normal
    warm-shutdown drain is never blocked or delayed by it.

    Daemon is deliberate: if the worker exits cleanly the thread dies with it having written
    nothing, which is exactly right -- a scan that finished needs no requeue.
    """
    if not inflight_scan_ids():
        return None  # nothing executing; no watchdog needed
    thread = threading.Thread(
        target=drain_and_requeue, name="mbs-shutdown-requeue", daemon=True
    )
    thread.start()
    return thread
