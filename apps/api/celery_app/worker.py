from celery import Celery

from apps.api.core.config import get_settings
import apps.api.core.models_all  # noqa: F401  -- register all ORM models on Base.metadata

settings = get_settings()

celery_app = Celery(
    "mbs_sc",
    broker=settings.redis_url,
    backend=settings.redis_url,
    # Explicit include: task modules aren't named literally "tasks" (they're
    # tasks/scan_tasks.py etc.), so autodiscover_tasks alone won't find them.
    include=[
        "apps.api.celery_app.tasks.scan_tasks",
        "apps.api.celery_app.tasks.schedule_tasks",
        "apps.api.celery_app.tasks.backup_tasks",
        # Phase 5.2: registered so the worker knows the task. NOT beat-scheduled -- it runs
        # only when invoked manually, and is double-gated OFF (retention_enabled + dry_run).
        "apps.api.celery_app.tasks.retention_tasks",
        # E2: async email delivery (default queue). Gated OFF unless email_enabled.
        "apps.api.celery_app.tasks.notification_tasks",
        # P1.1: beat-liveness heartbeat (default queue). Always scheduled; stamps a Redis timestamp.
        "apps.api.celery_app.tasks.reliability_tasks",
    ],
)
celery_app.conf.broker_connection_retry_on_startup = True

# --- Reliability (P1-6) -------------------------------------------------------
# acks_late + reject_on_worker_lost: a task is only acknowledged AFTER it finishes,
# so if a worker is killed mid-scan the broker re-delivers it (graceful recovery).
# Scans are idempotent (orchestrator skips already-finished scans), so redelivery
# is safe. prefetch=1 stops a worker hoarding long scans. Named queues let the
# heavy scan work scale/isolate separately from everything else.
# Phase 1.5: BOUND every task with a soft+hard time limit so a hung/very-long scan
# cannot block warm shutdown forever. The soft limit MUST fire before the hard limit
# (invariant enforced here): the soft one raises SoftTimeLimitExceeded inside the task
# so the orchestrator marks the scan 'failed' cleanly (reclaimable); the hard one is the
# force-kill backstop. A misconfiguration (soft >= hard) is auto-corrected so the soft
# path can never be pre-empted by the hard kill.
_soft_limit = settings.celery_task_soft_time_limit_seconds
_hard_limit = settings.celery_task_time_limit_seconds
if _soft_limit and (_hard_limit <= _soft_limit):
    _hard_limit = _soft_limit + 300  # keep a margin for clean in-task teardown

# Redis broker visibility timeout. kombu's default is 3600s -- BELOW the hard task time
# limit, so a scan legitimately running between 3600s and the hard limit had its message
# restored to the queue and redelivered WHILE its original worker was still executing it.
# The atomic claim stopped that redelivery executing, but it acked away the one message that
# gave the scan its acks_late safety net. Derived from the hard limit (never below it) so
# raising the limit cannot silently reintroduce the overlap; asserted in the worker tests.
_visibility_timeout = max(4200, (_hard_limit or 0) + 300)

celery_app.conf.update(
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    broker_transport_options={"visibility_timeout": _visibility_timeout},
    task_default_queue="default",
    task_routes={
        "scans.run_scan": {"queue": "scans"},
        # schedules.enqueue_due stays on the default queue (cheap, frequent).
    },
    # Task-level retry defaults; the scan task overrides max_retries/backoff.
    task_acks_on_failure_or_timeout=True,
    # Phase 1.5 time limits + child recycling (see config.py for rationale).
    task_soft_time_limit=_soft_limit or None,
    task_time_limit=_hard_limit or None,
    worker_max_tasks_per_child=settings.celery_worker_max_tasks_per_child or None,
)

# Continuous security: a beat tick every 60s launches any due recurring scans.
# Runs in the dedicated `beat` service (see docker-compose); the worker executes
# the scans it enqueues.
celery_app.conf.beat_schedule = {
    "enqueue-due-schedules": {
        "task": "schedules.enqueue_due",
        "schedule": 60.0,
    },
    # Phase 1.2: periodically recover scans stuck in 'running' after a worker crash
    # (worker claimed then died; acks_late redelivery would otherwise just skip it).
    "reap-orphaned-scans": {
        "task": "scans.reap_orphans",
        "schedule": float(settings.scan_orphan_reaper_interval_seconds),
    },
    # P1.1: beat-liveness heartbeat. A tiny task stamped every tick so a stalled scheduler is
    # alertable (mbs_beat_age_seconds -> MbsBeatStalled). Always scheduled -- beat liveness matters
    # in every deployment. Runs on the default queue, never `scans`; purely additive observability.
    "beat-heartbeat": {
        "task": "reliability.beat_heartbeat",
        "schedule": float(settings.beat_heartbeat_interval_seconds),
    },
}

# Phase 1.6: scheduled backups. Only registered when enabled, so a disabled deployment
# doesn't tick a no-op. Runs on the default queue (never the `scans` queue) so it cannot
# interfere with scan execution.
if settings.backup_enabled:
    celery_app.conf.beat_schedule["scheduled-backup"] = {
        "task": "backup.run",
        "schedule": float(settings.backup_interval_seconds),
    }


# Phase 5.3.3: scheduled retention purge. Mirrors the backup gating -- the beat entry is added
# ONLY when retention_enabled, so a disabled deployment never ticks it. The existing 5.2/5.3.2
# `retention.purge` task ALSO self-gates (retention_enabled + retention_dry_run), so even a
# stray tick can never delete unexpectedly. Runs on the default queue (never `scans`). Extracted
# into a helper purely so the enabled/disabled branch is unit-testable without reloading here.
def register_retention_schedule(app, cfg) -> None:
    if cfg.retention_enabled:
        app.conf.beat_schedule["retention-purge"] = {
            "task": "retention.purge",
            "schedule": float(cfg.retention_interval_seconds),
        }


register_retention_schedule(celery_app, settings)

celery_app.conf.timezone = "UTC"


# Phase 4.1: start the worker's Prometheus metrics endpoint once the worker is up. Registered
# unconditionally (the handler no-ops in the API process -- the signal only fires in a worker)
# and is fully best-effort, so it can never block worker startup.
from celery.signals import worker_ready, worker_shutting_down  # noqa: E402


@worker_ready.connect
def _start_worker_metrics(**_kwargs) -> None:
    from apps.api.celery_app.metrics import start_worker_metrics_server

    start_worker_metrics_server()


# P1-1: on a deliberate (warm) shutdown, return a still-executing scan to the queue so the
# redelivery that acks_late ALREADY performs is actually claimable -- without this the
# redelivered task hits `_claim_scan` on a 'running' row, skips, and ACKs away the only
# message that could restart the scan (leaving it stranded until the orphan reaper fails it).
# The handler writes nothing up front; see apps/api/celery_app/shutdown.py for why it waits
# out the drain first. Best-effort: it must never block or fail the worker's exit.
@worker_shutting_down.connect
def _requeue_inflight_scans(**_kwargs) -> None:
    try:
        from apps.api.celery_app.shutdown import on_worker_shutting_down

        on_worker_shutting_down()
    except Exception:  # noqa: BLE001 -- shutdown hygiene must never prevent shutdown
        import logging

        logging.getLogger("mbs.shutdown").warning("shutdown.hook_failed", exc_info=True)
