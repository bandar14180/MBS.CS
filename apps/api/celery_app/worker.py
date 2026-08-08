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

celery_app.conf.update(
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
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
}

# Phase 1.6: scheduled backups. Only registered when enabled, so a disabled deployment
# doesn't tick a no-op. Runs on the default queue (never the `scans` queue) so it cannot
# interfere with scan execution.
if settings.backup_enabled:
    celery_app.conf.beat_schedule["scheduled-backup"] = {
        "task": "backup.run",
        "schedule": float(settings.backup_interval_seconds),
    }

celery_app.conf.timezone = "UTC"


# Phase 4.1: start the worker's Prometheus metrics endpoint once the worker is up. Registered
# unconditionally (the handler no-ops in the API process -- the signal only fires in a worker)
# and is fully best-effort, so it can never block worker startup.
from celery.signals import worker_ready  # noqa: E402


@worker_ready.connect
def _start_worker_metrics(**_kwargs) -> None:
    from apps.api.celery_app.metrics import start_worker_metrics_server

    start_worker_metrics_server()
