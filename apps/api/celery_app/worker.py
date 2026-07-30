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
    ],
)
celery_app.conf.broker_connection_retry_on_startup = True

# --- Reliability (P1-6) -------------------------------------------------------
# acks_late + reject_on_worker_lost: a task is only acknowledged AFTER it finishes,
# so if a worker is killed mid-scan the broker re-delivers it (graceful recovery).
# Scans are idempotent (orchestrator skips already-finished scans), so redelivery
# is safe. prefetch=1 stops a worker hoarding long scans. Named queues let the
# heavy scan work scale/isolate separately from everything else.
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
)

# Continuous security: a beat tick every 60s launches any due recurring scans.
# Runs in the dedicated `beat` service (see docker-compose); the worker executes
# the scans it enqueues.
celery_app.conf.beat_schedule = {
    "enqueue-due-schedules": {
        "task": "schedules.enqueue_due",
        "schedule": 60.0,
    },
}
celery_app.conf.timezone = "UTC"
