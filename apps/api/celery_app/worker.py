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
    include=["apps.api.celery_app.tasks.scan_tasks"],
)
celery_app.conf.broker_connection_retry_on_startup = True
