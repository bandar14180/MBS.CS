from celery import Celery

from apps.api.core.config import get_settings

settings = get_settings()

celery_app = Celery("mbs_sc", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.broker_connection_retry_on_startup = True
celery_app.autodiscover_tasks(["apps.api.celery_app.tasks"])
