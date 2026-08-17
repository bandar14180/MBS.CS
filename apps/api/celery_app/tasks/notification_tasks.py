"""E2 -- async email delivery task.

Runs on the DEFAULT queue (never `scans`), so email delivery never competes with or blocks scan
execution. Follows the scan/backup task patterns: bounded soft/hard time limits and bounded
retries with exponential backoff for TRANSIENT SMTP faults only. Production-safety lives here:
per-alert dedup (E5), metrics (E5), and secret-free audit events (E5).

Nothing about a scan/backup depends on this task's outcome -- callers only enqueue it.
"""
import asyncio
import hashlib
import logging
import time

from apps.api.celery_app.worker import celery_app
from apps.api.core.config import get_settings

logger = logging.getLogger("mbs.notifications")

# Enforce soft < hard (mirrors worker.py / backup_tasks) so a misconfig can't invert them.
_cfg = get_settings()
_soft = _cfg.email_task_soft_time_limit_seconds
_hard = _cfg.email_task_time_limit_seconds
if _soft and _hard <= _soft:
    _hard = _soft + 15


def _dedup_key(category: str, workspace_id, subject: str) -> str:
    h = hashlib.sha1((subject or "").encode("utf-8")).hexdigest()[:16]
    return f"email:dedup:{category}:{workspace_id or '-'}:{h}"


def _dedup_seen_and_mark(settings, category, workspace_id, subject) -> bool:
    """True if an identical alert was already dispatched within the dedup window (skip sending).
    Uses SET NX EX so the check-and-mark is atomic. Best-effort: a Redis error fails OPEN (returns
    False so the email is still attempted)."""
    try:
        import redis

        client = redis.from_url(settings.redis_url)
        was_set = client.set(
            _dedup_key(category, workspace_id, subject), "1",
            nx=True, ex=settings.email_dedup_window_seconds,
        )
        return not bool(was_set)  # already existed -> seen
    except Exception:  # noqa: BLE001
        return False


def _backoff(retries: int) -> int:
    return min(300, 5 * (2 ** retries))  # 5s, 10s, 20s, ... capped at 5 min


@celery_app.task(
    bind=True,
    name="notifications.send_email",
    max_retries=_cfg.email_max_retries,
    soft_time_limit=_soft or None,
    time_limit=_hard or None,
)
def send_email_task(self, recipients, subject, body, category, workspace_id=None) -> str:
    """Deliver one alert email. Returns a short status string: disabled / no_recipients / deduped
    / sent / failed. Retries only TRANSIENT SMTP faults with exponential backoff; a permanent
    failure is recorded (metric + audit) and given up on (no retry storm)."""
    from apps.api.modules.auth.mfa_guard import security_event
    from apps.api.modules.notifications.email import EmailDeliveryError
    from apps.api.modules.notifications.metrics import record_email_failed, record_email_sent
    from apps.api.modules.notifications.providers import EmailNotificationProvider

    settings = get_settings()
    if not settings.email_enabled:
        return "disabled"
    if not recipients:
        return "no_recipients"
    # Dedup only on the FIRST attempt -- retries of THIS task must not be skipped by their own mark.
    if self.request.retries == 0 and _dedup_seen_and_mark(settings, category, workspace_id, subject):
        return "deduped"

    t0 = time.monotonic()
    try:
        asyncio.run(
            EmailNotificationProvider(settings, recipients).send(title=subject, body=body, type=category)
        )
    except EmailDeliveryError as exc:
        record_email_failed(category)
        try:
            raise self.retry(exc=exc, countdown=_backoff(self.request.retries))
        except self.MaxRetriesExceededError:
            security_event(
                "notification.email.failed", user_id=None,
                category=category, recipients=len(recipients), attempts=self.request.retries + 1,
            )
            logger.error("email.permanently_failed category=%s attempts=%s", category, self.request.retries + 1)
            return "failed"
    except Exception:  # noqa: BLE001 -- unexpected/permanent: record + give up (no retry storm)
        record_email_failed(category)
        security_event("notification.email.failed", user_id=None, category=category, recipients=len(recipients))
        logger.error("email.failed category=%s", category, exc_info=True)
        return "failed"

    record_email_sent(category, duration_s=time.monotonic() - t0)
    security_event("notification.email.sent", user_id=None, category=category, recipients=len(recipients))
    return "sent"
