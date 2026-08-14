"""E4 -- alert dispatch: turn a domain failure/notification into an ASYNC email task.

The single seam between "something happened" and "send an email". Two entry points:

  * email_scan_alert(db, note)   -- async, from the scan-notification path (workspace context).
  * email_system_alert(cat, ...) -- sync, from backup/DLQ failure sites (no workspace context).

Both are BEST-EFFORT and NEVER raise: a dispatch failure must never affect a scan, a backup, or
the in-app notification. Both only ENQUEUE the Celery task (delivery is async), so nothing here
blocks the caller. Everything is gated by settings.email_enabled (default OFF).
"""
import logging

from apps.api.core.config import get_settings

logger = logging.getLogger("mbs.notifications")

# Only these scan notification types generate an email (info completions are in-app only).
EMAILABLE_SCAN_TYPES = {"scan_failed", "critical_findings"}


async def email_scan_alert(db, note) -> None:
    """Enqueue an email for an emailable scan notification (workspace members are the recipients).
    Never raises."""
    try:
        settings = get_settings()
        if not settings.email_enabled or note.type not in EMAILABLE_SCAN_TYPES:
            return
        recipients = await _workspace_recipients(db, note.workspace_id)
        if not recipients:
            return
        _enqueue(recipients, note.title, note.body or "", note.type, str(note.workspace_id))
    except Exception:  # noqa: BLE001 -- dispatch must never break the scan / in-app notification
        logger.warning("email_scan_alert_failed", exc_info=True)


def email_system_alert(category: str, subject: str, body: str) -> None:
    """Enqueue a system-failure email (backup/DLQ) to the configured admin recipients. Sync +
    best-effort so it is safe to call from a Celery task or a sync failure site. Never raises."""
    try:
        settings = get_settings()
        if not settings.email_enabled:
            return
        recipients = list(settings.email_admin_recipients)
        if not recipients:
            return
        _enqueue(recipients, subject, body, category, None)
    except Exception:  # noqa: BLE001
        logger.warning("email_system_alert_failed", exc_info=True)


async def _workspace_recipients(db, workspace_id) -> list[str]:
    from sqlalchemy import select

    from apps.api.modules.users.models import User, WorkspaceMember

    rows = await db.scalars(
        select(User.email)
        .join(WorkspaceMember, WorkspaceMember.user_id == User.id)
        .where(WorkspaceMember.workspace_id == workspace_id, User.status == "active")
    )
    return [e for e in rows if e]


def _enqueue(recipients, subject, body, category, workspace_id) -> None:
    from apps.api.celery_app.tasks.notification_tasks import send_email_task
    from apps.api.core.log_redaction import redact_text

    # Defense-in-depth: scrub any stray secret/PII/token pattern out of the OUTGOING text (the
    # recipient addresses are the To-header, deliberately not redacted).
    send_email_task.delay(recipients, redact_text(subject), redact_text(body), category, workspace_id)
