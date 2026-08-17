import logging
import uuid

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.pagination import MAX_LIMIT, Pagination, paginate
from apps.api.modules.notifications.models import Notification

logger = logging.getLogger(__name__)


async def create_notification(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    type: str,
    title: str,
    *,
    severity: str = "info",
    body: str | None = None,
    project_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
) -> Notification:
    note = Notification(
        workspace_id=workspace_id,
        project_id=project_id,
        scan_id=scan_id,
        type=type,
        severity=severity,
        title=title,
        body=body,
    )
    db.add(note)
    await db.flush()
    return note


async def notify_scan_finished(db: AsyncSession, scan) -> None:
    """Emit an in-app notification for a finished scan. Best-effort: never let a
    notification failure affect the scan outcome (caller wraps this).

    Runs inside the worker's session with the workspace RLS GUC already set."""
    from apps.api.modules.vulnerabilities.models import Vulnerability

    if scan.status == "failed":
        note = await create_notification(
            db, scan.workspace_id, "scan_failed", "Scan failed",
            severity="warning",
            body="A scan did not complete. Open the project to see which tool failed and why.",
            project_id=scan.project_id, scan_id=scan.id,
        )
        await _dispatch_email(db, note)
        return

    # Completed: count NEW high/critical findings first detected by this scan.
    new_hi = await db.scalar(
        select(func.count())
        .select_from(Vulnerability)
        .where(
            Vulnerability.first_detected_scan_id == scan.id,
            Vulnerability.severity.in_(("critical", "high")),
        )
    ) or 0

    if new_hi > 0:
        note = await create_notification(
            db, scan.workspace_id, "critical_findings",
            f"{new_hi} new high/critical finding(s)",
            severity="critical",
            body="A completed scan surfaced new high or critical findings. Review them in the Vulnerabilities tab.",
            project_id=scan.project_id, scan_id=scan.id,
        )
        await _dispatch_email(db, note)
    else:
        await create_notification(
            db, scan.workspace_id, "scan_completed", "Scan completed",
            severity="info",
            body="A scan finished with no new high/critical findings.",
            project_id=scan.project_id, scan_id=scan.id,
        )


async def _dispatch_email(db: AsyncSession, note: Notification) -> None:
    """E4: fan an emailable scan notification out to the async email task (best-effort, never
    raises -- the in-app notification is the source of truth; email is an additional channel)."""
    from apps.api.modules.notifications.alerts import email_scan_alert

    await email_scan_alert(db, note)


async def list_notifications(
    db: AsyncSession, workspace_id: uuid.UUID, unread_only: bool = False, page: Pagination | None = None
) -> tuple[list[Notification], int]:
    query = select(Notification).where(Notification.workspace_id == workspace_id)
    if unread_only:
        query = query.where(Notification.read.is_(False))
    query = query.order_by(Notification.created_at.desc(), Notification.id)
    return await paginate(db, query, page or Pagination(limit=MAX_LIMIT, offset=0))


async def unread_count(db: AsyncSession, workspace_id: uuid.UUID) -> int:
    return await db.scalar(
        select(func.count())
        .select_from(Notification)
        .where(Notification.workspace_id == workspace_id, Notification.read.is_(False))
    ) or 0


async def mark_read(db: AsyncSession, workspace_id: uuid.UUID, notification_id: uuid.UUID) -> None:
    await db.execute(
        update(Notification)
        .where(Notification.id == notification_id, Notification.workspace_id == workspace_id)
        .values(read=True)
    )
    await db.commit()


async def mark_all_read(db: AsyncSession, workspace_id: uuid.UUID) -> int:
    result = await db.execute(
        update(Notification)
        .where(Notification.workspace_id == workspace_id, Notification.read.is_(False))
        .values(read=True)
    )
    await db.commit()
    return result.rowcount or 0
