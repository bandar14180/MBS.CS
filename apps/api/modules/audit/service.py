import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.pagination import MAX_LIMIT, Pagination, paginate
from apps.api.modules.audit.models import AuditEvent


async def record(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    actor_user_id: uuid.UUID | None,
    action: str,
    resource_type: str,
    *,
    resource_id: uuid.UUID | None = None,
    detail: str | None = None,
) -> None:
    """Append an audit event. Flushes (does NOT commit) so the event is atomic
    with the action's own transaction. Denormalizes the actor email so the record
    survives the user being deleted later."""
    actor_email = None
    if actor_user_id is not None:
        from apps.api.modules.users.models import User

        user = await db.get(User, actor_user_id)
        actor_email = user.email if user else None

    db.add(
        AuditEvent(
            workspace_id=workspace_id,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            detail=detail,
        )
    )
    await db.flush()


async def list_events(
    db: AsyncSession, workspace_id: uuid.UUID, action: str | None = None, page: Pagination | None = None
) -> tuple[list[AuditEvent], int]:
    query = select(AuditEvent).where(AuditEvent.workspace_id == workspace_id)
    if action:
        query = query.where(AuditEvent.action == action)
    query = query.order_by(AuditEvent.created_at.desc(), AuditEvent.id)
    return await paginate(db, query, page or Pagination(limit=MAX_LIMIT, offset=0))
