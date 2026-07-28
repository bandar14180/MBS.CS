import uuid

from fastapi import APIRouter, Depends, Query, status

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.modules.notifications import service
from apps.api.modules.notifications.schemas import NotificationRead, UnreadCount

router = APIRouter(prefix="/workspaces/{workspace_id}/notifications", tags=["notifications"])


@router.get("", response_model=list[NotificationRead], dependencies=[Depends(require_permission("workspace:view"))])
async def list_notifications(
    db: DbDep, ctx: WorkspaceContextDep, unread: bool = Query(default=False)
) -> list[NotificationRead]:
    notes = await service.list_notifications(db, ctx.workspace_id, unread_only=unread)
    return [NotificationRead.model_validate(n) for n in notes]


@router.get(
    "/unread-count", response_model=UnreadCount, dependencies=[Depends(require_permission("workspace:view"))]
)
async def unread_count(db: DbDep, ctx: WorkspaceContextDep) -> UnreadCount:
    return UnreadCount(count=await service.unread_count(db, ctx.workspace_id))


@router.post(
    "/read-all",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("workspace:view"))],
)
async def mark_all_read(db: DbDep, ctx: WorkspaceContextDep) -> None:
    await service.mark_all_read(db, ctx.workspace_id)


@router.post(
    "/{notification_id}/read",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("workspace:view"))],
)
async def mark_read(notification_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep) -> None:
    await service.mark_read(db, ctx.workspace_id, notification_id)
