import uuid

from fastapi import APIRouter, Depends, status

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.modules.schedules import service
from apps.api.modules.schedules.schemas import ScheduleCreate, ScheduleRead, ScheduleUpdate

router = APIRouter(
    prefix="/workspaces/{workspace_id}/projects/{project_id}/schedules", tags=["schedules"]
)


@router.post(
    "",
    response_model=ScheduleRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("scan:create"))],
)
async def create_schedule(
    project_id: uuid.UUID, payload: ScheduleCreate, db: DbDep, ctx: WorkspaceContextDep
) -> ScheduleRead:
    schedule = await service.create_schedule(
        db,
        ctx.workspace_id,
        project_id,
        ctx.member.user_id,
        payload.target_id,
        payload.scan_type,
        payload.requested_modules,
        payload.interval_minutes,
        payload.use_ai_planner,
    )
    return ScheduleRead.model_validate(schedule)


@router.get("", response_model=list[ScheduleRead], dependencies=[Depends(require_permission("scan:read"))])
async def list_schedules(project_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep) -> list[ScheduleRead]:
    schedules = await service.list_schedules(db, ctx.workspace_id, project_id)
    return [ScheduleRead.model_validate(s) for s in schedules]


@router.patch(
    "/{schedule_id}",
    response_model=ScheduleRead,
    dependencies=[Depends(require_permission("scan:create"))],
)
async def update_schedule(
    project_id: uuid.UUID, schedule_id: uuid.UUID, payload: ScheduleUpdate, db: DbDep, ctx: WorkspaceContextDep
) -> ScheduleRead:
    schedule = await service.update_schedule(
        db, ctx.workspace_id, project_id, schedule_id, payload.enabled, payload.interval_minutes
    )
    return ScheduleRead.model_validate(schedule)


@router.delete(
    "/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("scan:create"))],
)
async def delete_schedule(
    project_id: uuid.UUID, schedule_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> None:
    await service.delete_schedule(db, ctx.workspace_id, project_id, schedule_id)
