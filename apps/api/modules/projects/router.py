import uuid

from fastapi import APIRouter, Depends, Response, status

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.core.pagination import PaginationDep, set_page_headers
from apps.api.modules.projects import service
from apps.api.modules.projects.schemas import (
    ProjectCreate,
    ProjectRead,
    ProjectUpdate,
    TargetCreate,
    TargetRead,
    TargetUpdate,
)

router = APIRouter(prefix="/workspaces/{workspace_id}/projects", tags=["projects"])


@router.post(
    "",
    response_model=ProjectRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("project:create"))],
)
async def create_project(payload: ProjectCreate, db: DbDep, ctx: WorkspaceContextDep) -> ProjectRead:
    project = await service.create_project(db, ctx.workspace_id, ctx.member.user_id, payload.name, payload.description)
    return ProjectRead.model_validate(project)


@router.get(
    "",
    response_model=list[ProjectRead],
    dependencies=[Depends(require_permission("project:read"))],
)
async def list_projects(
    db: DbDep, ctx: WorkspaceContextDep, response: Response, page: PaginationDep
) -> list[ProjectRead]:
    projects, total = await service.list_projects(db, ctx.workspace_id, page)
    set_page_headers(response, total=total, page=page)
    return [ProjectRead.model_validate(p) for p in projects]


@router.get(
    "/{project_id}",
    response_model=ProjectRead,
    dependencies=[Depends(require_permission("project:read"))],
)
async def get_project(project_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep) -> ProjectRead:
    project = await service.get_project(db, ctx.workspace_id, project_id)
    return ProjectRead.model_validate(project)


@router.patch(
    "/{project_id}",
    response_model=ProjectRead,
    dependencies=[Depends(require_permission("project:update"))],
)
async def update_project(project_id: uuid.UUID, payload: ProjectUpdate, db: DbDep, ctx: WorkspaceContextDep) -> ProjectRead:
    project = await service.update_project(
        db, ctx.workspace_id, project_id, payload.name, payload.description, payload.status
    )
    return ProjectRead.model_validate(project)


@router.delete(
    "/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("project:delete"))],
)
async def delete_project(project_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep) -> None:
    await service.delete_project(db, ctx.workspace_id, project_id)


@router.post(
    "/{project_id}/targets",
    response_model=TargetRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("target:create"))],
)
async def create_target(project_id: uuid.UUID, payload: TargetCreate, db: DbDep, ctx: WorkspaceContextDep) -> TargetRead:
    # P7-2: `ctx.workspace_id` is the AUTHENTICATED workspace (from the path + membership
    # check), never a body field -- so `payload.site_id` is resolved against the caller's
    # own workspace inside the service. `network_zone` is not accepted at all; the service
    # derives it.
    target = await service.create_target(
        db, ctx.workspace_id, project_id, ctx.member.user_id, payload.type, payload.value,
        payload.criticality, site_id=payload.site_id,
    )
    return TargetRead.model_validate(target)


@router.patch(
    "/{project_id}/targets/{target_id}",
    response_model=TargetRead,
    dependencies=[Depends(require_permission("target:update"))],
)
async def update_target(
    project_id: uuid.UUID, target_id: uuid.UUID, payload: TargetUpdate, db: DbDep, ctx: WorkspaceContextDep
) -> TargetRead:
    target = await service.update_target_criticality(
        db, ctx.workspace_id, project_id, target_id, payload.criticality
    )
    return TargetRead.model_validate(target)


@router.get(
    "/{project_id}/targets",
    response_model=list[TargetRead],
    dependencies=[Depends(require_permission("target:read"))],
)
async def list_targets(
    project_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep, response: Response, page: PaginationDep
) -> list[TargetRead]:
    targets, total = await service.list_targets(db, ctx.workspace_id, project_id, page)
    set_page_headers(response, total=total, page=page)
    return [TargetRead.model_validate(t) for t in targets]
