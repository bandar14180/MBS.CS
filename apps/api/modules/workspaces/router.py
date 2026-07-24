import uuid

from fastapi import APIRouter, Depends, status

from apps.api.core.deps import CurrentUserDep, DbDep, require_permission
from apps.api.modules.workspaces import service
from apps.api.modules.workspaces.schemas import (
    MemberInvite,
    MemberRead,
    MemberRoleUpdate,
    RoleRead,
    WorkspaceCreate,
    WorkspaceRead,
)

router = APIRouter(prefix="/workspaces", tags=["workspaces"])
roles_router = APIRouter(tags=["workspaces"])


@router.post("", response_model=WorkspaceRead, status_code=status.HTTP_201_CREATED)
async def create_workspace(payload: WorkspaceCreate, db: DbDep, current_user: CurrentUserDep) -> WorkspaceRead:
    workspace = await service.create_workspace(db, current_user, payload.name)
    return WorkspaceRead.model_validate(workspace)


@router.get("", response_model=list[WorkspaceRead])
async def list_workspaces(db: DbDep, current_user: CurrentUserDep) -> list[WorkspaceRead]:
    workspaces = await service.list_workspaces_for_user(db, current_user.id)
    return [WorkspaceRead.model_validate(w) for w in workspaces]


@router.get(
    "/{workspace_id}/members",
    response_model=list[MemberRead],
    dependencies=[Depends(require_permission("workspace:view"))],
)
async def list_members(workspace_id: uuid.UUID, db: DbDep) -> list[MemberRead]:
    return await service.list_members(db, workspace_id)


@router.post(
    "/{workspace_id}/members/invite",
    response_model=MemberRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("workspace:manage"))],
)
async def invite_member(workspace_id: uuid.UUID, payload: MemberInvite, db: DbDep) -> MemberRead:
    return await service.invite_member(db, workspace_id, payload.email, payload.role_name)


@router.patch(
    "/{workspace_id}/members/{user_id}/role",
    response_model=MemberRead,
    dependencies=[Depends(require_permission("workspace:manage"))],
)
async def update_member_role(
    workspace_id: uuid.UUID, user_id: uuid.UUID, payload: MemberRoleUpdate, db: DbDep
) -> MemberRead:
    return await service.update_member_role(db, workspace_id, user_id, payload.role_name)


@router.delete(
    "/{workspace_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("workspace:manage"))],
)
async def remove_member(workspace_id: uuid.UUID, user_id: uuid.UUID, db: DbDep) -> None:
    await service.remove_member(db, workspace_id, user_id)


@roles_router.get("/roles", response_model=list[RoleRead])
async def list_roles(db: DbDep, current_user: CurrentUserDep) -> list[RoleRead]:
    roles = await service.list_system_roles(db)
    return [RoleRead.model_validate(r) for r in roles]
