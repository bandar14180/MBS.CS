import uuid

from fastapi import APIRouter, Depends, status

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.modules.authorization_scope import service
from apps.api.modules.authorization_scope.schemas import (
    AuthorizationScopeRead,
    AuthorizationScopeSubmit,
    AuthorizationScopeVerify,
)

router = APIRouter(
    prefix="/workspaces/{workspace_id}/projects/{project_id}/targets/{target_id}/authorization-scope",
    tags=["authorization-scope"],
)


@router.post(
    "",
    response_model=AuthorizationScopeRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("authorization_scope:submit"))],
)
async def submit_scope(
    project_id: uuid.UUID, target_id: uuid.UUID, payload: AuthorizationScopeSubmit, db: DbDep, ctx: WorkspaceContextDep
) -> AuthorizationScopeRead:
    scope = await service.submit_scope(
        db,
        ctx.workspace_id,
        project_id,
        target_id,
        payload.proof_type,
        payload.proof_reference,
        payload.scope_notes,
        payload.expires_at,
    )
    return AuthorizationScopeRead.model_validate(scope)


@router.get(
    "",
    response_model=AuthorizationScopeRead,
    dependencies=[Depends(require_permission("target:read"))],
)
async def read_current_scope(
    project_id: uuid.UUID, target_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> AuthorizationScopeRead:
    scope = await service.get_current_scope(db, ctx.workspace_id, project_id, target_id)
    return AuthorizationScopeRead.model_validate(scope)


@router.post(
    "/verify",
    response_model=AuthorizationScopeRead,
    dependencies=[Depends(require_permission("authorization_scope:verify"))],
)
async def verify_scope(
    project_id: uuid.UUID, target_id: uuid.UUID, payload: AuthorizationScopeVerify, db: DbDep, ctx: WorkspaceContextDep
) -> AuthorizationScopeRead:
    scope = await service.verify_scope(
        db,
        ctx.workspace_id,
        project_id,
        target_id,
        ctx.member.user_id,
        payload.active_testing_allowed,
        payload.expires_at,
        payload.scope_notes,
    )
    return AuthorizationScopeRead.model_validate(scope)
