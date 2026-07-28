import uuid

from fastapi import APIRouter, Depends, status

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.modules.api_keys import service
from apps.api.modules.api_keys.schemas import ApiKeyCreate, ApiKeyCreated, ApiKeyRead

# API keys are sensitive -> owner/admin only (workspace:manage).
router = APIRouter(prefix="/workspaces/{workspace_id}/api-keys", tags=["api-keys"])


@router.post(
    "",
    response_model=ApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("workspace:manage"))],
)
async def create_api_key(payload: ApiKeyCreate, db: DbDep, ctx: WorkspaceContextDep) -> ApiKeyCreated:
    key, secret = await service.create_key(db, ctx.workspace_id, ctx.member.user_id, payload.name)
    return ApiKeyCreated(**ApiKeyRead.model_validate(key).model_dump(), secret=secret)


@router.get("", response_model=list[ApiKeyRead], dependencies=[Depends(require_permission("workspace:manage"))])
async def list_api_keys(db: DbDep, ctx: WorkspaceContextDep) -> list[ApiKeyRead]:
    keys = await service.list_keys(db, ctx.workspace_id)
    return [ApiKeyRead.model_validate(k) for k in keys]


@router.delete(
    "/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("workspace:manage"))],
)
async def revoke_api_key(key_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep) -> None:
    await service.revoke_key(db, ctx.workspace_id, key_id)
