import uuid

from fastapi import APIRouter, Depends, Response

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.core.pagination import PaginationDep, set_page_headers
from apps.api.modules.assets import service
from apps.api.modules.assets.schemas import AssetRead

router = APIRouter(prefix="/workspaces/{workspace_id}", tags=["assets"])


@router.get(
    "/projects/{project_id}/assets",
    response_model=list[AssetRead],
    dependencies=[Depends(require_permission("asset:read"))],
)
async def list_assets(
    project_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep, response: Response, page: PaginationDep
) -> list[AssetRead]:
    assets, total = await service.list_assets(db, ctx.workspace_id, project_id, page)
    set_page_headers(response, total=total, page=page)
    return [AssetRead.model_validate(a) for a in assets]


@router.get(
    "/assets/{asset_id}",
    response_model=AssetRead,
    dependencies=[Depends(require_permission("asset:read"))],
)
async def get_asset(asset_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep) -> AssetRead:
    asset = await service.get_asset(db, ctx.workspace_id, asset_id)
    return AssetRead.model_validate(asset)
