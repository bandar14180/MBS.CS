from fastapi import APIRouter, Depends

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.modules.dashboard import service
from apps.api.modules.dashboard.schemas import DashboardSummary, Recommendation

router = APIRouter(prefix="/workspaces/{workspace_id}/dashboard", tags=["dashboard"])


@router.get(
    "/summary",
    response_model=DashboardSummary,
    dependencies=[Depends(require_permission("project:read"))],
)
async def get_summary(db: DbDep, ctx: WorkspaceContextDep) -> DashboardSummary:
    return await service.get_summary(db, ctx.workspace_id)


@router.get(
    "/recommendations",
    response_model=list[Recommendation],
    dependencies=[Depends(require_permission("vulnerability:read"))],
)
async def get_recommendations(db: DbDep, ctx: WorkspaceContextDep) -> list[Recommendation]:
    return await service.get_recommendations(db, ctx.workspace_id)
