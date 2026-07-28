from fastapi import APIRouter, Depends

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.modules.billing import service
from apps.api.modules.billing.schemas import PlanCatalogItem, PlanUpdate, UsageRead

# Public pricing catalog (no workspace context, no auth) for marketing/pricing UIs.
public_router = APIRouter(prefix="/plans", tags=["billing"])


@public_router.get("", response_model=list[PlanCatalogItem])
async def list_plans() -> list[PlanCatalogItem]:
    return [PlanCatalogItem(**p) for p in service.plan_catalog()]


# Workspace-scoped usage + plan management.
router = APIRouter(prefix="/workspaces/{workspace_id}/billing", tags=["billing"])


@router.get("/usage", response_model=UsageRead, dependencies=[Depends(require_permission("workspace:view"))])
async def get_usage(db: DbDep, ctx: WorkspaceContextDep) -> UsageRead:
    return UsageRead(**await service.get_usage(db, ctx.workspace_id))


@router.patch("/plan", response_model=UsageRead, dependencies=[Depends(require_permission("workspace:manage"))])
async def set_plan(payload: PlanUpdate, db: DbDep, ctx: WorkspaceContextDep) -> UsageRead:
    return UsageRead(**await service.set_plan(db, ctx.workspace_id, payload.tier, ctx.member.user_id))
