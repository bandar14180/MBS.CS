from datetime import date

from fastapi import APIRouter, Depends, Query

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.modules.ai_usage import service
from apps.api.modules.ai_usage.schemas import AIUsageReport

# AI-2.2B-2: workspace-scoped AI cost report. Mounted under /workspaces/{workspace_id}/... so
# WorkspaceContextDep binds the workspace + verifies membership; workspace:view gates access (cost
# aggregates are provider/model/token/cost only -- no prompts/findings/secrets).
router = APIRouter(prefix="/workspaces/{workspace_id}/ai-usage", tags=["ai-usage"])


@router.get("", response_model=AIUsageReport, dependencies=[Depends(require_permission("workspace:view"))])
async def get_ai_usage(
    db: DbDep,
    ctx: WorkspaceContextDep,
    from_date: date | None = Query(default=None, alias="from"),
    to_date: date | None = Query(default=None, alias="to"),
) -> AIUsageReport:
    """AI spend for this workspace over a date range (default: last 30 days). Metadata only."""
    return await service.get_usage_report(db, ctx.workspace_id, from_date, to_date)
