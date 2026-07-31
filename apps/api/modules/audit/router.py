from fastapi import APIRouter, Depends, Query, Response

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.core.pagination import PaginationDep, set_page_headers
from apps.api.modules.audit import service
from apps.api.modules.audit.schemas import AuditEventRead

# Audit is sensitive -> owner/admin only (workspace:manage).
router = APIRouter(prefix="/workspaces/{workspace_id}/audit", tags=["audit"])


@router.get("", response_model=list[AuditEventRead], dependencies=[Depends(require_permission("workspace:manage"))])
async def list_audit(
    db: DbDep, ctx: WorkspaceContextDep, response: Response, page: PaginationDep, action: str | None = Query(default=None)
) -> list[AuditEventRead]:
    events, total = await service.list_events(db, ctx.workspace_id, action=action, page=page)
    set_page_headers(response, total=total, page=page)
    return [AuditEventRead.model_validate(e) for e in events]
