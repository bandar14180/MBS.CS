import uuid

from fastapi import APIRouter, Depends, Response, status

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.core.pagination import PaginationDep, set_page_headers
from apps.api.modules.reports import service
from apps.api.modules.reports.schemas import ReportCreate, ReportRead

router = APIRouter(prefix="/workspaces/{workspace_id}/projects/{project_id}/reports", tags=["reports"])


@router.post(
    "",
    response_model=ReportRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("report:create"))],
)
async def create_report(
    project_id: uuid.UUID, payload: ReportCreate, db: DbDep, ctx: WorkspaceContextDep
) -> ReportRead:
    report = await service.create_report(
        db,
        ctx.workspace_id,
        project_id,
        payload.type,
        [str(s) for s in payload.scan_ids],
        ctx.member.user_id,
    )
    return ReportRead.model_validate(report)


@router.get(
    "",
    response_model=list[ReportRead],
    dependencies=[Depends(require_permission("report:read"))],
)
async def list_reports(
    project_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep, response: Response, page: PaginationDep
) -> list[ReportRead]:
    reports, total = await service.list_reports(db, ctx.workspace_id, project_id, page)
    set_page_headers(response, total=total, page=page)
    return [ReportRead.model_validate(r) for r in reports]


@router.get(
    "/{report_id}/download",
    dependencies=[Depends(require_permission("report:read"))],
)
async def download_report(
    project_id: uuid.UUID, report_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> Response:
    content, filename = await service.download_report(db, ctx.workspace_id, project_id, report_id)
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
