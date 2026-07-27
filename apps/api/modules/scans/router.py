import uuid

from fastapi import APIRouter, Depends, status

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.modules.scans import service
from apps.api.modules.scans.schemas import AIPlanRead, EvidenceRead, ScanCreate, ScanRead, ToolRunRead

router = APIRouter(prefix="/workspaces/{workspace_id}/projects/{project_id}/scans", tags=["scans"])


@router.post(
    "",
    response_model=ScanRead,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_permission("scan:create"))],
)
async def create_scan(project_id: uuid.UUID, payload: ScanCreate, db: DbDep, ctx: WorkspaceContextDep) -> ScanRead:
    scan = await service.create_scan(
        db,
        ctx.workspace_id,
        project_id,
        ctx.member.user_id,
        payload.target_id,
        payload.scan_type,
        payload.requested_modules,
    )
    return ScanRead.model_validate(scan)


@router.get(
    "",
    response_model=list[ScanRead],
    dependencies=[Depends(require_permission("scan:read"))],
)
async def list_scans(project_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep) -> list[ScanRead]:
    scans = await service.list_scans(db, ctx.workspace_id, project_id)
    return [ScanRead.model_validate(s) for s in scans]


@router.get(
    "/{scan_id}",
    response_model=ScanRead,
    dependencies=[Depends(require_permission("scan:read"))],
)
async def get_scan(project_id: uuid.UUID, scan_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep) -> ScanRead:
    scan = await service.get_scan(db, ctx.workspace_id, project_id, scan_id)
    return ScanRead.model_validate(scan)


@router.post(
    "/{scan_id}/cancel",
    response_model=ScanRead,
    dependencies=[Depends(require_permission("scan:create"))],
)
async def cancel_scan(project_id: uuid.UUID, scan_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep) -> ScanRead:
    scan = await service.cancel_scan(db, ctx.workspace_id, project_id, scan_id)
    return ScanRead.model_validate(scan)


@router.get(
    "/{scan_id}/tool-runs",
    response_model=list[ToolRunRead],
    dependencies=[Depends(require_permission("scan:read"))],
)
async def list_tool_runs(project_id: uuid.UUID, scan_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep) -> list[ToolRunRead]:
    runs = await service.list_tool_runs(db, ctx.workspace_id, project_id, scan_id)
    return [ToolRunRead.model_validate(r) for r in runs]


@router.get(
    "/{scan_id}/tool-runs/{tool_run_id}/evidence",
    response_model=list[EvidenceRead],
    dependencies=[Depends(require_permission("scan:read"))],
)
async def list_evidence(
    project_id: uuid.UUID, scan_id: uuid.UUID, tool_run_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> list[EvidenceRead]:
    evidence = await service.list_evidence(db, ctx.workspace_id, project_id, scan_id, tool_run_id)
    return [EvidenceRead.model_validate(e) for e in evidence]


@router.get(
    "/{scan_id}/ai-plan",
    response_model=AIPlanRead,
    dependencies=[Depends(require_permission("scan:read"))],
)
async def get_ai_plan(project_id: uuid.UUID, scan_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep) -> AIPlanRead:
    plan = await service.get_ai_plan(db, ctx.workspace_id, project_id, scan_id)
    return AIPlanRead.model_validate(plan)
