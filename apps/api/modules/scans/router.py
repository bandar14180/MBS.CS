import uuid

from fastapi import APIRouter, Depends, Response, status

from apps.api.core.deps import CurrentUserDep, DbDep, WorkspaceContextDep, require_permission
from apps.api.core.pagination import PaginationDep, set_page_headers
from apps.api.modules.attack import service as attack_service
from apps.api.modules.attack.schemas import KillChainRead, TacticMatrixRead
from apps.api.modules.scans import service
from apps.api.modules.scans.schemas import AIPlanRead, EvidenceRead, ScanCreate, ScanRead, ToolRunRead

router = APIRouter(prefix="/workspaces/{workspace_id}/projects/{project_id}/scans", tags=["scans"])

# Scanner capabilities are global (not tenant-specific): which target types can
# actually be scanned + which tools run for each. Lets clients avoid submitting a
# target type that has no engine (no hollow scans).
capabilities_router = APIRouter(prefix="/scan-capabilities", tags=["scans"])


@capabilities_router.get("")
async def get_scan_capabilities(current_user: CurrentUserDep) -> dict:
    from apps.api.scanner_engine.capabilities import capability_map

    return capability_map()


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
        payload.use_ai_planner,
        payload.use_agent,
        payload.exploitation_enabled,
        payload.approved_hosts,
    )
    return ScanRead.model_validate(scan)


@router.get(
    "",
    response_model=list[ScanRead],
    dependencies=[Depends(require_permission("scan:read"))],
)
async def list_scans(
    project_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep, response: Response, page: PaginationDep
) -> list[ScanRead]:
    scans, total = await service.list_scans(db, ctx.workspace_id, project_id, page)
    set_page_headers(response, total=total, page=page)
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


@router.get(
    "/{scan_id}/attack-matrix",
    response_model=list[TacticMatrixRead],
    dependencies=[Depends(require_permission("scan:read"))],
)
async def get_attack_matrix(
    project_id: uuid.UUID, scan_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> list[TacticMatrixRead]:
    """MITRE ATT&CK coverage for this scan: tactics -> techniques with hit counts."""
    await service.get_scan(db, ctx.workspace_id, project_id, scan_id)  # 404s if not in scope
    matrix = await attack_service.attack_matrix_for_scan(db, scan_id)
    return [TacticMatrixRead.model_validate(t) for t in matrix]


@router.get(
    "/{scan_id}/kill-chain",
    response_model=KillChainRead,
    dependencies=[Depends(require_permission("scan:read"))],
)
async def get_kill_chain(
    project_id: uuid.UUID, scan_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> KillChainRead:
    """The scan's Cyber Kill Chain view -- the AI Correlator's attack-path
    narrative when available, else the deterministic mapping."""
    await service.get_scan(db, ctx.workspace_id, project_id, scan_id)  # 404s if not in scope
    return KillChainRead.model_validate(await attack_service.kill_chain_for_scan(db, scan_id))
