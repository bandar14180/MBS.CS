import uuid

from fastapi import APIRouter, Depends, Query

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.modules.vulnerabilities import service
from apps.api.modules.vulnerabilities.schemas import VulnerabilityRead, VulnerabilityStatusUpdate

router = APIRouter(prefix="/workspaces/{workspace_id}/projects/{project_id}", tags=["vulnerabilities"])


@router.get(
    "/vulnerabilities",
    response_model=list[VulnerabilityRead],
    dependencies=[Depends(require_permission("vulnerability:read"))],
)
async def list_vulnerabilities(
    project_id: uuid.UUID,
    db: DbDep,
    ctx: WorkspaceContextDep,
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
) -> list[VulnerabilityRead]:
    vulns = await service.list_vulnerabilities(db, ctx.workspace_id, project_id, severity, status)
    return [VulnerabilityRead.model_validate(v) for v in vulns]


@router.get(
    "/vulnerabilities/{vuln_id}",
    response_model=VulnerabilityRead,
    dependencies=[Depends(require_permission("vulnerability:read"))],
)
async def get_vulnerability(
    project_id: uuid.UUID, vuln_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> VulnerabilityRead:
    vuln = await service.get_vulnerability(db, ctx.workspace_id, project_id, vuln_id)
    return VulnerabilityRead.model_validate(vuln)


@router.patch(
    "/vulnerabilities/{vuln_id}/status",
    response_model=VulnerabilityRead,
    dependencies=[Depends(require_permission("vulnerability:manage"))],
)
async def update_status(
    project_id: uuid.UUID,
    vuln_id: uuid.UUID,
    payload: VulnerabilityStatusUpdate,
    db: DbDep,
    ctx: WorkspaceContextDep,
) -> VulnerabilityRead:
    vuln = await service.set_status(
        db, ctx.workspace_id, project_id, vuln_id, payload.status, payload.justification, ctx.member.user_id
    )
    return VulnerabilityRead.model_validate(vuln)
