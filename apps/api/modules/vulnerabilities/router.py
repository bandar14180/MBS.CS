import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status as http_status
from starlette.responses import Response

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.core.pagination import PaginationDep, set_page_headers
from apps.api.modules.attack import service as attack_service
from apps.api.modules.attack.schemas import AttackMappingRead
from apps.api.modules.compliance import service as compliance_service
from apps.api.modules.compliance.schemas import ComplianceMappingRead
from apps.api.modules.risk import service as risk_service
from apps.api.modules.risk.schemas import RiskScoreRead
from apps.api.modules.vulnerabilities import ai_service, service
from apps.api.modules.vulnerabilities.schemas import (
    FPAnalysisRead,
    FPAssessmentRead,
    RemediationRead,
    VulnerabilityRead,
    VulnerabilityStatusUpdate,
)

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
    response: Response,
    page: PaginationDep,
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
) -> list[VulnerabilityRead]:
    vulns, total = await service.list_vulnerabilities(db, ctx.workspace_id, project_id, severity, status, page)
    set_page_headers(response, total=total, page=page)
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


@router.get(
    "/vulnerabilities/{vuln_id}/risk",
    response_model=RiskScoreRead,
    dependencies=[Depends(require_permission("vulnerability:read"))],
)
async def get_risk(project_id: uuid.UUID, vuln_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep) -> RiskScoreRead:
    # 404s if the vuln isn't in this workspace/project (tenancy.py's filter + explicit check)
    await service.get_vulnerability(db, ctx.workspace_id, project_id, vuln_id)
    risk = await risk_service.get_risk_score(db, vuln_id)
    if risk is None:
        raise HTTPException(http_status.HTTP_404_NOT_FOUND, "No risk score computed for this vulnerability")
    return RiskScoreRead.model_validate(risk)


@router.get(
    "/vulnerabilities/{vuln_id}/compliance-mappings",
    response_model=list[ComplianceMappingRead],
    dependencies=[Depends(require_permission("vulnerability:read"))],
)
async def get_compliance_mappings(
    project_id: uuid.UUID, vuln_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> list[ComplianceMappingRead]:
    await service.get_vulnerability(db, ctx.workspace_id, project_id, vuln_id)
    mappings = await compliance_service.list_mappings(db, vuln_id)
    return [ComplianceMappingRead.model_validate(m) for m in mappings]


@router.get(
    "/vulnerabilities/{vuln_id}/attack-mappings",
    response_model=list[AttackMappingRead],
    dependencies=[Depends(require_permission("vulnerability:read"))],
)
async def get_attack_mappings(
    project_id: uuid.UUID, vuln_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> list[AttackMappingRead]:
    """MITRE ATT&CK techniques + Cyber Kill Chain phases this finding maps to."""
    await service.get_vulnerability(db, ctx.workspace_id, project_id, vuln_id)
    mappings = await attack_service.list_attack_mappings(db, vuln_id)
    return [AttackMappingRead.model_validate(m) for m in mappings]


@router.get(
    "/vulnerabilities/{vuln_id}/remediation",
    response_model=RemediationRead,
    dependencies=[Depends(require_permission("vulnerability:read"))],
)
async def get_remediation(
    project_id: uuid.UUID, vuln_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> RemediationRead:
    rem = await ai_service.get_remediation(db, ctx.workspace_id, project_id, vuln_id)
    return RemediationRead.model_validate(rem)


@router.post(
    "/vulnerabilities/{vuln_id}/remediation",
    response_model=RemediationRead,
    status_code=http_status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("vulnerability:manage"))],
)
async def generate_remediation(
    project_id: uuid.UUID, vuln_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> RemediationRead:
    rem = await ai_service.generate_remediation(db, ctx.workspace_id, project_id, vuln_id)
    return RemediationRead.model_validate(rem)


@router.post(
    "/vulnerabilities/fp-analysis",
    response_model=FPAnalysisRead,
    dependencies=[Depends(require_permission("vulnerability:manage"))],
)
async def fp_analysis(project_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep) -> FPAnalysisRead:
    result = await ai_service.fp_analysis(db, ctx.workspace_id, project_id)
    return FPAnalysisRead(
        model_version=result.model_version,
        prompt_version=result.prompt_version,
        # AUDIT-013: build the declared model rather than a bare dict, so the response type is
        # actually checked instead of relying on pydantic coercing an untyped dict.
        assessments=[
            FPAssessmentRead(**{
                "finding_id": a.finding_id,
                "likely_false_positive": a.likely_false_positive,
                "confidence": a.confidence,
                "reasoning": a.reasoning,
            })
            for a in result.assessments
        ],
    )
