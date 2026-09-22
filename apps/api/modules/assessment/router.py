"""Client Risk Assessment API.

Permissions:
  * `risk_assessment:read`   -- list/detail/findings/comparison/preview. Owner, admin, member
                                AND client_viewer (this is the client-facing deliverable).
  * `risk_assessment:manage` -- create a draft and issue it. Owner and admin only: issuing is
                                publishing a client-facing document and freezing it forever.

There is no update or delete route. An issued assessment is immutable, and a draft is cheap to
replace -- so no endpoint exists that could mutate a frozen snapshot.
"""

import uuid

from fastapi import APIRouter, Depends, Response, status as http_status

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.core.pagination import PaginationDep, set_page_headers
from apps.api.modules.assessment import service
from apps.api.modules.assessment.schemas import (
    AssessmentComparisonRead,
    AssessmentCreate,
    AssessmentFindingRead,
    AssessmentRead,
)

router = APIRouter(
    prefix="/workspaces/{workspace_id}/projects/{project_id}/risk-assessments",
    tags=["risk-assessments"],
)


@router.get(
    "",
    response_model=list[AssessmentRead],
    dependencies=[Depends(require_permission("risk_assessment:read"))],
)
async def list_assessments(
    project_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep, response: Response, page: PaginationDep
) -> list[AssessmentRead]:
    items, total = await service.list_assessments(db, ctx.workspace_id, project_id, page)
    set_page_headers(response, total=total, page=page)
    return [AssessmentRead.model_validate(a) for a in items]


@router.get(
    "/preview",
    dependencies=[Depends(require_permission("risk_assessment:read"))],
)
async def preview(project_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep) -> dict:
    """What an assessment issued right now would say. Read-only -- writes nothing, freezes
    nothing, so it can be polled from the draft screen safely."""
    return await service.preview_snapshot(db, ctx.workspace_id, project_id)


@router.post(
    "",
    response_model=AssessmentRead,
    status_code=http_status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("risk_assessment:manage"))],
)
async def create_assessment(
    project_id: uuid.UUID, payload: AssessmentCreate, db: DbDep, ctx: WorkspaceContextDep
) -> AssessmentRead:
    assessment = await service.create_assessment(
        db, ctx.workspace_id, project_id, ctx.member.user_id,
        payload.title, payload.period_start, payload.period_end,
    )
    return AssessmentRead.model_validate(assessment)


@router.get(
    "/{assessment_id}",
    response_model=AssessmentRead,
    dependencies=[Depends(require_permission("risk_assessment:read"))],
)
async def get_assessment(
    project_id: uuid.UUID, assessment_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> AssessmentRead:
    assessment = await service.get_assessment(db, ctx.workspace_id, project_id, assessment_id)
    return AssessmentRead.model_validate(assessment)


@router.post(
    "/{assessment_id}/issue",
    response_model=AssessmentRead,
    dependencies=[Depends(require_permission("risk_assessment:manage"))],
)
async def issue_assessment(
    project_id: uuid.UUID, assessment_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> AssessmentRead:
    """Freeze the snapshot and publish. IRREVERSIBLE: re-issuing an already-issued assessment
    is a 409, because a client-facing document that can be silently restated is worthless."""
    assessment = await service.issue_assessment(
        db, ctx.workspace_id, project_id, assessment_id, ctx.member.user_id
    )
    return AssessmentRead.model_validate(assessment)


@router.get(
    "/{assessment_id}/findings",
    response_model=list[AssessmentFindingRead],
    dependencies=[Depends(require_permission("risk_assessment:read"))],
)
async def list_findings(
    project_id: uuid.UUID, assessment_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> list[AssessmentFindingRead]:
    rows = await service.list_findings(db, ctx.workspace_id, project_id, assessment_id)
    return [AssessmentFindingRead.model_validate(f) for f in rows]


@router.get(
    "/{assessment_id}/comparison",
    response_model=AssessmentComparisonRead,
    dependencies=[Depends(require_permission("risk_assessment:read"))],
)
async def get_comparison(
    project_id: uuid.UUID, assessment_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> AssessmentComparisonRead:
    """Trend against this assessment's recorded predecessor -- snapshot to snapshot, never
    against mutable live state."""
    return AssessmentComparisonRead(
        **await service.comparison_for(db, ctx.workspace_id, project_id, assessment_id)
    )
