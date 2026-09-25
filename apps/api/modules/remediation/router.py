"""Remediation workflow API.

AUTHORIZATION, at a glance -- every route below declares exactly one permission:
  * `remediation:read`   -- list/detail/timeline/evidence/verification/progress. Held by
                            owner, admin, member AND client_viewer.
  * `remediation:manage` -- create/update/transition/upload evidence/request verification.
                            Held by owner, admin, member. NOT client_viewer.
  * `risk:accept`        -- accept or revoke a risk acceptance. Owner and admin ONLY;
                            explicitly withheld from member and client_viewer.

Scope always comes from the PATH (`/workspaces/{workspace_id}/projects/{project_id}/...`), which
`get_workspace_context` resolves and binds; no handler reads a workspace/project id from a body.
"""

import uuid

from fastapi import APIRouter, Depends, Query, Response, status as http_status

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.core.pagination import PaginationDep, set_page_headers
from apps.api.modules.remediation import (
    evidence_confidence,
    evidence_service,
    risk_service,
    service,
    verification,
)
from apps.api.modules.remediation.schemas import (
    EvidenceConfidence,
    RemediationEventRead,
    RemediationEvidenceCreate,
    RemediationEvidenceRead,
    RemediationItemRead,
    RemediationItemUpdate,
    RemediationProgressRead,
    RemediationTransition,
    RiskAcceptanceCreate,
    RiskAcceptanceRead,
    RiskAcceptanceRevoke,
    VerificationRequestCreate,
    VerificationRequestRead,
)

router = APIRouter(
    prefix="/workspaces/{workspace_id}/projects/{project_id}/remediation", tags=["remediation"]
)


async def _read_with_confidence(db, item) -> RemediationItemRead:
    """RemediationItemRead plus its best-effort evidence_confidence block (Prompt 13,
    Finding #6). A classification failure must never break reading the item itself -- the
    workflow status is authoritative and always present regardless."""
    read = RemediationItemRead.model_validate(item)
    try:
        conf = await evidence_confidence.evidence_confidence_for_item(db, item)
    except Exception:  # noqa: BLE001 -- best-effort enrichment, see docstring
        conf = None
    read.evidence_confidence = EvidenceConfidence(**conf) if conf is not None else None
    return read


@router.get(
    "",
    response_model=list[RemediationItemRead],
    dependencies=[Depends(require_permission("remediation:read"))],
)
async def list_items(
    project_id: uuid.UUID,
    db: DbDep,
    ctx: WorkspaceContextDep,
    response: Response,
    page: PaginationDep,
    status: str | None = Query(default=None),
    priority: str | None = Query(default=None),
    assignee_user_id: uuid.UUID | None = Query(default=None),
    overdue: bool | None = Query(default=None),
) -> list[RemediationItemRead]:
    items, total = await service.list_items(
        db, ctx.workspace_id, project_id,
        status_filter=status, priority=priority, assignee_user_id=assignee_user_id,
        overdue=overdue, page=page,
    )
    set_page_headers(response, total=total, page=page)
    return [await _read_with_confidence(db, i) for i in items]


@router.post(
    "/sync",
    response_model=list[RemediationItemRead],
    status_code=http_status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("remediation:manage"))],
)
async def sync_items(
    project_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> list[RemediationItemRead]:
    """Create a remediation item for every scorable issue that lacks one. Idempotent: existing
    items (and their human-owned status/owner/due date/notes) are never modified."""
    created = await service.sync_items_for_project(db, ctx.workspace_id, project_id, ctx.member.user_id)
    return [RemediationItemRead.model_validate(i) for i in created]


@router.get(
    "/progress",
    response_model=RemediationProgressRead,
    dependencies=[Depends(require_permission("remediation:read"))],
)
async def get_progress(
    project_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> RemediationProgressRead:
    return RemediationProgressRead(
        **await service.progress_for_project(db, ctx.workspace_id, project_id)
    )


# --- risk treatment (separate permission) ----------------------------------------------------

@router.post(
    "/risk-acceptances",
    response_model=RiskAcceptanceRead,
    status_code=http_status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("risk:accept"))],
)
async def accept_risk(
    project_id: uuid.UUID, payload: RiskAcceptanceCreate, db: DbDep, ctx: WorkspaceContextDep
) -> RiskAcceptanceRead:
    acceptance = await risk_service.accept_risk(
        db, ctx.workspace_id, project_id, payload.vulnerability_id, ctx.member.user_id,
        payload.justification, payload.expires_at,
        review_due_at=payload.review_due_at,
        approved_by=payload.approved_by,
        remediation_item_id=payload.remediation_item_id,
        expected_version=payload.version,
    )
    return RiskAcceptanceRead.model_validate(acceptance)


@router.get(
    "/risk-acceptances",
    response_model=list[RiskAcceptanceRead],
    dependencies=[Depends(require_permission("remediation:read"))],
)
async def list_risk_acceptances(
    project_id: uuid.UUID,
    db: DbDep,
    ctx: WorkspaceContextDep,
    vulnerability_id: uuid.UUID | None = Query(default=None),
    status: str | None = Query(default=None),
) -> list[RiskAcceptanceRead]:
    """READING acceptances needs only `remediation:read` -- a client viewer must be able to see
    which risks their organisation has accepted. GRANTING one needs `risk:accept`."""
    rows = await risk_service.list_acceptances(
        db, ctx.workspace_id, project_id, vulnerability_id=vulnerability_id, status_filter=status
    )
    return [RiskAcceptanceRead.model_validate(r) for r in rows]


@router.post(
    "/risk-acceptances/{acceptance_id}/revoke",
    response_model=RiskAcceptanceRead,
    dependencies=[Depends(require_permission("risk:accept"))],
)
async def revoke_risk_acceptance(
    project_id: uuid.UUID,
    acceptance_id: uuid.UUID,
    payload: RiskAcceptanceRevoke,
    db: DbDep,
    ctx: WorkspaceContextDep,
) -> RiskAcceptanceRead:
    acceptance = await risk_service.revoke_risk_acceptance(
        db, ctx.workspace_id, project_id, acceptance_id, ctx.member.user_id, payload.reason
    )
    return RiskAcceptanceRead.model_validate(acceptance)


# --- item-scoped routes -----------------------------------------------------------------
# Declared AFTER every literal-prefix route above. FastAPI matches in declaration order, so
# a `/{item_id}` route declared first would swallow `/risk-acceptances` and reject it with a
# 422 (the literal is not a UUID). Ordering, not a path change, is the fix.
@router.get(
    "/{item_id}",
    response_model=RemediationItemRead,
    dependencies=[Depends(require_permission("remediation:read"))],
)
async def get_item(
    project_id: uuid.UUID, item_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> RemediationItemRead:
    item = await service.get_item(db, ctx.workspace_id, project_id, item_id)
    return await _read_with_confidence(db, item)


@router.patch(
    "/{item_id}",
    response_model=RemediationItemRead,
    dependencies=[Depends(require_permission("remediation:manage"))],
)
async def update_item(
    project_id: uuid.UUID,
    item_id: uuid.UUID,
    payload: RemediationItemUpdate,
    db: DbDep,
    ctx: WorkspaceContextDep,
) -> RemediationItemRead:
    item = await service.update_item(
        db, ctx.workspace_id, project_id, item_id, ctx.member.user_id, payload.version,
        assignee_user_id=payload.assignee_user_id,
        clear_assignee=payload.clear_assignee,
        due_date=payload.due_date,
        clear_due_date=payload.clear_due_date,
        priority=payload.priority,
        notes=payload.notes,
    )
    return RemediationItemRead.model_validate(item)


@router.post(
    "/{item_id}/transition",
    response_model=RemediationItemRead,
    dependencies=[Depends(require_permission("remediation:manage"))],
)
async def transition_item(
    project_id: uuid.UUID,
    item_id: uuid.UUID,
    payload: RemediationTransition,
    db: DbDep,
    ctx: WorkspaceContextDep,
) -> RemediationItemRead:
    item = await service.transition(
        db, ctx.workspace_id, project_id, item_id, ctx.member.user_id,
        payload.version, payload.to_status, detail=payload.detail,
    )
    return RemediationItemRead.model_validate(item)


@router.get(
    "/{item_id}/events",
    response_model=list[RemediationEventRead],
    dependencies=[Depends(require_permission("remediation:read"))],
)
async def list_events(
    project_id: uuid.UUID, item_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> list[RemediationEventRead]:
    """The item's immutable timeline. READ ONLY -- there is deliberately no PATCH or DELETE
    route for an event anywhere in this API."""
    events = await service.list_events(db, ctx.workspace_id, project_id, item_id)
    return [RemediationEventRead.model_validate(e) for e in events]


@router.get(
    "/{item_id}/evidence",
    response_model=list[RemediationEvidenceRead],
    dependencies=[Depends(require_permission("remediation:read"))],
)
async def list_evidence(
    project_id: uuid.UUID, item_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> list[RemediationEvidenceRead]:
    rows = await evidence_service.list_remediation_evidence(db, ctx.workspace_id, project_id, item_id)
    return [RemediationEvidenceRead.model_validate(e) for e in rows]


@router.post(
    "/{item_id}/evidence",
    response_model=RemediationEvidenceRead,
    status_code=http_status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("remediation:manage"))],
)
async def upload_evidence(
    project_id: uuid.UUID,
    item_id: uuid.UUID,
    payload: RemediationEvidenceCreate,
    db: DbDep,
    ctx: WorkspaceContextDep,
) -> RemediationEvidenceRead:
    """Attach proof of remediation WORK.

    JSON with base64 content rather than a multipart upload: every other endpoint in this API
    is JSON, and multipart would require adding `python-multipart` -- a new runtime dependency
    for one endpoint, which this scope does not justify. The payload model decodes and
    validates the base64 itself (see RemediationEvidenceCreate.content_bytes).

    Note what this does NOT do: it never transitions the item, and it is never accepted as
    technical proof that the vulnerability is gone -- only a retest establishes that."""
    evidence = await evidence_service.add_remediation_evidence(
        db, ctx.workspace_id, project_id, item_id, ctx.member.user_id,
        payload.filename, payload.content_bytes(), payload.content_type,
    )
    return RemediationEvidenceRead.model_validate(evidence)


@router.post(
    "/{item_id}/verification",
    response_model=VerificationRequestRead,
    status_code=http_status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("remediation:manage"))],
)
async def request_verification(
    project_id: uuid.UUID,
    item_id: uuid.UUID,
    payload: VerificationRequestCreate,
    db: DbDep,
    ctx: WorkspaceContextDep,
) -> VerificationRequestRead:
    request = await verification.request_verification(
        db, ctx.workspace_id, project_id, item_id, ctx.member.user_id,
        payload.version, scan_id=payload.scan_id,
    )
    return VerificationRequestRead.model_validate(request)


@router.get(
    "/{item_id}/verification",
    response_model=list[VerificationRequestRead],
    dependencies=[Depends(require_permission("remediation:read"))],
)
async def list_verifications(
    project_id: uuid.UUID, item_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> list[VerificationRequestRead]:
    rows = await verification.list_verification_requests(db, ctx.workspace_id, project_id, item_id)
    return [VerificationRequestRead.model_validate(r) for r in rows]


@router.post(
    "/verification/{request_id}/complete",
    response_model=VerificationRequestRead,
    dependencies=[Depends(require_permission("remediation:manage"))],
)
async def complete_verification(
    project_id: uuid.UUID, request_id: uuid.UUID, db: DbDep, ctx: WorkspaceContextDep
) -> VerificationRequestRead:
    """Evaluate the linked retest and apply its outcome.

    THE BODY IS EMPTY, deliberately: there is no field a caller could set to declare the
    result. The outcome is derived from what the retest scan actually observed for this
    issue -- see verification.complete_verification."""
    request = await verification.complete_verification(
        db, ctx.workspace_id, request_id, actor_user_id=ctx.member.user_id
    )
    return VerificationRequestRead.model_validate(request)
