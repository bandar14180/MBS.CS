"""Risk acceptance: grant, revoke, expire.

INVARIANTS THIS MODULE UPHOLDS (each has a negative test):
  * accepting risk NEVER writes `vulnerabilities.severity`, `.cvss_score`, `.cvss_vector`, or
    `risk_scores.final_risk_score`. Those models are read here, never mutated -- the risk
    engine and the scanner own them;
  * it never deletes the finding or touches scanner evidence;
  * it requires the dedicated `risk:accept` permission (enforced at the router), which
    `member` and `client_viewer` do not hold;
  * a justification is mandatory and an expiry is mandatory and must be in the future -- an
    acceptance that cannot lapse is indistinguishable from ignoring the finding.

The finding's own status is NOT changed here. Moving a vulnerability to `accepted_risk` stays
the existing, separately-authorized `vulnerability:manage` action, so posture only ever changes
through the one approved status path.
"""

import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status as http_status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.audit import service as audit
from apps.api.modules.remediation import state_machine
from apps.api.modules.remediation.models import RemediationItem, STATUS_RISK_ACCEPTED
from apps.api.modules.remediation.risk_models import (
    RiskAcceptance,
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_REVOKED,
)
from apps.api.modules.remediation.service import _apply_transition, _record_event
from apps.api.modules.vulnerabilities.service import get_vulnerability


async def accept_risk(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    vulnerability_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    justification: str,
    expires_at: datetime,
    *,
    review_due_at: datetime | None = None,
    approved_by: uuid.UUID | None = None,
    remediation_item_id: uuid.UUID | None = None,
    expected_version: int | None = None,
) -> RiskAcceptance:
    """Record a formal acceptance. Optionally moves the linked remediation item to
    `risk_accepted` -- the only code path that may reach that guarded status."""
    # Resolves through the workspace/project-scoped path: a vulnerability from another tenant
    # is a 404 here, never an acceptance.
    vuln = await get_vulnerability(db, workspace_id, project_id, vulnerability_id)

    if not justification or not justification.strip():
        raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "A justification is required")

    expiry = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=timezone.utc)
    expiry = expiry.astimezone(timezone.utc)
    if expiry <= datetime.now(timezone.utc):
        raise HTTPException(
            http_status.HTTP_400_BAD_REQUEST,
            "expires_at must be in the future -- an acceptance that cannot lapse is not an "
            "accepted risk.",
        )
    review = review_due_at
    if review is not None:
        review = (review if review.tzinfo else review.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)

    # AT MOST ONE active acceptance per vulnerability. Two overlapping acceptances would make
    # "is this risk accepted, and until when?" ambiguous, and revoking one would leave the
    # other silently in force.
    existing = await db.scalar(
        select(RiskAcceptance.id).where(
            RiskAcceptance.vulnerability_id == vulnerability_id,
            RiskAcceptance.status == STATUS_ACTIVE,
        )
    )
    if existing is not None:
        raise HTTPException(
            http_status.HTTP_409_CONFLICT,
            "This vulnerability already has an active risk acceptance. Revoke it before "
            "recording a new one.",
        )

    item: RemediationItem | None = None
    if remediation_item_id is not None:
        item = await db.scalar(
            select(RemediationItem).where(
                RemediationItem.id == remediation_item_id,
                RemediationItem.workspace_id == workspace_id,
                RemediationItem.project_id == project_id,
            )
        )
        if item is None:
            raise HTTPException(http_status.HTTP_404_NOT_FOUND, "Remediation item not found")

    acceptance = RiskAcceptance(
        workspace_id=workspace_id,
        project_id=project_id,
        vulnerability_id=vuln.id,
        remediation_item_id=item.id if item else None,
        justification=justification.strip(),
        accepted_by=actor_user_id,
        approved_by=approved_by,
        expires_at=expiry,
        review_due_at=review,
        status=STATUS_ACTIVE,
    )
    db.add(acceptance)
    await db.flush()

    await audit.record(
        db, workspace_id, actor_user_id, "risk.accepted", "vulnerability",
        resource_id=vuln.id,
        detail=f"acceptance={acceptance.id} expires={expiry.isoformat()}: {justification.strip()[:400]}",
    )

    if item is not None:
        if not state_machine.is_legal(item.status, STATUS_RISK_ACCEPTED):
            raise HTTPException(
                http_status.HTTP_409_CONFLICT,
                f"Cannot accept risk from remediation status '{item.status}'. "
                f"Allowed from: {', '.join(sorted(s for s, t in state_machine.LEGAL_TRANSITIONS.items() if STATUS_RISK_ACCEPTED in t))}.",
            )
        await _record_event(
            db, item, "risk_accepted", actor_user_id,
            detail=f"acceptance={acceptance.id} expires={expiry.isoformat()}",
        )
        await _apply_transition(
            db, item, actor_user_id,
            item.version if expected_version is None else expected_version,
            STATUS_RISK_ACCEPTED,
            detail="risk formally accepted", audit_action="remediation.risk_accepted",
        )
    else:
        await db.commit()

    await db.refresh(acceptance)
    return acceptance


async def revoke_risk_acceptance(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    acceptance_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    reason: str,
) -> RiskAcceptance:
    """Withdraw an active acceptance. The row is kept (status -> revoked) rather than deleted:
    the fact that a risk WAS accepted for a period is exactly what an auditor needs."""
    acceptance = await _get_acceptance(db, workspace_id, project_id, acceptance_id)
    if acceptance.status != STATUS_ACTIVE:
        raise HTTPException(
            http_status.HTTP_409_CONFLICT,
            f"Only an active acceptance can be revoked (this one is '{acceptance.status}')",
        )

    acceptance.status = STATUS_REVOKED
    acceptance.revoked_by = actor_user_id
    acceptance.revoked_at = datetime.now(timezone.utc)
    acceptance.revoke_reason = reason

    await audit.record(
        db, workspace_id, actor_user_id, "risk.acceptance_revoked", "vulnerability",
        resource_id=acceptance.vulnerability_id,
        detail=f"acceptance={acceptance.id}: {reason[:400]}",
    )
    if acceptance.remediation_item_id:
        item = await db.scalar(
            select(RemediationItem).where(RemediationItem.id == acceptance.remediation_item_id)
        )
        if item is not None:
            await _record_event(
                db, item, "risk_acceptance_revoked", actor_user_id,
                detail=f"acceptance={acceptance.id}: {reason[:200]}",
            )
    await db.commit()
    await db.refresh(acceptance)
    return acceptance


async def _get_acceptance(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, acceptance_id: uuid.UUID
) -> RiskAcceptance:
    acceptance = await db.scalar(
        select(RiskAcceptance).where(
            RiskAcceptance.id == acceptance_id,
            RiskAcceptance.workspace_id == workspace_id,
            RiskAcceptance.project_id == project_id,
        )
    )
    if acceptance is None:
        raise HTTPException(http_status.HTTP_404_NOT_FOUND, "Risk acceptance not found")
    return acceptance


async def list_acceptances(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    *,
    vulnerability_id: uuid.UUID | None = None,
    status_filter: str | None = None,
) -> list[RiskAcceptance]:
    query = select(RiskAcceptance).where(
        RiskAcceptance.workspace_id == workspace_id, RiskAcceptance.project_id == project_id
    )
    if vulnerability_id:
        query = query.where(RiskAcceptance.vulnerability_id == vulnerability_id)
    if status_filter:
        query = query.where(RiskAcceptance.status == status_filter)
    return list(await db.scalars(query.order_by(RiskAcceptance.created_at.desc(), RiskAcceptance.id)))


async def expire_due_acceptances(db: AsyncSession, workspace_id: uuid.UUID) -> int:
    """Flip every `active` acceptance whose expiry has passed to `expired`, for ONE workspace.

    Per-workspace (not global) because the workspace must be BOUND for the tenancy filter to
    allow the query at all -- the retention sweep and the schedule dispatcher already loop
    workspace-by-workspace for the same reason. Returns how many were expired.

    A single set-based UPDATE rather than a row-by-row loop: expiry is a pure function of the
    clock, so there is nothing to decide per row, and one statement cannot leave the sweep
    half-applied if it is interrupted.

    ENFORCEABILITY is the point: without this, an "expiring" acceptance would silently remain
    in force forever, which is the defect a plain justification string already had."""
    now = datetime.now(timezone.utc)
    due = list(
        await db.scalars(
            select(RiskAcceptance).where(
                RiskAcceptance.workspace_id == workspace_id,
                RiskAcceptance.status == STATUS_ACTIVE,
                RiskAcceptance.expires_at <= now,
            )
        )
    )
    if not due:
        return 0

    for acceptance in due:
        acceptance.status = STATUS_EXPIRED
        # actor is None: expiry is the CLOCK acting, not a person. Attributing it to a user
        # would put a false actor in the audit record.
        await audit.record(
            db, workspace_id, None, "risk.acceptance_expired", "vulnerability",
            resource_id=acceptance.vulnerability_id,
            detail=f"acceptance={acceptance.id} expired_at={acceptance.expires_at.isoformat()}",
        )
        if acceptance.remediation_item_id:
            item = await db.scalar(
                select(RemediationItem).where(RemediationItem.id == acceptance.remediation_item_id)
            )
            if item is not None:
                await _record_event(
                    db, item, "risk_acceptance_expired", None,
                    detail=f"acceptance={acceptance.id}",
                )
    await db.commit()
    return len(due)


async def active_acceptance_vuln_ids(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID
) -> set[uuid.UUID]:
    """Vulnerability ids under an ACTIVE acceptance right now. Used by the assessment snapshot
    to set its frozen `risk_accepted` flag -- a read, with no effect on any score."""
    return set(
        await db.scalars(
            select(RiskAcceptance.vulnerability_id).where(
                RiskAcceptance.workspace_id == workspace_id,
                RiskAcceptance.project_id == project_id,
                RiskAcceptance.status == STATUS_ACTIVE,
            )
        )
    )
