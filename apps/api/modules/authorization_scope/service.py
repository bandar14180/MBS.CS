import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.authorization_scope.models import AuthorizationScope
from apps.api.modules.projects.service import get_target


async def submit_scope(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    target_id: uuid.UUID,
    proof_type: str,
    proof_reference: str,
    scope_notes: str | None,
    expires_at: datetime | None,
) -> AuthorizationScope:
    await get_target(db, workspace_id, project_id, target_id)  # 404s if target isn't in this project/workspace

    # A fresh, unverified row every time -- re-submission (e.g. after a rejection
    # or expiry) never mutates history, and `verified` always starts False here:
    # only the /verify step (a separate permission) can flip it.
    scope = AuthorizationScope(
        target_id=target_id,
        proof_type=proof_type,
        proof_reference=proof_reference,
        scope_notes=scope_notes,
        expires_at=expires_at,
    )
    db.add(scope)
    await db.commit()
    await db.refresh(scope)
    return scope


async def get_current_scope(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, target_id: uuid.UUID
) -> AuthorizationScope:
    await get_target(db, workspace_id, project_id, target_id)

    scope = await db.scalar(
        select(AuthorizationScope)
        .where(AuthorizationScope.target_id == target_id)
        .order_by(AuthorizationScope.created_at.desc())
        .limit(1)
    )
    if scope is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No authorization scope submitted for this target")
    return scope


async def require_verified_target(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, target_id: uuid.UUID
) -> AuthorizationScope:
    """The guardrail from blueprint §7 step 1: 'Orchestrator confirms
    authorization_scope.verified == true -- if not verified: scan creation is
    blocked at the API layer (403), not just a warning.' Called both at scan
    creation (HTTP request) and again at execution time (orchestrator, right
    before a tool actually runs) since authorization can be revoked in between.
    """
    from apps.api.core.config import get_settings

    # Unconditional short-circuit: this must override an EXISTING scope too, not just fill in
    # a missing/unverified/expired one -- a target manually verified earlier with "allow active
    # testing" left unchecked (the checkbox's default) would otherwise still block nuclei/etc.
    # even with the escape hatch on, which defeats the point of it for local development.
    if get_settings().dev_auto_authorize_targets:
        return await _dev_auto_authorize(db, target_id)

    try:
        scope = await get_current_scope(db, workspace_id, project_id, target_id)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "No authorization scope has been submitted for this target"
            )
        raise

    expired = scope.expires_at is not None and scope.expires_at < datetime.now(timezone.utc)

    if not scope.verified:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This target's authorization scope is not verified")

    if expired:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This target's authorization scope has expired")

    return scope


async def _dev_auto_authorize(db: AsyncSession, target_id: uuid.UUID) -> AuthorizationScope:
    """DEV_AUTO_AUTHORIZE_TARGETS escape hatch (local development only; refused at startup
    in production -- see Settings.validate_production). Creates, or updates, a verified,
    active-testing-allowed authorization scope for `target_id` on the fly -- see the flag's
    docstring in core/config.py. Reuses the latest existing row (if any) rather than always
    inserting a new one, so re-running a dev scan doesn't pile up scope history."""
    scope = await db.scalar(
        select(AuthorizationScope)
        .where(AuthorizationScope.target_id == target_id)
        .order_by(AuthorizationScope.created_at.desc())
        .limit(1)
    )
    if scope is None:
        scope = AuthorizationScope(
            target_id=target_id, proof_type="dev_auto", proof_reference="DEV_AUTO_AUTHORIZE_TARGETS"
        )
        db.add(scope)
    scope.verified = True
    scope.verified_at = datetime.now(timezone.utc)
    scope.active_testing_allowed = True
    scope.expires_at = None
    await db.commit()
    await db.refresh(scope)
    return scope


async def verify_scope(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    target_id: uuid.UUID,
    verifier_id: uuid.UUID,
    active_testing_allowed: bool,
    expires_at: datetime | None,
    scope_notes: str | None,
) -> AuthorizationScope:
    scope = await get_current_scope(db, workspace_id, project_id, target_id)

    scope.verified = True
    scope.verified_by = verifier_id
    scope.verified_at = datetime.now(timezone.utc)
    scope.active_testing_allowed = active_testing_allowed
    if expires_at is not None:
        scope.expires_at = expires_at
    if scope_notes is not None:
        scope.scope_notes = scope_notes

    await db.commit()
    await db.refresh(scope)
    return scope
