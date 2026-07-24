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
