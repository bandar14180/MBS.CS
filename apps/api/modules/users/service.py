"""User self-service data-privacy operations (Data Privacy Hardening).

Two data-subject rights, both operating on the authenticated user only:

  * export_user_data -- GDPR Art. 15/20 access & portability. Returns the personal
    data we hold, as structured metadata. NEVER includes a secret or a hash
    (password_hash, mfa_secret_encrypted, api-key/refresh-token hashes are excluded).

  * erase_user -- GDPR Art. 17 erasure. Implemented as crypto-shred / anonymization
    rather than a physical DELETE: several FKs into `users` are ondelete=RESTRICT
    (workspaces.owner, scans/projects/schedules.created_by), so a row delete would be
    blocked, and the audit trail must survive for compliance. Instead we scrub the
    PII on the user row, purge credentials, revoke API keys, and anonymize the
    denormalized `audit_events.actor_email`. The account can never authenticate again
    (status != "active" + unusable password), and no personal data remains.
"""
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.security import hash_password, verify_password
from apps.api.modules.api_keys.models import ApiKey
from apps.api.modules.audit.models import AuditEvent
from apps.api.modules.auth.mfa_guard import security_event
from apps.api.modules.auth.models import MfaRecoveryCode, RefreshToken
from apps.api.modules.reports.models import Report
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import Role, User, WorkspaceMember
from apps.api.modules.users.schemas import (
    DataExportResponse,
    ExportedApiKey,
    ExportedAuditEvent,
    ExportedMembership,
    ExportedReport,
    ExportedScan,
    ExportProfile,
    ExportSummary,
)
from apps.api.modules.workspaces.models import Workspace

# Value written over a deleted user's denormalized email in the audit log. Non-PII,
# constant, and clearly signals an erased actor while keeping actor_user_id intact.
ANONYMIZED_ACTOR_EMAIL = "[deleted]"

# Upper bound on rows per collection in an export -- keeps a data-subject export bounded in
# memory/size. Newest-first, so the most recent activity is always included.
EXPORT_ROW_LIMIT = 5000


async def export_user_data(db: AsyncSession, user: User) -> DataExportResponse:
    """Assemble the authenticated user's personal data for export. Read-only.
    Secrets and hashes are structurally excluded (never selected into a schema)."""
    keys = list(
        await db.scalars(
            select(ApiKey).where(ApiKey.created_by == user.id).order_by(ApiKey.created_at.desc())
        )
    )
    membership_rows = (
        await db.execute(
            select(WorkspaceMember, Role, Workspace)
            .join(Role, Role.id == WorkspaceMember.role_id)
            .join(Workspace, Workspace.id == WorkspaceMember.workspace_id)
            .where(WorkspaceMember.user_id == user.id)
            .order_by(WorkspaceMember.invited_at)
        )
    ).all()

    memberships = [
        ExportedMembership(
            workspace_id=ws.id,
            workspace_name=ws.name,
            role_name=role.name,
            invited_at=member.invited_at,
            joined_at=member.joined_at,
        )
        for member, role, ws in membership_rows
    ]
    api_keys = [
        ExportedApiKey(
            name=k.name,
            prefix=k.prefix,
            revoked=k.revoked,
            created_at=k.created_at,
            last_used_at=k.last_used_at,
        )
        for k in keys
    ]

    workspace_ids = [m.workspace_id for m in memberships]
    scans = await _export_scans(db, user.id)
    reports, audit_events = await _export_rls_scoped(db, user.id, workspace_ids)

    response = DataExportResponse(
        generated_at=datetime.now(timezone.utc),
        profile=ExportProfile(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            status=user.status,
            mfa_enabled=user.mfa_enabled,
            mfa_enabled_at=user.mfa_enabled_at,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
        ),
        workspaces=memberships,
        api_keys=api_keys,
        scans=scans,
        reports=reports,
        audit_events=audit_events,
        activity_summary=ExportSummary(
            workspace_count=len(memberships),
            api_key_count=len(api_keys),
            active_api_key_count=sum(1 for k in keys if not k.revoked),
            scan_count=len(scans),
            report_count=len(reports),
            audit_event_count=len(audit_events),
            last_login_at=user.last_login_at,
        ),
    )
    # Audit the access itself (GDPR accountability). Counts only -- never the exported data.
    security_event(
        "account.exported", user_id=user.id,
        scans=len(scans), reports=len(reports), audit_events=len(audit_events),
    )
    return response


async def _export_scans(db: AsyncSession, user_id: uuid.UUID) -> list[ExportedScan]:
    """Scans the user initiated. `scans` is RLS-EXEMPT by design (worker bootstrap), so it is
    filtered explicitly by initiated_by -- returning ONLY this user's scans, never a whole
    workspace. Metadata only; scan config/evidence/tool output are never included."""
    rows = await db.scalars(
        select(Scan)
        .where(Scan.initiated_by == user_id)
        .order_by(Scan.created_at.desc())
        .limit(EXPORT_ROW_LIMIT)
    )
    return [
        ExportedScan(
            id=s.id,
            workspace_id=s.workspace_id,
            scan_type=s.scan_type,
            status=s.status,
            created_at=s.created_at,
            started_at=s.started_at,
            completed_at=s.completed_at,
        )
        for s in rows
    ]


async def _export_rls_scoped(
    db: AsyncSession, user_id: uuid.UUID, workspace_ids: list[uuid.UUID]
) -> tuple[list[ExportedReport], list[ExportedAuditEvent]]:
    """Reports the user generated + audit events where the user was the actor. Both tables are
    FORCE-RLS, so we set the workspace GUC per membership before querying (a query without the GUC
    would be RLS-filtered to zero under a non-superuser production role). Scoping to the user's own
    memberships + filtering by generated_by/actor_user_id preserves tenant isolation -- another
    tenant's data can never appear. Reports exclude storage_uri; audit events exclude free-text."""
    reports: list[ExportedReport] = []
    audit_events: list[ExportedAuditEvent] = []
    for ws_id in workspace_ids:
        await db.execute(
            text("SELECT set_config('app.current_workspace_id', :wid, true)"),
            {"wid": str(ws_id)},
        )
        rrows = await db.scalars(
            select(Report)
            .where(Report.generated_by == user_id)
            .order_by(Report.generated_at.desc())
            .limit(EXPORT_ROW_LIMIT)
        )
        for r in rrows:
            reports.append(
                ExportedReport(
                    id=r.id,
                    project_id=r.project_id,
                    type=r.type,
                    format=r.format,
                    scan_ids=[str(sid) for sid in (r.scan_ids or [])],
                    generated_at=r.generated_at,
                )
            )
        arows = await db.scalars(
            select(AuditEvent)
            .where(AuditEvent.actor_user_id == user_id)
            .order_by(AuditEvent.created_at.desc())
            .limit(EXPORT_ROW_LIMIT)
        )
        for a in arows:
            audit_events.append(
                ExportedAuditEvent(
                    id=a.id,
                    workspace_id=a.workspace_id,
                    action=a.action,
                    resource_type=a.resource_type,
                    resource_id=a.resource_id,
                    created_at=a.created_at,
                )
            )
    return reports, audit_events


async def _anonymize_audit_actor(db: AsyncSession, user_id: uuid.UUID) -> None:
    """Scrub the denormalized actor_email from this user's audit events. audit_events is
    FORCE-RLS on workspace_id, so we set the workspace GUC per membership before each
    UPDATE (a global UPDATE would be an RLS-filtered silent no-op under a non-superuser
    production role -- the same footgun retention/repo.py guards against). actor_user_id
    is deliberately left intact so the audit trail stays attributable to the (now
    anonymized) user record."""
    workspace_ids = list(
        await db.scalars(
            select(WorkspaceMember.workspace_id).where(WorkspaceMember.user_id == user_id)
        )
    )
    for ws_id in workspace_ids:
        await db.execute(
            text("SELECT set_config('app.current_workspace_id', :wid, true)"),
            {"wid": str(ws_id)},
        )
        await db.execute(
            text(
                "UPDATE audit_events SET actor_email = :anon "
                "WHERE actor_user_id = :uid AND actor_email IS NOT NULL"
            ),
            {"anon": ANONYMIZED_ACTOR_EMAIL, "uid": str(user_id)},
        )


async def erase_user(db: AsyncSession, user: User, password: str) -> None:
    """Erase the authenticated user's personal data (anonymization). Requires the
    account password as confirmation so a stolen access token alone cannot erase an
    account. Idempotent-safe: a re-run after status flips to 'deleted' is blocked at
    the auth layer (the account can no longer obtain a token)."""
    if not verify_password(password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect password")

    uid = user.id
    # 1) Anonymize the denormalized PII in the audit trail (per-workspace, RLS-scoped).
    await _anonymize_audit_actor(db, uid)
    # 2) Destroy credentials outright (user-scoped, non-RLS tables).
    await db.execute(delete(RefreshToken).where(RefreshToken.user_id == uid))
    await db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == uid))
    # 3) Revoke every API key the user created (kept for audit, but rendered unusable).
    await db.execute(update(ApiKey).where(ApiKey.created_by == uid).values(revoked=True))
    # 4) Scrub the user row itself. Email stays UNIQUE + NOT NULL via a per-id tombstone;
    #    the password is replaced with a fresh unguessable hash (never "" -- avoids a
    #    malformed-hash crash path) and MFA state is cleared.
    user.email = f"deleted+{uid}@deleted.invalid"
    user.full_name = "Deleted User"
    user.password_hash = hash_password(secrets.token_urlsafe(32))
    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    user.mfa_enabled_at = None
    user.status = "deleted"

    await db.commit()
    security_event("account.erased", user_id=uid)
