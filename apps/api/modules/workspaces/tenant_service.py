"""Tenant (workspace-level) export and deletion.

DELETION is staged and retry-safe:
  active -> deleting (status gate) -> deactivate schedules + revoke running scans
         -> capture object references
         -> write DURABLE platform audit row + DELETE workspace row (one transaction)
         -> best-effort object cleanup.

Object cleanup REUSES retention's _cleanup_storage / _StorageTargets rather than duplicating the
storage abstraction.

The deletion audit is DATABASE-BACKED, not a log line: audit_service.record_platform_event writes
a row into `platform_audit_events`, a table with NO foreign key to `workspaces`, so it is not
cascade-removed and SURVIVES the workspace's hard deletion (unlike audit_events, which is
workspace-cascaded). The audit row is staged in the SAME transaction as, and BEFORE, the workspace
DELETE -- so if the audit write or the commit fails, the deletion does not happen either; there is
no path where the tenant is deleted while its audit record is missing. `security_event` (logger
"mbs.security") is still emitted, but only as an ADDITIONAL log signal, never as the record of
truth. tenant.delete.requested / .completed / .failed are all persisted this way.

EXPORT is synchronous and read-only, scoped by an explicit workspace_id on every query (the
tenancy.EXEMPT_TABLES -- scans, api_keys, scan_schedules -- are filtered explicitly too). Its scope is
derived from the workspace OWNERSHIP graph (every table reachable from `workspaces` by FK), not a
hand-kept list. Secrets are excluded by construction (see tenant_schemas): no hash/secret/token
field exists to serialize. Object BYTES are never embedded -- storage_uri references only.
"""
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.ai_agent.models import AIPlan, AIUsageRow
from apps.api.core.config import get_settings
from apps.api.modules.agent.models import AgentDecision, AgentStep, EngagementState
from apps.api.modules.api_keys.models import ApiKey
from apps.api.modules.assets.models import Asset
from apps.api.modules.attack.models import AttackMapping, AttackNarrative
from apps.api.modules.authorization_scope.models import AuthorizationScope
from apps.api.modules.audit import service as audit_service
from apps.api.modules.audit.models import AuditEvent
from apps.api.modules.auth.mfa_guard import security_event
from apps.api.modules.compliance.models import ComplianceMapping
from apps.api.modules.notifications.models import Notification
from apps.api.modules.private_sites.models import PrivateSite
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scanner_workers.models import ScannerWorker
from apps.api.modules.reports.models import Report
from apps.api.modules.risk.models import RiskScore
from apps.api.modules.scans.models import Scan
from apps.api.modules.schedules.models import ScanSchedule
from apps.api.modules.users.models import Permission, Role, RolePermission, User, WorkspaceMember
from apps.api.modules.vulnerabilities.models import (
    Vulnerability,
    VulnerabilityEvidence,
    VulnerabilityHistory,
    VulnerabilityLineage,
)
from apps.api.modules.assessment.models import RiskAssessment, RiskAssessmentFinding
from apps.api.modules.remediation.models import (
    RemediationEvent,
    RemediationEvidence,
    RemediationItem,
    VerificationRequest,
)
from apps.api.modules.remediation.risk_models import RiskAcceptance
from apps.api.modules.vulnerabilities.remediation_models import Remediation
from apps.api.modules.workspaces.models import Workspace
from apps.api.modules.workspaces.tenant_schemas import (
    ExportedAgentDecision,
    ExportedAgentStep,
    ExportedAiPlan,
    ExportedAiUsage,
    ExportedApiKeyMeta,
    ExportedAsset,
    ExportedAttackMapping,
    ExportedAttackNarrative,
    ExportedAuditEvent,
    ExportedAuthorizationScope,
    ExportedComplianceMapping,
    ExportedEngagementState,
    ExportedEvidence,
    ExportedMember,
    ExportedNotification,
    ExportedProject,
    ExportedRemediation,
    ExportedRemediationEvent,
    ExportedRemediationEvidence,
    ExportedRemediationItem,
    ExportedReport,
    ExportedRiskAcceptance,
    ExportedRiskAssessment,
    ExportedRiskAssessmentFinding,
    ExportedRiskScore,
    ExportedRole,
    ExportedRolePermission,
    ExportedSchedule,
    ExportedScan,
    ExportedPrivateSite,
    ExportedScannerWorker,
    ExportedTarget,
    ExportedToolRun,
    ExportedVerificationRequest,
    ExportedVulnerability,
    ExportedVulnerabilityEvidence,
    ExportedVulnerabilityHistory,
    ExportedVulnerabilityLineage,
    WorkspaceExport,
    WorkspaceExportSummary,
)
from apps.api.scanner_engine.models import Evidence, ToolRun
# Reuse retention's storage-cleanup seam -- do NOT duplicate the storage abstraction.
from apps.api.retention.service import _StorageTargets, _cleanup_storage

_ACTIVE_SCAN_STATUSES = ("queued", "running")


async def _require_active_workspace(db: AsyncSession, workspace_id: uuid.UUID) -> Workspace:
    ws = await db.get(Workspace, workspace_id)
    if ws is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")
    return ws


# --- deletion ------------------------------------------------------------------------------

async def request_workspace_deletion(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    actor: User,
    confirm_name: str,
) -> None:
    """Owner-only, name-confirmed. Flips the workspace to `deleting` (the gate that blocks new
    mutating operations) and enqueues the async deletion task. Idempotent: a workspace already
    `deleting` short-circuits so a duplicate request is a no-op, not an error."""
    ws = await _require_active_workspace(db, workspace_id)

    if ws.owner_user_id != actor.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only the workspace owner may delete it")
    if confirm_name != ws.name:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Confirmation name does not match the workspace name")

    if ws.status == "deleting":
        return  # already in progress -- idempotent

    ws.status = "deleting"
    # Durable audit + the status flip commit together, so a `requested` record always exists the
    # moment the workspace is marked for deletion. security_event is kept as an extra log signal.
    await audit_service.record_platform_event(db, workspace_id, actor.id, "tenant.delete.requested")
    await db.commit()

    security_event("tenant.delete.requested", user_id=actor.id, workspace_id=str(workspace_id))

    from apps.api.celery_app.tasks.tenant_tasks import delete_workspace_task

    delete_workspace_task.delay(str(workspace_id), str(actor.id))


async def _deactivate_and_revoke(db: AsyncSession, workspace_id: uuid.UUID) -> None:
    """Stop new work before tearing down: deactivate every schedule so beat cannot dispatch a
    fresh scan mid-delete, and revoke any queued/running scan's Celery task (existing
    control.revoke mechanism)."""
    for sched in await db.scalars(
        select(ScanSchedule).where(ScanSchedule.workspace_id == workspace_id)
    ):
        sched.enabled = False

    running = list(
        await db.scalars(
            select(Scan).where(
                Scan.workspace_id == workspace_id,
                Scan.status.in_(_ACTIVE_SCAN_STATUSES),
            )
        )
    )
    if running:
        from apps.api.celery_app.worker import celery_app

        for scan in running:
            if scan.celery_task_id:
                # Best-effort revoke -- a broker hiccup must not stall the delete; the row is
                # about to be cascade-removed anyway.
                try:
                    celery_app.control.revoke(scan.celery_task_id, terminate=True)
                except Exception:  # noqa: BLE001
                    pass
            scan.status = "cancelled"
            scan.completed_at = datetime.now(timezone.utc)
    await db.commit()


async def _capture_storage_targets(db: AsyncSession, workspace_id: uuid.UUID) -> _StorageTargets:
    """Collect object references BEFORE the rows vanish: every tool_run id (evidence prefixes)
    and every report storage_uri owned by the workspace."""
    targets = _StorageTargets()

    tool_run_ids = list(
        await db.scalars(
            select(ToolRun.id)
            .join(Scan, Scan.id == ToolRun.scan_id)
            .where(Scan.workspace_id == workspace_id)
        )
    )
    targets.tool_run_ids.extend(tool_run_ids)

    report_uris = list(
        await db.scalars(
            select(Report.storage_uri)
            .join(Project, Project.id == Report.project_id)
            .where(Project.workspace_id == workspace_id, Report.storage_uri.is_not(None))
        )
    )
    targets.report_uris.extend(report_uris)

    # P1-1: EVERY evidence object this workspace owns, by exact URI, captured before the
    # cascade removes the rows. Both ownership paths are covered, mirroring
    # tenancy._evidence_criterion -- a tool-run-only query would silently omit human-uploaded
    # remediation proof, whose tool_run_id is NULL:
    #   scanner evidence + screenshots -> tool_runs -> scans -> workspace
    #   remediation proof              -> remediation_evidence.workspace_id
    # Screenshots matter here specifically: their keys are `vulnerabilities/{id}/...`, so the
    # `tool-runs/{id}/` prefix deletion never reached them.
    _tool_runs_of_ws = select(ToolRun.id).join(Scan, Scan.id == ToolRun.scan_id).where(
        Scan.workspace_id == workspace_id
    )
    _remediation_evidence_ids = select(RemediationEvidence.evidence_id).where(
        RemediationEvidence.workspace_id == workspace_id
    )
    evidence_uris = list(
        await db.scalars(
            select(Evidence.storage_uri).where(
                Evidence.storage_uri.is_not(None),
                Evidence.tool_run_id.in_(_tool_runs_of_ws)
                | Evidence.id.in_(_remediation_evidence_ids),
            )
        )
    )
    targets.evidence_uris.extend(evidence_uris)
    # Belt-and-braces prefix sweep for this workspace's remediation artifacts.
    targets.workspace_ids.append(workspace_id)
    return targets


async def _delete_unreferenced_evidence(db: AsyncSession, workspace_id: uuid.UUID) -> int:
    """Delete this workspace's REMEDIATION-PROOF evidence rows explicitly, before the cascade.

    WHY THIS IS NEEDED (found by test_workspace_deletion_removes_evidence_objects_not_just_rows).
    `evidence` reaches `workspaces` only through `tool_run_id -> tool_runs -> scans`. A human
    -uploaded remediation proof has `tool_run_id IS NULL` by design -- fabricating a tool run
    would be a false claim in the evidence chain -- so such a row has NO foreign-key path to
    the workspace at all. Deleting the workspace cascades `remediation_evidence` away and
    leaves the `evidence` row behind permanently: owned by nobody, visible to no tenant (its
    ownership link is gone, so tenancy._evidence_criterion matches it for no workspace), and
    impossible to clean up afterwards.

    The rows are identified through `remediation_evidence`, which still carries the
    workspace_id at this point -- so this is strictly workspace-scoped and cannot reach
    another tenant's artifacts. Runs BEFORE `db.delete(ws)` in the same transaction, so the
    row removal is atomic with the workspace removal. The objects themselves were already
    captured into `_StorageTargets.evidence_uris` by the caller and are deleted after commit.

    Returns how many rows were removed (for the audit detail)."""
    orphan_ids = select(RemediationEvidence.evidence_id).where(
        RemediationEvidence.workspace_id == workspace_id
    )
    result = await db.execute(
        delete(Evidence).where(
            Evidence.id.in_(orphan_ids),
            # Only the FK-orphaned rows. Scanner evidence still has a tool run and is removed
            # by the existing cascade, so touching it here would be redundant.
            Evidence.tool_run_id.is_(None),
        )
    )
    return result.rowcount or 0


async def perform_workspace_deletion(db: AsyncSession, workspace_id: uuid.UUID, actor_id: uuid.UUID) -> bool:
    """The idempotent, retry-safe body run by the Celery task. Returns True if it deleted the
    workspace this call, False if there was nothing to delete (already gone -- a safe retry).

    Order: revoke/deactivate -> capture object refs -> DELETE workspace (cascade) -> cleanup
    objects (best-effort, AFTER the DB commit) -> platform audit."""
    ws = await db.get(Workspace, workspace_id)
    if ws is None:
        # Already deleted by a prior (partial) run -- converge silently. Idempotent.
        return False

    await _deactivate_and_revoke(db, workspace_id)
    targets = await _capture_storage_targets(db, workspace_id)
    await _delete_unreferenced_evidence(db, workspace_id)

    # Hard delete: the workspace row's ON DELETE CASCADE FKs clear the entire subtree in one
    # transaction. No "deleted" tombstone -- the row itself is removed. The durable audit record
    # is written into the SAME transaction; because platform_audit_events has no FK to workspaces,
    # it is NOT cascade-removed and survives the commit that deletes the workspace.
    detail = (
        f"tool_runs={len(targets.tool_run_ids)} reports={len(targets.report_uris)} "
        f"evidence_objects={len(targets.evidence_uris)}"
    )
    await audit_service.record_platform_event(
        db, workspace_id, actor_id, "tenant.delete.completed", detail=detail
    )
    await db.delete(ws)
    await db.commit()

    # Objects have no FK, so they are cleaned AFTER the DB commit. Best-effort: a storage
    # failure leaves a stranded object (logged inside _cleanup_storage), never a failed delete.
    _cleanup_storage(get_settings(), targets)

    security_event(
        "tenant.delete.completed",
        user_id=actor_id,
        workspace_id=str(workspace_id),
        tool_runs=len(targets.tool_run_ids),
        reports=len(targets.report_uris),
        evidence_objects=len(targets.evidence_uris),
    )
    return True


# --- export --------------------------------------------------------------------------------

async def export_workspace(db: AsyncSession, workspace_id: uuid.UUID) -> WorkspaceExport:
    """Complete, read-only, workspace-scoped export. Every query filters explicitly on
    workspace_id (or a project/scan join into it); the EXEMPT_TABLES are filtered explicitly
    too. Secrets are structurally excluded (no hash/secret/token field exists in the schemas)."""
    ws = await db.get(Workspace, workspace_id)
    if ws is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")

    member_rows = (
        await db.execute(
            select(WorkspaceMember, User, Role)
            .join(User, User.id == WorkspaceMember.user_id)
            .join(Role, Role.id == WorkspaceMember.role_id)
            .where(WorkspaceMember.workspace_id == workspace_id)
            .order_by(WorkspaceMember.invited_at)
        )
    ).all()
    members = [
        ExportedMember(
            user_id=u.id, email=u.email, full_name=u.full_name, role_name=r.name,
            invited_at=m.invited_at, joined_at=m.joined_at,
        )
        for m, u, r in member_rows
    ]

    # api_keys is in tenancy.EXEMPT_TABLES -> explicit workspace_id filter. Metadata only, never key_hash.
    api_keys = [
        ExportedApiKeyMeta(
            name=k.name, prefix=k.prefix, revoked=k.revoked,
            created_at=k.created_at, last_used_at=k.last_used_at,
        )
        for k in await db.scalars(
            select(ApiKey).where(ApiKey.workspace_id == workspace_id).order_by(ApiKey.created_at)
        )
    ]

    projects = [
        ExportedProject(
            id=p.id, name=p.name, description=p.description, status=p.status, created_at=p.created_at,
        )
        for p in await db.scalars(
            select(Project).where(Project.workspace_id == workspace_id).order_by(Project.created_at)
        )
    ]

    # scans is in tenancy.EXEMPT_TABLES -> explicit workspace_id filter. Metadata only (no config/evidence).
    scans = [
        ExportedScan(
            id=s.id, project_id=s.project_id, scan_type=s.scan_type, status=s.status,
            created_at=s.created_at, started_at=s.started_at, completed_at=s.completed_at,
        )
        for s in await db.scalars(
            select(Scan).where(Scan.workspace_id == workspace_id).order_by(Scan.created_at)
        )
    ]

    # vulnerabilities/reports hang off projects -> join into the workspace.
    vuln_rows = (
        await db.execute(
            select(Vulnerability, RiskScore.final_risk_score)
            .join(Project, Project.id == Vulnerability.project_id)
            .join(RiskScore, RiskScore.vulnerability_id == Vulnerability.id, isouter=True)
            .where(Project.workspace_id == workspace_id)
            .order_by(Vulnerability.created_at)
        )
    ).all()
    vulnerabilities = [
        ExportedVulnerability(
            id=v.id, project_id=v.project_id, title=v.title, severity=v.severity, status=v.status,
            cvss_score=v.cvss_score, final_risk_score=risk, fingerprint=v.fingerprint,
        )
        for v, risk in vuln_rows
    ]

    reports = [
        ExportedReport(
            id=r.id, project_id=r.project_id, type=r.type, format=r.format,
            storage_uri=r.storage_uri, generated_at=r.generated_at,
        )
        for r in await db.scalars(
            select(Report)
            .join(Project, Project.id == Report.project_id)
            .where(Project.workspace_id == workspace_id)
            .order_by(Report.generated_at)
        )
    ]

    # audit_events carries workspace_id directly.
    audit_events = [
        ExportedAuditEvent(
            id=a.id, actor_user_id=a.actor_user_id, actor_email=a.actor_email,
            action=a.action, resource_type=a.resource_type, created_at=a.created_at,
        )
        for a in await db.scalars(
            select(AuditEvent).where(AuditEvent.workspace_id == workspace_id).order_by(AuditEvent.created_at)
        )
    ]

    # targets / assets hang off projects -> join into the workspace.
    targets = [
        ExportedTarget(id=t.id, project_id=t.project_id, type=t.type, value=t.value,
                       criticality=t.criticality, network_zone=t.network_zone,
                       site_id=t.site_id, created_at=t.created_at)
        for t in await db.scalars(
            select(Target).join(Project, Project.id == Target.project_id)
            .where(Project.workspace_id == workspace_id).order_by(Target.created_at)
        )
    ]

    # MBS.SC -- private sites carry workspace_id DIRECTLY (tenancy._DIRECT_TABLES), so this
    # is a plain filter. NO private key material exists to export (see ExportedPrivateSite).
    private_sites = [
        ExportedPrivateSite(
            id=p.id, name=p.name, authorized_cidrs=list(p.authorized_cidrs or []),
            dns_servers=list(p.dns_servers or []),
            dns_search_domains=list(p.dns_search_domains or []),
            wg_endpoint_host=p.wg_endpoint_host, wg_endpoint_port=p.wg_endpoint_port,
            peer_public_key=p.peer_public_key, worker_public_key=p.worker_public_key,
            scanner_pool_id=p.scanner_pool_id, status=p.status,
            last_handshake_at=p.last_handshake_at, last_verified_at=p.last_verified_at,
            created_at=p.created_at,
        )
        for p in await db.scalars(
            select(PrivateSite).where(PrivateSite.workspace_id == workspace_id)
            .order_by(PrivateSite.created_at)
        )
    ]
    # scanner_workers is in EXEMPT_TABLES (authenticated before the workspace is known, and
    # a shared PUBLIC worker has workspace_id NULL), so it is NOT auto-filtered -- the
    # explicit predicate below is what scopes it. Only workers bound to THIS workspace are
    # exported; the shared public pool belongs to no tenant. Credential columns
    # (token_hash / cert_fingerprint) are deliberately not in the export model.
    scanner_workers = [
        ExportedScannerWorker(
            worker_id=w.worker_id, pool_id=w.pool_id, site_id=w.site_id, status=w.status,
            health_state=w.health_state, last_seen_at=w.last_seen_at,
            revoked_at=w.revoked_at, created_at=w.created_at,
        )
        for w in await db.scalars(
            select(ScannerWorker).where(ScannerWorker.workspace_id == workspace_id)
            .order_by(ScannerWorker.created_at)
        )
    ]
    assets = [
        ExportedAsset(id=a.id, project_id=a.project_id, target_id=a.target_id,
                      asset_type=a.asset_type, value=a.value, first_seen=a.first_seen)
        for a in await db.scalars(
            select(Asset).where(Asset.project_id.in_(select(Project.id).where(
                Project.workspace_id == workspace_id))).order_by(Asset.first_seen)
        )
    ]

    # scan_schedules carries workspace_id directly (in EXEMPT_TABLES) -> explicit filter.
    schedules = [
        ExportedSchedule(id=s.id, project_id=s.project_id, scan_type=s.scan_type,
                         interval_minutes=s.interval_minutes, enabled=s.enabled,
                         next_run_at=s.next_run_at, last_run_at=s.last_run_at, created_at=s.created_at)
        for s in await db.scalars(
            select(ScanSchedule).where(ScanSchedule.workspace_id == workspace_id).order_by(ScanSchedule.created_at)
        )
    ]

    # tool_runs -> scans -> workspace.
    tool_runs = [
        ExportedToolRun(id=tr.id, scan_id=tr.scan_id, tool_name=tr.tool_name,
                        tool_version=tr.tool_version, status=tr.status, started_at=tr.started_at,
                        completed_at=tr.completed_at, exit_code=tr.exit_code)
        for tr in await db.scalars(
            select(ToolRun).join(Scan, Scan.id == ToolRun.scan_id)
            .where(Scan.workspace_id == workspace_id).order_by(ToolRun.started_at)
        )
    ]

    # risk/compliance/attack/remediation hang off vulnerabilities -> projects -> workspace.
    _vuln_ids = select(Vulnerability.id).join(Project, Project.id == Vulnerability.project_id).where(
        Project.workspace_id == workspace_id)
    risk_scores = [
        ExportedRiskScore(vulnerability_id=r.vulnerability_id, business_impact_score=r.business_impact_score,
                          asset_criticality_weight=r.asset_criticality_weight,
                          final_risk_score=r.final_risk_score, rationale=r.rationale)
        for r in await db.scalars(select(RiskScore).where(RiskScore.vulnerability_id.in_(_vuln_ids)))
    ]
    compliance_mappings = [
        ExportedComplianceMapping(vulnerability_id=c.vulnerability_id, framework=c.framework,
                                  control_id=c.control_id, control_description=c.control_description)
        for c in await db.scalars(select(ComplianceMapping).where(ComplianceMapping.vulnerability_id.in_(_vuln_ids)))
    ]
    attack_mappings = [
        ExportedAttackMapping(vulnerability_id=am.vulnerability_id, tactic_id=am.tactic_id,
                              tactic_name=am.tactic_name, technique_id=am.technique_id,
                              technique_name=am.technique_name, kill_chain_phase=am.kill_chain_phase)
        for am in await db.scalars(select(AttackMapping).where(AttackMapping.vulnerability_id.in_(_vuln_ids)))
    ]
    remediations = [
        ExportedRemediation(id=rm.id, vulnerability_id=rm.vulnerability_id, summary=rm.summary,
                            model_version=rm.model_version, created_at=rm.created_at)
        for rm in await db.scalars(select(Remediation).where(Remediation.vulnerability_id.in_(_vuln_ids)))
    ]

    # notifications / ai_usage / attack_narratives / engagement / agent carry workspace_id
    # directly (or via scan). All filtered into this workspace explicitly.
    notifications = [
        ExportedNotification(id=n.id, project_id=n.project_id, type=n.type, severity=n.severity,
                             title=n.title, read=n.read, created_at=n.created_at)
        for n in await db.scalars(
            select(Notification).where(Notification.workspace_id == workspace_id).order_by(Notification.created_at)
        )
    ]
    ai_usage = [
        ExportedAiUsage(id=au.id, scan_id=au.scan_id, provider=au.provider, model=au.model,
                        agent_role=au.agent_role, prompt_tokens=au.prompt_tokens,
                        completion_tokens=au.completion_tokens, estimated_cost_usd=au.estimated_cost_usd,
                        created_at=au.created_at)
        for au in await db.scalars(
            select(AIUsageRow).where(AIUsageRow.workspace_id == workspace_id).order_by(AIUsageRow.created_at)
        )
    ]
    _scan_ids = select(Scan.id).where(Scan.workspace_id == workspace_id)
    ai_plans = [
        ExportedAiPlan(id=ap.id, scan_id=ap.scan_id, reasoning_summary=ap.reasoning_summary,
                       model_version=ap.model_version, created_at=ap.created_at)
        for ap in await db.scalars(select(AIPlan).where(AIPlan.scan_id.in_(_scan_ids)).order_by(AIPlan.created_at))
    ]
    agent_steps = [
        ExportedAgentStep(id=st.id, scan_id=st.scan_id, step_no=st.step_no, phase=st.phase,
                          action_type=st.action_type, status=st.status, created_at=st.created_at)
        for st in await db.scalars(
            select(AgentStep).where(AgentStep.workspace_id == workspace_id).order_by(AgentStep.created_at)
        )
    ]
    agent_decisions = [
        ExportedAgentDecision(id=d.id, scan_id=d.scan_id, step_no=d.step_no, phase=d.phase,
                              action=d.action, selected_tool=d.selected_tool, stop_reason=d.stop_reason,
                              created_at=d.created_at)
        for d in await db.scalars(
            select(AgentDecision).where(AgentDecision.workspace_id == workspace_id).order_by(AgentDecision.created_at)
        )
    ]
    engagement_states = [
        ExportedEngagementState(id=e.id, scan_id=e.scan_id, status=e.status, current_phase=e.current_phase,
                                objective=e.objective, approval_state=e.approval_state, created_at=e.created_at)
        for e in await db.scalars(
            select(EngagementState).where(EngagementState.workspace_id == workspace_id).order_by(EngagementState.created_at)
        )
    ]
    attack_narratives = [
        ExportedAttackNarrative(id=an.id, scan_id=an.scan_id, summary=an.summary,
                                model_version=an.model_version, created_at=an.created_at)
        for an in await db.scalars(
            select(AttackNarrative).where(AttackNarrative.workspace_id == workspace_id).order_by(AttackNarrative.created_at)
        )
    ]

    # --- newly covered workspace-owned entities -------------------------------------------
    # Each is anchored to THIS workspace through its own FK chain; no query relies on the
    # auto-filter alone.
    #   authorization_scopes -> targets -> projects -> workspace
    #   evidence             -> tool_runs -> scans   -> workspace
    #   vulnerability_evidence -> vulnerabilities -> projects -> workspace
    #   roles / role_permissions -> workspace_id (workspace-SCOPED rows only)
    _target_ids = select(Target.id).join(Project, Project.id == Target.project_id).where(
        Project.workspace_id == workspace_id)
    authorization_scopes = [
        ExportedAuthorizationScope(
            id=a.id, target_id=a.target_id, proof_type=a.proof_type,
            proof_reference=a.proof_reference, verified=a.verified, verified_by=a.verified_by,
            verified_at=a.verified_at, active_testing_allowed=a.active_testing_allowed,
            scope_notes=a.scope_notes, expires_at=a.expires_at, created_at=a.created_at)
        for a in await db.scalars(
            select(AuthorizationScope)
            .where(AuthorizationScope.target_id.in_(_target_ids))
            .order_by(AuthorizationScope.created_at)
        )
    ]

    _tool_run_ids = select(ToolRun.id).join(Scan, Scan.id == ToolRun.scan_id).where(
        Scan.workspace_id == workspace_id)
    # NULLABLE-tool_run AUDIT: `evidence` now holds TWO kinds of artifact reached by two
    # disjoint paths -- scanner output (tool_run -> scan -> workspace) and human remediation
    # proof (tool_run_id IS NULL, owned through remediation_evidence.workspace_id). Filtering
    # on the tool-run subquery ALONE would silently omit every remediation artifact from the
    # tenant export, so both paths are ORed here. Mirrors tenancy._evidence_criterion exactly,
    # for the same reason.
    _remediation_evidence_ids = select(RemediationEvidence.evidence_id).where(
        RemediationEvidence.workspace_id == workspace_id)
    evidence_rows = [
        ExportedEvidence(
            id=ev.id, tool_run_id=ev.tool_run_id, evidence_type=ev.evidence_type,
            # storage_uri is a REFERENCE; checksum is an integrity digest, not a secret.
            storage_uri=ev.storage_uri, checksum=ev.checksum, uploaded_by=ev.uploaded_by,
            created_at=ev.created_at)
        for ev in await db.scalars(
            select(Evidence)
            .where(
                Evidence.tool_run_id.in_(_tool_run_ids)
                | Evidence.id.in_(_remediation_evidence_ids)
            )
            .order_by(Evidence.created_at)
        )
    ]

    # --- remediation workflow + client assessments ------------------------------------------
    # Every one of these tables carries workspace_id DIRECTLY (they are _DIRECT_TABLES in
    # tenancy.py), so each is anchored with a single explicit equality -- no join chain, and
    # nothing left to the auto-filter.
    remediation_items = [
        ExportedRemediationItem(
            id=r.id, project_id=r.project_id, issue_key=r.issue_key,
            vulnerability_id=r.vulnerability_id, title=r.title, status=r.status,
            priority=r.priority, assignee_user_id=r.assignee_user_id, due_date=r.due_date,
            notes=r.notes, notes_source=r.notes_source, source=r.source,
            resolved_at=r.resolved_at, verified_at=r.verified_at, version=r.version,
            created_at=r.created_at)
        for r in await db.scalars(
            select(RemediationItem)
            .where(RemediationItem.workspace_id == workspace_id)
            .order_by(RemediationItem.created_at)
        )
    ]
    remediation_events = [
        ExportedRemediationEvent(
            id=e.id, remediation_item_id=e.remediation_item_id, event_type=e.event_type,
            from_status=e.from_status, to_status=e.to_status, actor_user_id=e.actor_user_id,
            detail=e.detail, created_at=e.created_at)
        for e in await db.scalars(
            select(RemediationEvent)
            .where(RemediationEvent.workspace_id == workspace_id)
            .order_by(RemediationEvent.created_at)
        )
    ]
    remediation_evidence = [
        ExportedRemediationEvidence(
            remediation_item_id=re_.remediation_item_id, evidence_id=re_.evidence_id,
            uploaded_by=re_.uploaded_by, created_at=re_.created_at)
        for re_ in await db.scalars(
            select(RemediationEvidence)
            .where(RemediationEvidence.workspace_id == workspace_id)
            .order_by(RemediationEvidence.created_at)
        )
    ]
    verification_requests = [
        ExportedVerificationRequest(
            id=v.id, remediation_item_id=v.remediation_item_id, status=v.status,
            result=v.result, scan_id=v.scan_id, requested_by=v.requested_by,
            completed_at=v.completed_at, detail=v.detail or {}, created_at=v.created_at)
        for v in await db.scalars(
            select(VerificationRequest)
            .where(VerificationRequest.workspace_id == workspace_id)
            .order_by(VerificationRequest.created_at)
        )
    ]
    risk_acceptances = [
        ExportedRiskAcceptance(
            id=a.id, project_id=a.project_id, vulnerability_id=a.vulnerability_id,
            remediation_item_id=a.remediation_item_id, justification=a.justification,
            accepted_by=a.accepted_by, approved_by=a.approved_by, expires_at=a.expires_at,
            review_due_at=a.review_due_at, status=a.status, revoked_by=a.revoked_by,
            revoked_at=a.revoked_at, revoke_reason=a.revoke_reason, created_at=a.created_at)
        for a in await db.scalars(
            select(RiskAcceptance)
            .where(RiskAcceptance.workspace_id == workspace_id)
            .order_by(RiskAcceptance.created_at)
        )
    ]
    risk_assessments = [
        ExportedRiskAssessment(
            id=a.id, project_id=a.project_id, title=a.title, period_start=a.period_start,
            period_end=a.period_end, status=a.status, security_score=a.security_score,
            score_band=a.score_band, summary=a.summary or {}, narrative=a.narrative,
            narrative_source=a.narrative_source,
            previous_assessment_id=a.previous_assessment_id, report_id=a.report_id,
            issued_by=a.issued_by, issued_at=a.issued_at, created_at=a.created_at)
        for a in await db.scalars(
            select(RiskAssessment)
            .where(RiskAssessment.workspace_id == workspace_id)
            .order_by(RiskAssessment.created_at)
        )
    ]
    risk_assessment_findings = [
        ExportedRiskAssessmentFinding(
            id=f.id, assessment_id=f.assessment_id, issue_key=f.issue_key,
            vulnerability_id=f.vulnerability_id, frozen_title=f.frozen_title,
            frozen_severity=f.frozen_severity, frozen_cvss_score=f.frozen_cvss_score,
            frozen_final_risk_score=f.frozen_final_risk_score,
            frozen_vulnerability_status=f.frozen_vulnerability_status,
            frozen_remediation_status=f.frozen_remediation_status,
            risk_accepted=f.risk_accepted, location_count=f.location_count,
            created_at=f.created_at)
        for f in await db.scalars(
            select(RiskAssessmentFinding)
            .where(RiskAssessmentFinding.workspace_id == workspace_id)
            .order_by(RiskAssessmentFinding.created_at)
        )
    ]

    # Anchored on the VULNERABILITY side (vulns -> projects -> workspace) so the exported
    # finding <-> evidence relationship is preserved and cannot pull another tenant's join rows.
    vulnerability_evidence = [
        ExportedVulnerabilityEvidence(
            vulnerability_id=ve.vulnerability_id, evidence_id=ve.evidence_id,
            tool_run_id=ve.tool_run_id, created_at=ve.created_at)
        for ve in await db.scalars(
            select(VulnerabilityEvidence)
            .where(VulnerabilityEvidence.vulnerability_id.in_(_vuln_ids))
            .order_by(VulnerabilityEvidence.created_at)
        )
    ]

    # Anchored on new_vulnerability_id (Prompt 13, Finding #2) -- same VIA-scoping rationale as
    # vulnerability_evidence immediately above: filtering by the vulnerability side this
    # workspace already owns cannot pull another tenant's lineage row even if a UUID collision
    # were somehow guessed, since `_vuln_ids` is itself workspace-scoped.
    vulnerability_lineage = [
        ExportedVulnerabilityLineage(
            id=vl.id, project_id=vl.project_id,
            old_vulnerability_id=vl.old_vulnerability_id, new_vulnerability_id=vl.new_vulnerability_id,
            match_rule=vl.match_rule, matched_location=vl.matched_location,
            inherited_status=vl.inherited_status, created_at=vl.created_at)
        for vl in await db.scalars(
            select(VulnerabilityLineage)
            .where(VulnerabilityLineage.new_vulnerability_id.in_(_vuln_ids))
            .order_by(VulnerabilityLineage.created_at)
        )
    ]

    # Anchored on vulnerability_id (Prompt 13, Finding #4) -- same VIA-scoping rationale as
    # vulnerability_evidence/vulnerability_lineage above.
    vulnerability_history = [
        ExportedVulnerabilityHistory(
            id=vh.id, project_id=vh.project_id, vulnerability_id=vh.vulnerability_id,
            scan_id=vh.scan_id, tool_run_id=vh.tool_run_id, fingerprint=vh.fingerprint,
            title=vh.title, category=vh.category, description=vh.description,
            severity=vh.severity, cvss_vector=vh.cvss_vector, cvss_score=vh.cvss_score,
            change_reason=vh.change_reason, created_at=vh.created_at)
        for vh in await db.scalars(
            select(VulnerabilityHistory)
            .where(VulnerabilityHistory.vulnerability_id.in_(_vuln_ids))
            .order_by(VulnerabilityHistory.created_at)
        )
    ]

    # WORKSPACE-SCOPED roles ONLY. roles.workspace_id is NULLABLE and NULL means a global/system
    # role (owner/admin/member) -- platform data, shared across tenants, NOT this tenant's to
    # export. The equality filter excludes NULL in SQL, so system roles can never be included.
    workspace_roles = [
        ExportedRole(id=r.id, name=r.name, description=r.description)
        for r in await db.scalars(
            select(Role).where(Role.workspace_id == workspace_id).order_by(Role.name)
        )
    ]
    _role_ids = select(Role.id).where(Role.workspace_id == workspace_id)
    role_permission_rows = (
        await db.execute(
            select(RolePermission, Permission.key)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(RolePermission.role_id.in_(_role_ids))
            .order_by(Permission.key)
        )
    ).all()
    role_permissions = [
        ExportedRolePermission(role_id=rp.role_id, permission_id=rp.permission_id, permission_key=key)
        for rp, key in role_permission_rows
    ]

    return WorkspaceExport(
        generated_at=datetime.now(timezone.utc),
        workspace_id=ws.id,
        workspace_name=ws.name,
        plan_tier=ws.plan_tier,
        status=ws.status,
        owner_user_id=ws.owner_user_id,
        members=members,
        api_keys=api_keys,
        projects=projects,
        targets=targets,
        private_sites=private_sites,
        scanner_workers=scanner_workers,
        assets=assets,
        schedules=schedules,
        scans=scans,
        tool_runs=tool_runs,
        vulnerabilities=vulnerabilities,
        risk_scores=risk_scores,
        compliance_mappings=compliance_mappings,
        attack_mappings=attack_mappings,
        remediations=remediations,
        reports=reports,
        audit_events=audit_events,
        notifications=notifications,
        ai_usage=ai_usage,
        ai_plans=ai_plans,
        agent_steps=agent_steps,
        agent_decisions=agent_decisions,
        engagement_states=engagement_states,
        attack_narratives=attack_narratives,
        authorization_scopes=authorization_scopes,
        evidence=evidence_rows,
        vulnerability_evidence=vulnerability_evidence,
        vulnerability_lineage=vulnerability_lineage,
        vulnerability_history=vulnerability_history,
        remediation_items=remediation_items,
        remediation_events=remediation_events,
        remediation_evidence=remediation_evidence,
        verification_requests=verification_requests,
        risk_acceptances=risk_acceptances,
        risk_assessments=risk_assessments,
        risk_assessment_findings=risk_assessment_findings,
        roles=workspace_roles,
        role_permissions=role_permissions,
        summary=WorkspaceExportSummary(
            member_count=len(members),
            api_key_count=len(api_keys),
            project_count=len(projects),
            target_count=len(targets),
            asset_count=len(assets),
            schedule_count=len(schedules),
            scan_count=len(scans),
            tool_run_count=len(tool_runs),
            vulnerability_count=len(vulnerabilities),
            risk_score_count=len(risk_scores),
            compliance_mapping_count=len(compliance_mappings),
            attack_mapping_count=len(attack_mappings),
            remediation_count=len(remediations),
            report_count=len(reports),
            audit_event_count=len(audit_events),
            notification_count=len(notifications),
            ai_usage_count=len(ai_usage),
            ai_plan_count=len(ai_plans),
            agent_step_count=len(agent_steps),
            agent_decision_count=len(agent_decisions),
            engagement_state_count=len(engagement_states),
            attack_narrative_count=len(attack_narratives),
            authorization_scope_count=len(authorization_scopes),
            evidence_count=len(evidence_rows),
            vulnerability_evidence_count=len(vulnerability_evidence),
            vulnerability_lineage_count=len(vulnerability_lineage),
            vulnerability_history_count=len(vulnerability_history),
            remediation_item_count=len(remediation_items),
            remediation_event_count=len(remediation_events),
            remediation_evidence_count=len(remediation_evidence),
            verification_request_count=len(verification_requests),
            risk_acceptance_count=len(risk_acceptances),
            risk_assessment_count=len(risk_assessments),
            risk_assessment_finding_count=len(risk_assessment_findings),
            role_count=len(workspace_roles),
            role_permission_count=len(role_permissions),
        ),
    )
