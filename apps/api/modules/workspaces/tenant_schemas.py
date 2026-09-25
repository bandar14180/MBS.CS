"""Schemas for tenant (workspace-level) export and deletion.

Kept separate from schemas.py so the existing member/role schemas stay untouched. Secret-safe by
construction: every field here is non-sensitive metadata -- there is NO field for a password hash,
MFA secret, API-key hash/secret, JWT secret, or execution token, so none can ever be serialized.
Each model hand-lists its safe fields (no blanket from_attributes on the row models), so adding a
secret column to an ORM model cannot silently leak it into the export.

Object/file BYTES are never embedded; artifacts appear as storage_uri references only.
"""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class WorkspaceDeleteConfirm(BaseModel):
    # Typed confirmation: the caller must echo the exact workspace name. A mismatch is rejected
    # before anything destructive happens (defends against fat-finger / CSRF-style deletes).
    confirm_name: str = Field(min_length=1, max_length=255)


# --- export --------------------------------------------------------------------------------

class ExportedMember(BaseModel):
    user_id: uuid.UUID
    email: str
    full_name: str
    role_name: str
    invited_at: datetime
    joined_at: datetime | None


class ExportedApiKeyMeta(BaseModel):
    # Metadata ONLY -- never key_hash. name/prefix/revoked/dates are non-sensitive.
    name: str
    prefix: str
    revoked: bool
    created_at: datetime
    last_used_at: datetime | None


class ExportedProject(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    status: str
    created_at: datetime


class ExportedScan(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    scan_type: str
    status: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class ExportedVulnerability(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    title: str
    severity: str
    status: str
    cvss_score: float | None
    final_risk_score: float | None
    fingerprint: str


class ExportedTarget(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    type: str
    value: str
    criticality: str
    # MBS.SC: which network zone this target lives in, and (for a private target) the site
    # whose tunnel and authorized CIDRs govern it. Exported because it is the customer's own
    # configuration and materially describes what was scanned.
    network_zone: str
    site_id: uuid.UUID | None
    created_at: datetime


class ExportedPrivateSite(BaseModel):
    """MBS.SC: a customer's private site, as exported to that customer.

    NOTE WHAT IS ABSENT. `peer_public_key` and `worker_public_key` are the customer's own
    public key material and are safe to return to them. There is no private key field here
    because there is no private key ANYWHERE in the control plane -- the worker generates
    and keeps its own (see docs/architecture/scanner-isolation.md). This export therefore
    cannot leak tunnel credentials even to the legitimate owner, which is the correct
    property: a GDPR export lands in a ticket, an email, or an S3 bucket.
    """

    id: uuid.UUID
    name: str
    authorized_cidrs: list
    dns_servers: list
    dns_search_domains: list
    wg_endpoint_host: str | None
    wg_endpoint_port: int | None
    peer_public_key: str | None
    worker_public_key: str | None
    scanner_pool_id: str | None
    status: str
    last_handshake_at: datetime | None
    last_verified_at: datetime | None
    created_at: datetime


class ExportedScannerWorker(BaseModel):
    """MBS.SC: a scanner worker bound to this workspace (private workers only).

    `token_hash` and `cert_fingerprint` are deliberately NOT exported: they are
    authentication material, and a hash is still a credential-shaped secret that does not
    belong in a document the customer forwards.
    """

    worker_id: str
    pool_id: str
    site_id: uuid.UUID | None
    status: str
    health_state: str
    last_seen_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class ExportedAsset(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    target_id: uuid.UUID
    asset_type: str
    value: str
    first_seen: datetime


class ExportedSchedule(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    scan_type: str
    interval_minutes: int
    enabled: bool
    next_run_at: datetime | None
    last_run_at: datetime | None
    created_at: datetime


class ExportedToolRun(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    tool_name: str
    tool_version: str
    status: str
    started_at: datetime
    completed_at: datetime | None
    exit_code: int | None


class ExportedRiskScore(BaseModel):
    vulnerability_id: uuid.UUID
    business_impact_score: float | None
    asset_criticality_weight: float | None
    final_risk_score: float | None
    rationale: str | None


class ExportedComplianceMapping(BaseModel):
    vulnerability_id: uuid.UUID
    framework: str
    control_id: str
    control_description: str | None


class ExportedAttackMapping(BaseModel):
    vulnerability_id: uuid.UUID
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    kill_chain_phase: str | None


class ExportedRemediation(BaseModel):
    id: uuid.UUID
    vulnerability_id: uuid.UUID
    summary: str | None
    model_version: str | None
    created_at: datetime


class ExportedReport(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    type: str
    format: str
    # A REFERENCE to the object, not its bytes -- the export never embeds file/object bytes.
    storage_uri: str | None
    generated_at: datetime


class ExportedNotification(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID | None
    type: str
    severity: str | None
    title: str
    read: bool
    created_at: datetime


class ExportedAiUsage(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID | None
    provider: str
    model: str
    agent_role: str | None
    prompt_tokens: int | None
    completion_tokens: int | None
    estimated_cost_usd: float | None
    created_at: datetime


class ExportedAiPlan(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    reasoning_summary: str | None
    model_version: str | None
    created_at: datetime


class ExportedAgentStep(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    step_no: int
    phase: str | None
    action_type: str | None
    status: str | None
    created_at: datetime


class ExportedAgentDecision(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    step_no: int | None
    phase: str | None
    action: str | None
    selected_tool: str | None
    stop_reason: str | None
    created_at: datetime


class ExportedEngagementState(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    status: str | None
    current_phase: str | None
    objective: str | None
    # AUDIT-013 (found by the new type-check gate): this was `str | None`, but
    # EngagementState.approval_state is `Mapped[dict]` -- a NON-NULLABLE JSON column whose
    # default is `dict`. Pydantic rejects a dict for a `str` field, so exporting ANY workspace
    # holding an engagement_state row raised
    #   ValidationError: approval_state Input should be a valid string
    # and the tenant's GDPR data export failed outright. Verified empirically: {'approved':
    # True} and even {} were both REJECTED; only None passed, which the column can never be.
    approval_state: dict | None
    created_at: datetime


class ExportedAttackNarrative(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    summary: str | None
    model_version: str | None
    created_at: datetime


class ExportedAuthorizationScope(BaseModel):
    """Authorization-to-test proof for a target. `proof_reference` is the customer's own
    authorization pointer (ticket / contract / email reference), NOT a credential."""

    id: uuid.UUID
    target_id: uuid.UUID
    proof_type: str
    proof_reference: str
    verified: bool
    verified_by: uuid.UUID | None
    verified_at: datetime | None
    active_testing_allowed: bool
    scope_notes: str | None
    expires_at: datetime | None
    created_at: datetime


class ExportedEvidence(BaseModel):
    """Evidence artifact metadata. `storage_uri` is a REFERENCE to the object, never its bytes;
    `checksum` is the artifact's integrity digest (content hash), not a credential."""

    id: uuid.UUID
    # NULLABLE: human-uploaded remediation proof has no tool run (fabricating one would be a
    # false claim in the evidence chain). Widening this field is why the export query below is
    # anchored on BOTH paths rather than on tool_runs alone.
    tool_run_id: uuid.UUID | None
    evidence_type: str
    storage_uri: str
    checksum: str
    uploaded_by: uuid.UUID | None
    created_at: datetime


class ExportedVulnerabilityEvidence(BaseModel):
    """Join row preserving the vulnerability <-> evidence relationship (and the tool_run that
    produced it), so the exported finding/proof chain stays reconstructable."""

    vulnerability_id: uuid.UUID
    evidence_id: uuid.UUID
    tool_run_id: uuid.UUID
    created_at: datetime


class ExportedVulnerabilityLineage(BaseModel):
    """A deterministic fingerprint-drift link (Prompt 13, Finding #2) between two Vulnerability
    rows this workspace owns, and whether an analyst decision was inherited across it."""

    id: uuid.UUID
    project_id: uuid.UUID
    old_vulnerability_id: uuid.UUID
    new_vulnerability_id: uuid.UUID
    match_rule: str
    matched_location: str | None
    inherited_status: str | None
    created_at: datetime


class ExportedVulnerabilityHistory(BaseModel):
    """One immutable content snapshot of a Vulnerability this workspace owns (Prompt 13,
    Finding #4) -- the chronology an operator/auditor would use to answer "what did this
    finding look like at an earlier scan"."""

    id: uuid.UUID
    project_id: uuid.UUID
    vulnerability_id: uuid.UUID
    scan_id: uuid.UUID | None
    tool_run_id: uuid.UUID | None
    fingerprint: str
    title: str
    category: str | None
    description: str | None
    severity: str
    cvss_vector: str | None
    cvss_score: float | None
    change_reason: str
    created_at: datetime


class ExportedRemediationItem(BaseModel):
    """Remediation WORK item, at the issue level. `issue_key` is the canonical issue identity
    shared with the score and the reports, so an export stays cross-referenceable."""

    id: uuid.UUID
    project_id: uuid.UUID
    issue_key: str
    vulnerability_id: uuid.UUID | None
    title: str
    status: str
    priority: str
    assignee_user_id: uuid.UUID | None
    due_date: datetime | None
    notes: str | None
    notes_source: str | None
    source: str
    resolved_at: datetime | None
    verified_at: datetime | None
    version: int
    created_at: datetime


class ExportedRemediationEvent(BaseModel):
    """One immutable entry from a remediation item's timeline."""

    id: uuid.UUID
    remediation_item_id: uuid.UUID
    event_type: str
    from_status: str | None
    to_status: str | None
    actor_user_id: uuid.UUID | None
    detail: str | None
    created_at: datetime


class ExportedRemediationEvidence(BaseModel):
    """Join row preserving the remediation <-> evidence relationship."""

    remediation_item_id: uuid.UUID
    evidence_id: uuid.UUID
    uploaded_by: uuid.UUID | None
    created_at: datetime


class ExportedVerificationRequest(BaseModel):
    """A retest request and its outcome. `detail` holds the reproducible basis for the result
    (the scan and the live-location count), not prose."""

    id: uuid.UUID
    remediation_item_id: uuid.UUID
    status: str
    result: str | None
    scan_id: uuid.UUID | None
    requested_by: uuid.UUID | None
    completed_at: datetime | None
    detail: dict
    created_at: datetime


class ExportedRiskAcceptance(BaseModel):
    """A formal risk-treatment decision with its justification, approver and expiry."""

    id: uuid.UUID
    project_id: uuid.UUID
    vulnerability_id: uuid.UUID
    remediation_item_id: uuid.UUID | None
    justification: str
    accepted_by: uuid.UUID | None
    approved_by: uuid.UUID | None
    expires_at: datetime
    review_due_at: datetime | None
    status: str
    revoked_by: uuid.UUID | None
    revoked_at: datetime | None
    revoke_reason: str | None
    created_at: datetime


class ExportedRiskAssessment(BaseModel):
    """An immutable client-facing snapshot. `summary` is the frozen posture payload."""

    id: uuid.UUID
    project_id: uuid.UUID | None
    title: str
    period_start: datetime
    period_end: datetime
    status: str
    security_score: int | None
    score_band: str | None
    summary: dict
    narrative: str | None
    narrative_source: str | None
    previous_assessment_id: uuid.UUID | None
    report_id: uuid.UUID | None
    issued_by: uuid.UUID | None
    issued_at: datetime | None
    created_at: datetime


class ExportedRiskAssessmentFinding(BaseModel):
    """A finding as it stood at issue time. Every value is a frozen copy."""

    id: uuid.UUID
    assessment_id: uuid.UUID
    issue_key: str
    vulnerability_id: uuid.UUID | None
    frozen_title: str
    frozen_severity: str
    frozen_cvss_score: float | None
    frozen_final_risk_score: float | None
    frozen_vulnerability_status: str
    frozen_remediation_status: str | None
    risk_accepted: bool
    location_count: int
    created_at: datetime


class ExportedRole(BaseModel):
    """A WORKSPACE-SCOPED role definition only (roles.workspace_id == this workspace). Global
    /system roles (workspace_id IS NULL) are platform data, not tenant data, and are excluded."""

    id: uuid.UUID
    name: str
    description: str | None


class ExportedRolePermission(BaseModel):
    """Permission grant for a workspace-scoped role. `permission_key` is the human-readable
    permission name (e.g. `scan:create`) -- a capability label, not a secret."""

    role_id: uuid.UUID
    permission_id: uuid.UUID
    permission_key: str


class ExportedAuditEvent(BaseModel):
    id: uuid.UUID
    actor_user_id: uuid.UUID | None
    actor_email: str | None
    action: str
    resource_type: str
    created_at: datetime


class WorkspaceExportSummary(BaseModel):
    member_count: int
    api_key_count: int
    project_count: int
    target_count: int
    asset_count: int
    schedule_count: int
    scan_count: int
    tool_run_count: int
    vulnerability_count: int
    risk_score_count: int
    compliance_mapping_count: int
    attack_mapping_count: int
    remediation_count: int
    report_count: int
    audit_event_count: int
    notification_count: int
    ai_usage_count: int
    ai_plan_count: int
    agent_step_count: int
    agent_decision_count: int
    engagement_state_count: int
    attack_narrative_count: int
    authorization_scope_count: int
    evidence_count: int
    vulnerability_evidence_count: int
    vulnerability_lineage_count: int
    vulnerability_history_count: int
    remediation_item_count: int
    remediation_event_count: int
    remediation_evidence_count: int
    verification_request_count: int
    risk_acceptance_count: int
    risk_assessment_count: int
    risk_assessment_finding_count: int
    role_count: int
    role_permission_count: int


class WorkspaceExport(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    generated_at: datetime
    workspace_id: uuid.UUID
    workspace_name: str
    plan_tier: str
    status: str
    owner_user_id: uuid.UUID
    members: list[ExportedMember]
    api_keys: list[ExportedApiKeyMeta]
    projects: list[ExportedProject]
    targets: list[ExportedTarget]
    # MBS.SC -- the customer's private-network configuration and the workers bound to it.
    private_sites: list[ExportedPrivateSite]
    scanner_workers: list[ExportedScannerWorker]
    assets: list[ExportedAsset]
    schedules: list[ExportedSchedule]
    scans: list[ExportedScan]
    tool_runs: list[ExportedToolRun]
    vulnerabilities: list[ExportedVulnerability]
    risk_scores: list[ExportedRiskScore]
    compliance_mappings: list[ExportedComplianceMapping]
    attack_mappings: list[ExportedAttackMapping]
    remediations: list[ExportedRemediation]
    reports: list[ExportedReport]
    audit_events: list[ExportedAuditEvent]
    notifications: list[ExportedNotification]
    ai_usage: list[ExportedAiUsage]
    ai_plans: list[ExportedAiPlan]
    agent_steps: list[ExportedAgentStep]
    agent_decisions: list[ExportedAgentDecision]
    engagement_states: list[ExportedEngagementState]
    attack_narratives: list[ExportedAttackNarrative]
    authorization_scopes: list[ExportedAuthorizationScope]
    evidence: list[ExportedEvidence]
    vulnerability_evidence: list[ExportedVulnerabilityEvidence]
    vulnerability_lineage: list[ExportedVulnerabilityLineage]
    vulnerability_history: list[ExportedVulnerabilityHistory]
    remediation_items: list[ExportedRemediationItem]
    remediation_events: list[ExportedRemediationEvent]
    remediation_evidence: list[ExportedRemediationEvidence]
    verification_requests: list[ExportedVerificationRequest]
    risk_acceptances: list[ExportedRiskAcceptance]
    risk_assessments: list[ExportedRiskAssessment]
    risk_assessment_findings: list[ExportedRiskAssessmentFinding]
    roles: list[ExportedRole]
    role_permissions: list[ExportedRolePermission]
    summary: WorkspaceExportSummary
