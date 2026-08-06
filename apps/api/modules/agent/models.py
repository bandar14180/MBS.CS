import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class EngagementState(Base):
    """The autonomous agent's live state machine for one scan-as-an-engagement.
    Tenant-scoped by its own workspace_id with ENABLE + FORCE RLS (scans are
    RLS-exempt, so we scope directly like ai_usage/attack_narratives)."""

    __tablename__ = "engagement_state"
    __table_args__ = (UniqueConstraint("scan_id", name="uq_engagement_state_scan"),)

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # running | paused_for_approval | completed | killed | failed
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")
    current_phase: Mapped[str] = mapped_column(String(32), nullable=False, default="reconnaissance")
    objective: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Per-host approval decisions for active exploitation (human-in-the-loop).
    approval_state: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Accumulated attack graph (nodes/edges: hosts, services, findings, access).
    attack_graph: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AgentStep(Base):
    """Immutable audit log: every decision, action, and safety verdict the agent
    made -- the accountability backbone for autonomous actions. Tenant-scoped via
    its own workspace_id (ENABLE + FORCE RLS)."""

    __tablename__ = "agent_steps"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    step_no: Mapped[int] = mapped_column(Integer, nullable=False)
    phase: Mapped[str] = mapped_column(String(32), nullable=False)
    # tool_run | exploit | analysis | decision | approval_wait
    action_type: Mapped[str] = mapped_column(String(32), nullable=False)
    tool_or_module: Mapped[str | None] = mapped_column(String(64), nullable=True)
    safety_tier: Mapped[str | None] = mapped_column(String(16), nullable=True)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    # executed | blocked | skipped | failed
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="executed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AgentDecision(Base):
    """Structured reasoning audit for one autonomous decision cycle (M4.4).

    Complements -- never replaces -- AgentStep: AgentStep stays the immutable
    chronological *action* audit (one row per tool_run/exploit/decision/etc.), while
    this captures the *structured reasoning* behind a `decide()` cycle that AgentStep's
    free-text `rationale` can only flatten: the evidence tiers (observations /
    inferences / hypotheses -- kept semantically distinct), the ranked candidate set
    the model proposed, the code-selected action, the stop reason, and the budget
    snapshot at decision time. Correlated to its AgentStep by (scan_id, step_no) plus
    the nullable `agent_step_id` FK -- no change to agent_steps. Findings, graph nodes
    and ATT&CK rows are NOT duplicated here; they live in their own tables and are
    referenced implicitly by scan_id + step_no. Tenant-scoped by its own workspace_id
    with ENABLE + FORCE RLS, same pattern as agent_steps / attack_narratives."""

    __tablename__ = "agent_decisions"
    __table_args__ = (UniqueConstraint("scan_id", "step_no", name="uq_agent_decisions_scan_step"),)

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Hard link to the chronological audit row for this cycle (agent_steps is NOT
    # modified; SET NULL keeps the decision if the step is ever removed).
    agent_step_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("agent_steps.id", ondelete="SET NULL"), nullable=True
    )
    step_no: Mapped[int] = mapped_column(Integer, nullable=False)
    phase: Mapped[str] = mapped_column(String(32), nullable=False)
    # run_tool | finish
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    # Evidence tiers -- kept DISTINCT (a hypothesis is never promoted to a fact).
    observations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    inferences: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    hypotheses: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # Ranked candidate set the model proposed (already allowlist-vetted): each
    # {tool, confidence, expected_value, risk, expected_evidence, rationale}.
    candidates: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    selected_tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    selected_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    stop_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Snapshot of the deterministic budget state at decision time (step/ai-call/
    # wall-clock counters + limits). Populated by the M4.4.3 stop policy.
    budget_state: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    model_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
