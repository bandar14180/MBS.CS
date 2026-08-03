import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
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
