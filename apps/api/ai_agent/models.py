import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Integer, Numeric, String, Text, text, UniqueConstraint
from apps.api.core.db_types import GUID, JSONType, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class AIPlan(Base):
    """A tool-sequencing decision produced by the AI Planner for one scan
    (blueprint §5). One plan per scan; the scan references it via scan_id."""

    __tablename__ = "ai_plans"
    # F3.4: one AI plan per scan -- the DB backstop to the F3.1 planner-reuse guard.
    __table_args__ = (UniqueConstraint("scan_id", name="uq_ai_plans_scan"),)

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool_sequence: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    reasoning_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    # model id + prompt version, so a plan is attributable to exactly what produced it
    model_version: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))


class AIUsageRow(Base):
    """One row per AI provider call: token counts + estimated cost, attributed to
    a workspace (and scan, when the call happened inside a scan). Feeds cost
    tracking (Task 15) and is written best-effort in its own transaction so a
    logging failure never affects the AI call or the scan. Tenant-scoped via
    workspace_id as a DIRECT table in apps/api/core/tenancy.py, like other tenant tables."""

    __tablename__ = "ai_usage"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), nullable=True, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_role: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prompt_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    estimated_cost_usd: Mapped[float] = mapped_column(Numeric(12, 6), nullable=False, default=0)
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prompt_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"), index=True
    )
