import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class AIPlan(Base):
    """A tool-sequencing decision produced by the AI Planner for one scan
    (blueprint §5). One plan per scan; the scan references it via scan_id."""

    __tablename__ = "ai_plans"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool_sequence: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    reasoning_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    # model id + prompt version, so a plan is attributable to exactly what produced it
    model_version: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
