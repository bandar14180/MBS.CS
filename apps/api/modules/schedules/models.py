import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, String, text
from apps.api.core.db_types import GUID, JSONType, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class ScanSchedule(Base):
    """A recurring scan. Deliberately NOT RLS-protected -- same rationale as the
    `scans` table: the Celery-beat scheduler has no HTTP request / workspace
    context, so it reads ALL due schedules across workspaces by trusted internal
    query, then bootstraps the RLS session var from this row's trusted
    workspace_id before creating each scan. API endpoints scope by workspace_id
    explicitly + require_permission."""

    __tablename__ = "scan_schedules"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )

    scan_type: Mapped[str] = mapped_column(String(32), nullable=False)
    requested_modules: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    use_ai_planner: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    next_run_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
