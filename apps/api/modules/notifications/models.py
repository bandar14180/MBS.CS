import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, String, Text, text
from apps.api.core.db_types import GUID, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class Notification(Base):
    """In-app notification (continuous-security alerts + scan outcomes). Tenant-
    scoped: a DIRECT table in apps/api/core/tenancy.py, auto-filtered on workspace_id. The
    Celery worker inserts these with the workspace already bound (it's mid-scan for that
    workspace)."""

    __tablename__ = "notifications"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), nullable=True)

    # scan_completed | scan_failed | critical_findings
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    # info | warning | critical
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"), index=True)
