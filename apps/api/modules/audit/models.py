import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, text, Text
from apps.api.core.db_types import GUID, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class AuditEvent(Base):
    """Immutable security-relevant activity log (append-only). Tenant-scoped with
    a DIRECT table in apps/api/core/tenancy.py, auto-filtered on workspace_id. Supports
    ISO 27001 / SOC-2 style logging requirements. Written in the same request session and
    bound workspace context as the action it records."""

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Nullable: the actor may be removed later (ondelete SET NULL keeps the event).
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_email: Mapped[str | None] = mapped_column(String(255), nullable=True)  # denormalized for durability

    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # e.g. scan.created
    resource_type: Mapped[str] = mapped_column(String(48), nullable=False)  # e.g. scan, vulnerability
    resource_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Prompt 34. OUTCOME of the recorded action ("success" / "failure" / "denied"), so a
    # reader can distinguish an attempted action from a completed one without parsing
    # `detail` prose. Nullable because events written before this column existed -- and
    # callers that genuinely have no outcome to report -- carry NULL rather than a
    # fabricated "success".
    outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Prompt 34. Joins this event to the originating HTTP request / background task via the
    # SAME id the middleware puts in X-Request-ID and the logs (core/observability.py).
    # Nullable: work outside a request context (a Celery task with no inbound header) has
    # no correlation id, and "-" (the contextvar default) is normalized to NULL.
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"), index=True)
