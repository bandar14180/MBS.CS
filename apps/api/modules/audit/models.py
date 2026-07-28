import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class AuditEvent(Base):
    """Immutable security-relevant activity log (append-only). Tenant-scoped with
    ENABLE + FORCE RLS on workspace_id. Supports ISO 27001 / SOC-2 style logging
    requirements. Written in the same request session/RLS context as the action."""

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Nullable: the actor may be removed later (ondelete SET NULL keeps the event).
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_email: Mapped[str | None] = mapped_column(String(255), nullable=True)  # denormalized for durability

    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # e.g. scan.created
    resource_type: Mapped[str] = mapped_column(String(48), nullable=False)  # e.g. scan, vulnerability
    resource_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
