import uuid
from datetime import datetime

from sqlalchemy import String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base
from apps.api.core.db_types import GUID, UTCDateTime


class PlatformAuditEvent(Base):
    """Durable, NON-cascading platform-level audit for destructive tenant operations.

    Deliberately unlike AuditEvent: `workspace_id` is a BARE GUID column with NO foreign key to
    workspaces, so the record SURVIVES the workspace's hard deletion (an FK + ON DELETE CASCADE
    would take the record with the tenant). It is also NOT workspace-auto-filtered by
    apps/api/core/tenancy.py -- it is a platform record, written from the deletion task with
    an explicit workspace_id. Append-only; secret-free.

    Used for tenant.delete.requested / tenant.delete.completed / tenant.delete.failed, each with
    the workspace_id, actor, event/outcome, timestamp, and optional non-sensitive detail.
    """

    __tablename__ = "platform_audit_events"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    # NO ForeignKey -- must outlive the workspace row.
    #
    # NULLABLE since P8-G (migration e6f7a8b9c0d1): NULL means PLATFORM-SCOPED -- an event
    # that genuinely has no workspace, such as the private-scanning emergency kill switch
    # (platform-wide by definition) or an action on a SHARED PUBLIC scanner worker, whose
    # own `scanner_workers.workspace_id` is already NULL. This follows the convention the
    # repository already uses for exactly this meaning (`roles.workspace_id` NULL = a
    # system/global role); there is no sentinel-UUID convention here, and inventing one
    # would have produced a value that looks like a foreign key but references nothing.
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), nullable=True, index=True)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(GUID(), nullable=True)
    event: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # e.g. tenant.delete.completed
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)  # non-sensitive summary only
    # Prompt 34: joins this platform event to the originating request/task. Same id the
    # middleware exposes as X-Request-ID; NULL when written outside a correlated context.
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"), index=True
    )
