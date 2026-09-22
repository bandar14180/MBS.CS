import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, text
from apps.api.core.db_types import GUID, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class Workspace(Base):
    __tablename__ = "workspaces"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    plan_tier: Mapped[str] = mapped_column(String(32), nullable=False, default="pilot")
    owner_user_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    # Lifecycle gate for tenant deletion. "active" is the normal state; a workspace flips to
    # "deleting" the instant a delete is requested, and the row is then HARD-removed once the
    # async task finishes (no "deleted" tombstone -- hard deletion removes the workspace row).
    # While "deleting", get_workspace_context rejects new mutating operations so nothing can be
    # created into a half-torn-down tenant.
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default="active", default="active")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
