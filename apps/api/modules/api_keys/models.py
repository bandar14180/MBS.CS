import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, String, text
from apps.api.core.db_types import GUID, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class ApiKey(Base):
    """A workspace-scoped API key for programmatic access. Deliberately NOT
    auto-filtered: the key is looked up by hash during authentication, BEFORE any workspace
    context is bound (the key itself determines the workspace). It is in
    tenancy.EXEMPT_TABLES and its call sites filter workspace_id explicitly.
    Same rationale as the `scans` table. Tenant isolation for the management
    endpoints is by explicit workspace_id filter + workspace:manage permission.

    Only the SHA-256 hash of the secret is stored; the plaintext is shown once.
    A key acts as its creator within its bound workspace."""

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    prefix: Mapped[str] = mapped_column(String(20), nullable=False)  # shown in UI, e.g. mbsk_Ab3xY9z
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
