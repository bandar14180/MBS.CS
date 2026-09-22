import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, String, Text, text
from apps.api.core.db_types import GUID, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class AuthorizationScope(Base):
    __tablename__ = "authorization_scopes"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    target_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    proof_type: Mapped[str] = mapped_column(String(32), nullable=False)
    proof_reference: Mapped[str] = mapped_column(Text, nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    verified_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    active_testing_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    scope_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
