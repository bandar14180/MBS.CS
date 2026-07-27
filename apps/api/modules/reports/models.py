import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class Report(Base):
    """A generated report over a project's findings (blueprint §5). The PDF bytes
    live in object storage; this row is the record + pointer."""

    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    type: Mapped[str] = mapped_column(String(16), nullable=False)  # executive | technical
    format: Mapped[str] = mapped_column(String(8), nullable=False, default="pdf")
    storage_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    # scans included in the report; empty/absent = the whole project
    scan_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    generated_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
