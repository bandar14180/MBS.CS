import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint, func
from apps.api.core.db_types import GUID, JSONType, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class Remediation(Base):
    """Remediation guidance for one vulnerability (blueprint §5). One row per
    vuln (regenerated/overwritten on demand)."""

    __tablename__ = "remediations"
    __table_args__ = (UniqueConstraint("vulnerability_id", name="uq_remediations_vulnerability"),)

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    steps: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    # "references" is a reserved SQL word -> reference_links (exposed as `references` in the API).
    reference_links: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    generated_by: Mapped[str] = mapped_column(String(16), nullable=False, default="ai")  # ai | human
    model_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=func.now())
