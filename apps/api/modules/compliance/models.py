import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Text, text, UniqueConstraint
from apps.api.core.db_types import GUID, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class ComplianceMapping(Base):
    """Maps one vulnerability to a control in a compliance framework
    (blueprint §5). A finding maps to zero-or-more controls across frameworks."""

    __tablename__ = "compliance_mappings"
    __table_args__ = (
        UniqueConstraint(
            "vulnerability_id", "framework", "control_id", name="uq_compliance_vuln_framework_control"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    framework: Mapped[str] = mapped_column(String(32), nullable=False)  # owasp | nist | iso27001 | pci_dss | cis
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    control_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
