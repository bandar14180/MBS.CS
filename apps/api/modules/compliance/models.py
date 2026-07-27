import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
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

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    framework: Mapped[str] = mapped_column(String(32), nullable=False)  # owasp | nist | iso27001 | pci_dss | cis
    control_id: Mapped[str] = mapped_column(String(64), nullable=False)
    control_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
