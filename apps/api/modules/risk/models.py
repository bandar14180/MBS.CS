import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class RiskScore(Base):
    """Business risk for one vulnerability (blueprint §5). Distinct from CVSS:
    CVSS is technical severity; this weights it by asset criticality + business
    context. One row per vulnerability, recomputed on re-detection."""

    __tablename__ = "risk_scores"
    __table_args__ = (UniqueConstraint("vulnerability_id", name="uq_risk_scores_vulnerability"),)

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    business_impact_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    asset_criticality_weight: Mapped[float] = mapped_column(Float, nullable=False)
    final_risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
