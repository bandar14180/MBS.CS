import uuid
from datetime import datetime

from sqlalchemy import Float, ForeignKey, Text, text, UniqueConstraint
from apps.api.core.db_types import GUID, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class RiskScore(Base):
    """Business risk for one vulnerability (blueprint §5). Distinct from CVSS:
    CVSS is technical severity; this weights it by asset criticality + business
    context. One row per vulnerability, recomputed on re-detection."""

    __tablename__ = "risk_scores"
    __table_args__ = (UniqueConstraint("vulnerability_id", name="uq_risk_scores_vulnerability"),)

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    business_impact_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    asset_criticality_weight: Mapped[float] = mapped_column(Float, nullable=False)
    final_risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    computed_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
