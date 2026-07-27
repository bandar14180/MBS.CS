import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class RiskScoreRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    vulnerability_id: uuid.UUID
    business_impact_score: float | None
    asset_criticality_weight: float
    final_risk_score: float | None
    rationale: str | None
    computed_at: datetime
