import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SettableStatus = Literal["open", "confirmed", "false_positive", "fixed", "accepted_risk"]


class VulnerabilityRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    asset_id: uuid.UUID | None
    first_detected_scan_id: uuid.UUID | None
    last_seen_scan_id: uuid.UUID | None
    fingerprint: str
    title: str
    category: str | None
    description: str | None
    severity: str
    cvss_vector: str | None
    cvss_score: float | None
    status: str
    status_justification: str | None
    ai_validated: bool
    ai_confidence: float | None
    created_at: datetime
    updated_at: datetime


class VulnerabilityStatusUpdate(BaseModel):
    status: SettableStatus
    # Required: marking something false-positive / accepted-risk is itself a
    # security-relevant, auditable decision (blueprint §6).
    justification: str = Field(min_length=1, max_length=4096)


class RemediationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    vulnerability_id: uuid.UUID
    summary: str | None
    steps: list
    references: list = Field(validation_alias="reference_links", serialization_alias="references")
    generated_by: str
    model_version: str | None
    prompt_version: str | None
    created_at: datetime


class FPAssessmentRead(BaseModel):
    finding_id: uuid.UUID
    likely_false_positive: bool
    confidence: str
    reasoning: str


class FPAnalysisRead(BaseModel):
    model_version: str
    prompt_version: str
    assessments: list[FPAssessmentRead]
