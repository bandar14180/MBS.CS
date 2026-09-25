"""Request/response models for Client Risk Assessments.

There is deliberately NO update model for an issued assessment and no writable field for
`security_score`, `score_band`, `summary`, or any frozen finding value. Those are taken from
the reporting pipeline at issue time; a client-supplied score would be exactly the "second
calculation" this design forbids.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

_STRICT = ConfigDict(extra="forbid")


class AssessmentCreate(BaseModel):
    model_config = _STRICT

    title: str = Field(min_length=1, max_length=255)
    period_start: datetime
    period_end: datetime


class AssessmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    workspace_id: uuid.UUID
    project_id: uuid.UUID | None
    title: str
    period_start: datetime
    period_end: datetime
    status: str
    # NULL while draft -- distinct from a score of 0, which would be a real (terrible) posture.
    security_score: int | None
    score_band: str | None
    summary: dict
    narrative: str | None
    narrative_source: str | None
    previous_assessment_id: uuid.UUID | None
    report_id: uuid.UUID | None
    created_by: uuid.UUID | None
    issued_by: uuid.UUID | None
    issued_at: datetime | None
    created_at: datetime


class AssessmentFindingRead(BaseModel):
    """A finding AS IT STOOD at issue time. Every value is a frozen copy -- reading through
    `vulnerability_id` to today's row would defeat the freeze, so clients must use these."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    assessment_id: uuid.UUID
    issue_key: str
    vulnerability_id: uuid.UUID | None
    frozen_title: str
    frozen_severity: str
    frozen_cvss_score: float | None
    frozen_final_risk_score: float | None
    frozen_vulnerability_status: str
    frozen_remediation_status: str | None
    risk_accepted: bool
    location_count: int
    created_at: datetime


class AssessmentComparisonRead(BaseModel):
    """Trend between two IMMUTABLE snapshots. Every delta is nullable: None means "no basis for
    comparison", which is deliberately distinct from 0 ("measured, unchanged")."""

    has_previous: bool
    previous_security_score: int | None = None
    security_score_delta: int | None = None
    direction: str | None = None
    active_findings_delta: int | None = None
    unresolved_issue_delta: int | None = None
    critical_delta: int | None = None
    high_delta: int | None = None
    remediation_completion_delta: int | None = None
