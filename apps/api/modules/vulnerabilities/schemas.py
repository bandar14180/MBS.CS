import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, computed_field, ConfigDict, Field

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

    @computed_field  # type: ignore[prop-decorator]
    @property
    def classification(self) -> str:
        """"vulnerability" or "detection" -- DERIVED, never stored.

        WHY IT IS EXPOSED: the security score excludes detection-only findings
        (reports/scoring.is_scorable), so without this field a client sees an open
        medium-severity finding that contributes nothing to the score, with no way to tell
        why. The PDF already labels it; the API did not, so the same row read as a
        DETECTION in the technical report and as an ordinary vulnerability everywhere else.

        WHY IT IS NOT A COLUMN: the value is a pure function of fields already stored
        (fingerprint/cvss_score/category/title). Persisting it would go stale whenever the
        classifier's rules change and would need a migration plus a backfill, so it is
        derived on read from the SAME canonical classifier the report and the score use --
        there is exactly one set of rules (reports/classification.py), including the CVE
        recovery and detection guards.

        Additive only: existing consumers that ignore the field are unaffected."""
        from apps.api.modules.reports.classification import classify_row
        from apps.api.modules.reports.data import _parse_fingerprint

        # classify_row reads template_id; the stored form is the fingerprint
        # (`template_id|matcher|matched_at`), parsed by the canonical helper so the API and
        # the report always recover the same template_id.
        template_id, _matcher, _matched_at = _parse_fingerprint(self.fingerprint)

        class _Row:
            pass

        row = _Row()
        row.template_id = template_id
        row.title = self.title
        row.cvss_score = self.cvss_score
        row.category = self.category
        return classify_row(row)


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
