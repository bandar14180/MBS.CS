import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ReportCreate(BaseModel):
    # `risk_assessment` is issued through the assessment endpoints, which call
    # reports.service.create_report internally with the assessment id. It is deliberately
    # NOT offered here: a client-initiated risk_assessment report would have no snapshot to
    # render, and allowing the type without an assessment_id could only ever 400.
    type: Literal["executive", "technical"]
    scan_ids: list[uuid.UUID] = Field(default_factory=list, description="Optional; empty = whole project")


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    type: str
    format: str
    storage_uri: str | None
    scan_ids: list
    # Prompt 13, Finding #8: True once the retention sweep has deleted at least one scan named
    # in `scan_ids` after this report was generated. `scan_ids` itself is never rewritten, so a
    # client reading this report can always see BOTH what was originally cited AND whether that
    # citation is now stale, rather than silently trusting a dangling reference.
    scans_purged: bool
    generated_by: uuid.UUID | None
    generated_at: datetime
