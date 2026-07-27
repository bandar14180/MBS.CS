import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ReportCreate(BaseModel):
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
    generated_by: uuid.UUID | None
    generated_at: datetime
