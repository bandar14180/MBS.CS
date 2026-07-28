import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ScheduleCreate(BaseModel):
    target_id: uuid.UUID
    scan_type: str
    requested_modules: list[str] = Field(min_length=1)
    interval_minutes: int = Field(ge=5, le=60 * 24 * 30, description="How often to run, in minutes (5 min – 30 days).")
    use_ai_planner: bool = False


class ScheduleUpdate(BaseModel):
    enabled: bool | None = None
    interval_minutes: int | None = Field(default=None, ge=5, le=60 * 24 * 30)


class ScheduleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    workspace_id: uuid.UUID
    project_id: uuid.UUID
    target_id: uuid.UUID
    scan_type: str
    requested_modules: list
    use_ai_planner: bool
    interval_minutes: int
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    last_scan_id: uuid.UUID | None
    last_error: str | None
    created_at: datetime
