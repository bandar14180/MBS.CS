import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class NotificationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    workspace_id: uuid.UUID
    project_id: uuid.UUID | None
    scan_id: uuid.UUID | None
    type: str
    severity: str
    title: str
    body: str | None
    read: bool
    created_at: datetime


class UnreadCount(BaseModel):
    count: int
