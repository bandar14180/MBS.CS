import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    actor_user_id: uuid.UUID | None
    actor_email: str | None
    action: str
    resource_type: str
    resource_id: uuid.UUID | None
    detail: str | None
    outcome: str | None
    correlation_id: str | None
    created_at: datetime
