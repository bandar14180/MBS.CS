import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ComplianceMappingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    vulnerability_id: uuid.UUID
    framework: str
    control_id: str
    control_description: str | None
    created_at: datetime
