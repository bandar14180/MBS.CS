import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    target_id: uuid.UUID
    asset_type: str
    value: str
    metadata: dict = Field(validation_alias="metadata_", serialization_alias="metadata")
    first_seen: datetime
    last_seen: datetime
