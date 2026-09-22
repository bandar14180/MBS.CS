import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

TargetType = Literal["domain", "ip_range", "api", "cloud_account", "repo"]


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    status: str | None = None


class ProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    workspace_id: uuid.UUID
    name: str
    description: str | None
    status: str
    created_by: uuid.UUID
    created_at: datetime


Criticality = Literal["low", "medium", "high", "critical"]


class TargetCreate(BaseModel):
    # P7-2. `site_id` is the ONLY new authority-adjacent input, and it is an IDENTIFIER
    # REQUIRING AUTHORIZATION -- never proof of it. The service resolves it against the
    # caller's own workspace (`get_site_for_workspace`) before it may influence anything.
    #
    # `network_zone` is deliberately NOT a field. It is DERIVED server-side:
    # site_id present -> "private", absent -> "public". Accepting it would let a client
    # state its own execution context, which is exactly the bypass P7-2 must not create.
    # `extra="forbid"` makes a client that tries to send it fail loudly (422) instead of
    # having the value silently dropped and believing it took effect.
    model_config = ConfigDict(extra="forbid")

    type: TargetType
    value: str = Field(min_length=1, max_length=512)
    criticality: Criticality = "medium"
    site_id: uuid.UUID | None = None


class TargetUpdate(BaseModel):
    criticality: Criticality


class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    type: str
    value: str
    criticality: str
    # P7-2: the SERVER-DERIVED execution context, echoed back so a caller can see what was
    # actually recorded rather than what it asked for. Read-only by construction -- these
    # come from the persisted row, and `TargetCreate` has no `network_zone` to set.
    network_zone: str
    site_id: uuid.UUID | None
    added_by: uuid.UUID
    created_at: datetime
