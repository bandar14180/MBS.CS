import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ScanType = Literal["web", "api", "network", "cloud"]


class ScanCreate(BaseModel):
    target_id: uuid.UUID
    scan_type: ScanType
    requested_modules: list[str] = Field(
        min_length=1, description="Tool keys from the scanner_engine tool registry, e.g. ['naabu']"
    )


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    workspace_id: uuid.UUID
    project_id: uuid.UUID
    target_id: uuid.UUID
    initiated_by: uuid.UUID
    scan_type: str
    status: str
    config: dict
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class ToolRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    tool_name: str
    tool_version: str
    status: str
    command_hash: str
    started_at: datetime
    completed_at: datetime | None
    exit_code: int | None
    raw_output_ref: str | None


class EvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tool_run_id: uuid.UUID
    evidence_type: str
    storage_uri: str
    checksum: str
    created_at: datetime
