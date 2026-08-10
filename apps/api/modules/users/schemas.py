import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    full_name: str
    status: str
    mfa_enabled: bool
    created_at: datetime
    last_login_at: datetime | None


class ProfileUpdate(BaseModel):
    full_name: str = Field(min_length=1, max_length=255)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=8, max_length=200)


class AccountDeleteRequest(BaseModel):
    """Confirmation for irreversible account erasure. The password re-check means a
    leaked access token alone cannot erase the account."""

    password: str = Field(min_length=1)


# --- Personal data export (GDPR Art. 15/20). Metadata only -- no secrets or hashes. ---


class ExportProfile(BaseModel):
    id: uuid.UUID
    email: EmailStr
    full_name: str
    status: str
    mfa_enabled: bool
    mfa_enabled_at: datetime | None
    created_at: datetime
    last_login_at: datetime | None


class ExportedMembership(BaseModel):
    workspace_id: uuid.UUID
    workspace_name: str
    role_name: str
    invited_at: datetime
    joined_at: datetime | None


class ExportedApiKey(BaseModel):
    name: str
    prefix: str  # non-secret display prefix; the key hash is never exported
    revoked: bool
    created_at: datetime
    last_used_at: datetime | None


class ExportedScan(BaseModel):
    # Metadata only -- no scan config, no evidence, no tool output.
    id: uuid.UUID
    workspace_id: uuid.UUID
    scan_type: str
    status: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class ExportedReport(BaseModel):
    # Metadata only -- the storage_uri (internal object path) and PDF bytes are NEVER exported.
    id: uuid.UUID
    project_id: uuid.UUID
    type: str
    format: str
    scan_ids: list[str]
    generated_at: datetime


class ExportedAuditEvent(BaseModel):
    # Safe metadata only -- the free-text `detail` is deliberately excluded (may reference
    # other subjects/resources), preserving compliance integrity without over-sharing.
    id: uuid.UUID
    workspace_id: uuid.UUID
    action: str
    resource_type: str
    resource_id: uuid.UUID | None
    created_at: datetime


class ExportSummary(BaseModel):
    workspace_count: int
    api_key_count: int
    active_api_key_count: int
    # Additive counts (backward compatible -- default 0 so older snapshots still validate).
    scan_count: int = 0
    report_count: int = 0
    audit_event_count: int = 0
    last_login_at: datetime | None


class DataExportResponse(BaseModel):
    generated_at: datetime
    profile: ExportProfile
    workspaces: list[ExportedMembership]
    api_keys: list[ExportedApiKey]
    # Additive lists (default [] -> backward compatible; existing clients ignore new fields).
    scans: list[ExportedScan] = []
    reports: list[ExportedReport] = []
    audit_events: list[ExportedAuditEvent] = []
    activity_summary: ExportSummary
