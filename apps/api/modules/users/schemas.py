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


class ExportSummary(BaseModel):
    workspace_count: int
    api_key_count: int
    active_api_key_count: int
    last_login_at: datetime | None


class DataExportResponse(BaseModel):
    generated_at: datetime
    profile: ExportProfile
    workspaces: list[ExportedMembership]
    api_keys: list[ExportedApiKey]
    activity_summary: ExportSummary
