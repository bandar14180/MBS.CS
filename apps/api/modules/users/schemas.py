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
