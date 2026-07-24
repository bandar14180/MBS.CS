import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class WorkspaceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)


class WorkspaceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    plan_tier: str
    owner_user_id: uuid.UUID
    created_at: datetime


class MemberInvite(BaseModel):
    email: EmailStr
    role_name: str = Field(description="Name of an existing system or workspace role, e.g. 'admin'")


class MemberRoleUpdate(BaseModel):
    role_name: str


class MemberRead(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    email: EmailStr
    full_name: str
    role_name: str
    invited_at: datetime
    joined_at: datetime | None


class RoleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    workspace_id: uuid.UUID | None
    name: str
    description: str | None
