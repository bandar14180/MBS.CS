import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ProofType = Literal["dns_txt", "file_upload", "signed_letter", "cloud_iam_role"]


class AuthorizationScopeSubmit(BaseModel):
    proof_type: ProofType
    proof_reference: str = Field(
        min_length=1,
        max_length=4096,
        description="e.g. the expected DNS TXT value, a URL to the uploaded file/letter, or a cloud role ARN",
    )
    scope_notes: str | None = Field(default=None, max_length=4096)
    expires_at: datetime | None = None


class AuthorizationScopeVerify(BaseModel):
    active_testing_allowed: bool = False
    expires_at: datetime | None = None
    scope_notes: str | None = Field(default=None, max_length=4096)


class AuthorizationScopeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    proof_type: str
    proof_reference: str
    verified: bool
    verified_by: uuid.UUID | None
    verified_at: datetime | None
    active_testing_allowed: bool
    scope_notes: str | None
    expires_at: datetime | None
    created_at: datetime
