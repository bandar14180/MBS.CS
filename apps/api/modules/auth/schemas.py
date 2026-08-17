from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=255)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# --- MFA (Sprint 1, Step 2) ----------------------------------------------------------------

class LoginResponse(BaseModel):
    """Login result. Backward compatible: a user WITHOUT MFA gets access_token/refresh_token
    exactly as before (mfa_required=False). A user WITH MFA gets mfa_required=True + a short-lived
    mfa_token to complete the second factor at /auth/mfa/login (no session tokens yet)."""

    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    mfa_required: bool = False
    mfa_token: str | None = None


class MfaEnableResponse(BaseModel):
    # Returned ONLY during setup (before verification). The secret is never returned again.
    provisioning_uri: str
    secret: str


class MfaVerifyEnableRequest(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class MfaRecoveryCodesResponse(BaseModel):
    recovery_codes: list[str]


class MfaLoginRequest(BaseModel):
    mfa_token: str
    code: str = Field(min_length=6, max_length=32)  # a TOTP (6 digits) or a recovery code


class MfaDisableRequest(BaseModel):
    password: str
    code: str = Field(min_length=6, max_length=32)
