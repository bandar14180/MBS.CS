from fastapi import APIRouter, status

from apps.api.core.deps import CurrentUserDep, DbDep
from apps.api.modules.auth import service
from apps.api.modules.auth.schemas import (
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    MfaDisableRequest,
    MfaEnableResponse,
    MfaLoginRequest,
    MfaRecoveryCodesResponse,
    MfaVerifyEnableRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, db: DbDep) -> TokenResponse:
    user = await service.register_user(db, payload.email, payload.password, payload.full_name)
    return await service.issue_token_pair(db, user)


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, db: DbDep) -> LoginResponse:
    # Backward compatible: no-MFA users still get access_token/refresh_token here; MFA users get
    # mfa_required + a challenge token to finish at /auth/mfa/login.
    return await service.begin_login(db, payload.email, payload.password)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(payload: RefreshRequest, db: DbDep) -> TokenResponse:
    return await service.rotate_refresh_token(db, payload.refresh_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(payload: LogoutRequest, db: DbDep) -> None:
    await service.revoke_refresh_token(db, payload.refresh_token)


# --- MFA management (authenticated) --------------------------------------------------------

@router.post("/mfa/enable", response_model=MfaEnableResponse)
async def mfa_enable(db: DbDep, current_user: CurrentUserDep) -> MfaEnableResponse:
    """Begin enrollment: returns the provisioning URI (+ secret for manual entry). MFA is NOT
    enabled until /auth/mfa/verify-enable confirms a code."""
    return await service.start_mfa_enrollment(db, current_user)


@router.post("/mfa/verify-enable", response_model=MfaRecoveryCodesResponse)
async def mfa_verify_enable(
    payload: MfaVerifyEnableRequest, db: DbDep, current_user: CurrentUserDep
) -> MfaRecoveryCodesResponse:
    """Confirm the first code, enable MFA, and return one-time recovery codes (shown once)."""
    return await service.verify_and_enable_mfa(db, current_user, payload.code)


@router.post("/mfa/login", response_model=TokenResponse)
async def mfa_login(payload: MfaLoginRequest, db: DbDep) -> TokenResponse:
    """Complete a login that required MFA: exchange the mfa challenge token + code for tokens."""
    return await service.complete_mfa_login(db, payload.mfa_token, payload.code)


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_disable(payload: MfaDisableRequest, db: DbDep, current_user: CurrentUserDep) -> None:
    """Disable MFA (requires password + a current TOTP or recovery code)."""
    await service.disable_mfa(db, current_user, payload.password, payload.code)
