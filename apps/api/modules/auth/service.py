import uuid
from datetime import datetime, timezone

import jwt
from fastapi import HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core import mfa
from apps.api.core.security import (
    create_access_token,
    create_mfa_challenge_token,
    decode_mfa_challenge_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    refresh_token_expiry,
    verify_password,
)
from apps.api.modules.auth import mfa_guard
from apps.api.modules.auth.models import MfaRecoveryCode, RefreshToken
from apps.api.modules.auth.schemas import (
    LoginResponse,
    MfaEnableResponse,
    MfaRecoveryCodesResponse,
    TokenResponse,
)
from apps.api.modules.users.models import User


async def register_user(db: AsyncSession, email: str, password: str, full_name: str) -> User:
    existing = await db.scalar(select(User).where(User.email == email))
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    user = User(email=email, password_hash=hash_password(password), full_name=full_name)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def authenticate_user(db: AsyncSession, email: str, password: str) -> User:
    user = await db.scalar(select(User).where(User.email == email))
    if user is None or not verify_password(password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password")
    if user.status != "active":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account is not active")
    # NOTE (Step 3): last_login_at is deliberately NOT set here. A correct password is only the
    # FIRST factor; for MFA users the login is not complete until the second factor. It is set at
    # the point tokens are actually issued -- begin_login (no-MFA) / complete_mfa_login (MFA).
    return user


async def issue_token_pair(db: AsyncSession, user: User) -> TokenResponse:
    raw_refresh = generate_refresh_token()
    db.add(
        RefreshToken(
            user_id=user.id,
            token_hash=hash_refresh_token(raw_refresh),
            expires_at=refresh_token_expiry(),
        )
    )
    await db.commit()
    return TokenResponse(access_token=create_access_token(user.id), refresh_token=raw_refresh)


async def rotate_refresh_token(db: AsyncSession, raw_token: str) -> TokenResponse:
    token_hash = hash_refresh_token(raw_token)
    existing = await db.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))

    now = datetime.now(timezone.utc)
    if existing is None or existing.revoked_at is not None or existing.expires_at < now:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired refresh token")

    user = await db.get(User, existing.user_id)
    if user is None or user.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")

    new_raw_refresh = generate_refresh_token()
    new_token = RefreshToken(
        user_id=user.id,
        token_hash=hash_refresh_token(new_raw_refresh),
        expires_at=refresh_token_expiry(),
    )
    db.add(new_token)
    await db.flush()

    existing.revoked_at = now
    existing.replaced_by_id = new_token.id
    await db.commit()

    return TokenResponse(access_token=create_access_token(user.id), refresh_token=new_raw_refresh)


async def revoke_refresh_token(db: AsyncSession, raw_token: str) -> None:
    token_hash = hash_refresh_token(raw_token)
    existing = await db.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    if existing is not None and existing.revoked_at is None:
        existing.revoked_at = datetime.now(timezone.utc)
        await db.commit()


# --- MFA (Sprint 1, Step 2) ----------------------------------------------------------------

async def begin_login(db: AsyncSession, email: str, password: str) -> LoginResponse:
    """Password step. UNCHANGED for users without MFA (tokens issued immediately). A user WITH MFA
    receives an mfa_required challenge instead of tokens -- no session exists until the second
    factor succeeds. Reuses the existing authenticate_user + issue_token_pair verbatim."""
    user = await authenticate_user(db, email, password)  # verifies password + active status
    if user.mfa_enabled:
        return LoginResponse(mfa_required=True, mfa_token=create_mfa_challenge_token(user.id))
    user.last_login_at = datetime.now(timezone.utc)  # no-MFA login is complete here
    tokens = await issue_token_pair(db, user)         # commits (persists last_login_at too)
    return LoginResponse(access_token=tokens.access_token, refresh_token=tokens.refresh_token)


async def start_mfa_enrollment(db: AsyncSession, user: User) -> MfaEnableResponse:
    """Generate + store an ENCRYPTED TOTP secret and return the provisioning URI. Does NOT enable
    MFA -- that requires a verified code (prevents locking a user out with a mistyped secret)."""
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already enabled")
    secret = mfa.generate_totp_secret()
    user.mfa_secret_encrypted = mfa.encrypt_secret(secret)  # never persisted in plaintext
    await db.commit()
    return MfaEnableResponse(
        provisioning_uri=mfa.provisioning_uri(secret, account_name=user.email), secret=secret
    )


async def verify_and_enable_mfa(db: AsyncSession, user: User, code: str) -> MfaRecoveryCodesResponse:
    """Confirm the first TOTP code, enable MFA, and issue one-time recovery codes (returned once,
    stored only as hashes)."""
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already enabled")
    if not user.mfa_secret_encrypted:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Start enrollment via /auth/mfa/enable first")
    await mfa_guard.assert_not_locked(user.id)  # per-user brute-force lockout
    if not mfa.verify_totp(mfa.decrypt_secret(user.mfa_secret_encrypted), code):
        await mfa_guard.record_failure(user.id)
        mfa_guard.security_event("mfa.verify_failed", user_id=user.id)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid MFA code")
    await mfa_guard.clear(user.id)

    user.mfa_enabled = True
    user.mfa_enabled_at = datetime.now(timezone.utc)
    raw_codes = mfa.generate_recovery_codes()
    for c in raw_codes:
        db.add(MfaRecoveryCode(user_id=user.id, code_hash=mfa.hash_recovery_code(c)))
    await db.commit()
    mfa_guard.security_event("mfa.enabled", user_id=user.id)
    return MfaRecoveryCodesResponse(recovery_codes=raw_codes)


async def _consume_recovery_code(db: AsyncSession, user: User, code: str) -> bool:
    """Redeem an unused recovery code (one-time). Flushes; the caller commits."""
    rc = await db.scalar(
        select(MfaRecoveryCode).where(
            MfaRecoveryCode.user_id == user.id,
            MfaRecoveryCode.code_hash == mfa.hash_recovery_code(code),
            MfaRecoveryCode.used_at.is_(None),
        )
    )
    if rc is None:
        return False
    rc.used_at = datetime.now(timezone.utc)
    await db.flush()
    return True


async def complete_mfa_login(db: AsyncSession, mfa_token: str, code: str) -> TokenResponse:
    """Second factor: validate the mfa challenge token + a TOTP (or recovery code), then issue the
    normal token pair via the existing issue_token_pair."""
    try:
        payload = decode_mfa_challenge_token(mfa_token)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired MFA challenge")

    user = await db.get(User, uuid.UUID(payload["sub"]))
    if user is None or user.status != "active" or not user.mfa_enabled:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid MFA state")

    await mfa_guard.assert_not_locked(user.id)  # per-user brute-force lockout
    secret = mfa.decrypt_secret(user.mfa_secret_encrypted) if user.mfa_secret_encrypted else ""
    used_recovery = False
    if secret and mfa.verify_totp(secret, code):
        ok = True
    else:
        ok = await _consume_recovery_code(db, user, code)
        used_recovery = ok
    if not ok:
        await mfa_guard.record_failure(user.id)
        mfa_guard.security_event("mfa.login_failed", user_id=user.id)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid MFA code")

    await mfa_guard.clear(user.id)
    user.last_login_at = datetime.now(timezone.utc)  # MFA login is complete only now
    mfa_guard.security_event("mfa.login_success", user_id=user.id, method="recovery_code" if used_recovery else "totp")
    if used_recovery:
        mfa_guard.security_event("mfa.recovery_code_used", user_id=user.id)
    return await issue_token_pair(db, user)


async def disable_mfa(db: AsyncSession, user: User, password: str, code: str) -> None:
    """Disable MFA securely -- requires the account password AND a current TOTP (or recovery code).
    Clears the encrypted secret + all recovery codes."""
    if not user.mfa_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MFA is not enabled")
    if not verify_password(password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect password")
    secret = mfa.decrypt_secret(user.mfa_secret_encrypted) if user.mfa_secret_encrypted else ""
    if not ((secret and mfa.verify_totp(secret, code)) or await _consume_recovery_code(db, user, code)):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid MFA code")

    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    user.mfa_enabled_at = None
    await db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    await db.commit()
    mfa_guard.security_event("mfa.disabled", user_id=user.id)
