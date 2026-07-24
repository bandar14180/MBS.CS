from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    refresh_token_expiry,
    verify_password,
)
from apps.api.modules.auth.models import RefreshToken
from apps.api.modules.auth.schemas import TokenResponse
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

    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()
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
