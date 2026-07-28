import hashlib
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.api_keys.models import ApiKey

KEY_PREFIX = "mbsk_"


def _hash(raw: str) -> str:
    # API keys are 256-bit random tokens, so a fast SHA-256 is appropriate for
    # constant-time-ish indexed lookup (unlike low-entropy passwords).
    return hashlib.sha256(raw.encode()).hexdigest()


def _generate() -> tuple[str, str, str]:
    """Returns (raw_key, display_prefix, key_hash). The raw key is shown once."""
    raw = KEY_PREFIX + secrets.token_urlsafe(32)
    return raw, raw[:12], _hash(raw)


async def create_key(
    db: AsyncSession, workspace_id: uuid.UUID, created_by: uuid.UUID, name: str
) -> tuple[ApiKey, str]:
    raw, prefix, key_hash = _generate()
    key = ApiKey(
        workspace_id=workspace_id, created_by=created_by, name=name, prefix=prefix, key_hash=key_hash
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return key, raw


async def list_keys(db: AsyncSession, workspace_id: uuid.UUID) -> list[ApiKey]:
    result = await db.scalars(
        select(ApiKey).where(ApiKey.workspace_id == workspace_id).order_by(ApiKey.created_at.desc())
    )
    return list(result)


async def revoke_key(db: AsyncSession, workspace_id: uuid.UUID, key_id: uuid.UUID) -> None:
    key = await db.scalar(select(ApiKey).where(ApiKey.id == key_id, ApiKey.workspace_id == workspace_id))
    if key is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")
    key.revoked = True
    await db.commit()


async def authenticate_key(db: AsyncSession, raw: str) -> ApiKey | None:
    """Resolve a raw API key to its (non-revoked) row and stamp last_used_at.
    Returns None if unknown or revoked. Runs during auth, before any workspace
    RLS context (api_keys is RLS-exempt by design)."""
    key = await db.scalar(
        select(ApiKey).where(ApiKey.key_hash == _hash(raw), ApiKey.revoked.is_(False))
    )
    if key is None:
        return None
    # Best-effort usage stamp; committed now so it persists even on read-only
    # requests. Isolated UPDATE so it doesn't entangle later request state.
    await db.execute(
        update(ApiKey).where(ApiKey.id == key.id).values(last_used_at=datetime.now(timezone.utc))
    )
    await db.commit()
    return key
