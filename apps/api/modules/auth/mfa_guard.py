"""MFA production hardening (Sprint 1, Step 3): per-user brute-force lockout + security audit
logging. Independent of the IP-based RateLimitMiddleware -- a distributed attacker rotating IPs is
still throttled per account.

Lockout is Redis-backed and BEST-EFFORT: if Redis is unreachable it fails OPEN (allows the
attempt) and logs a warning, matching the IP rate limiter's availability-over-enforcement stance.

Audit events go to the 'mbs.security' structured logger (auth happens before any workspace
context, so the tenant-scoped audit_events table is not the right sink). Events NEVER include a
secret, a code, or a token -- only the user id + outcome.
"""
import logging

from fastapi import HTTPException, status

from apps.api.core.config import get_settings

logger = logging.getLogger("mbs.security")


def security_event(event: str, *, user_id, **fields) -> None:
    """Emit a secret-free structured security event (mfa.enabled / mfa.disabled /
    mfa.verify_failed / mfa.login_success / mfa.login_failed / mfa.recovery_code_used)."""
    logger.info(event, extra={"event": event, "user_id": str(user_id), **fields})


def _key(user_id) -> str:
    return f"mfa:fail:{user_id}"


async def _redis():
    import redis.asyncio as aioredis

    return aioredis.from_url(get_settings().redis_url, encoding="utf-8", decode_responses=True)


async def assert_not_locked(user_id) -> None:
    """Raise 429 if the user has reached mfa_max_attempts within the lockout window. Best-effort:
    a Redis outage fails open (does not raise)."""
    settings = get_settings()
    try:
        client = await _redis()
        try:
            count = await client.get(_key(user_id))
        finally:
            await client.aclose()
    except Exception:  # noqa: BLE001 -- availability over enforcement (fail open)
        logger.warning("mfa lockout check unavailable; allowing attempt", exc_info=True)
        return
    if count is not None and int(count) >= settings.mfa_max_attempts:
        security_event("mfa.locked", user_id=user_id)
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many MFA attempts; try again later")


async def record_failure(user_id) -> None:
    """Increment the per-user failure counter (with a lockout-window TTL). Best-effort."""
    settings = get_settings()
    try:
        client = await _redis()
        try:
            async with client.pipeline(transaction=True) as pipe:
                pipe.incr(_key(user_id))
                pipe.expire(_key(user_id), settings.mfa_lockout_seconds)
                await pipe.execute()
        finally:
            await client.aclose()
    except Exception:  # noqa: BLE001
        logger.warning("mfa failure counter unavailable", exc_info=True)


async def clear(user_id) -> None:
    """Reset the failure counter after a successful second factor. Best-effort."""
    try:
        client = await _redis()
        try:
            await client.delete(_key(user_id))
        finally:
            await client.aclose()
    except Exception:  # noqa: BLE001
        pass
