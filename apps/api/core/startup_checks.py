"""Startup security checks (M4.6.1).

A clean, extensible home for fail-fast production security validations. Two kinds:

  * PURE predicates (no I/O) -- unit-testable in isolation; also reused by
    Settings.validate_production for the config-only checks.
  * RUNTIME checks that need DB context (e.g. the DB role) -- run once from the app
    lifespan via `run_startup_security_checks`.

Add future hardening checks here so there is a single, testable place for them.
This module does NOT import core.config (kept dependency-free of Settings) so config
can call the pure predicates without an import cycle.
"""
import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = logging.getLogger("mbs.startup")


class StartupSecurityError(RuntimeError):
    """Raised to REFUSE application startup when a production security invariant is
    violated (fail closed)."""


# --- F2: derived-target authorization enforcement -----------------------------------

def derived_scope_problem(*, is_production: bool, enforce: bool, ack: bool) -> str | None:
    """Config-only predicate (M4.6.1 / F2). Returns a problem string when the
    derived-target authorization control (`scan_enforce_derived_scope`) is disabled in
    production WITHOUT the emergency acknowledgement; else None. Development is never a
    problem (returns None) -- see the startup WARNING in `run_startup_security_checks`."""
    if is_production and not enforce and not ack:
        return (
            "scan_enforce_derived_scope is DISABLED in production: derived-target "
            "authorization enforcement is OFF, so out-of-scope discovered hosts could be "
            "actively probed. Set scan_enforce_derived_scope_ack=true ONLY as a documented "
            "emergency override."
        )
    return None


# --- F4: database role / FORCE RLS protection ---------------------------------------

def assert_db_role_secure(*, is_production: bool, is_superuser: bool) -> None:
    """A PostgreSQL SUPERUSER role BYPASSES `FORCE ROW LEVEL SECURITY`, silently
    defeating workspace isolation. Production MUST NOT run as a superuser -- fail
    closed, with NO override (M4.6.1 / F4). Development may continue with a warning so
    local setups (which often use a superuser role) stay usable."""
    if not is_superuser:
        return
    if is_production:
        raise StartupSecurityError(
            "Database role is a SUPERUSER, which bypasses FORCE ROW LEVEL SECURITY "
            "(workspace isolation / RLS). Refusing to start in production. Use a "
            "non-superuser application database role."
        )
    logger.warning(
        "db.role_superuser: the application database role is a SUPERUSER; FORCE RLS is "
        "bypassed. Acceptable for development ONLY -- production will refuse to start."
    )


async def _current_role_is_superuser(engine: AsyncEngine) -> bool:
    async with engine.connect() as conn:
        return bool(await conn.scalar(text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")))


async def run_startup_security_checks(
    engine: AsyncEngine, *, is_production: bool, enforce_derived_scope: bool
) -> None:
    """Runtime/DB-backed startup security checks (called once from the app lifespan).
    Emits a WARNING when derived-scope enforcement is disabled (any env), then enforces
    the DB-role invariant. Extend with additional checks as hardening grows."""
    if not enforce_derived_scope:
        logger.warning(
            "scan_enforce_derived_scope is DISABLED: derived-target authorization "
            "enforcement is OFF; out-of-scope discovered hosts may be actively probed. "
            "Emergency use only."
        )
    is_superuser = await _current_role_is_superuser(engine)
    assert_db_role_secure(is_production=is_production, is_superuser=is_superuser)
