"""Startup security checks (M4.6.1).

A clean, extensible home for fail-fast production security validations. Two kinds:

  * PURE predicates (no I/O) -- unit-testable in isolation; also reused by
    Settings.validate_production for the config-only checks.
  * RUNTIME checks that need DB context (connectivity, schema version, tenancy install) --
    run once from the app lifespan via `run_startup_security_checks`.

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


# --- F4: workspace isolation is actually wired up (Phase 0 MySQL cutover) -----------
#
# PRE-MIGRATION, this section checked for a PostgreSQL SUPERUSER role, which BYPASSES
# `FORCE ROW LEVEL SECURITY` and would silently defeat workspace isolation -- a
# privilege-based bypass of a database-enforced policy. That check no longer applies:
# MySQL has no RLS and isolation is no longer privilege-based at all (see
# apps/api/core/tenancy.py's module docstring for the full rationale). There is no
# database role that can "bypass" tenancy.py, because it isn't a database policy --
# it's a filter the application attaches to every ORM query it issues.
#
# The equivalent failure mode in the new architecture isn't a misconfigured DB role;
# it's tenancy.install() never having been called (e.g. a future refactor of main.py's
# lifespan drops the call). That's what this now checks, with the same fail-closed-in-
# -production / warn-in-development posture as the check it replaces.

def assert_tenancy_installed(*, is_production: bool, installed: bool) -> None:
    """The app-layer workspace-isolation filter (apps/api/core/tenancy.py) MUST be
    installed before the process serves any request or task -- an uninstalled filter
    means every workspace-scoped table is queried completely unfiltered. Fail closed in
    production, with NO override (M4.6.1 / F4, MySQL-cutover successor check).
    Development may continue with a warning."""
    if installed:
        return
    if is_production:
        raise StartupSecurityError(
            "Workspace isolation (apps.api.core.tenancy) is NOT installed. Every "
            "workspace-scoped table would be queried unfiltered. Refusing to start in "
            "production. Ensure tenancy.install() runs during startup before this check."
        )
    logger.warning(
        "tenancy.not_installed: workspace isolation is not installed; workspace-scoped "
        "tables are UNFILTERED. Acceptable for development ONLY -- production will "
        "refuse to start."
    )


async def _can_connect(engine: AsyncEngine) -> bool:
    """Cheap connectivity sanity check at boot -- replaces the old role-lookup query's
    role as "the thing that proves we can actually talk to the database", without
    assuming any Postgres-specific catalog exists."""
    async with engine.connect() as conn:
        return bool(await conn.scalar(text("SELECT 1")))


async def run_startup_security_checks(
    engine: AsyncEngine, *, is_production: bool, enforce_derived_scope: bool
) -> None:
    """Runtime/DB-backed startup security checks (called once from the app lifespan).
    Emits a WARNING when derived-scope enforcement is disabled (any env), verifies
    connectivity, then enforces the workspace-isolation-installed invariant. Extend with
    additional checks as hardening grows."""
    if not enforce_derived_scope:
        logger.warning(
            "scan_enforce_derived_scope is DISABLED: derived-target authorization "
            "enforcement is OFF; out-of-scope discovered hosts may be actively probed. "
            "Emergency use only."
        )
    await _can_connect(engine)

    # AUDIT-002: connectivity is NOT schema readiness. `SELECT 1` succeeds against a database
    # that is missing tables this build's code requires (verified: a DB two revisions behind
    # head, with no `risk_assessments` table at all, answered SELECT 1 and was reported
    # healthy). Compare the live alembic_version against this build's migration head and
    # refuse to start in production on any mismatch. Deliberately AFTER _can_connect so an
    # unreachable database still reports as a connectivity failure rather than a schema one.
    from apps.api.core.schema_version import enforce_schema_version

    await enforce_schema_version(engine, is_production=is_production)

    from apps.api.core import tenancy

    assert_tenancy_installed(is_production=is_production, installed=tenancy.is_installed())
