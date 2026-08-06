"""M4.6.1 -- startup security guardrails (F2 derived-scope kill-switch, F4 DB
superuser / FORCE RLS protection). Pure predicates are unit-tested in isolation; the
DB-role check is also verified against the real database. No scanner behavior touched.
"""
import asyncio

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core.config import Settings, get_settings
from apps.api.core.startup_checks import (
    StartupSecurityError,
    assert_db_role_secure,
    derived_scope_problem,
    run_startup_security_checks,
)


# --- F2: derived_scope_problem (pure) ---

def test_f2_production_with_derived_scope_disabled_is_a_problem():
    msg = derived_scope_problem(is_production=True, enforce=False, ack=False)
    assert msg is not None and "scan_enforce_derived_scope" in msg


def test_f2_development_with_derived_scope_disabled_is_ok():
    assert derived_scope_problem(is_production=False, enforce=False, ack=False) is None


def test_f2_production_disabled_with_emergency_ack_is_allowed():
    assert derived_scope_problem(is_production=True, enforce=False, ack=True) is None


def test_f2_production_with_enforcement_enabled_is_ok():
    assert derived_scope_problem(is_production=True, enforce=True, ack=False) is None


# --- F2: wired into Settings.validate_production ---

def test_f2_validate_production_refuses_when_disabled():
    s = Settings(environment="production", scan_enforce_derived_scope=False)
    with pytest.raises(RuntimeError) as ei:
        s.validate_production()
    assert "scan_enforce_derived_scope" in str(ei.value)


def test_f2_validate_production_allows_with_ack():
    # With the emergency ack set, the derived-scope problem is not raised. (Other
    # placeholder-config problems are irrelevant here -- assert our message is absent.)
    s = Settings(environment="production", scan_enforce_derived_scope=False, scan_enforce_derived_scope_ack=True)
    try:
        s.validate_production()
    except RuntimeError as exc:
        assert "scan_enforce_derived_scope" not in str(exc)


def test_f2_validate_production_is_noop_in_development():
    # Development never fails on this control (or any) -- must stay usable.
    Settings(environment="development", scan_enforce_derived_scope=False).validate_production()


# --- F4: assert_db_role_secure (pure) ---

def test_f4_production_superuser_refuses():
    with pytest.raises(StartupSecurityError):
        assert_db_role_secure(is_production=True, is_superuser=True)


def test_f4_production_non_superuser_is_ok():
    assert_db_role_secure(is_production=True, is_superuser=False)  # no raise


def test_f4_development_superuser_warns_and_continues():
    assert_db_role_secure(is_production=False, is_superuser=True)  # no raise (warn only)


def test_f4_development_non_superuser_is_ok():
    assert_db_role_secure(is_production=False, is_superuser=False)


# --- F4: run_startup_security_checks against the REAL database (role is superuser) ---

def _run_checks(is_production: bool):
    async def scenario():
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        try:
            await run_startup_security_checks(
                engine, is_production=is_production, enforce_derived_scope=True
            )
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_f4_real_db_role_dev_tolerated():
    # The dev DB role is a superuser; in development this warns and continues.
    _run_checks(is_production=False)  # must not raise


def test_f4_real_db_role_production_refuses():
    # Same real (superuser) role, but production must fail closed.
    with pytest.raises(StartupSecurityError):
        _run_checks(is_production=True)
