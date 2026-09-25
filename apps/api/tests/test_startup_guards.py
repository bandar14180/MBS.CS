"""M4.6.1 -- startup security guardrails (F2 derived-scope kill-switch, F4 workspace-isolation
installed check). Pure predicates are unit-tested in isolation; the F4 check is also verified
against the real database. No scanner behavior touched.

Phase 0 MySQL cutover: F4 used to be `assert_db_role_secure` (refuses a Postgres SUPERUSER role
in production, because SUPERUSER bypasses FORCE ROW LEVEL SECURITY). MySQL has no RLS and no
equivalent privilege-based bypass -- workspace isolation is now an application-layer filter
(apps.api.core.tenancy), so the failure mode F4 now guards against is that filter never having
been installed. See apps/api/core/startup_checks.py's module comment for the full rationale.
"""
import asyncio

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import Settings, get_settings
from apps.api.core.startup_checks import (
    StartupSecurityError,
    assert_tenancy_installed,
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


# --- dev_auto_authorize_targets: never allowed in production ---

def test_dev_auto_authorize_targets_refused_in_production():
    s = Settings(environment="production", dev_auto_authorize_targets=True)
    with pytest.raises(RuntimeError) as ei:
        s.validate_production()
    assert "DEV_AUTO_AUTHORIZE_TARGETS" in str(ei.value)


def test_dev_auto_authorize_targets_is_noop_in_development():
    Settings(environment="development", dev_auto_authorize_targets=True).validate_production()


# --- F-05: the authorization guardrail may only be bypassed on a LOCAL machine -------------
# The two tests above only ever asked "is ENVIRONMENT exactly 'production'?". `is_production`
# is a free-text comparison against that one literal, so ENVIRONMENT=staging / prod / qa -- or
# a typo like " production" -- booted happily with the guardrail fully disabled, meaning a
# deployed non-prod stack would actively scan targets with no proof of ownership. The rule is
# now an ALLOW-list of local environment names: anything else fails closed.

@pytest.mark.parametrize(
    "env", ["staging", "prod", "qa", "uat", "preprod", "sandbox", " production", "Staging", ""]
)
def test_f05_dev_auto_authorize_refused_outside_a_local_environment(env):
    """THE F-05 PROPERTY. Every one of these booted with the bypass active before the fix."""
    s = Settings(environment=env, dev_auto_authorize_targets=True)
    with pytest.raises(RuntimeError) as ei:
        s.validate_production()
    assert "DEV_AUTO_AUTHORIZE_TARGETS" in str(ei.value)


@pytest.mark.parametrize("env", ["development", "dev", "local", "test", "testing"])
def test_f05_dev_auto_authorize_still_allowed_on_a_local_machine(env):
    """The escape hatch must keep working for its actual purpose -- otherwise developers
    route around it, which is worse than the hole this closes."""
    Settings(environment=env, dev_auto_authorize_targets=True).validate_production()


@pytest.mark.parametrize("env", ["DEVELOPMENT", "  dev  ", "Local"])
def test_f05_local_environment_matching_is_case_and_whitespace_insensitive(env):
    """ENVIRONMENT is hand-edited in a .env file; casing/padding must not decide security."""
    Settings(environment=env, dev_auto_authorize_targets=True).validate_production()


@pytest.mark.parametrize("env", ["staging", "prod", "qa", "production"])
def test_f05_guard_is_inert_when_the_flag_is_off(env):
    """The guard must fire on the FLAG, not on the environment name -- a normal deployment
    with the bypass off must not be blocked by this check."""
    s = Settings(environment=env, dev_auto_authorize_targets=False)
    try:
        s.validate_production()
    except RuntimeError as exc:
        assert "DEV_AUTO_AUTHORIZE_TARGETS" not in str(exc), (
            "the F-05 guard fired even though the bypass flag was disabled"
        )


def test_f05_error_names_the_environment_and_the_remedy():
    """A fail-closed startup error is only useful if the operator can act on it."""
    s = Settings(environment="staging", dev_auto_authorize_targets=True)
    with pytest.raises(RuntimeError) as ei:
        s.validate_production()
    msg = str(ei.value)
    assert "staging" in msg              # what tripped it
    assert "authorization" in msg.lower()  # why it matters
    assert "development" in msg          # which values are acceptable


# --- F-06: a metered AI provider in production must carry a spend cap ----------------------
# The shipped production overlay sets AI_PROVIDER=openrouter with a real key on api, worker and
# worker-default, while ai_budget_enforce defaulted False and ai_daily_budget_usd defaulted 0.0
# -- so production billed a paid API with no ceiling. Reachable by any authenticated member with
# project:read (POST /assistant/ask); RATE_LIMIT_AI caps request RATE, never COST.

def _prod_ai(**over):
    """Production Settings with a LIVE metered provider, plus the other prod prerequisites so
    the only thing under test is the AI budget rule."""
    base = dict(
        environment="production",
        ai_provider="openrouter",
        openrouter_api_key="sk-or-test",
        jwt_secret_key="z" * 48,
        mfa_encryption_key="k" * 32,
        # F-08: production now requires the refresh cookie to be Secure (it carries a
        # long-lived credential). A 'hardened production config' must therefore set it.
        refresh_cookie_secure=True,
        database_url="mysql+aiomysql://u:realpw@mysql:3306/mbs",
        s3_access_key="ak", s3_secret_key="sk",
        trusted_proxy_count=1, trusted_hosts=["h.example.com"],
        cors_allow_origins=["https://h.example.com"],
        rate_limit_enabled=True, enable_hsts=True,
        metrics_mode="token", metrics_token="t",
    )
    base.update(over)
    return Settings(**base)


def test_f06_production_metered_ai_without_enforcement_is_refused():
    """THE F-06 PROPERTY: the configuration as shipped must not start."""
    with pytest.raises(RuntimeError) as ei:
        _prod_ai().validate_production()
    assert "AI_BUDGET_ENFORCE" in str(ei.value)


def test_f06_enforcement_on_but_zero_cap_is_refused():
    """The subtler trap: enforcement true + cap 0 is inert, so spend is still unlimited."""
    with pytest.raises(RuntimeError) as ei:
        _prod_ai(ai_budget_enforce=True, ai_daily_budget_usd=0.0).validate_production()
    assert "AI_DAILY_BUDGET_USD" in str(ei.value)


def test_f06_positive_cap_but_enforcement_off_is_refused():
    """The mirror trap: a cap that nothing enforces."""
    with pytest.raises(RuntimeError) as ei:
        _prod_ai(ai_budget_enforce=False, ai_daily_budget_usd=50.0).validate_production()
    assert "AI_BUDGET_ENFORCE" in str(ei.value)


def test_f06_both_switches_set_correctly_boots():
    """A correctly capped production must start -- the guard must not block a valid deploy."""
    _prod_ai(ai_budget_enforce=True, ai_daily_budget_usd=50.0).validate_production()


@pytest.mark.parametrize("provider", ["openrouter", "anthropic", "deepseek"])
def test_f06_applies_to_every_metered_provider(provider):
    keys = {"openrouter": "openrouter_api_key", "anthropic": "anthropic_api_key",
            "deepseek": "deepseek_api_key"}
    # Clear every provider key, then set only the one under test, so `ai_enabled` is true
    # solely because of `provider`.
    over = {k: "" for k in keys.values()}
    over[keys[provider]] = "sk-test"
    s = _prod_ai(ai_provider=provider, **over)
    with pytest.raises(RuntimeError) as ei:
        s.validate_production()
    assert "AI_BUDGET_ENFORCE" in str(ei.value)


def test_f06_self_hosted_local_provider_is_exempt():
    """`local` (Ollama) has no per-token cost -- demanding a dollar cap there would be noise."""
    _prod_ai(ai_provider="local", openrouter_api_key="").validate_production()


def test_f06_guard_is_inert_when_ai_is_not_live():
    """No API key => AI is off => no billing surface => nothing to cap."""
    _prod_ai(openrouter_api_key="").validate_production()


def test_f06_development_is_unaffected():
    """Local development must stay usable with AI on and no budget configured."""
    Settings(environment="development", ai_provider="openrouter",
             openrouter_api_key="sk-or-test").validate_production()


def test_f06_error_names_both_switches_and_the_provider():
    """A fail-closed startup error must tell the operator exactly what to set."""
    with pytest.raises(RuntimeError) as ei:
        _prod_ai().validate_production()
    msg = str(ei.value)
    assert "openrouter" in msg
    assert "AI_BUDGET_ENFORCE" in msg
    assert "cost" in msg.lower() or "bill" in msg.lower()


# --- F-08: the refresh cookie must be Secure + SameSite in production --------------------
# The refresh token moved from localStorage into an HttpOnly cookie. That only helps if the
# cookie cannot be lifted off the wire or attached to cross-site requests, so production
# refuses to start without Secure, and refuses a SameSite value that would reintroduce CSRF.

def test_f08_production_requires_a_secure_refresh_cookie():
    s = _prod_ai(ai_budget_enforce=True, ai_daily_budget_usd=50.0, refresh_cookie_secure=False)
    with pytest.raises(RuntimeError) as ei:
        s.validate_production()
    assert "REFRESH_COOKIE_SECURE" in str(ei.value)


@pytest.mark.parametrize("bad", ["none", "None", "NONE"])
def test_f08_production_rejects_samesite_none(bad):
    """SameSite=none would attach the refresh cookie to cross-site requests -- exactly the
    CSRF exposure the strict cookie exists to prevent."""
    s = _prod_ai(
        ai_budget_enforce=True, ai_daily_budget_usd=50.0,
        refresh_cookie_secure=True, refresh_cookie_samesite=bad,
    )
    with pytest.raises(RuntimeError) as ei:
        s.validate_production()
    assert "REFRESH_COOKIE_SAMESITE" in str(ei.value)


@pytest.mark.parametrize("ok", ["strict", "lax"])
def test_f08_production_accepts_strict_or_lax(ok):
    _prod_ai(
        ai_budget_enforce=True, ai_daily_budget_usd=50.0,
        refresh_cookie_secure=True, refresh_cookie_samesite=ok,
    ).validate_production()


def test_f08_development_does_not_require_a_secure_cookie():
    """Local dev serves plain http; a Secure cookie would simply be dropped."""
    Settings(environment="development", refresh_cookie_secure=False).validate_production()


# --- F4: assert_tenancy_installed (pure) ---

def test_f4_production_uninstalled_refuses():
    with pytest.raises(StartupSecurityError):
        assert_tenancy_installed(is_production=True, installed=False)


def test_f4_production_installed_is_ok():
    assert_tenancy_installed(is_production=True, installed=True)  # no raise


def test_f4_development_uninstalled_warns_and_continues():
    assert_tenancy_installed(is_production=False, installed=False)  # no raise (warn only)


def test_f4_development_installed_is_ok():
    assert_tenancy_installed(is_production=False, installed=True)


# --- F4: run_startup_security_checks against the REAL database -----------------------------

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


def test_f4_real_db_installed_tolerated_in_both_envs(monkeypatch):
    # tenancy.install() registers a process-wide SQLAlchemy event listener (idempotent -- see
    # tenancy.py) rather than per-engine state, so once installed (as conftest's app import
    # already does via apps.api.main's lifespan-equivalent startup path) it stays installed for
    # the rest of the process; this test just confirms the check reads that state correctly.
    monkeypatch.setattr(tenancy, "is_installed", lambda: True)
    _run_checks(is_production=False)  # must not raise
    _run_checks(is_production=True)   # must not raise


def test_f4_real_db_uninstalled_dev_tolerated(monkeypatch):
    monkeypatch.setattr(tenancy, "is_installed", lambda: False)
    _run_checks(is_production=False)  # warns, does not raise


def test_f4_real_db_uninstalled_production_refuses(monkeypatch):
    monkeypatch.setattr(tenancy, "is_installed", lambda: False)
    with pytest.raises(StartupSecurityError):
        _run_checks(is_production=True)
