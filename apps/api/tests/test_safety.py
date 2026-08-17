"""Safety layer tests (M1) -- the non-bypassable boundary for the autonomous agent.
Pure: no DB/network. These guard the 'never cause damage' invariant."""
import pytest

from apps.api.core.config import get_settings
from apps.api.scanner_engine.safety import (
    DEFAULT_POST_EXPLOIT_ALLOWLIST,
    RulesOfEngagement,
    SafetyTier,
    SafetyViolation,
    assert_action_allowed,
    is_destructive,
    tier_at_most,
)


def test_tier_ordering() -> None:
    assert tier_at_most(SafetyTier.PASSIVE, SafetyTier.ACTIVE_SAFE) is True
    assert tier_at_most(SafetyTier.ACTIVE_SAFE, SafetyTier.ACTIVE_SAFE) is True
    assert tier_at_most(SafetyTier.INTRUSIVE, SafetyTier.ACTIVE_SAFE) is False


@pytest.mark.parametrize("op", [
    "DROP TABLE users", "delete from x", "rm -rf /", "UPDATE accounts SET",
    "write file", "install backdoor", "exfiltrate data", "echo x > /etc/passwd",
])
def test_destructive_operations_detected(op) -> None:
    assert is_destructive(op) is True


@pytest.mark.parametrize("op", [
    "whoami", "id", "SELECT 1", "select count(*) from t", "hostname",
    # word-boundary regressions: these end in / contain "rm" etc. but are benign
    "version_confirm", "login_check", "confirm", "perform check", "transform data", "form",
])
def test_benign_operations_not_flagged(op) -> None:
    assert is_destructive(op) is False


# --- the gate ---

def _roe(**kw):
    return RulesOfEngagement(**kw)


def test_passive_and_active_safe_allowed_by_default() -> None:
    assert_action_allowed(safety_tier=SafetyTier.PASSIVE, roe=_roe())
    assert_action_allowed(safety_tier=SafetyTier.ACTIVE_SAFE, roe=_roe())


def test_intrusive_denied_without_exploitation() -> None:
    with pytest.raises(SafetyViolation):
        assert_action_allowed(safety_tier=SafetyTier.INTRUSIVE, roe=_roe())  # ceiling active_safe + no exploit


def test_intrusive_allowed_when_enabled_and_within_ceiling() -> None:
    roe = _roe(max_tier=SafetyTier.INTRUSIVE, exploitation_enabled=True)
    assert_action_allowed(safety_tier=SafetyTier.INTRUSIVE, roe=roe)


def test_intrusive_denied_when_ceiling_lower_even_if_enabled() -> None:
    roe = _roe(max_tier=SafetyTier.ACTIVE_SAFE, exploitation_enabled=True)
    with pytest.raises(SafetyViolation):
        assert_action_allowed(safety_tier=SafetyTier.INTRUSIVE, roe=roe)


def test_destructive_operation_always_denied() -> None:
    roe = _roe(max_tier=SafetyTier.INTRUSIVE, exploitation_enabled=True)
    with pytest.raises(SafetyViolation):
        assert_action_allowed(safety_tier=SafetyTier.INTRUSIVE, roe=roe, operation="DROP TABLE customers")


def test_post_exploit_allowlist_enforced() -> None:
    roe = _roe(max_tier=SafetyTier.INTRUSIVE, exploitation_enabled=True)
    assert_action_allowed(safety_tier=SafetyTier.INTRUSIVE, roe=roe, post_exploit_primitive="whoami")
    with pytest.raises(SafetyViolation):
        assert_action_allowed(safety_tier=SafetyTier.INTRUSIVE, roe=roe, post_exploit_primitive="cat_etc_shadow")


def test_simulated_never_touches_target_always_allowed() -> None:
    # a modeled (never-executed) action is analysis -> allowed even with scary text
    assert_action_allowed(safety_tier=SafetyTier.SIMULATED, roe=_roe(), operation="attacker could DELETE data")


# --- RoE from config: config can restrict but never exceed the settings ceiling ---

def test_roe_from_config_caps_to_settings_ceiling() -> None:
    get_settings()  # defaults: ceiling active_safe, exploitation disabled
    roe = RulesOfEngagement.from_config({"safety_tier": "intrusive", "exploitation_enabled": True})
    assert roe.max_tier == SafetyTier.ACTIVE_SAFE          # capped by settings ceiling
    assert roe.exploitation_enabled is False               # settings gate off -> stays off
    assert roe.allowed_post_exploit == DEFAULT_POST_EXPLOIT_ALLOWLIST


def test_roe_from_config_allows_intrusive_when_deployment_permits(monkeypatch) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "agent_safety_ceiling", "intrusive")
    monkeypatch.setattr(s, "agent_exploitation_enabled", True)
    roe = RulesOfEngagement.from_config({"safety_tier": "intrusive", "exploitation_enabled": True})
    assert roe.max_tier == SafetyTier.INTRUSIVE
    assert roe.exploitation_enabled is True
