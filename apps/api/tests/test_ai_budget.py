"""AI-2.2A -- AI budget enforcement regression suite.

Covers: disabled/zero-cap = off, under-budget allowed, over-budget blocked, Redis fail-open,
fallback cannot bypass the cap, spend accumulation, and the metric + audit event. Hermetic: a fake
Redis, monkeypatched settings, and a minimal BaseAIProvider stub (so the real complete_json hook is
exercised). No network, no live Redis.
"""
import logging

import pytest

from apps.api.ai_agent import budget
from apps.api.ai_agent.budget import AIBudgetExceededError, add_spend, get_spend, over_budget
from apps.api.ai_agent.providers.base import AIProviderError, BaseAIProvider, _Attempt
from apps.api.ai_agent.providers.fallback import FallbackClient
from apps.api.ai_agent.providers.usage import AIUsage, collect_ai_usage
from apps.api.core.config import get_settings


class FakeRedis:
    """Minimal Redis stand-in. `spend` seeds get(); `fail=True` makes every op raise."""

    def __init__(self, spend: float = 0.0, fail: bool = False):
        self._spend = spend
        self.fail = fail
        self.added = 0.0

    def get(self, key):
        if self.fail:
            raise RuntimeError("redis down")
        return str(self._spend) if self._spend else None

    def incrbyfloat(self, key, val):
        if self.fail:
            raise RuntimeError("redis down")
        self.added += float(val)
        return self.added

    def expire(self, key, ttl):
        if self.fail:
            raise RuntimeError("redis down")
        return True


class _StubProvider(BaseAIProvider):
    """A BaseAIProvider whose _invoke is a no-op success -- lets us exercise the real complete_json
    budget hook without a network call. `invoked` counts how many times the AI was actually run."""

    provider_name = "stub"

    def __init__(self):
        super().__init__(model="stub-model", max_tokens=10, timeout_s=1.0, max_retries=0)
        self.invoked = 0

    def _invoke(self, system, user):
        self.invoked += 1
        return _Attempt(
            text='{"ok": true}',
            usage=AIUsage(provider="stub", model="stub-model", estimated_cost_usd=0.0),
        )

    def _is_retryable(self, exc):
        return False


def _budget(monkeypatch, *, enforce, cap, redis):
    s = get_settings()
    monkeypatch.setattr(s, "ai_budget_enforce", enforce)
    monkeypatch.setattr(s, "ai_daily_budget_usd", cap)
    monkeypatch.setattr(budget, "_redis", lambda: redis)
    return s


# --- accumulator primitives -----------------------------------------------------------------

def test_add_and_get_spend(monkeypatch):
    fake = FakeRedis(spend=0.0)
    monkeypatch.setattr(budget, "_redis", lambda: fake)
    add_spend("w1", 0.25)
    add_spend("w1", 0.75)
    assert fake.added == pytest.approx(1.0)


def test_add_spend_ignores_nonpositive(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(budget, "_redis", lambda: fake)
    add_spend("w1", 0)
    add_spend("", 5)
    assert fake.added == 0.0


def test_over_budget_thresholds(monkeypatch):
    _budget(monkeypatch, enforce=True, cap=10.0, redis=FakeRedis(spend=9.99))
    assert over_budget("w1") is False
    _budget(monkeypatch, enforce=True, cap=10.0, redis=FakeRedis(spend=10.0))
    assert over_budget("w1") is True


def test_over_budget_off_when_disabled_or_zero_cap(monkeypatch):
    _budget(monkeypatch, enforce=False, cap=10.0, redis=FakeRedis(spend=1000.0))
    assert over_budget("w1") is False                  # enforcement off
    _budget(monkeypatch, enforce=True, cap=0.0, redis=FakeRedis(spend=1000.0))
    assert over_budget("w1") is False                  # zero cap = off


def test_get_spend_fails_open_on_redis_error(monkeypatch):
    monkeypatch.setattr(budget, "_redis", lambda: FakeRedis(spend=50.0, fail=True))
    assert get_spend("w1") == 0.0                       # error -> 0, never raises


# --- enforcement through the real complete_json hook ----------------------------------------

def test_disabled_ai_works_normally(monkeypatch):
    _budget(monkeypatch, enforce=False, cap=0.0, redis=FakeRedis(spend=9999.0))
    p = _StubProvider()
    with collect_ai_usage(agent_role="agent", workspace_id="w1"):
        assert p.complete_json("s", "u") == {"ok": True}
    assert p.invoked == 1                               # never blocked when disabled


def test_zero_budget_is_off(monkeypatch):
    _budget(monkeypatch, enforce=True, cap=0.0, redis=FakeRedis(spend=9999.0))
    p = _StubProvider()
    with collect_ai_usage(agent_role="agent", workspace_id="w1"):
        assert p.complete_json("s", "u") == {"ok": True}
    assert p.invoked == 1


def test_under_budget_allowed(monkeypatch):
    _budget(monkeypatch, enforce=True, cap=10.0, redis=FakeRedis(spend=3.0))
    p = _StubProvider()
    with collect_ai_usage(agent_role="agent", workspace_id="w1"):
        assert p.complete_json("s", "u") == {"ok": True}
    assert p.invoked == 1


def test_over_budget_blocked_before_invoke(monkeypatch):
    _budget(monkeypatch, enforce=True, cap=10.0, redis=FakeRedis(spend=15.0))
    p = _StubProvider()
    with collect_ai_usage(agent_role="agent", workspace_id="w1"):
        with pytest.raises(AIBudgetExceededError):
            p.complete_json("s", "u")
    assert p.invoked == 0                               # blocked BEFORE the provider call


def test_budget_error_is_non_availability_and_aiprovidererror():
    err = AIBudgetExceededError("cap reached")
    assert isinstance(err, AIProviderError) and err.availability is False


def test_redis_failure_fails_open_no_block(monkeypatch):
    _budget(monkeypatch, enforce=True, cap=10.0, redis=FakeRedis(spend=9999.0, fail=True))
    p = _StubProvider()
    with collect_ai_usage(agent_role="agent", workspace_id="w1"):
        assert p.complete_json("s", "u") == {"ok": True}   # Redis down -> allow, never block
    assert p.invoked == 1


def test_no_workspace_is_not_enforced(monkeypatch):
    _budget(monkeypatch, enforce=True, cap=10.0, redis=FakeRedis(spend=9999.0))
    p = _StubProvider()
    # no collect_ai_usage context -> no workspace attribution -> cannot enforce
    assert p.complete_json("s", "u") == {"ok": True}
    assert p.invoked == 1


# --- fallback cannot bypass the cap ---------------------------------------------------------

def test_fallback_cannot_bypass_budget(monkeypatch):
    _budget(monkeypatch, enforce=True, cap=10.0, redis=FakeRedis(spend=20.0))
    p1, p2 = _StubProvider(), _StubProvider()
    fc = FallbackClient([p1, p2])
    with collect_ai_usage(agent_role="agent", workspace_id="w1"):
        with pytest.raises(AIBudgetExceededError):
            fc.complete_json("s", "u")
    assert p1.invoked == 0 and p2.invoked == 0          # blocked; no failover to the second provider


# --- observability + audit ------------------------------------------------------------------

def test_block_increments_metric_and_emits_audit(monkeypatch, caplog):
    import apps.api.core.observability as obs

    _budget(monkeypatch, enforce=True, cap=10.0, redis=FakeRedis(spend=15.0))
    p = _StubProvider()
    before = obs.AI_BUDGET_BLOCKED.labels("agent")._value.get() if getattr(obs, "_PROM", False) else 0
    with caplog.at_level(logging.INFO, logger="mbs.ai.security"):
        with collect_ai_usage(agent_role="agent", workspace_id="w1"):
            with pytest.raises(AIBudgetExceededError):
                p.complete_json("s", "u")
    if getattr(obs, "_PROM", False):
        assert obs.AI_BUDGET_BLOCKED.labels("agent")._value.get() - before == 1
    recs = [r for r in caplog.records if r.name == "mbs.ai.security"]
    assert any(r.getMessage() == "ai.budget_exceeded" and getattr(r, "agent", None) == "agent" for r in recs)
    # no secret/key in the audit event (workspace UUID label is acceptable tenant metadata)
    assert "redis" not in " ".join(str(r.__dict__) for r in recs).lower()
