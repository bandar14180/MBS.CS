"""AI-2.1 -- provider fallback regression suite.

Covers: no-failover on success, failover on availability failure, no-failover on config/invalid
errors, degradation preserved when all fail, deterministic factory chain (dedupe/self-ref/keyless
filtering), single-emission of usage, secret-free failover events, and an agent driven through the
fallback client. Hermetic: fake providers, no API key, no network.
"""
import logging

import pytest

from apps.api.ai_agent.providers.base import AIProviderError
from apps.api.ai_agent.providers.fallback import FallbackClient


class FakeProvider:
    """SupportsComplete fake. Either returns `result` or raises `error`; on success it appends its
    name to `sink` (mirrors BaseAIProvider emitting usage ONLY on a successful call)."""

    def __init__(self, name, *, result=None, error=None, sink=None):
        self.provider_name = name
        self._result = result if result is not None else {"ok": name}
        self._error = error
        self._sink = sink
        self.calls = 0

    def complete_json(self, system, user):
        self.calls += 1
        if self._error is not None:
            raise self._error
        if self._sink is not None:
            self._sink.append(self.provider_name)
        return self._result

    @property
    def model_version(self):
        return f"{self.provider_name}-model"


def _avail(msg="429 rate limited"):
    return AIProviderError(msg, availability=True)


def _config(msg="400 bad request"):
    return AIProviderError(msg, availability=False)


# --- classification at the provider layer ---------------------------------------------------

def test_aiprovidererror_defaults_to_non_availability():
    assert AIProviderError("x").availability is False
    assert AIProviderError("x", availability=True).availability is True


# --- fallback behavior ----------------------------------------------------------------------

def test_primary_succeeds_no_fallback():
    p1 = FakeProvider("p1", result={"ok": 1})
    p2 = FakeProvider("p2")
    fc = FallbackClient([p1, p2])
    assert fc.complete_json("s", "u") == {"ok": 1}
    assert p1.calls == 1 and p2.calls == 0        # secondary never touched
    assert fc.model_version == "p1-model"


def test_primary_availability_failure_falls_over_to_secondary(caplog):
    p1 = FakeProvider("p1", error=_avail("429 rate limited"))
    p2 = FakeProvider("p2", result={"ok": 2})
    fc = FallbackClient([p1, p2])
    with caplog.at_level(logging.WARNING, logger="mbs.ai"):
        assert fc.complete_json("s", "u") == {"ok": 2}
    assert p1.calls == 1 and p2.calls == 1
    assert fc.model_version == "p2-model"         # reflects the serving provider
    evt = [r for r in caplog.records if r.getMessage().startswith("ai.provider_failover")]
    assert evt and getattr(evt[0], "from_provider") == "p1" and getattr(evt[0], "to_provider") == "p2"


@pytest.mark.parametrize("reason", ["429 rate limited", "402 credits", "503 upstream", "timeout"])
def test_all_availability_reasons_fall_over(reason):
    p1 = FakeProvider("p1", error=_avail(reason))
    p2 = FakeProvider("p2", result={"ok": True})
    assert FallbackClient([p1, p2]).complete_json("s", "u") == {"ok": True}


def test_invalid_request_does_not_trigger_fallback():
    p1 = FakeProvider("p1", error=_config("400 bad request"))
    p2 = FakeProvider("p2", result={"ok": 2})
    with pytest.raises(AIProviderError):
        FallbackClient([p1, p2]).complete_json("s", "u")
    assert p1.calls == 1 and p2.calls == 0        # config error -> NO failover


def test_auth_error_does_not_trigger_fallback():
    p1 = FakeProvider("p1", error=AIProviderError("401 unauthorized", availability=False))
    p2 = FakeProvider("p2", result={"ok": 2})
    with pytest.raises(AIProviderError):
        FallbackClient([p1, p2]).complete_json("s", "u")
    assert p2.calls == 0


def test_all_providers_fail_preserves_last_error():
    last = _avail("503 upstream (last)")
    p1 = FakeProvider("p1", error=_avail("429"))
    p2 = FakeProvider("p2", error=last)
    with pytest.raises(AIProviderError) as exc:
        FallbackClient([p1, p2]).complete_json("s", "u")
    assert exc.value is last                       # degradation contract preserved (last error)


def test_usage_recorded_only_for_successful_provider():
    sink: list[str] = []
    p1 = FakeProvider("p1", error=_avail(), sink=sink)      # fails -> never emits
    p2 = FakeProvider("p2", result={"ok": 1}, sink=sink)    # succeeds -> emits once
    p3 = FakeProvider("p3", result={"ok": 1}, sink=sink)    # never reached
    FallbackClient([p1, p2, p3]).complete_json("s", "u")
    assert sink == ["p2"]                          # exactly one emission, from the serving provider


def test_failover_event_and_metric_contain_no_secrets(caplog):
    secret_msg = "429 from provider key=sk-SUPERSECRET endpoint=https://api.evil/x body={leak}"
    p1 = FakeProvider("openrouter", error=_avail(secret_msg))
    p2 = FakeProvider("anthropic", result={"ok": 1})
    with caplog.at_level(logging.WARNING, logger="mbs.ai"):
        FallbackClient([p1, p2]).complete_json("s", "u")
    blob = " ".join(str(r.__dict__) for r in caplog.records if r.name == "mbs.ai")
    assert "sk-SUPERSECRET" not in blob and "api.evil" not in blob and "{leak}" not in blob
    assert "openrouter" in blob and "anthropic" in blob     # names only


def test_empty_chain_rejected():
    with pytest.raises(ValueError):
        FallbackClient([])


# --- agent through the fallback client -------------------------------------------------------

def test_agent_runs_through_fallback():
    from apps.api.ai_agent.agent import RedTeamAgent

    p1 = FakeProvider("p1", error=_avail("429"))
    p2 = FakeProvider("p2", result={"candidate_actions": [
        {"tool": "nmap", "confidence": 0.9, "expected_value": "high", "risk": "low", "rationale": "x"}
    ]})
    agent = RedTeamAgent(client=FallbackClient([p1, p2]))
    d = agent.decide(target_type="ip_range", target_value="10.0.0.1", current_phase="reconnaissance",
                     findings_summary="", available=["nmap"])
    assert d.action == "run_tool" and d.tool == "nmap"      # survived the primary's outage


# --- factory chain construction --------------------------------------------------------------

def _cfg(monkeypatch, **over):
    from apps.api.core.config import get_settings

    s = get_settings()
    for k, v in over.items():
        monkeypatch.setattr(s, k, v)
    return s


def test_factory_single_client_when_no_fallbacks(monkeypatch):
    from apps.api.ai_agent.providers.factory import get_ai_client
    from apps.api.ai_agent.providers.openrouter import OpenRouterClient

    _cfg(monkeypatch, ai_provider="openrouter", ai_fallback_providers=[], openrouter_api_key="k")
    client = get_ai_client()
    assert isinstance(client, OpenRouterClient) and not isinstance(client, FallbackClient)


def test_factory_builds_ordered_deduped_chain(monkeypatch):
    from apps.api.ai_agent.providers.factory import get_ai_client

    _cfg(monkeypatch, ai_provider="openrouter",
         ai_fallback_providers=["deepseek", "openrouter", "deepseek", "local"],  # self + dup + keyless-safe
         openrouter_api_key="k", deepseek_api_key="k")
    client = get_ai_client()
    assert isinstance(client, FallbackClient)
    names = [p.provider_name for p in client._providers]
    assert names == ["openrouter", "deepseek", "local"]     # primary first, self+dup dropped, order kept


def test_factory_skips_keyless_fallback(monkeypatch):
    from apps.api.ai_agent.providers.factory import get_ai_client
    from apps.api.ai_agent.providers.openrouter import OpenRouterClient

    # anthropic has no key -> dropped -> only the primary remains -> single client, not a chain.
    _cfg(monkeypatch, ai_provider="openrouter", ai_fallback_providers=["anthropic"],
         openrouter_api_key="k", anthropic_api_key="")
    client = get_ai_client()
    assert isinstance(client, OpenRouterClient) and not isinstance(client, FallbackClient)


# --- production validation -------------------------------------------------------------------

def test_validate_production_rejects_unknown_and_self_fallback():
    from apps.api.core.config import Settings

    base = dict(
        environment="production", jwt_secret_key="a" * 48, s3_access_key="r", s3_secret_key="r",
        database_url="postgresql+asyncpg://u:p@db:5432/mbs", cors_allow_origins=["https://x.example.com"],
        trusted_hosts=["x.example.com"], rate_limit_enabled=True, metrics_mode="token",
        mfa_encryption_key="k", ai_provider="openrouter",
    )
    with pytest.raises(RuntimeError) as exc:
        Settings(**base, ai_fallback_providers=["nope"]).validate_production()
    assert "unknown provider" in str(exc.value)
    with pytest.raises(RuntimeError) as exc2:
        Settings(**base, ai_fallback_providers=["openrouter"]).validate_production()
    assert "primary provider" in str(exc2.value)
