"""AI-2.5 -- AI observability metrics + dashboard artifact.

Verifies the latency histogram and error counter recorders, that emit_usage observes latency and
base.complete_json counts a failed call, and that the shipped Grafana dashboard is valid and only
references metrics we actually export.
"""
import json
import re
from pathlib import Path

import pytest

import apps.api.core.observability as obs
from apps.api.ai_agent.providers.base import AIProviderError, BaseAIProvider
from apps.api.ai_agent.providers.usage import AIUsage, collect_ai_usage, emit_usage

REPO_ROOT = Path(__file__).resolve().parents[3]
DASHBOARD = REPO_ROOT / "infra" / "grafana" / "ai-dashboard.json"

# Series the AI dashboard is allowed to reference (what observability.py exports).
_EXPORTED = {
    "mbs_ai_cost_usd_total", "mbs_ai_calls_total", "mbs_ai_tokens_total",
    "mbs_ai_latency_seconds_bucket", "mbs_ai_errors_total",
    "mbs_ai_failover_total", "mbs_ai_budget_blocked_total",
}


def _prom_or_skip():
    if not getattr(obs, "_PROM", False):
        pytest.skip("prometheus_client not installed")


# --- recorders ------------------------------------------------------------------------------

def test_record_ai_latency_and_error():
    _prom_or_skip()
    s0 = obs.AI_LATENCY.labels("planner")._sum.get()
    obs.record_ai_latency("planner", 2.0)
    assert obs.AI_LATENCY.labels("planner")._sum.get() - s0 == pytest.approx(2.0)

    e0 = obs.AI_ERRORS.labels("openrouter")._value.get()
    obs.record_ai_error("openrouter")
    assert obs.AI_ERRORS.labels("openrouter")._value.get() - e0 == 1


def test_emit_usage_observes_latency():
    _prom_or_skip()
    before = obs.AI_LATENCY.labels("agent")._sum.get()
    with collect_ai_usage(agent_role="agent", workspace_id="w1"):
        emit_usage(AIUsage(provider="p", model="m", agent_role="agent"), latency_ms=1500)
    assert obs.AI_LATENCY.labels("agent")._sum.get() - before == pytest.approx(1.5, abs=0.01)


class _FailProvider(BaseAIProvider):
    provider_name = "failstub"

    def __init__(self, exc):
        super().__init__(model="m", max_tokens=1, timeout_s=1.0, max_retries=0)
        self._exc = exc

    def _invoke(self, system, user):
        raise self._exc

    def _is_retryable(self, exc):
        return False


def test_complete_json_counts_terminal_error():
    _prom_or_skip()
    before = obs.AI_ERRORS.labels("failstub")._value.get()
    with pytest.raises(AIProviderError):
        _FailProvider(AIProviderError("terminal")).complete_json("s", "u")
    assert obs.AI_ERRORS.labels("failstub")._value.get() - before == 1


def test_complete_json_counts_exhausted_error():
    _prom_or_skip()
    before = obs.AI_ERRORS.labels("failstub")._value.get()
    with pytest.raises(AIProviderError):
        _FailProvider(RuntimeError("boom")).complete_json("s", "u")   # non-retryable -> exhausted -> failed
    assert obs.AI_ERRORS.labels("failstub")._value.get() - before == 1


# --- dashboard artifact ---------------------------------------------------------------------

def test_dashboard_is_valid_and_references_only_exported_metrics():
    if not DASHBOARD.is_file():
        pytest.skip("infra/grafana not present in this environment")
    d = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    assert d.get("title") and isinstance(d.get("panels"), list) and d["panels"], "dashboard must have title + panels"

    exprs = [t["expr"] for p in d["panels"] for t in p.get("targets", []) if "expr" in t]
    assert exprs, "every panel should have at least one prometheus target"
    referenced = {m for e in exprs for m in re.findall(r"mbs_[a-z0-9_]+", e)}
    assert referenced, "dashboard should reference AI metrics"
    unknown = referenced - _EXPORTED
    assert not unknown, f"dashboard references metrics we do not export: {unknown}"
