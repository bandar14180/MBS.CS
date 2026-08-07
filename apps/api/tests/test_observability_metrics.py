"""Phase 1.3 -- metrics wiring. Verifies the new/wired counters increment on real
record calls and that labels stay low-cardinality (never scan_id/workspace_id/host)."""
from apps.api.core import observability as obs

import pytest

pytestmark = pytest.mark.skipif(not obs._PROM, reason="prometheus_client not installed; metrics are no-ops")


def _c(counter, *labels):
    return (counter.labels(*labels) if labels else counter)._value.get()


def test_scan_result_success_increments_and_wires_outcomes():
    s0 = _c(obs.SCAN_SUCCESS)
    o0 = _c(obs.SCAN_OUTCOMES, "completed")
    d0 = obs.SCAN_DURATION.labels("completed")._sum.get()
    obs.record_scan_result("completed", 2.5)
    assert _c(obs.SCAN_SUCCESS) == s0 + 1
    assert _c(obs.SCAN_OUTCOMES, "completed") == o0 + 1   # previously-dead record_scan_outcome now wired
    assert obs.SCAN_DURATION.labels("completed")._sum.get() >= d0 + 2.5


def test_scan_result_failed_increments_failure_counter():
    f0 = _c(obs.SCAN_FAILED)
    obs.record_scan_result("failed", 1.0)
    assert _c(obs.SCAN_FAILED) == f0 + 1


def test_tool_failure_and_ai_decision_counters():
    t0 = _c(obs.TOOL_FAILURE, "nmap")
    obs.record_tool_failure("nmap")
    assert _c(obs.TOOL_FAILURE, "nmap") == t0 + 1
    a0 = _c(obs.AI_DECISION, "run_tool")
    obs.record_ai_decision("run_tool")
    assert _c(obs.AI_DECISION, "run_tool") == a0 + 1


def test_labels_are_low_cardinality_only():
    # No scan_id / workspace_id / host / target labels anywhere.
    assert obs.SCAN_SUCCESS._labelnames == ()
    assert obs.SCAN_FAILED._labelnames == ()
    assert obs.TOOL_FAILURE._labelnames == ("tool",)
    assert obs.AI_DECISION._labelnames == ("action",)
    assert obs.SCAN_DURATION._labelnames == ("status",)
    assert obs.SCAN_REAPED._labelnames == ("reason",)
    forbidden = {"scan_id", "workspace_id", "host", "hostname", "target"}
    for m in (obs.SCAN_SUCCESS, obs.SCAN_FAILED, obs.TOOL_FAILURE, obs.AI_DECISION, obs.SCAN_DURATION, obs.SCAN_REAPED):
        assert not (set(m._labelnames) & forbidden)


def test_metrics_appear_in_exposition():
    obs.record_scan_result("completed", 0.1)
    obs.record_tool_failure("httpx")
    obs.record_ai_decision("finish")
    body = obs.metrics_response_body().decode()
    for name in ("mbs_scan_success_total", "mbs_scan_failed_total", "mbs_tool_failure_total",
                 "mbs_scan_duration_seconds", "mbs_ai_decision_total", "mbs_scan_reaped_total"):
        assert name in body
