"""Reliability/Operations Grafana dashboard artifact validation.

Mirrors test_ai_observability.py's dashboard test: the shipped dashboard must be valid JSON, have
panels with Prometheus targets, and reference ONLY metrics the app actually exports. Additionally
asserts each allowed metric name genuinely appears in core/observability.py (the source of truth),
so the dashboard can never drift onto an invented metric.
"""
import json
import re
from pathlib import Path

import pytest

import apps.api.core.observability as obs

REPO_ROOT = Path(__file__).resolve().parents[3]
DASHBOARD = REPO_ROOT / "infra" / "grafana" / "reliability-dashboard.json"

# The operational series this dashboard is allowed to reference. Every name is exported by the app:
# gauges from the API-side ReliabilityCollector/DependencyHealthCollector (queue/dlq depth, backup &
# beat freshness, dependency liveness) and worker-emitted counters (scan outcomes, reaper, relay).
_EXPORTED = {
    "mbs_queue_depth", "mbs_dlq_depth", "mbs_dependency_up",
    "mbs_backup_age_seconds", "mbs_beat_age_seconds",
    "mbs_scan_success_total", "mbs_scan_failed_total",
    "mbs_scan_reaped_total", "mbs_scan_relayed_total",
}


def test_allowed_metrics_exist_in_observability_source():
    """Every name in the allow-list is a real exported metric (defined in core/observability.py) --
    guards against the allow-list itself drifting onto an invented metric."""
    src = Path(obs.__file__).read_text(encoding="utf-8")
    missing = {name for name in _EXPORTED if name not in src}
    assert not missing, f"allow-list references metrics not defined in observability.py: {missing}"


def test_dashboard_is_valid_and_references_only_exported_metrics():
    if not DASHBOARD.is_file():
        pytest.skip("infra/grafana not present in this environment")
    d = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    assert d.get("title") and isinstance(d.get("panels"), list) and d["panels"], "dashboard must have title + panels"

    exprs = [t["expr"] for p in d["panels"] for t in p.get("targets", []) if "expr" in t]
    assert exprs, "every panel should have at least one prometheus target"
    referenced = {m for e in exprs for m in re.findall(r"mbs_[a-z0-9_]+", e)}
    assert referenced, "dashboard should reference reliability metrics"
    unknown = referenced - _EXPORTED
    assert not unknown, f"dashboard references metrics we do not export: {unknown}"
