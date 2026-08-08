"""Phase 5.2 -- retention purge FOUNDATION tests.

Pure/offline: no DB, no broker. Proves the double-gated safety contract (disabled = no-op,
dry-run never deletes, a live run is refused until 5.3), the config defaults, task
registration, and the metrics/logging hooks. NOTHING here deletes or reads production data.
"""
import logging
from datetime import datetime, timezone

import pytest

from apps.api.core.config import get_settings
from apps.api.retention import service


# --- configuration defaults ----------------------------------------------------------------

def test_config_defaults_are_double_gated_off():
    s = get_settings()
    assert s.retention_enabled is False          # master switch off
    assert s.retention_dry_run is True           # and dry-run on -> plan only
    assert s.retention_batch_size > 0
    assert s.retention_min_keep > 0
    # requested per-resource windows
    assert s.retention_evidence_days == 90
    assert s.retention_scan_days == 180
    assert s.retention_ai_usage_days == 180
    assert s.retention_report_days == 365
    assert s.retention_refresh_token_grace_days == 7
    assert s.retention_notification_days == 90
    assert s.retention_audit_days == 730


def test_every_policy_maps_to_a_real_settings_window():
    s = get_settings()
    for pol in service.POLICIES:
        assert isinstance(getattr(s, pol.days_attr), int)


# --- disabled = no-op ----------------------------------------------------------------------

def test_disabled_retention_does_nothing(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "retention_enabled", False)
    result = service.run_purge(s)
    assert result.mode == "disabled"
    assert result.plans == []          # never even builds a plan
    assert result.total_eligible == 0


# --- dry-run never deletes -----------------------------------------------------------------

def test_dry_run_plans_but_deletes_nothing(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "retention_enabled", True)     # enabled...
    monkeypatch.setattr(s, "retention_dry_run", True)     # ...but dry-run
    result = service.run_purge(s)
    assert result.mode == "dry_run"
    assert result.dry_run is True
    # foundation performs no DB access -> nothing is ever counted as eligible yet
    assert result.total_eligible == 0
    assert {p.resource for p in result.plans} == {p.resource for p in service.POLICIES}


def test_dry_run_flag_overrides_settings(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "retention_enabled", True)
    monkeypatch.setattr(s, "retention_dry_run", False)    # settings say live...
    # ...but an explicit dry_run=True must win and stay safe
    result = service.run_purge(s, dry_run=True)
    assert result.mode == "dry_run"


def test_live_run_is_refused_until_phase_5_3(monkeypatch):
    """The single most important safety test: an enabled, non-dry-run pass must NOT silently
    delete or no-op -- deletion isn't built yet, so it fails LOUD."""
    s = get_settings()
    monkeypatch.setattr(s, "retention_enabled", True)
    monkeypatch.setattr(s, "retention_dry_run", False)
    with pytest.raises(NotImplementedError):
        service.run_purge(s, dry_run=False)


# --- plan / cutoff math --------------------------------------------------------------------

def test_build_plan_cutoffs_use_configured_windows():
    s = get_settings()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    plans = {p.resource: p for p in service.build_plan(s, now=now)}
    # e.g. evidence window 90d -> cutoff 90 days before `now`, and nothing eligible yet
    ev = plans["evidence"]
    assert ev.retention_days == s.retention_evidence_days
    assert (now - ev.cutoff).days == s.retention_evidence_days
    assert ev.eligible == 0


# --- task registration ---------------------------------------------------------------------

def test_task_is_registered_and_not_beat_scheduled():
    from apps.api.celery_app.worker import celery_app
    import apps.api.celery_app.tasks.retention_tasks  # noqa: F401  (registers the task)

    assert "retention.purge" in celery_app.tasks
    # NOT auto-scheduled: no beat entry references the retention task (no automatic deletion).
    assert "retention.purge" not in {
        entry.get("task") for entry in celery_app.conf.beat_schedule.values()
    }


def test_task_wrapper_returns_structured_summary(monkeypatch):
    from apps.api.celery_app.tasks import retention_tasks

    s = get_settings()
    monkeypatch.setattr(s, "retention_enabled", False)
    out = retention_tasks.retention_purge_task.run()  # call the task body directly (no broker)
    assert out["mode"] == "disabled"
    assert out["total_eligible"] == 0
    assert isinstance(out["resources"], list)


# --- metrics + logging hooks ---------------------------------------------------------------

def test_run_emits_structured_log_events(monkeypatch, caplog):
    s = get_settings()
    monkeypatch.setattr(s, "retention_enabled", True)
    monkeypatch.setattr(s, "retention_dry_run", True)
    with caplog.at_level(logging.INFO, logger="mbs.retention"):
        service.run_purge(s)
    events = {r.__dict__.get("event") for r in caplog.records}
    assert "retention.run" in events
    assert "retention.plan" in events


def test_run_increments_metrics_hook(monkeypatch):
    if not service._PROM:
        pytest.skip("prometheus_client not installed; metrics are no-ops")
    s = get_settings()
    monkeypatch.setattr(s, "retention_enabled", True)
    monkeypatch.setattr(s, "retention_dry_run", True)
    before = service.RETENTION_RUNS.labels("dry_run")._value.get()
    service.run_purge(s)
    assert service.RETENTION_RUNS.labels("dry_run")._value.get() == before + 1


# --- CLI ------------------------------------------------------------------------------------

def test_cli_plan_prints_and_exits_zero(capsys):
    from apps.api.retention import cli

    assert cli.main(["plan"]) == 0
    out = capsys.readouterr().out
    assert "evidence" in out and "would_delete=0" in out


def test_cli_dry_run_exits_zero_and_deletes_nothing(capsys):
    from apps.api.retention import cli

    assert cli.main(["dry-run"]) == 0
    out = capsys.readouterr().out
    assert "mode=" in out and "total_would_delete=0" in out
