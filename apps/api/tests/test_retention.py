"""Phase 5.2 / 5.3.3 -- retention purge FOUNDATION + scheduling tests.

Pure/offline: no DB, no broker. Proves the double-gated safety contract (disabled = no-op,
dry-run never deletes), config defaults, task registration, the metrics/logging hooks, and the
Phase 5.3.3 beat gating. NOTHING here deletes or reads production data.
"""
import logging
import types
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
    assert result.total_deleted == 0


# --- dry-run never deletes -----------------------------------------------------------------

def test_dry_run_plans_but_deletes_nothing(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "retention_enabled", True)     # enabled...
    monkeypatch.setattr(s, "retention_dry_run", True)     # ...but dry-run
    result = service.run_purge(s)
    assert result.mode == "dry_run"
    assert result.dry_run is True
    assert result.total_deleted == 0                      # dry-run reads counts but NEVER deletes
    assert {p.resource for p in result.plans} == set(service.PROCESSED)


def test_dry_run_flag_overrides_settings(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "retention_enabled", True)
    monkeypatch.setattr(s, "retention_dry_run", False)    # settings say live...
    # ...but an explicit dry_run=True must win and stay safe
    result = service.run_purge(s, dry_run=True)
    assert result.mode == "dry_run"
    assert result.total_deleted == 0


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


# --- Phase 5.3.3: beat scheduling ----------------------------------------------------------

def test_retention_interval_default_present():
    assert get_settings().retention_interval_seconds > 0


def test_register_retention_schedule_gates_on_enabled():
    """The beat entry is added ONLY when retention_enabled, and points at the EXISTING task
    (no duplicate). Uses a throwaway app so the real celery_app.beat_schedule is untouched."""
    from apps.api.celery_app.worker import register_retention_schedule

    disabled_app = types.SimpleNamespace(conf=types.SimpleNamespace(beat_schedule={}))
    register_retention_schedule(
        disabled_app, types.SimpleNamespace(retention_enabled=False, retention_interval_seconds=86400)
    )
    assert "retention-purge" not in disabled_app.conf.beat_schedule  # safe default: no entry

    enabled_app = types.SimpleNamespace(conf=types.SimpleNamespace(beat_schedule={}))
    register_retention_schedule(
        enabled_app, types.SimpleNamespace(retention_enabled=True, retention_interval_seconds=123.0)
    )
    entry = enabled_app.conf.beat_schedule["retention-purge"]
    assert entry["task"] == "retention.purge"   # reuses the existing task, no new one
    assert entry["schedule"] == 123.0


def test_default_deployment_has_no_retention_beat_entry():
    # With retention_enabled=False (default), the real worker must not schedule a purge.
    from apps.api.celery_app.worker import celery_app

    assert "retention-purge" not in celery_app.conf.beat_schedule


def test_scheduled_task_disabled_skips_purge_entirely(monkeypatch):
    from apps.api.celery_app.tasks import retention_tasks
    from apps.api.retention import service as svc

    s = get_settings()
    monkeypatch.setattr(s, "retention_enabled", False)

    reached_db = {"async": False}

    async def _boom(*a, **k):  # run_purge must short-circuit BEFORE any async/DB work
        reached_db["async"] = True
        return {}

    monkeypatch.setattr(svc, "_run_async", _boom)
    out = retention_tasks.retention_purge_task.run()
    assert out["mode"] == "disabled"
    assert reached_db["async"] is False  # zero DB deletion path when disabled


def test_scheduled_task_dry_run_deletes_nothing(monkeypatch):
    from apps.api.celery_app.tasks import retention_tasks

    s = get_settings()
    monkeypatch.setattr(s, "retention_enabled", True)
    monkeypatch.setattr(s, "retention_dry_run", True)
    out = retention_tasks.retention_purge_task.run()
    assert out["mode"] == "dry_run" and out["dry_run"] is True  # counts only, never deletes


def test_scheduled_task_enabled_invokes_existing_purge_service(monkeypatch):
    """Enabled mode delegates to the EXISTING 5.3.2 service -- the task adds no deletion logic."""
    from apps.api.celery_app.tasks import retention_tasks
    from apps.api.retention import service as svc

    calls: list = []

    def _spy(*a, **k):
        calls.append((a, k))
        return svc.RetentionRunResult(mode="live", dry_run=False, plans=[])

    monkeypatch.setattr(svc, "run_purge", _spy)
    out = retention_tasks.retention_purge_task.run()
    assert len(calls) == 1            # the task calls the service exactly once
    assert out["mode"] == "live"
