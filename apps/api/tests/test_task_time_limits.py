"""F5 -- per-task Celery time limits for backup.run and retention.purge.

These tasks get their OWN soft/hard limits (independent of the scan-tuned global) and handle a
SoftTimeLimitExceeded gracefully (log + F4 reliability metric). The scan task's global timeout
behavior is unchanged. Pure/offline: run_backup / run_purge are monkeypatched; no broker/DB.
"""
from celery.exceptions import SoftTimeLimitExceeded

from apps.api.celery_app.tasks.backup_tasks import scheduled_backup_task
from apps.api.celery_app.tasks.retention_tasks import retention_purge_task
from apps.api.core.config import get_settings


# --- configuration ------------------------------------------------------------------------

def test_per_task_limits_are_configured_and_soft_below_hard():
    s = get_settings()
    assert scheduled_backup_task.soft_time_limit == s.backup_task_soft_time_limit_seconds == 7200
    assert scheduled_backup_task.time_limit == s.backup_task_time_limit_seconds == 7800
    assert scheduled_backup_task.soft_time_limit < scheduled_backup_task.time_limit

    assert retention_purge_task.soft_time_limit == s.retention_task_soft_time_limit_seconds == 5400
    assert retention_purge_task.time_limit == s.retention_task_time_limit_seconds == 6000
    assert retention_purge_task.soft_time_limit < retention_purge_task.time_limit


def test_global_scan_time_limits_unchanged():
    # F5 must NOT touch the global (scan) limits; the scan task inherits them (no per-task override).
    from apps.api.celery_app.tasks.scan_tasks import run_scan_task
    from apps.api.celery_app.worker import celery_app

    s = get_settings()
    assert celery_app.conf.task_soft_time_limit == s.celery_task_soft_time_limit_seconds == 3600
    assert celery_app.conf.task_time_limit == s.celery_task_time_limit_seconds == 3900
    assert run_scan_task.soft_time_limit is None  # scan task uses the GLOBAL limit, no override
    assert run_scan_task.time_limit is None


# --- backup soft-timeout handling ---------------------------------------------------------

def test_backup_task_handles_soft_timeout(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "backup_enabled", True)

    def _boom(_settings):
        raise SoftTimeLimitExceeded()

    # run_backup is imported inside the task from its source module -- patch it there.
    import apps.api.dr.service as dr_service

    monkeypatch.setattr(dr_service, "run_backup", _boom)

    recorded = {"n": 0}
    from apps.api.core import observability as obs

    monkeypatch.setattr(obs, "record_backup_failure", lambda: recorded.__setitem__("n", recorded["n"] + 1))

    result = scheduled_backup_task.run()
    assert result == "timeout"        # graceful, not an unhandled crash
    assert recorded["n"] == 1         # F4 reliability metric recorded


def test_backup_task_disabled_short_circuits(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "backup_enabled", False)
    assert scheduled_backup_task.run() == "disabled"


# --- retention soft-timeout handling ------------------------------------------------------

def test_retention_task_handles_soft_timeout(monkeypatch):
    def _boom(*a, **k):
        raise SoftTimeLimitExceeded()

    from apps.api.retention import service as retention_service

    monkeypatch.setattr(retention_service, "run_purge", _boom)

    out = retention_purge_task.run()
    assert out["mode"] == "timeout"   # graceful summary, not an unhandled crash
    assert out["total_eligible"] == 0
    assert out["resources"] == []
