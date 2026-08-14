"""Email Alert System (E1..E5) -- provider, async task, dispatch, metrics, audit, safety.

All hermetic: SMTP is faked (no network), the Celery task is exercised via .apply() (no broker),
and the settings singleton is monkeypatched. Redis dedup is stubbed where it isn't under test.
"""
import asyncio
import logging
import os
import uuid
from types import SimpleNamespace

import pytest

from apps.api.core.config import Settings, get_settings
from apps.api.modules.notifications import alerts, email as email_mod, metrics as email_metrics
from apps.api.modules.notifications.providers import EmailNotificationProvider


def _enable_email(monkeypatch, **over):
    s = get_settings()
    base = dict(
        email_enabled=True, email_provider="smtp", smtp_host="smtp.test", smtp_port=587,
        smtp_username="", smtp_password="", smtp_use_tls=True, smtp_timeout_seconds=5,
        email_from_address="alerts@mbs.test", email_admin_recipients=["admin@mbs.test"],
        email_dedup_window_seconds=300, email_max_retries=3,
    )
    base.update(over)
    for k, v in base.items():
        monkeypatch.setattr(s, k, v)
    return s


# --- E1: provider -------------------------------------------------------------------------

def test_provider_disabled_is_noop(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "email_enabled", False)
    called = {"n": 0}
    monkeypatch.setattr(email_mod, "smtp_send", lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    asyncio.run(EmailNotificationProvider(s, ["x@y.com"]).send(title="t", body="b"))
    assert called["n"] == 0  # disabled -> nothing sent


def test_provider_enabled_sends_via_smtp(monkeypatch):
    s = _enable_email(monkeypatch)
    captured = {}
    monkeypatch.setattr(email_mod, "smtp_send",
                        lambda settings, recipients, subject, body: captured.update(
                            recipients=recipients, subject=subject, body=body))
    asyncio.run(EmailNotificationProvider(s, ["x@y.com"]).send(title="Subj", body="Body", type="scan_failed"))
    assert captured == {"recipients": ["x@y.com"], "subject": "Subj", "body": "Body"}


def test_provider_falls_back_to_admins_when_no_recipients(monkeypatch):
    s = _enable_email(monkeypatch, email_admin_recipients=["admin@mbs.test"])
    captured = {}
    monkeypatch.setattr(email_mod, "smtp_send",
                        lambda settings, recipients, *a: captured.update(recipients=recipients))
    asyncio.run(EmailNotificationProvider(s, []).send(title="t", body="b"))
    assert captured["recipients"] == ["admin@mbs.test"]


def test_smtp_send_wraps_failure(monkeypatch):
    import smtplib

    class _Boom:
        def __init__(self, *a, **k): raise OSError("connection refused")

    monkeypatch.setattr(smtplib, "SMTP", _Boom)
    s = _enable_email(monkeypatch)
    with pytest.raises(email_mod.EmailDeliveryError):
        email_mod.smtp_send(s, ["x@y.com"], "s", "b")


def test_smtp_password_loads_from_file(monkeypatch, tmp_path):
    from apps.api.core import config as cfg

    secret = tmp_path / "smtp_pw.txt"
    secret.write_text("s3cr3t-smtp-pass\n", encoding="utf-8")
    monkeypatch.setenv("SMTP_PASSWORD_FILE", str(secret))
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    cfg._resolve_file_secrets()
    assert os.environ["SMTP_PASSWORD"] == "s3cr3t-smtp-pass"
    assert Settings().smtp_password == "s3cr3t-smtp-pass"


# --- E2: async delivery task --------------------------------------------------------------

def _run_task(monkeypatch, **over):
    from apps.api.celery_app.tasks import notification_tasks as nt

    monkeypatch.setattr(nt, "_dedup_seen_and_mark", lambda *a, **k: over.pop("_deduped", False))
    monkeypatch.setattr(nt, "_backoff", lambda retries: 0)  # no sleeping in tests
    return nt


def test_task_disabled_returns_disabled(monkeypatch):
    monkeypatch.setattr(get_settings(), "email_enabled", False)
    nt = _run_task(monkeypatch)
    assert nt.send_email_task.apply(args=[["x@y.com"], "s", "b", "scan_failed", None]).result == "disabled"


def test_task_no_recipients(monkeypatch):
    _enable_email(monkeypatch)
    nt = _run_task(monkeypatch)
    assert nt.send_email_task.apply(args=[[], "s", "b", "scan_failed", None]).result == "no_recipients"


def test_task_deduped(monkeypatch):
    _enable_email(monkeypatch)
    nt = _run_task(monkeypatch, _deduped=True)
    assert nt.send_email_task.apply(args=[["x@y.com"], "s", "b", "scan_failed", None]).result == "deduped"


def test_task_sends_successfully(monkeypatch, caplog):
    _enable_email(monkeypatch)
    nt = _run_task(monkeypatch)
    monkeypatch.setattr(email_mod, "smtp_send", lambda *a, **k: None)  # success
    with caplog.at_level(logging.INFO, logger="mbs.security"):
        res = nt.send_email_task.apply(args=[["x@y.com"], "Subj", "Body", "scan_failed", "w1"]).result
    assert res == "sent"
    assert "notification.email.sent" in {r.getMessage() for r in caplog.records}


def test_task_permanent_failure_returns_failed(monkeypatch, caplog):
    _enable_email(monkeypatch)
    nt = _run_task(monkeypatch)

    def _boom(*a, **k):
        raise ValueError("bad address")  # non-transient -> no retry

    monkeypatch.setattr(email_mod, "smtp_send", _boom)
    with caplog.at_level(logging.INFO, logger="mbs.security"):
        res = nt.send_email_task.apply(args=[["x@y.com"], "s", "b", "scan_failed", None]).result
    assert res == "failed"
    assert "notification.email.failed" in {r.getMessage() for r in caplog.records}


def test_task_transient_failure_retries_then_gives_up(monkeypatch):
    from apps.api.celery_app.worker import celery_app

    _enable_email(monkeypatch)
    nt = _run_task(monkeypatch)
    monkeypatch.setattr(celery_app.conf, "task_always_eager", True)
    monkeypatch.setattr(celery_app.conf, "task_eager_propagates", False)

    def _transient(*a, **k):
        raise email_mod.EmailDeliveryError("SMTP delivery failed: SMTPServerDisconnected")

    monkeypatch.setattr(email_mod, "smtp_send", _transient)
    before = _failed_count("scan_failed")
    nt.send_email_task.apply(args=[["x@y.com"], "s", "b", "scan_failed", None])
    # the transient path recorded at least one delivery failure (retry attempts were made)
    assert _failed_count("scan_failed") - before >= 1


# --- E4: dispatch / event integration -----------------------------------------------------

def _capture_delay(monkeypatch):
    from apps.api.celery_app.tasks import notification_tasks as nt

    calls = []
    monkeypatch.setattr(nt.send_email_task, "delay", lambda *a, **k: calls.append((a, k)))
    return calls


def test_scan_alert_enqueues_for_emailable_type(monkeypatch):
    _enable_email(monkeypatch)
    calls = _capture_delay(monkeypatch)
    monkeypatch.setattr(alerts, "_workspace_recipients",
                        lambda db, ws: _await_value(["u@ws.com"]))
    note = SimpleNamespace(type="scan_failed", title="Scan failed", body="body", workspace_id=uuid.uuid4())
    asyncio.run(alerts.email_scan_alert(db=None, note=note))
    assert len(calls) == 1
    recipients, subject, body, category, wsid = calls[0][0]
    assert recipients == ["u@ws.com"] and category == "scan_failed"


def test_scan_alert_skips_non_emailable_type(monkeypatch):
    _enable_email(monkeypatch)
    calls = _capture_delay(monkeypatch)
    note = SimpleNamespace(type="scan_completed", title="ok", body="b", workspace_id=uuid.uuid4())
    asyncio.run(alerts.email_scan_alert(db=None, note=note))
    assert calls == []  # info completion is in-app only


def test_scan_alert_skips_when_disabled(monkeypatch):
    monkeypatch.setattr(get_settings(), "email_enabled", False)
    calls = _capture_delay(monkeypatch)
    note = SimpleNamespace(type="scan_failed", title="x", body="b", workspace_id=uuid.uuid4())
    asyncio.run(alerts.email_scan_alert(db=None, note=note))
    assert calls == []


def test_system_alert_enqueues_to_admins(monkeypatch):
    _enable_email(monkeypatch, email_admin_recipients=["ops@mbs.test"])
    calls = _capture_delay(monkeypatch)
    alerts.email_system_alert("backup_failed", "Backup run failed", "see runbook")
    assert len(calls) == 1
    recipients, subject, body, category, wsid = calls[0][0]
    assert recipients == ["ops@mbs.test"] and category == "backup_failed" and wsid is None


def test_system_alert_skips_without_admins(monkeypatch):
    _enable_email(monkeypatch, email_admin_recipients=[])
    calls = _capture_delay(monkeypatch)
    alerts.email_system_alert("backup_failed", "x", "y")
    assert calls == []


# --- E5: metrics + leakage prevention -----------------------------------------------------

def test_metrics_record_sent_and_failed():
    if not getattr(email_metrics, "_PROM", False):
        pytest.skip("prometheus_client not installed")
    sent_before = _sent_count("critical_findings")
    email_metrics.record_email_sent("critical_findings", duration_s=0.1)
    assert _sent_count("critical_findings") - sent_before == 1
    failed_before = _failed_count("critical_findings")
    email_metrics.record_email_failed("critical_findings")
    assert _failed_count("critical_findings") - failed_before == 1


def test_dispatch_redacts_secrets_and_pii(monkeypatch):
    _enable_email(monkeypatch)
    calls = _capture_delay(monkeypatch)
    # subject/body carry an email + a bearer token; both must be scrubbed before enqueue.
    alerts.email_system_alert(
        "backup_failed",
        "alert for admin@corp.com",
        "token Authorization: Bearer sk-abc.def-123 and key mbsk_supersecret",
    )
    _, subject, body, _, _ = calls[0][0]
    assert "admin@corp.com" not in subject
    assert "sk-abc.def-123" not in body and "mbsk_supersecret" not in body


def test_audit_event_carries_no_recipient_address(monkeypatch, caplog):
    _enable_email(monkeypatch)
    nt = _run_task(monkeypatch)
    monkeypatch.setattr(email_mod, "smtp_send", lambda *a, **k: None)
    with caplog.at_level(logging.INFO, logger="mbs.security"):
        nt.send_email_task.apply(args=[["secret-user@corp.com"], "s", "b", "scan_failed", None])
    rec = next(r for r in caplog.records if r.getMessage() == "notification.email.sent")
    # the audit record has a recipient COUNT, never the address itself, and no body
    assert getattr(rec, "recipients", None) == 1
    assert "secret-user@corp.com" not in str(rec.__dict__)


# --- helpers -------------------------------------------------------------------------------

def _await_value(value):
    async def _coro():
        return value
    return _coro()


def _sent_count(cat: str) -> float:
    return email_metrics.EMAIL_SENT.labels(cat)._value.get()


def _failed_count(cat: str) -> float:
    return email_metrics.EMAIL_FAILED.labels(cat)._value.get()
