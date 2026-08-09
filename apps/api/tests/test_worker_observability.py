"""Phase 4.1 -- worker observability: the worker Prometheus endpoint, the new reliability
counters, and correlation-id propagation API -> Celery task.
"""
import socket
import urllib.request

import pytest

from apps.api.core import observability as obs
from apps.api.core.config import get_settings
from apps.api.tests.test_scans import _auth, _make_target, _register, _verify_target

_prom = pytest.mark.skipif(not obs._PROM, reason="prometheus_client not installed")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --- 1) worker metrics endpoint ----------------------------------------------------------

@_prom
def test_worker_metrics_server_starts_and_serves(monkeypatch):
    from apps.api.celery_app.metrics import start_worker_metrics_server

    port = _free_port()
    monkeypatch.setattr(get_settings(), "worker_metrics_enabled", True)
    monkeypatch.setattr(get_settings(), "worker_metrics_port", port)

    assert start_worker_metrics_server() is True
    body = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5).read().decode()
    assert "mbs_" in body   # our metric families are exposed by the worker endpoint


def test_worker_metrics_disabled_returns_false(monkeypatch):
    from apps.api.celery_app.metrics import start_worker_metrics_server

    monkeypatch.setattr(get_settings(), "worker_metrics_enabled", False)
    assert start_worker_metrics_server() is False   # nothing bound when disabled


@_prom
def test_worker_metrics_start_is_best_effort(monkeypatch):
    """A bind/start failure must be swallowed -- worker startup never fails on metrics."""
    from apps.api.celery_app import metrics

    monkeypatch.setattr(get_settings(), "worker_metrics_enabled", True)

    def _boom(*a, **k):
        raise OSError("address already in use")

    monkeypatch.setattr("prometheus_client.start_http_server", _boom)
    assert metrics.start_worker_metrics_server() is False   # error swallowed, no raise


# --- 2) new reliability metrics registered + increment -----------------------------------

@_prom
def test_reliability_metrics_registered_and_increment():
    assert obs.SCHEDULE_LAUNCHED._labelnames == ("result",)
    assert obs.SCAN_RELAYED._labelnames == ()

    before = obs.SCHEDULE_LAUNCHED.labels("launched")._value.get()
    obs.record_schedule_launched("launched")
    assert obs.SCHEDULE_LAUNCHED.labels("launched")._value.get() == before + 1

    r0 = obs.SCAN_RELAYED._value.get()
    obs.record_scan_relayed(3)
    assert obs.SCAN_RELAYED._value.get() == r0 + 3
    obs.record_scan_relayed(0)                       # no-op guard
    assert obs.SCAN_RELAYED._value.get() == r0 + 3


# --- 3) correlation-id propagation -------------------------------------------------------

def test_run_scan_task_sets_correlation_from_kwarg(monkeypatch):
    """The task binds the propagated correlation id so worker/scan logs join the request."""
    from apps.api.celery_app.tasks import scan_tasks
    from apps.api.core.observability import get_correlation_id

    captured = {}

    async def _fake_run(_scan_id):
        captured["cid"] = get_correlation_id()

    monkeypatch.setattr(scan_tasks, "_run", _fake_run)
    scan_tasks.run_scan_task.apply(args=["scan-x"], kwargs={"correlation_id": "trace-XYZ"})
    assert captured["cid"] == "trace-XYZ"


def test_run_scan_task_generates_correlation_when_missing(monkeypatch):
    from apps.api.celery_app.tasks import scan_tasks
    from apps.api.core.observability import get_correlation_id, set_correlation_id

    set_correlation_id("-")   # reset ambient
    captured = {}

    async def _fake_run(_scan_id):
        captured["cid"] = get_correlation_id()

    monkeypatch.setattr(scan_tasks, "_run", _fake_run)
    scan_tasks.run_scan_task.apply(args=["scan-y"])           # no correlation_id passed
    assert captured["cid"] and captured["cid"] != "-"         # a fresh id was generated


def test_create_scan_propagates_request_correlation_id(client, monkeypatch):
    """A create-scan request's X-Request-ID reaches run_scan_task.delay(correlation_id=...)."""
    from apps.api.celery_app.tasks import scan_tasks

    captured = {}

    class _Res:
        id = "task-1"

    def _fake_delay(sid, **kw):
        captured["sid"] = sid
        captured["cid"] = kw.get("correlation_id")
        return _Res()

    monkeypatch.setattr(scan_tasks.run_scan_task, "delay", _fake_delay)

    headers = _auth(_register(client, "CorrProp"))
    ws, project, target = _make_target(client, headers)
    _verify_target(client, headers, ws, project, target)
    r = client.post(
        f"/api/v1/workspaces/{ws}/projects/{project}/scans",
        headers={**headers, "X-Request-ID": "req-trace-999"},
        json={"target_id": target, "scan_type": "network", "requested_modules": ["naabu"]},
    )
    assert r.status_code == 202, r.text
    assert captured["cid"] == "req-trace-999"                 # request id propagated to the task
