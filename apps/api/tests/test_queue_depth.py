"""Scan-queue-depth exporter -- mbs_queue_depth{queue}.

The API-side ReliabilityCollector exposes the pending length of each Celery broker queue (LLEN of
the queue's Redis list) so a scan backlog is directly visible/alertable. Best-effort: a Redis error
yields nothing and never breaks a /metrics scrape. Uses a fake Redis so the tests are hermetic.
"""
import pytest

import apps.api.core.observability as obs


def _prom_or_skip():
    if not getattr(obs, "_PROM", False):
        pytest.skip("prometheus_client not installed")


class FakeRedis:
    """Minimal Redis stand-in: llen returns configured per-key lengths (default 0); get returns
    None (so the backup/retention/age signals stay absent). Set raise_on=True to simulate an outage."""

    def __init__(self, lens=None, raise_on=False):
        self._lens = lens or {}
        self._raise = raise_on

    def llen(self, key):
        if self._raise:
            raise RuntimeError("redis unavailable")
        return self._lens.get(key, 0)

    def get(self, key):
        if self._raise:
            raise RuntimeError("redis unavailable")
        return None


def _queue_samples(monkeypatch, fake):
    monkeypatch.setattr(obs, "_reliability_redis", lambda: fake)
    families = {mf.name: mf for mf in obs.ReliabilityCollector().collect()}
    assert "mbs_queue_depth" in families
    return {s.labels["queue"]: s.value for s in families["mbs_queue_depth"].samples}


def test_scans_queue_depth_exported(monkeypatch):
    _prom_or_skip()
    vals = _queue_samples(monkeypatch, FakeRedis(lens={"scans": 7}))
    assert vals["scans"] == 7.0
    assert vals["default"] == 0.0            # other queue still reported, at 0


def test_default_queue_depth_exported(monkeypatch):
    _prom_or_skip()
    vals = _queue_samples(monkeypatch, FakeRedis(lens={"default": 3}))
    assert vals["default"] == 3.0
    assert vals["scans"] == 0.0


def test_both_queues_reported(monkeypatch):
    _prom_or_skip()
    vals = _queue_samples(monkeypatch, FakeRedis(lens={"scans": 5, "default": 2}))
    assert vals == {"scans": 5.0, "default": 2.0}


def test_empty_or_missing_queues_are_zero(monkeypatch):
    _prom_or_skip()
    vals = _queue_samples(monkeypatch, FakeRedis(lens={}))   # no keys -> LLEN 0
    assert vals == {"scans": 0.0, "default": 0.0}


def test_redis_failure_does_not_break_collector(monkeypatch):
    _prom_or_skip()
    monkeypatch.setattr(obs, "_reliability_redis", lambda: FakeRedis(raise_on=True))
    # collect() must swallow the Redis error and simply yield nothing -- never raise.
    families = list(obs.ReliabilityCollector().collect())
    assert families == []
