"""F4 -- reliability signals (DLQ depth + backup/retention failure counters).

The signals live in Redis (shared across processes) and are exposed on the API /metrics via a
custom collector, so they surface without the worker prefork/multiprocess machinery. These tests
inject a fake Redis (no broker/network) and assert: the recorders INCR the right keys, the
collector emits the right metric families/values, best-effort no-ops when Redis is down, and a
failed retention run records the failure signal.
"""
import pytest

from apps.api.core import observability as obs


class _FakeRedis:
    def __init__(self, dlq=0, backup=0, retention=0):
        self._dlq = dlq
        self._vals = {obs.BACKUP_FAILURES_KEY: backup, obs.RETENTION_FAILURES_KEY: retention}
        self.incrs: list[str] = []

    def llen(self, key):
        return self._dlq if key == obs.DLQ_REDIS_KEY else 0

    def get(self, key):
        return self._vals.get(key)

    def incr(self, key):
        self._vals[key] = int(self._vals.get(key) or 0) + 1
        self.incrs.append(key)
        return self._vals[key]


# --- recorders ------------------------------------------------------------------------------

def test_record_backup_failure_increments_key(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(obs, "_reliability_redis", lambda: fake)
    obs.record_backup_failure()
    assert fake.incrs == [obs.BACKUP_FAILURES_KEY]


def test_record_retention_failure_increments_key(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(obs, "_reliability_redis", lambda: fake)
    obs.record_retention_failure()
    assert fake.incrs == [obs.RETENTION_FAILURES_KEY]


def test_recorders_are_best_effort_when_redis_down(monkeypatch):
    monkeypatch.setattr(obs, "_reliability_redis", lambda: None)
    # must not raise
    obs.record_backup_failure()
    obs.record_retention_failure()


# --- collector ------------------------------------------------------------------------------

def _samples(families):
    out = {}
    for fam in families:
        for s in fam.samples:
            out[s.name] = (s.labels, s.value)
    return out


def test_collector_emits_dlq_depth_and_failure_counters(monkeypatch):
    if not obs._PROM:
        pytest.skip("prometheus_client not installed")
    fake = _FakeRedis(dlq=3, backup=2, retention=5)
    monkeypatch.setattr(obs, "_reliability_redis", lambda: fake)

    samples = _samples(list(obs.ReliabilityCollector().collect()))
    assert samples["mbs_dlq_depth"] == ({"queue": "scans.run_scan"}, 3.0)
    # CounterMetricFamily exposes the sample as <name>_total
    assert samples["mbs_backup_failures_total"][1] == 2.0
    assert samples["mbs_retention_failures_total"][1] == 5.0


def test_collector_is_best_effort_when_redis_down(monkeypatch):
    if not obs._PROM:
        pytest.skip("prometheus_client not installed")
    monkeypatch.setattr(obs, "_reliability_redis", lambda: None)
    assert list(obs.ReliabilityCollector().collect()) == []  # yields nothing, never raises


def test_register_reliability_collector_is_idempotent(monkeypatch):
    if not obs._PROM:
        pytest.skip("prometheus_client not installed")
    # Whether or not it was already registered by app creation, a further call must not raise
    # and must not double-register.
    first = obs.register_reliability_collector()
    second = obs.register_reliability_collector()
    assert second is False  # idempotent: never registers twice
    assert isinstance(first, bool)


# --- retention failure path records the signal ---------------------------------------------

def test_run_purge_records_failure_and_reraises(monkeypatch):
    from apps.api.core.config import get_settings
    from apps.api.retention import service

    s = get_settings()
    monkeypatch.setattr(s, "retention_enabled", True)
    monkeypatch.setattr(s, "retention_dry_run", True)

    async def _boom(*a, **k):
        raise RuntimeError("purge blew up")

    monkeypatch.setattr(service, "_run_async", _boom)

    recorded = {"n": 0}
    monkeypatch.setattr(obs, "record_retention_failure", lambda: recorded.__setitem__("n", recorded["n"] + 1))

    with pytest.raises(RuntimeError):
        service.run_purge(s)
    assert recorded["n"] == 1  # the failure signal was recorded before re-raising
