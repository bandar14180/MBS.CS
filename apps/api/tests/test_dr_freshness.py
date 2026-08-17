"""DR-4 -- backup freshness signal.

record_backup_success() stamps the last-success time in Redis; the API-side ReliabilityCollector
exposes it as mbs_backup_age_seconds so a SILENTLY stalled backup pipeline (no explicit failure)
is alertable. Uses a fake Redis so the test is hermetic.
"""
import time

import pytest

import apps.api.core.observability as obs


class FakeRedis:
    def __init__(self):
        self.kv: dict[str, str] = {}

    def set(self, k, v):
        self.kv[k] = str(v)

    def get(self, k):
        return self.kv.get(k)

    def llen(self, k):
        return 0


def test_record_backup_success_stamps_timestamp(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(obs, "_reliability_redis", lambda: fake)
    obs.record_backup_success(ts=1000)
    assert fake.get(obs.BACKUP_LAST_SUCCESS_KEY) == "1000"


def test_record_backup_success_defaults_to_now(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(obs, "_reliability_redis", lambda: fake)
    obs.record_backup_success()
    assert int(fake.get(obs.BACKUP_LAST_SUCCESS_KEY)) == pytest.approx(int(time.time()), abs=5)


def test_collector_emits_backup_age(monkeypatch):
    if not getattr(obs, "_PROM", False):
        pytest.skip("prometheus_client not installed")
    fake = FakeRedis()
    fake.set(obs.BACKUP_LAST_SUCCESS_KEY, int(time.time()) - 50)
    monkeypatch.setattr(obs, "_reliability_redis", lambda: fake)
    families = {mf.name: mf for mf in obs.ReliabilityCollector().collect()}
    assert "mbs_backup_age_seconds" in families
    value = families["mbs_backup_age_seconds"].samples[0].value
    assert 40 <= value <= 120


def test_collector_omits_age_when_never_backed_up(monkeypatch):
    if not getattr(obs, "_PROM", False):
        pytest.skip("prometheus_client not installed")
    monkeypatch.setattr(obs, "_reliability_redis", lambda: FakeRedis())  # no last-success key
    families = {mf.name for mf in obs.ReliabilityCollector().collect()}
    assert "mbs_backup_age_seconds" not in families  # no misleading age before first backup
    assert "mbs_dlq_depth" in families                # other reliability signals still present
