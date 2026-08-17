"""P1.1 -- beat-liveness heartbeat signal.

record_beat_tick() stamps the last beat-heartbeat time in Redis; the API-side ReliabilityCollector
exposes it as mbs_beat_age_seconds so a stalled scheduler (beat down, or worker-default not draining
the default queue) is alertable. The beat_heartbeat task is a thin best-effort wrapper, and the
real worker schedules it every tick. Uses a fake Redis so the tests are hermetic.
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


# --- signal (record + collector) ------------------------------------------------------------

def test_record_beat_tick_stamps_timestamp(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(obs, "_reliability_redis", lambda: fake)
    obs.record_beat_tick(ts=2000)
    assert fake.get(obs.BEAT_LAST_TICK_KEY) == "2000"


def test_record_beat_tick_defaults_to_now(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(obs, "_reliability_redis", lambda: fake)
    obs.record_beat_tick()
    assert int(fake.get(obs.BEAT_LAST_TICK_KEY)) == pytest.approx(int(time.time()), abs=5)


def test_record_beat_tick_safe_without_redis(monkeypatch):
    # best-effort: a missing Redis client must never raise into the caller (beat/worker)
    monkeypatch.setattr(obs, "_reliability_redis", lambda: None)
    obs.record_beat_tick()  # no exception


def test_collector_emits_beat_age(monkeypatch):
    if not getattr(obs, "_PROM", False):
        pytest.skip("prometheus_client not installed")
    fake = FakeRedis()
    fake.set(obs.BEAT_LAST_TICK_KEY, int(time.time()) - 45)
    monkeypatch.setattr(obs, "_reliability_redis", lambda: fake)
    families = {mf.name: mf for mf in obs.ReliabilityCollector().collect()}
    assert "mbs_beat_age_seconds" in families
    value = families["mbs_beat_age_seconds"].samples[0].value
    assert 35 <= value <= 120


def test_collector_omits_beat_age_when_never_ticked(monkeypatch):
    if not getattr(obs, "_PROM", False):
        pytest.skip("prometheus_client not installed")
    monkeypatch.setattr(obs, "_reliability_redis", lambda: FakeRedis())  # no tick key set
    families = {mf.name for mf in obs.ReliabilityCollector().collect()}
    assert "mbs_beat_age_seconds" not in families   # no misleading age before the first tick
    assert "mbs_dlq_depth" in families               # other reliability signals still present


# --- task + schedule wiring -----------------------------------------------------------------

def test_beat_heartbeat_task_records_tick(monkeypatch):
    import apps.api.celery_app.tasks.reliability_tasks as rt

    calls = []
    monkeypatch.setattr(
        "apps.api.core.observability.record_beat_tick", lambda *a, **k: calls.append(1)
    )
    result = rt.beat_heartbeat_task()
    assert result == {"ok": True}
    assert calls == [1]   # the task stamps exactly one heartbeat


def test_beat_heartbeat_is_scheduled():
    """The real worker schedules the heartbeat unconditionally, pointing at the task by name."""
    from apps.api.celery_app.worker import celery_app

    entry = celery_app.conf.beat_schedule.get("beat-heartbeat")
    assert entry is not None, "beat-heartbeat must be scheduled in every deployment"
    assert entry["task"] == "reliability.beat_heartbeat"
    assert entry["schedule"] > 0
