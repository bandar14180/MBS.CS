"""A -- dependency-health metric (mbs_dependency_up).

The API exposes a scrape-time gauge for the liveness of its core backing services (MySQL,
Redis) via short-timeout SYNCHRONOUS probes. Probes are best-effort: an underlying error is
reported as down (0) and never raises, so a dependency outage can never break a /metrics scrape.
"""
import pytest

import apps.api.core.observability as obs


def _prom_or_skip():
    if not getattr(obs, "_PROM", False):
        pytest.skip("prometheus_client not installed")


# --- probes are best-effort (never raise) ---------------------------------------------------

def test_probe_mysql_reports_down_on_error(monkeypatch):
    monkeypatch.setattr("pymysql.connect", lambda *a, **k: (_ for _ in ()).throw(OSError("down")))
    assert obs._probe_mysql() is False   # returns, does not raise


def test_probe_redis_reports_down_on_error(monkeypatch):
    def boom(*a, **k):
        raise OSError("down")

    monkeypatch.setattr("redis.from_url", boom)
    assert obs._probe_redis() is False


# --- collector maps probe results to the gauge ----------------------------------------------

def test_collector_reports_up_and_down(monkeypatch):
    _prom_or_skip()
    monkeypatch.setattr(obs, "_probe_mysql", lambda: True)
    monkeypatch.setattr(obs, "_probe_redis", lambda: False)
    families = {mf.name: mf for mf in obs.DependencyHealthCollector().collect()}
    assert "mbs_dependency_up" in families
    vals = {s.labels["component"]: s.value for s in families["mbs_dependency_up"].samples}
    assert vals == {"mysql": 1.0, "redis": 0.0}


def test_collector_reports_all_up(monkeypatch):
    _prom_or_skip()
    monkeypatch.setattr(obs, "_probe_mysql", lambda: True)
    monkeypatch.setattr(obs, "_probe_redis", lambda: True)
    fam = {mf.name: mf for mf in obs.DependencyHealthCollector().collect()}["mbs_dependency_up"]
    assert {s.labels["component"]: s.value for s in fam.samples} == {"mysql": 1.0, "redis": 1.0}


# --- registration is API-side + idempotent --------------------------------------------------

def test_collector_registered_on_app_import():
    _prom_or_skip()
    # importing apps.api.main (via conftest) builds the app, which registers the collector once;
    # a second call is a no-op (idempotent) and returns False.
    assert obs._dependency_registered is True
    assert obs.register_dependency_health_collector() is False
