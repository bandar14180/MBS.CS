"""Phase 8 reliability hardening -- worker exit codes and fleet-capacity visibility.

TWO INCIDENTS, ONE ROOT SHAPE
-----------------------------
Both of these let a total scanning outage look like a healthy system for four days.

  1. EXIT CODE. `lease_loop` stops when the manager refuses this worker's identity (403
     revoked/suspended/unknown), but `main()` returned 0 -- the same code as a clean
     shutdown. Docker's `restart: unless-stopped` restarted it, and `docker ps` showed
     `Restarting (0)`: an exit code an operator reads as success. Observed live: 58
     restarts against a 403 WORKER_SUSPENDED, never once a non-zero code.

  2. CAPACITY METRIC. Every worker alert keyed off LIVENESS
     (`mbs_scanner_worker_heartbeat_age_seconds`), but a suspended worker is refused at
     AUTHENTICATION and so can never refresh `last_seen_at`. The staleness metric stops
     ageing -- or is never emitted -- exactly when the fleet is suspended, so
     `MbsScannerWorkerHeartbeatStale` goes QUIET at the worst possible moment.

WHAT THESE TESTS GUARD
----------------------
  * an identity refusal exits NON-ZERO, and a transient failure still does not;
  * transient failures keep their existing retry/backoff behaviour (the dangerous
     over-correction: turning a network blip into a crash loop);
  * a status-derived capacity gauge exists and reads 0 for a suspended fleet, whether or
     not anything is still heartbeating.
"""
import asyncio

import pytest

from apps.api.scanner_manager.app import _worker_metric_lines
from apps.api.scanner_worker import lease_loop as ll


# =========================================================================================
# 1. CRASH BEHAVIOUR -- identity refusal vs transient failure
# =========================================================================================

class _Client:
    """A ManagerClient stand-in whose `lease` raises whatever the test needs."""

    def __init__(self, error=None):
        self.error = error
        self.lease_calls = 0
        self.heartbeats = 0

    async def heartbeat(self, **kw):
        self.heartbeats += 1
        return {"ok": True}

    async def lease(self, max_jobs=1):
        self.lease_calls += 1
        if self.error:
            raise self.error
        return []

    async def complete(self, **kw):
        return {"accepted": True}


def _identity():
    return ll.WorkerIdentity(
        worker_id="wk-test", pool_id="public-default", site_id=None,
        manager_url="http://manager:8100", token="t",
    )


def _loop(client, *, iterations=3):
    loop = ll.LeaseLoop(_identity(), client, executor=None, max_iterations=iterations)
    # Zero delays so a backoff path does not make the test slow.
    loop.backoff = ll.BackoffPolicy(base_seconds=0, max_seconds=0, idle_seconds=0,
                                    heartbeat_seconds=0)
    return loop


def test_identity_refusal_sets_a_fatal_reason():
    """A 403 (revoked / suspended / unknown worker) is terminal -- no retry can clear it,
    so the loop stops AND records why."""
    client = _Client(ll.LeaseError(ll.REASON_AUTH_FAILED, "manager refused this worker"))
    loop = _loop(client)
    asyncio.run(loop.run())
    assert loop.fatal_reason == ll.REASON_AUTH_FAILED
    # Stopped immediately: it did not keep hammering the manager.
    assert client.lease_calls == 1


def test_identity_refusal_exits_non_zero(monkeypatch):
    """THE REGRESSION TEST FOR THE INCIDENT. `main()` must surface an identity refusal as a
    PROCESS FAILURE, not as the exit 0 that made a 4-day outage read as a clean shutdown."""
    from apps.api.scanner_worker import main as worker_main

    client = _Client(ll.LeaseError(ll.REASON_AUTH_FAILED, "WORKER_SUSPENDED"))
    loop = _loop(client)

    monkeypatch.setattr(worker_main, "build_loop", lambda *a, **k: loop)
    monkeypatch.setattr(worker_main, "enforce_execution_plane_credentials", lambda: None)
    monkeypatch.setattr(worker_main, "configure_networking", lambda s: None)

    rc = worker_main.main()
    assert rc != 0, "an identity refusal must not exit 0 -- it reads as a clean shutdown"
    assert rc == 3


def test_a_clean_shutdown_still_exits_zero(monkeypatch):
    """The other direction. A loop that stops for a survivable reason (here: the test's
    iteration bound, in production a SIGTERM drain) must keep exiting 0, or every normal
    redeploy would look like a failure."""
    from apps.api.scanner_worker import main as worker_main

    loop = _loop(_Client())  # no error: polls, finds nothing, stops on max_iterations
    monkeypatch.setattr(worker_main, "build_loop", lambda *a, **k: loop)
    monkeypatch.setattr(worker_main, "enforce_execution_plane_credentials", lambda: None)
    monkeypatch.setattr(worker_main, "configure_networking", lambda s: None)

    assert worker_main.main() == 0
    assert loop.fatal_reason is None


def test_a_transient_manager_failure_does_not_become_fatal():
    """THE DANGEROUS OVER-CORRECTION, guarded. A manager outage or transport error must NOT
    set `fatal_reason` and must NOT stop the loop -- otherwise a network blip becomes the
    very crash loop this work exists to remove."""
    client = _Client(ConnectionError("manager unreachable"))
    loop = _loop(client, iterations=3)
    asyncio.run(loop.run())
    assert loop.fatal_reason is None
    # Retried on every iteration rather than stopping after the first failure.
    assert client.lease_calls == 3


def test_a_transient_failure_exits_zero(monkeypatch):
    """A worker that could not reach the manager has not failed permanently, so it must not
    report a fatal exit either -- the restart is the correct recovery there."""
    from apps.api.scanner_worker import main as worker_main

    loop = _loop(_Client(ConnectionError("boom")), iterations=2)
    monkeypatch.setattr(worker_main, "build_loop", lambda *a, **k: loop)
    monkeypatch.setattr(worker_main, "enforce_execution_plane_credentials", lambda: None)
    monkeypatch.setattr(worker_main, "configure_networking", lambda s: None)

    assert worker_main.main() == 0


def test_a_non_auth_lease_error_is_retried_not_fatal():
    """A LeaseError that is not an identity refusal (e.g. a job-shaped refusal) keeps its
    existing backoff-and-continue behaviour."""
    client = _Client(ll.LeaseError(ll.REASON_MANAGER_UNAVAILABLE, "temporarily unavailable"))
    loop = _loop(client, iterations=2)
    asyncio.run(loop.run())
    assert loop.fatal_reason is None
    assert client.lease_calls == 2


# =========================================================================================
# 2. ZERO ELIGIBLE WORKERS -- a status-derived capacity gauge
# =========================================================================================

from datetime import datetime, timedelta, timezone  # noqa: E402  (kept beside its users)

NOW = datetime(2026, 9, 17, 12, 0, 0, tzinfo=timezone.utc)


class _Row:
    """A `scanner_workers` row stand-in (the projection reads attributes only)."""

    def __init__(self, **kw):
        self.pool_id = kw.get("pool_id", "public-default")
        self.site_id = kw.get("site_id")
        self.workspace_id = kw.get("workspace_id")
        self.worker_id = kw.get("worker_id", "wk")
        self.status = kw.get("status", "active")
        self.revoked_at = kw.get("revoked_at")
        self.health_state = kw.get("health_state", "healthy")
        self.last_handshake_age_s = kw.get("last_handshake_age_s")
        self.last_seen_at = kw.get("last_seen_at", NOW - timedelta(seconds=5))


def _value(rows, metric, pool="public-default"):
    want = f'{metric}{{pool_id="{pool}"}} '
    for line in _worker_metric_lines(rows, now=NOW):
        if line.startswith(want):
            return float(line[len(want):])
    return None


def test_an_active_worker_counts_as_lease_eligible():
    assert _value([_Row(status="active")], "mbs_scanner_workers_lease_eligible") == 1
    assert _value([_Row(status="active")], "mbs_scanner_workers_registered") == 1


@pytest.mark.parametrize("status", ["suspended", "revoked", "draining", "pending"])
def test_a_non_leasable_status_is_not_counted_as_eligible(status):
    """Mirrors `LEASE_ELIGIBLE_STATUSES` exactly. `draining` is the subtle one: it may still
    authenticate and finish its work, but it may never be handed MORE -- so it is not
    capacity."""
    rows = [_Row(status=status)]
    assert _value(rows, "mbs_scanner_workers_lease_eligible") == 0
    assert _value(rows, "mbs_scanner_workers_registered") == 1


def test_a_suspended_fleet_reports_zero_eligible_even_while_it_looks_healthy():
    """THE REGRESSION TEST FOR THE BLIND SPOT.

    `health_state` is the worker's own last self-report and the reaper never overwrites it,
    so a suspended fleet keeps claiming `healthy` -- exactly what the live rows showed for
    four days. The capacity gauge must read 0 regardless, because it is derived from STATUS,
    not from anything the worker says about itself.
    """
    rows = [_Row(worker_id="w1", status="suspended", health_state="healthy"),
            _Row(worker_id="w2", status="suspended", health_state="healthy")]
    assert _value(rows, "mbs_scanner_workers_lease_eligible") == 0
    assert _value(rows, "mbs_scanner_workers_registered") == 2


def test_a_revoked_worker_is_not_eligible_even_if_its_status_says_otherwise():
    """`revoked_at` is checked independently of `status`, matching the authentication gate
    -- a row whose status drifted must not be counted as capacity."""
    rows = [_Row(status="active", revoked_at=NOW - timedelta(days=1))]
    assert _value(rows, "mbs_scanner_workers_lease_eligible") == 0


def test_the_zero_series_is_emitted_not_omitted():
    """THE FAIL-CLOSED RULE, and the reason the incident was invisible. A metric that
    DISAPPEARS cannot fire an alert: `mbs_scanner_workers_lease_eligible == 0` needs a
    series to match. A pool with only suspended workers must still emit the zero."""
    lines = _worker_metric_lines([_Row(status="suspended")], now=NOW)
    assert any(ln.startswith('mbs_scanner_workers_lease_eligible{pool_id="public-default"} 0')
               for ln in lines)


def test_pools_are_counted_independently():
    """One pool losing capacity must not be masked by another pool having it -- the alert
    is per-pool, so the gauge has to be too."""
    rows = [_Row(worker_id="a", pool_id="public-default", status="active"),
            _Row(worker_id="b", pool_id="private-lab-a", status="suspended")]
    assert _value(rows, "mbs_scanner_workers_lease_eligible", "public-default") == 1
    assert _value(rows, "mbs_scanner_workers_lease_eligible", "private-lab-a") == 0


def test_an_empty_pool_emits_no_series_so_it_cannot_page():
    """A pool with no registered workers is not an incident -- it is decommissioned or not
    yet populated. The alert is guarded by `registered > 0`; this pins that there is nothing
    to match in the first place."""
    lines = _worker_metric_lines([], now=NOW)
    assert not any("mbs_scanner_workers_lease_eligible{" in ln for ln in lines)


def test_existing_liveness_metrics_are_unchanged():
    """Additive only: the capacity gauge must not disturb the P8-C tunnel/heartbeat
    projection that existing alerts depend on."""
    rows = [_Row(worker_id="p", pool_id="private-lab-a", site_id="s1",
                 status="active", health_state="healthy", last_handshake_age_s=12)]
    assert _value(rows, "mbs_tunnel_up", "private-lab-a") == 1
    assert _value(rows, "mbs_tunnel_handshake_age_seconds", "private-lab-a") == 12
    assert _value(rows, "mbs_scanner_worker_heartbeat_age_seconds", "private-lab-a") == 5.0
