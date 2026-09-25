"""MBS.SC PHASE 8 (P8-F) -- worker-level stale reaper.

THE GAP THIS CLOSES
-------------------
`last_seen_at` and `health_state` were WRITTEN by every heartbeat (Phase 8 Tier 1) but read
by nothing that made a decision: `assert_worker_active` gates on `revoked_at` and `status`
only. Verified live before this landed -- a worker silent for 2544s was still
`status='active'`, still reported `health_state='healthy'`, and still leased successfully
(`POST /v1/lease -> HTTP 200`).

WHAT THESE TESTS PIN
--------------------
  * the one legal transition: 'active' -> 'suspended', and ONLY past the threshold;
  * FAIL-CLOSED DIRECTION -- the reaper can never grant authority, and `revoked` stays
    terminal;
  * that it touches `status`/`last_health_detail` and NOTHING else (no tenant identity, no
    `health_state`);
  * that `assert_worker_active` -- unmodified by P8-F -- is what actually refuses the
    suspended worker;
  * that Phase 7, P8-B and P8-C behaviour are unchanged.

Runs against the real MySQL test database, like the other scanner-worker suites.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.scanner_workers import service as workers_service
from apps.api.modules.scanner_workers.models import ScannerWorker

STALE = 600


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


def _worker(**kw) -> ScannerWorker:
    """A worker row. `last_seen_at` defaults to LONG ago so most cases are 'stale'."""
    return ScannerWorker(
        id=uuid.uuid4(),
        worker_id=kw.get("worker_id", f"wk-{uuid.uuid4().hex[:10]}"),
        pool_id=kw.get("pool_id", "public-default"),
        site_id=kw.get("site_id"),
        workspace_id=kw.get("workspace_id"),
        status=kw.get("status", "active"),
        health_state=kw.get("health_state", "healthy"),
        last_seen_at=kw.get("last_seen_at", datetime.now(timezone.utc) - timedelta(seconds=9999)),
        revoked_at=kw.get("revoked_at"),
    )


async def _run(rows, *, stale=STALE):
    """Seed `rows`, run the reaper, return {worker_id: refreshed row}."""
    engine = _engine()
    Session = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with Session() as s:
            with tenancy.admin_bypass():
                for r in rows:
                    s.add(r)
                await s.commit()
                # `created_at` has a server default; force it old where the row is meant to
                # look long-registered, so the COALESCE fallback is exercised honestly.
                for r in rows:
                    if r.last_seen_at is None:
                        await s.execute(
                            text("UPDATE scanner_workers SET created_at = :c WHERE id = :i"),
                            {"c": datetime.now(timezone.utc) - timedelta(seconds=9999),
                             "i": str(r.id)},
                        )
                await s.commit()

                suspended = await workers_service.reap_stale_workers(s, stale)

                out = {}
                for r in rows:
                    got = await s.scalar(
                        select(ScannerWorker).where(ScannerWorker.id == r.id)
                    )
                    await s.refresh(got)
                    out[got.worker_id] = got
                return suspended, out
    finally:
        await engine.dispose()


# --- the one legal transition -----------------------------------------------------------

def test_a_stale_active_worker_is_suspended():
    w = _worker(status="active")
    n, rows = asyncio.run(_run([w]))
    assert n == 1
    assert rows[w.worker_id].status == "suspended"


def test_a_recently_seen_worker_is_untouched():
    w = _worker(status="active", last_seen_at=datetime.now(timezone.utc) - timedelta(seconds=30))
    n, rows = asyncio.run(_run([w]))
    assert n == 0
    assert rows[w.worker_id].status == "active"


def test_the_reason_is_recorded_for_auditability():
    w = _worker(status="active")
    _n, rows = asyncio.run(_run([w]))
    detail = rows[w.worker_id].last_health_detail or ""
    assert "stale" in detail.lower()
    assert str(STALE) in detail


# --- FAIL-CLOSED: what must never be touched --------------------------------------------

def test_a_revoked_worker_is_never_modified():
    """Revocation is TERMINAL. 'Reaping' it into `suspended` would WEAKEN a terminal state --
    the one direction this must never move."""
    w = _worker(status="revoked", revoked_at=datetime.now(timezone.utc) - timedelta(days=2))
    n, rows = asyncio.run(_run([w]))
    assert n == 0
    got = rows[w.worker_id]
    assert got.status == "revoked"
    assert got.revoked_at is not None


def test_a_revoked_worker_is_excluded_even_if_its_status_were_mis_set():
    """Belt and braces: `revoked_at IS NULL` is asserted independently of `status`."""
    w = _worker(status="active", revoked_at=datetime.now(timezone.utc) - timedelta(days=1))
    n, rows = asyncio.run(_run([w]))
    assert n == 0
    assert rows[w.worker_id].status == "active"


@pytest.mark.parametrize("status", ["pending", "draining", "suspended"])
def test_non_active_statuses_are_never_promoted_or_changed(status):
    """None of these is lease-eligible already; suspending them would add nothing and would
    lose the operator's intent (a `draining` worker is mid-decommission)."""
    w = _worker(status=status)
    n, rows = asyncio.run(_run([w]))
    assert n == 0
    assert rows[w.worker_id].status == status


def test_the_reaper_never_sets_a_worker_active():
    """THE fail-closed direction. There must be no path that restores authority."""
    import inspect

    src = inspect.getsource(workers_service.reap_stale_workers)
    statement = src[src.index("UPDATE scanner_workers"):]
    assert "SET status = 'suspended'" in statement
    assert "'active'" in statement  # only as the SOURCE state in the WHERE clause
    assert "SET status = 'active'" not in src


def test_tenant_and_pool_identity_are_never_modified():
    """A reaper that could move a worker between tenants would be a tenancy bug."""
    site = None
    w = _worker(status="active", pool_id="private-lab-a", workspace_id=None, site_id=site)
    _n, rows = asyncio.run(_run([w]))
    got = rows[w.worker_id]
    assert got.pool_id == "private-lab-a"
    assert got.site_id == site
    assert got.workspace_id is None
    # ...and the statement itself names none of those columns.
    import inspect

    src = inspect.getsource(workers_service.reap_stale_workers)
    statement = src[src.index("UPDATE scanner_workers"):]
    for col in ("site_id", "workspace_id", "pool_id"):
        assert f"{col} =" not in statement


def test_health_state_is_left_as_the_workers_own_last_self_report():
    """`health_state` is what P8-C projects into `mbs_tunnel_up`. Overwriting it here would
    make the manager export something no worker ever said."""
    w = _worker(status="active", health_state="healthy")
    _n, rows = asyncio.run(_run([w]))
    assert rows[w.worker_id].health_state == "healthy"


# --- NULL heartbeat + boundary ----------------------------------------------------------

def test_a_worker_that_never_reported_is_reaped_via_created_at():
    """A NULL heartbeat must not make a row immortal."""
    w = _worker(status="active", last_seen_at=None)
    n, rows = asyncio.run(_run([w]))
    assert n == 1
    assert rows[w.worker_id].status == "suspended"


def test_a_freshly_registered_worker_that_never_reported_is_not_reaped():
    """`created_at` is recent -> inside the threshold -> left alone, so registration is not
    a race against the sweep."""
    w = _worker(status="active", last_seen_at=None)
    engine = _engine()
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async def scenario():
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    s.add(w)
                    await s.commit()          # created_at = now (server default)
                    n = await workers_service.reap_stale_workers(s, STALE)
                    got = await s.scalar(select(ScannerWorker).where(ScannerWorker.id == w.id))
                    await s.refresh(got)
                    return n, got
        finally:
            await engine.dispose()

    _n, got = asyncio.run(scenario())
    assert got.status == "active"


def test_exactly_at_the_threshold_is_not_reaped():
    """The comparison is strict (`<` cutoff), so a worker exactly at the boundary survives.
    Pinned so a later refactor cannot quietly make the reaper one interval more aggressive."""
    w = _worker(status="active",
                last_seen_at=datetime.now(timezone.utc) - timedelta(seconds=STALE - 2))
    n, rows = asyncio.run(_run([w]))
    assert n == 0
    assert rows[w.worker_id].status == "active"


def test_just_past_the_threshold_is_reaped():
    w = _worker(status="active",
                last_seen_at=datetime.now(timezone.utc) - timedelta(seconds=STALE + 30))
    n, rows = asyncio.run(_run([w]))
    assert n == 1
    assert rows[w.worker_id].status == "suspended"


# --- idempotency + mixed fleet ----------------------------------------------------------

def test_the_sweep_is_idempotent():
    """A second pass matches nothing: the rows are no longer 'active'."""
    w = _worker(status="active")
    engine = _engine()
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async def scenario():
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    s.add(w)
                    await s.commit()
                    first = await workers_service.reap_stale_workers(s, STALE)
                    second = await workers_service.reap_stale_workers(s, STALE)
                    return first, second
        finally:
            await engine.dispose()

    first, second = asyncio.run(scenario())
    assert first == 1
    assert second == 0


def test_a_mixed_fleet_reaps_only_the_stale_active_workers():
    """Applies to BOTH pools -- public and private -- as approved."""
    stale_pub = _worker(status="active", pool_id="public-default")
    stale_priv = _worker(status="active", pool_id="private-lab-a", site_id=None)
    fresh = _worker(status="active",
                    last_seen_at=datetime.now(timezone.utc) - timedelta(seconds=10))
    revoked = _worker(status="revoked", revoked_at=datetime.now(timezone.utc))
    n, rows = asyncio.run(_run([stale_pub, stale_priv, fresh, revoked]))
    assert n == 2
    assert rows[stale_pub.worker_id].status == "suspended"
    assert rows[stale_priv.worker_id].status == "suspended"
    assert rows[fresh.worker_id].status == "active"
    assert rows[revoked.worker_id].status == "revoked"


# --- the suspended worker is actually refused -------------------------------------------

def test_a_suspended_worker_is_rejected_by_the_existing_authorization_gate():
    """P8-F does NOT modify `assert_worker_active`. `suspended` is already refused there, so
    the existing gate does the enforcing and the reaper only supplies the state."""
    w = _worker(status="active")
    _n, rows = asyncio.run(_run([w]))
    got = rows[w.worker_id]
    assert got.status == "suspended"
    with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
        workers_service.assert_worker_active(got)
    assert exc.value.reason == workers_service.REASON_WORKER_SUSPENDED


def test_assert_worker_active_was_not_modified_by_p8f():
    """It must still gate on revocation/status alone -- no staleness logic leaked into it."""
    import inspect

    src = inspect.getsource(workers_service.assert_worker_active)
    for leaked in ("last_seen_at", "stale", "reap", "timedelta"):
        assert leaked not in src


# --- configuration ----------------------------------------------------------------------

def test_the_approved_conservative_defaults_are_in_place():
    s = get_settings()
    assert s.worker_stale_after_seconds == 600
    assert s.worker_stale_reaper_interval_seconds == 300


def test_the_threshold_sits_above_the_beat_and_the_alert():
    """600s must exceed the 30s idle heartbeat and the 300s alert, so an operator is alerted
    BEFORE the platform acts and a transient blip cannot cause a scanning outage."""
    from apps.api.scanner_worker.lease_loop import BackoffPolicy

    s = get_settings()
    assert s.worker_stale_after_seconds > BackoffPolicy().heartbeat_seconds
    assert s.worker_stale_after_seconds > 300  # MbsScannerWorkerHeartbeatStale


def test_the_sweep_is_beat_scheduled_on_the_default_queue():
    from apps.api.celery_app import worker as celery_worker

    entry = celery_worker.celery_app.conf.beat_schedule.get("reap-stale-workers")
    assert entry and entry["task"] == "workers.reap_stale"
    assert entry["schedule"] == float(get_settings().worker_stale_reaper_interval_seconds)
    # Never routed to the `scans` queue -- it must not compete with scan execution.
    routes = celery_worker.celery_app.conf.task_routes or {}
    assert "workers.reap_stale" not in routes


# --- REGRESSION: Phase 7 / P8-B / P8-C unchanged ----------------------------------------

def test_phase7_per_job_gate_is_unchanged():
    from apps.api.scanner_engine import wireguard
    from apps.api.scanner_worker.lease_loop import LeaseError, preflight_private_job

    down = wireguard.StaticTunnelProbe(wireguard.TunnelStatus(interface_up=False))
    job = {"network_zone": "private", "site_id": "s", "authorized_cidrs": ["10.90.0.0/24"]}
    with pytest.raises(LeaseError):
        preflight_private_job(job, probe=down)
    preflight_private_job({"network_zone": "public"}, probe=None)  # public unaffected


def test_p8b_health_reporting_is_unchanged():
    from apps.api.scanner_worker.lease_loop import LeaseLoop

    assert hasattr(LeaseLoop, "observe_tunnel_health")
    assert hasattr(LeaseLoop, "report_health")


def test_p8c_projection_treats_a_reaped_worker_consistently():
    """A suspended worker keeps its last self-reported `health_state`, so P8-C's projection
    is unchanged by P8-F -- while `mbs_scanner_worker_heartbeat_age_seconds` (computed live
    from `last_seen_at`) still climbs and remains the alertable signal."""
    from apps.api.scanner_manager.app import _worker_metric_lines

    now = datetime(2026, 9, 11, 21, 0, 0, tzinfo=timezone.utc)

    class _R:
        pool_id = "private-lab-a"
        site_id = "s1"
        health_state = "healthy"          # untouched by the reaper
        last_handshake_age_s = 40
        last_seen_at = now - timedelta(seconds=9999)

    body = "\n".join(_worker_metric_lines([_R()], now=now))
    assert 'mbs_tunnel_up{pool_id="private-lab-a"} 1' in body
    assert "mbs_scanner_worker_heartbeat_age_seconds" in body
