"""MBS.SC PHASE 8 (P8-F) -- stale-worker reaper COLD-START protection.

THE INCIDENT THESE PIN
----------------------
A host restart took the whole platform down for ~11 minutes. A healthy worker could not
heartbeat -- nothing was running to receive one -- so `scanner_workers.last_seen_at` froze at
04:47:38 while the wall clock kept moving. Beat came back at 04:59:16 and dispatched the
sweep 163ms later (its PERSISTED `last_run_at` predated the outage, so the task was
immediately due), and the sweep suspended 2/2 workers at 04:59:22 for 703s of "silence" --
677s of which (96.3%) was the platform being off.

Because a suspended worker is refused at AUTHENTICATION, it could no longer heartbeat either,
so the state was self-sealing: 58 container restarts, 0 lease-eligible workers, 24 scans
stuck queued with no consumer.

WHAT THE FIX IS, AND WHAT THESE TESTS GUARD
-------------------------------------------
`reap_stale_workers` skips the sweep entirely while the process running it has been up for
less than `startup_grace_seconds` -- a worker must not be judged silent for time during which
the platform judging it was itself unavailable.

These pin BOTH directions, because the dangerous over-correction is as bad as the bug:
  * a cold platform must not mass-suspend a healthy fleet;
  * an ESTABLISHED platform must still suspend a genuinely dead worker, exactly as before
    (`test_a_genuinely_stale_worker_is_still_suspended_once_established` is the mandatory
    proof that P8-F was not quietly disabled).

Separate file from `test_p8f_worker_stale_reaper.py` so the original 26 predicate tests stay
byte-for-byte unchanged and keep proving the predicate independently of this gate.

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
    """A worker row. `last_seen_at` defaults to LONG ago, so a row is 'stale' unless the
    test says otherwise -- which makes every non-suspension below attributable to the gate."""
    return ScannerWorker(
        id=uuid.uuid4(),
        worker_id=kw.get("worker_id", f"cs-{uuid.uuid4().hex[:10]}"),
        pool_id=kw.get("pool_id", "public-default"),
        site_id=kw.get("site_id"),
        workspace_id=kw.get("workspace_id"),
        status=kw.get("status", "active"),
        health_state=kw.get("health_state", "healthy"),
        last_seen_at=kw.get("last_seen_at", datetime.now(timezone.utc) - timedelta(seconds=9999)),
        revoked_at=kw.get("revoked_at"),
    )


async def _run(rows, *, stale=STALE, grace=0.0):
    """Seed `rows`, run the reaper with `grace`, return (suspended, {worker_id: row})."""
    engine = _engine()
    Session = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with Session() as s:
            with tenancy.admin_bypass():
                for r in rows:
                    s.add(r)
                await s.commit()
                for r in rows:
                    if r.last_seen_at is None:
                        await s.execute(
                            text("UPDATE scanner_workers SET created_at = :c WHERE id = :i"),
                            {"c": datetime.now(timezone.utc) - timedelta(seconds=9999),
                             "i": str(r.id)},
                        )
                await s.commit()

                suspended = await workers_service.reap_stale_workers(
                    s, stale, startup_grace_seconds=grace
                )

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


def _uptime(monkeypatch, seconds: float):
    """Pin this process's apparent uptime.

    Patches the monotonic CLOCK the gate reads rather than the gate itself, so the real
    boundary arithmetic in `within_startup_grace` is exercised instead of stubbed out."""
    from apps.api.core import platform_uptime

    monkeypatch.setattr(
        platform_uptime.time, "monotonic",
        lambda: platform_uptime._PROCESS_START_MONOTONIC + seconds,
    )


# --- Test 1: platform outage longer than the threshold -----------------------------------

def test_a_platform_outage_longer_than_the_threshold_does_not_suspend(monkeypatch):
    """THE REGRESSION TEST FOR THE INCIDENT, with its real numbers: 13s of platform uptime
    (what the live platform had when the reaper fired) and 703s of apparent silence."""
    _uptime(monkeypatch, 13.0)
    w = _worker(status="active",
                last_seen_at=datetime.now(timezone.utc) - timedelta(seconds=703))
    n, rows = asyncio.run(_run([w], grace=STALE))
    assert n == 0
    assert rows[w.worker_id].status == "active"
    # The row is left completely alone, not merely un-suspended: a gated sweep runs no
    # statement at all, so the audit reason is never stamped either.
    assert rows[w.worker_id].last_health_detail is None


# --- Test 2: the startup boundary --------------------------------------------------------

def test_just_before_the_startup_grace_expires_the_sweep_is_skipped(monkeypatch):
    _uptime(monkeypatch, STALE - 1)
    w = _worker(status="active")
    n, rows = asyncio.run(_run([w], grace=STALE))
    assert n == 0
    assert rows[w.worker_id].status == "active"


def test_exactly_at_the_startup_grace_normal_evaluation_resumes(monkeypatch):
    """The boundary is EXCLUSIVE on the grace side (`<`), mirroring the reaper's own strict
    `<` cutoff comparison so the two boundaries agree. At exactly the grace, the sweep runs."""
    _uptime(monkeypatch, STALE)
    w = _worker(status="active")
    n, rows = asyncio.run(_run([w], grace=STALE))
    assert n == 1
    assert rows[w.worker_id].status == "suspended"


def test_the_boundary_is_not_off_by_one(monkeypatch):
    """MUTATION GUARD. `<=` instead of `<` would gate one extra instant and fail the
    at-boundary case above; `>` would fail the sub-boundary case here."""
    from apps.api.core.platform_uptime import within_startup_grace

    _uptime(monkeypatch, STALE - 0.001)
    assert within_startup_grace(STALE) is True
    _uptime(monkeypatch, STALE)
    assert within_startup_grace(STALE) is False
    _uptime(monkeypatch, STALE + 0.001)
    assert within_startup_grace(STALE) is False


# --- Test 3: MANDATORY -- proof that P8-F is NOT disabled --------------------------------

def test_a_genuinely_stale_worker_is_still_suspended_once_established(monkeypatch):
    """MANDATORY. With the platform long established, a genuinely silent worker is suspended
    exactly as before, carrying the same audit reason. This is the test that fails if the fix
    ever degenerates into "disable the reaper"."""
    _uptime(monkeypatch, STALE * 10)
    w = _worker(status="active",
                last_seen_at=datetime.now(timezone.utc) - timedelta(seconds=STALE + 30))
    n, rows = asyncio.run(_run([w], grace=STALE))
    assert n == 1
    assert rows[w.worker_id].status == "suspended"
    assert "stale: no worker heartbeat" in (rows[w.worker_id].last_health_detail or "")


def test_the_gate_is_off_by_default_so_existing_callers_are_unchanged(monkeypatch):
    """The parameter defaults to 0.0 (no gate). Even at ZERO uptime -- the most hostile case
    -- a caller that does not opt in sweeps exactly as it always did. This is what keeps the
    change purely additive for the other 26 P8-F tests and every non-Celery caller."""
    _uptime(monkeypatch, 0.0)
    w = _worker(status="active")
    n, rows = asyncio.run(_run([w]))  # no grace= -> default 0.0
    assert n == 1
    assert rows[w.worker_id].status == "suspended"


# --- Test 4: healthy worker --------------------------------------------------------------

def test_a_healthy_worker_is_untouched_after_the_grace(monkeypatch):
    _uptime(monkeypatch, STALE * 10)
    w = _worker(status="active",
                last_seen_at=datetime.now(timezone.utc) - timedelta(seconds=30))
    n, rows = asyncio.run(_run([w], grace=STALE))
    assert n == 0
    assert rows[w.worker_id].status == "active"


# --- Test 5: non-active statuses, on BOTH sides of the gate ------------------------------

@pytest.mark.parametrize("status", ["draining", "suspended", "pending", "revoked"])
@pytest.mark.parametrize("uptime", [13.0, STALE * 10], ids=["during_grace", "established"])
def test_non_active_statuses_are_untouched_in_both_gate_states(monkeypatch, status, uptime):
    """The security invariants hold on BOTH sides of the gate: during the grace nothing runs
    at all, and after it the `status = 'active'` source-state filter is still the only door.
    In particular `draining` is never suspended by P8-F and `revoked` stays terminal."""
    _uptime(monkeypatch, uptime)
    kw = {"status": status}
    if status == "revoked":
        kw["revoked_at"] = datetime.now(timezone.utc) - timedelta(seconds=9999)
    w = _worker(**kw)
    n, rows = asyncio.run(_run([w], grace=STALE))
    assert n == 0
    assert rows[w.worker_id].status == status


# --- Test 6: full fleet ------------------------------------------------------------------

def test_a_whole_fleet_silent_during_platform_downtime_is_not_mass_suspended(monkeypatch):
    """The blast radius the incident actually had: a public worker and a private/site worker,
    different pools, all silent for the same platform outage. The sweep has no pool/site/
    workspace scoping, which is exactly why one outage could take the whole fleet."""
    _uptime(monkeypatch, 13.0)
    pub = _worker(status="active", worker_id="cs-fleet-public", pool_id="public-default")
    priv = _worker(status="active", worker_id="cs-fleet-private", pool_id="private-lab-a")
    n, rows = asyncio.run(_run([pub, priv], grace=STALE))
    assert n == 0
    assert rows["cs-fleet-public"].status == "active"
    assert rows["cs-fleet-private"].status == "active"


def test_the_same_fleet_is_reaped_normally_once_established(monkeypatch):
    """...and that fleet is NOT permanently immune: once the platform is established, the
    same genuinely-silent workers are suspended normally."""
    _uptime(monkeypatch, STALE * 10)
    pub = _worker(status="active", worker_id="cs-fleet2-public", pool_id="public-default")
    priv = _worker(status="active", worker_id="cs-fleet2-private", pool_id="private-lab-a")
    n, rows = asyncio.run(_run([pub, priv], grace=STALE))
    assert n == 2
    assert rows["cs-fleet2-public"].status == "suspended"
    assert rows["cs-fleet2-private"].status == "suspended"


# --- Test 7: Beat restart semantics ------------------------------------------------------

def test_protection_does_not_depend_on_beat_scheduling_delay(monkeypatch):
    """Beat dispatches this sweep ~163ms after it restarts, because `ScheduleEntry.update()`
    preserves the PERSISTED `last_run_at` -- so the task is immediately due and NO scheduling
    delay protects anything. This pins that the protection lives at the REAPER EXECUTION
    layer: simulate the measured worst case (dispatch at t+0.163s) and assert it still holds.

    Reads and mutates no Celery scheduler state, by design."""
    _uptime(monkeypatch, 0.163)
    w = _worker(status="active")
    n, rows = asyncio.run(_run([w], grace=STALE))
    assert n == 0
    assert rows[w.worker_id].status == "active"


def test_the_celery_task_opts_into_the_grace_reusing_the_stale_threshold():
    """The gate defaults to OFF, so the one caller whose process lifetime tracks the
    platform's must actually opt in -- a task that forgot to would be silently unprotected,
    which is precisely the regression this pins."""
    import inspect

    from apps.api.celery_app.tasks import scan_tasks

    src = inspect.getsource(scan_tasks._reap_stale_workers)
    assert "startup_grace_seconds=" in src
    # Reuses the existing knob rather than introducing a second one to keep in sync.
    assert "worker_stale_after_seconds" in src


# --- Test 8: idempotency -----------------------------------------------------------------

def test_the_sweep_remains_idempotent_after_the_grace(monkeypatch):
    """Two sweeps past the grace: the first suspends, the second matches nothing because the
    row is no longer 'active'. The gate does not disturb this."""
    _uptime(monkeypatch, STALE * 10)
    w = _worker(status="active")
    engine = _engine()
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async def scenario():
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    s.add(w)
                    await s.commit()
                    first = await workers_service.reap_stale_workers(
                        s, STALE, startup_grace_seconds=STALE)
                    second = await workers_service.reap_stale_workers(
                        s, STALE, startup_grace_seconds=STALE)
                    got = await s.scalar(
                        select(ScannerWorker).where(ScannerWorker.id == w.id))
                    await s.refresh(got)
                    return first, second, got
        finally:
            await engine.dispose()

    first, second, got = asyncio.run(scenario())
    assert (first, second) == (1, 0)
    assert got.status == "suspended"


# --- the production invariants the gate must not have disturbed --------------------------

def test_the_stale_predicate_and_atomic_update_are_unchanged():
    """MUTATION GUARD. The gate decides WHETHER the sweep runs, never which rows it may
    touch. The SQL defining the transition must still be the same conditional UPDATE."""
    import inspect

    src = inspect.getsource(workers_service.reap_stale_workers)
    assert "WHERE status = 'active' " in src
    assert "AND revoked_at IS NULL " in src
    assert "AND COALESCE(last_seen_at, created_at) < :cutoff" in src
    assert "SET status = 'suspended'" in src
    # ...and it still never grants authority to anyone.
    assert "SET status = 'active'" not in src


def test_the_gate_uses_a_monotonic_clock_not_wall_clock():
    """A host restart is exactly when a wall clock is most likely to jump (NTP correction on
    boot). Pinned so a later refactor cannot reintroduce `datetime.now()` arithmetic for the
    process-local uptime check, which could read as negative or hours-long after a jump."""
    import inspect

    from apps.api.core import platform_uptime

    src = inspect.getsource(platform_uptime)
    assert "time.monotonic()" in src
    assert "datetime" not in src


def test_a_gated_sweep_writes_no_audit_row(monkeypatch):
    """P8-G writes one audit row per ACTUALLY-suspended worker. A gated sweep suspends
    nobody, so it must record nothing -- an audit trail of non-events hides the real ones."""
    from apps.api.modules.audit import scanner_ops

    calls = []

    async def _spy(*a, **kw):
        calls.append(kw)

    monkeypatch.setattr(scanner_ops, "record_worker_reaped_stale", _spy)
    _uptime(monkeypatch, 13.0)
    w = _worker(status="active")
    n, _rows = asyncio.run(_run([w], grace=STALE))
    assert n == 0
    assert calls == []
