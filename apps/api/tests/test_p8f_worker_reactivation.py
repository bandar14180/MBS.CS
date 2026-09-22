"""MBS.SC PHASE 8 (P8-F) -- operator RECOVERY of a suspended worker.

THE INCIDENT THESE PIN
----------------------
`reap_stale_workers` moves a silent worker `active` -> `suspended` and documents that state
as "REVERSIBLE (an operator reactivates)". Nothing that could perform that reactivation
existed: an audit found zero code paths writing `status = 'active'`, so `suspended` was
documented as reversible and was, in practice, TERMINAL.

Because a suspended worker is refused at AUTHENTICATION it cannot heartbeat, so
`last_seen_at` can never be refreshed, so it stays stale and stays suspended:

    suspended -> 403 at auth -> cannot heartbeat -> last_seen_at frozen -> still stale

Verified live: a host restart on 2026-09-13 suspended the whole fleet in two sweeps
(04:35:06, 04:59:22). Four days later both workers were still suspended, the public worker
container was crash-looping against a 403 WORKER_SUSPENDED, and a scan created
2026-09-17 11:32:30 was still `queued` with 0 tool runs.

WHAT THESE TESTS GUARD
----------------------
Both directions, because the over-correction is as dangerous as the bug:

  * a suspended worker IS recoverable by an explicit operator action;
  * recovery is NOT a weakening of the fail-closed model -- revoked stays terminal, pending
    stays unapproved, draining stays drained, and nothing automatic ever reactivates.

Separate file from `test_p8f_worker_stale_reaper.py` and `test_p8f_reaper_cold_start.py` so
those suites keep proving the DETECTION half independently of this RECOVERY half.

Runs against the real MySQL test database, like the other scanner-worker suites.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.scanner_workers import service as workers_service
from apps.api.modules.scanner_workers.models import ScannerWorker


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


def _worker(**kw) -> ScannerWorker:
    """A worker row. Defaults to `suspended` with a stale heartbeat -- i.e. exactly the
    state the P8-F reaper leaves behind, so each test starts from the real incident shape."""
    return ScannerWorker(
        id=uuid.uuid4(),
        worker_id=kw.get("worker_id", f"ra-{uuid.uuid4().hex[:10]}"),
        pool_id=kw.get("pool_id", "public-default"),
        site_id=kw.get("site_id"),
        workspace_id=kw.get("workspace_id"),
        status=kw.get("status", "suspended"),
        health_state=kw.get("health_state", "healthy"),
        last_seen_at=kw.get(
            "last_seen_at", datetime.now(timezone.utc) - timedelta(seconds=9999)
        ),
        last_health_detail=kw.get("last_health_detail", "stale: no worker heartbeat for 600s"),
        revoked_at=kw.get("revoked_at"),
    )


async def _reactivate(row, *, reason="worker confirmed running"):
    """Seed `row`, attempt reactivation, return (outcome, refreshed_row).

    `outcome` is "ok" or the refusal's stable reason code, so a test asserts on the same
    vocabulary an operator would see rather than on an exception type.
    """
    engine = _engine()
    Session = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with Session() as s:
            with tenancy.admin_bypass():
                s.add(row)
                await s.commit()
                try:
                    await workers_service.reactivate_worker(s, row.worker_id, reason=reason)
                    outcome = "ok"
                except workers_service.WorkerNotReactivatable as exc:
                    outcome = exc.reason
                except workers_service.WorkerNotAuthorized as exc:
                    outcome = exc.reason
                await s.commit()
                got = await s.scalar(select(ScannerWorker).where(ScannerWorker.id == row.id))
                await s.refresh(got)
                return outcome, got
    finally:
        await engine.dispose()


# --- Test 2a: the recovery path itself ---------------------------------------------------

def test_a_suspended_worker_can_be_reactivated_by_an_operator():
    """THE REGRESSION TEST FOR THE INCIDENT: the transition that did not exist.

    Before this fix there was no code in the repository that could produce this assertion --
    `status` could never become 'active' again by any means.
    """
    w = _worker(status="suspended")
    outcome, row = asyncio.run(_reactivate(w))
    assert outcome == "ok"
    assert row.status == "active"


def test_reactivation_records_why_replacing_the_reapers_stale_note():
    """The row must explain its CURRENT state, not the one it left. An operator reading
    `last_health_detail` after a recovery should not still see the reaper's staleness note."""
    w = _worker(status="suspended", last_health_detail="stale: no worker heartbeat for 600s")
    outcome, row = asyncio.run(_reactivate(w, reason="host rebooted, worker verified up"))
    assert outcome == "ok"
    assert "stale" not in (row.last_health_detail or "")
    assert "host rebooted, worker verified up" in (row.last_health_detail or "")


def test_reactivation_does_not_backdate_liveness():
    """`last_seen_at` is NOT written. The worker proves its own liveness by heartbeating
    once it can authenticate again; stamping it here would fabricate an observation no
    worker ever made -- and would re-arm the same staleness from the wrong side."""
    seen = datetime.now(timezone.utc) - timedelta(seconds=9999)
    w = _worker(status="suspended", last_seen_at=seen)
    outcome, row = asyncio.run(_reactivate(w))
    assert outcome == "ok"
    assert row.last_seen_at is not None
    # Unchanged to the second: the reactivation touched status/detail and nothing else.
    assert abs((row.last_seen_at - seen).total_seconds()) < 1


def test_reactivation_does_not_move_pool_site_or_workspace():
    """A recovery tool that could move a worker between tenants would be a tenancy bug, not
    a liveness feature -- the same rule the reaper states for itself."""
    ws, site = None, None
    w = _worker(status="suspended", pool_id="public-default", site_id=site, workspace_id=ws)
    outcome, row = asyncio.run(_reactivate(w))
    assert outcome == "ok"
    assert row.pool_id == "public-default"
    assert row.site_id is None
    assert row.workspace_id is None


# --- Test 2b: FAIL-CLOSED -- every state that must NOT be reachable -----------------------

def test_a_revoked_worker_is_never_reactivated():
    """Revocation is TERMINAL. Reactivating it would weaken a terminal state -- the one
    direction this must never move. Guarded twice over in the SQL (status predicate AND
    `revoked_at IS NULL`), so a revoked row with a stale status could not slip through."""
    w = _worker(status="revoked", revoked_at=datetime.now(timezone.utc))
    outcome, row = asyncio.run(_reactivate(w))
    assert outcome == workers_service.REASON_NOT_REACTIVATABLE
    assert row.status == "revoked"
    assert row.revoked_at is not None


def test_a_revoked_but_suspended_looking_row_is_still_refused():
    """The `revoked_at IS NULL` half of the guard, proven independently: even if a row's
    status said 'suspended', a non-NULL `revoked_at` must still refuse."""
    w = _worker(status="suspended", revoked_at=datetime.now(timezone.utc))
    outcome, row = asyncio.run(_reactivate(w))
    assert outcome == workers_service.REASON_NOT_REACTIVATABLE
    assert row.status == "suspended"


def test_a_pending_worker_is_not_approved_by_reactivation():
    """`pending` has never been cleared to do anything. Readmitting it here would bypass
    approval entirely -- recovery is not approval."""
    w = _worker(status="pending")
    outcome, row = asyncio.run(_reactivate(w))
    assert outcome == workers_service.REASON_NOT_REACTIVATABLE
    assert row.status == "pending"


def test_a_draining_worker_is_not_un_drained_by_reactivation():
    """`ops/drain_worker` explicitly offers no un-drain. Reactivation must not become one
    by the back door."""
    w = _worker(status="draining")
    outcome, row = asyncio.run(_reactivate(w))
    assert outcome == workers_service.REASON_NOT_REACTIVATABLE
    assert row.status == "draining"


def test_an_already_active_worker_is_a_no_op_refusal():
    """Reactivating twice is refused rather than silently succeeding, so an operator racing
    another operator is told so instead of assuming they caused the transition."""
    w = _worker(status="active")
    outcome, row = asyncio.run(_reactivate(w))
    assert outcome == workers_service.REASON_NOT_REACTIVATABLE
    assert row.status == "active"


def test_an_unknown_worker_is_refused():
    """Nothing is written for a worker id that does not exist."""
    engine = _engine()
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async def _go():
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
                        await workers_service.reactivate_worker(
                            s, f"no-such-{uuid.uuid4().hex}", reason="x"
                        )
                    return exc.value.reason
        finally:
            await engine.dispose()

    assert asyncio.run(_go()) == workers_service.REASON_UNKNOWN_WORKER


# --- Test 1: the suspended worker is still refused BEFORE recovery -----------------------

def test_a_suspended_worker_is_refused_at_authentication_and_at_lease():
    """The fail-closed half, unchanged by this work: until an operator acts, a suspended
    worker is refused everywhere. This is the 403 the live worker was crash-looping on."""
    w = _worker(status="suspended")
    with pytest.raises(workers_service.WorkerNotAuthorized) as active_exc:
        workers_service.assert_worker_active(w)
    assert active_exc.value.reason == workers_service.REASON_WORKER_SUSPENDED

    with pytest.raises(workers_service.WorkerNotAuthorized) as lease_exc:
        workers_service.assert_worker_may_lease(w)
    assert lease_exc.value.reason == workers_service.REASON_WORKER_SUSPENDED


def test_after_reactivation_the_worker_passes_both_gates():
    """The point of the whole exercise: a reactivated worker may authenticate (so it can
    heartbeat) AND may lease. Asserted against the same two functions the manager calls, so
    this cannot pass while the real endpoints still refuse."""
    w = _worker(status="suspended")
    outcome, row = asyncio.run(_reactivate(w))
    assert outcome == "ok"
    # Neither raises now.
    workers_service.assert_worker_active(row)
    workers_service.assert_worker_may_lease(row)


# --- Detection is untouched by recovery --------------------------------------------------

def test_reactivation_does_not_disable_the_reaper():
    """MANDATORY PROOF that P8-F detection survives: a reactivated worker that stays silent
    is suspended again by the next sweep. Recovery grants the ABILITY to heartbeat, never a
    guarantee -- this readmits a worker, it does not vouch for one."""
    engine = _engine()
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async def _go():
        w = _worker(status="suspended",
                    last_seen_at=datetime.now(timezone.utc) - timedelta(seconds=9999))
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    s.add(w)
                    await s.commit()
                    await workers_service.reactivate_worker(s, w.worker_id, reason="recovery")
                    await s.commit()
                    # Still silent (last_seen_at untouched) -> the next sweep re-suspends it.
                    # grace=0 so the cold-start gate is not what decides this.
                    n = await workers_service.reap_stale_workers(s, 600, startup_grace_seconds=0.0)
                    await s.commit()
                    got = await s.scalar(select(ScannerWorker).where(ScannerWorker.id == w.id))
                    await s.refresh(got)
                    return n, got.status
        finally:
            await engine.dispose()

    suspended, status = asyncio.run(_go())
    assert suspended >= 1
    assert status == "suspended"
