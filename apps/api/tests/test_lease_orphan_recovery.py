"""MBS.SC -- orphan recovery for a LEASE-abandoned scan.

The scenario this file exists for: a worker leases a scan, starts running it, and then
dies without ever reporting a terminal state. Nothing is left to finalise the row, so
without recovery the scan would sit `running` forever.

The recovery mechanism itself is NOT new -- `reap_orphaned_scans` has always keyed on
executor liveness and has always cleared `execution_token` as part of the same atomic
statement. What is new is that a lease-executed scan now feeds that mechanism: the lease
worker refreshes `scans.last_heartbeat_at` through the manager (fenced on its token), so
its silence is what the reaper detects.

These tests drive the REAL reaper against REAL rows. The three properties that matter:

  1. an abandoned lease is detected and the scan is recovered to a claimable state;
  2. the dead worker's token is revoked, so a straggler cannot overwrite the recovery;
  3. a replacement worker can reclaim it -- but only if it is genuinely authorized.
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
from apps.api.modules.private_sites.models import PrivateSite
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scanner_workers import service as workers_service
from apps.api.modules.scanner_workers.models import ScannerWorker
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.orchestrator import (
    _claim_scan,
    _finalize_status,
    _stamp_heartbeat,
    reap_orphaned_scans,
)


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _seed(session, label, *, private=False, site_status="active"):
    """One tenant with a queued scan and a worker able to run it."""
    user = User(email=f"{label}-{uuid.uuid4()}@t.local", password_hash="x", full_name=label)
    session.add(user)
    await session.flush()
    ws = Workspace(name=f"{label}-{uuid.uuid4().hex[:8]}", owner_user_id=user.id)
    session.add(ws)
    await session.flush()

    site = None
    if private:
        site = PrivateSite(
            id=uuid.uuid4(), workspace_id=ws.id, name=f"{label}-site",
            authorized_cidrs=["10.0.0.0/16"], dns_servers=["10.0.0.53"],
            dns_search_domains=[], status=site_status, scanner_pool_id=f"pool-{label}",
        )
        session.add(site)
        await session.flush()

    project = Project(id=uuid.uuid4(), workspace_id=ws.id, name=f"{label}-p",
                      created_by=user.id)
    session.add(project)
    await session.flush()
    target = Target(
        id=uuid.uuid4(), project_id=project.id,
        type="ip_range" if private else "domain",
        value="10.0.5.0/24" if private else "scanme.example.com",
        added_by=user.id, network_zone="private" if private else "public",
        site_id=site.id if site else None,
    )
    session.add(target)
    await session.flush()
    scan = Scan(
        id=uuid.uuid4(), workspace_id=ws.id, project_id=project.id, target_id=target.id,
        initiated_by=user.id, scan_type="recon", status="queued",
        config={"requested_modules": ["httpx"],
                "network_zone": "private" if private else "public",
                "site_id": str(site.id) if site else None},
    )
    session.add(scan)
    token = workers_service.generate_worker_token()
    worker = ScannerWorker(
        id=uuid.uuid4(), worker_id=f"wk-{label}-{uuid.uuid4().hex[:6]}",
        pool_id=f"pool-{label}" if private else "public-default",
        site_id=site.id if site else None,
        workspace_id=ws.id if private else None,
        status="active", token_hash=workers_service.hash_worker_token(token),
    )
    session.add(worker)
    await session.flush()
    await session.commit()
    return {"ws": ws.id, "scan": scan, "site": site, "worker": worker, "token": token}


async def _age_heartbeat(session, scan_id, *, seconds: int) -> None:
    """Backdate a scan's liveness to simulate a worker that stopped reporting.

    An UPDATE of two timestamp columns on ONE test-created row -- not a destructive
    command, and it touches nothing else. This is how a dead worker is simulated without
    actually killing a process: the reaper's whole input is "how long since this executor
    last said it was alive", so moving that timestamp back is a faithful simulation of
    silence, and it makes the test deterministic instead of sleeping for minutes.
    """
    past = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    await session.execute(
        text("UPDATE scans SET last_heartbeat_at = :t, started_at = :t WHERE id = :id"),
        {"t": past, "id": str(scan_id)},
    )
    await session.commit()


async def _status_of(session, scan_id) -> tuple:
    row = (await session.execute(
        text("SELECT status, execution_token FROM scans WHERE id = :id"),
        {"id": str(scan_id)},
    )).first()
    return (row[0], row[1]) if row else (None, None)


# =======================================================================================
# 1-3: abandoned lease -> detected -> recoverable
# =======================================================================================

def test_leased_scan_abandoned_by_worker_is_reaped_and_becomes_claimable():
    """Requirements 1, 2, 3 -- the core scenario.

    Worker A leases (claims) the scan, stamps liveness, then goes silent. The reaper must
    detect the silence, recover the row, and leave it in a state a new worker can claim.
    """
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    t = await _seed(s, "orph")
                    scan_id = t["scan"].id

                    # --- Worker A leases it (the same atomic claim /v1/lease performs).
                    token_a = uuid.uuid4()
                    assert await _claim_scan(s, scan_id, token_a) is True
                    await s.commit()
                    status, tok = await _status_of(s, scan_id)
                    assert status == "running", "the lease did not claim the scan"
                    assert tok is not None, "no execution token was recorded"

                    # It reports liveness while running, exactly as the lease loop does.
                    await _stamp_heartbeat(s, scan_id, token_a)
                    await s.commit()

                    # A HEALTHY worker must NOT be reaped, however long it runs.
                    reaped = await reap_orphaned_scans(s, timeout_seconds=3600,
                                                       stale_heartbeat_seconds=300)
                    await s.commit()
                    assert reaped == 0, "a live, heartbeating scan was reaped"
                    assert (await _status_of(s, scan_id))[0] == "running"

                    # --- Worker A dies: the heartbeats stop.
                    await _age_heartbeat(s, scan_id, seconds=600)

                    reaped = await reap_orphaned_scans(s, timeout_seconds=3600,
                                                       stale_heartbeat_seconds=300)
                    await s.commit()
                    assert reaped >= 1, "the abandoned lease was not detected"

                    status, tok = await _status_of(s, scan_id)
                    assert status == "failed", f"recovered to {status!r}, expected 'failed'"
                    assert tok is None, "the dead worker's execution token was not revoked"

                    # And the recovery reason is persisted for an operator to read.
                    cfg = (await s.execute(
                        text("SELECT config FROM scans WHERE id = :id"),
                        {"id": str(scan_id)})).scalar()
                    assert "recovery" in str(cfg), "no recovery reason recorded"
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_a_scan_that_never_heartbeat_still_falls_back_to_the_age_rule():
    """A worker that died before its first beat must still be recoverable -- a NULL
    heartbeat must never make a scan immortal."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    t = await _seed(s, "nobeat")
                    scan_id = t["scan"].id
                    assert await _claim_scan(s, scan_id, uuid.uuid4()) is True
                    await s.commit()
                    # started_at backdated, last_heartbeat_at left NULL.
                    past = datetime.now(timezone.utc) - timedelta(seconds=7200)
                    await s.execute(
                        text("UPDATE scans SET started_at = :t, last_heartbeat_at = NULL "
                             "WHERE id = :id"),
                        {"t": past, "id": str(scan_id)})
                    await s.commit()

                    reaped = await reap_orphaned_scans(s, timeout_seconds=3600,
                                                       stale_heartbeat_seconds=300)
                    await s.commit()
                    assert reaped >= 1
                    assert (await _status_of(s, scan_id))[0] == "failed"
        finally:
            await engine.dispose()

    asyncio.run(scenario())


# =======================================================================================
# 4-6: reclaim, old-token rejection, no duplicate authoritative result
# =======================================================================================

def test_worker_b_reclaims_and_worker_a_cannot_overwrite_it():
    """Requirements 4, 5, 6 -- the fencing core.

    After recovery, worker B claims the scan and gets a NEW token. Worker A (the straggler
    that was merely slow, not dead) must not be able to finalise anything: its token was
    revoked by the reaper, so its terminal write matches zero rows.
    """
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    t = await _seed(s, "reclaim")
                    scan_id = t["scan"].id

                    token_a = uuid.uuid4()
                    assert await _claim_scan(s, scan_id, token_a) is True
                    await s.commit()
                    await _age_heartbeat(s, scan_id, seconds=600)
                    assert await reap_orphaned_scans(
                        s, timeout_seconds=3600, stale_heartbeat_seconds=300) >= 1
                    await s.commit()

                    # --- Worker B reclaims. 'failed' is claimable by design, which is what
                    #     makes the reaper's recovery re-runnable rather than terminal.
                    token_b = uuid.uuid4()
                    assert await _claim_scan(s, scan_id, token_b) is True, (
                        "a recovered scan was not reclaimable"
                    )
                    await s.commit()
                    status, tok = await _status_of(s, scan_id)
                    assert status == "running"
                    assert str(tok) == str(token_b)
                    assert str(tok) != str(token_a), "B inherited A's token"

                    # --- Worker A returns from the dead and tries to finalise. REFUSED.
                    scan = await s.get(Scan, scan_id)
                    await s.refresh(scan)
                    won_a = await _finalize_status(s, scan, "completed", token_a)
                    await s.commit()
                    assert won_a is False, "the revoked worker overwrote the new execution"

                    status, tok = await _status_of(s, scan_id)
                    assert status == "running", (
                        f"A's write changed the scan to {status!r} -- B's execution was "
                        f"clobbered"
                    )
                    assert str(tok) == str(token_b), "A's write disturbed B's ownership"

                    # --- Worker B finalises. Accepted, exactly once.
                    await s.refresh(scan)
                    assert await _finalize_status(s, scan, "completed", token_b) is True
                    await s.commit()
                    assert (await _status_of(s, scan_id))[0] == "completed"

                    # --- A DUPLICATE completion from B is refused too: the row is no
                    #     longer 'running', so no second authoritative result can exist.
                    await s.refresh(scan)
                    assert await _finalize_status(s, scan, "completed", token_b) is False, (
                        "a duplicate authoritative completion was accepted"
                    )
                    await s.commit()
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_only_one_of_two_racing_workers_wins_the_reclaim():
    """The reclaim itself is atomic -- two workers cannot both take a recovered scan."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    t = await _seed(s, "race")
                    scan_id = t["scan"].id
                    assert await _claim_scan(s, scan_id, uuid.uuid4()) is True
                    await s.commit()
                    await _age_heartbeat(s, scan_id, seconds=600)
                    await reap_orphaned_scans(s, timeout_seconds=3600,
                                              stale_heartbeat_seconds=300)
                    await s.commit()

                    first = await _claim_scan(s, scan_id, uuid.uuid4())
                    await s.commit()
                    second = await _claim_scan(s, scan_id, uuid.uuid4())
                    await s.commit()
                    assert first is True
                    assert second is False, "two workers both claimed the recovered scan"
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_a_revoked_lease_cannot_keep_a_scan_looking_alive():
    """The straggler must not be able to heartbeat a scan it no longer owns -- otherwise
    it could hold off the reaper on behalf of the executor that replaced it."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    t = await _seed(s, "zombie")
                    scan_id = t["scan"].id
                    token_a = uuid.uuid4()
                    assert await _claim_scan(s, scan_id, token_a) is True
                    await s.commit()
                    await _age_heartbeat(s, scan_id, seconds=600)
                    await reap_orphaned_scans(s, timeout_seconds=3600,
                                              stale_heartbeat_seconds=300)
                    await s.commit()

                    token_b = uuid.uuid4()
                    assert await _claim_scan(s, scan_id, token_b) is True
                    await s.commit()
                    before = (await s.execute(
                        text("SELECT last_heartbeat_at FROM scans WHERE id = :id"),
                        {"id": str(scan_id)})).scalar()

                    # A stamps with its DEAD token -> fenced out, changes nothing.
                    await _stamp_heartbeat(s, scan_id, token_a)
                    await s.commit()
                    after = (await s.execute(
                        text("SELECT last_heartbeat_at FROM scans WHERE id = :id"),
                        {"id": str(scan_id)})).scalar()
                    assert before == after, (
                        "a revoked worker refreshed the liveness of a scan it does not own"
                    )
        finally:
            await engine.dispose()

    asyncio.run(scenario())


# =======================================================================================
# 7-10: authorization still enforced on reclaim
# =======================================================================================

def test_revoked_worker_cannot_reclaim_recovered_work():
    """Requirement 7: revocation is enforced at authentication, so a revoked worker never
    reaches the lease at all."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    t = await _seed(s, "revoked")
                    await workers_service.revoke_worker(
                        s, t["worker"].worker_id, reason="test")
                    await s.commit()

                    with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
                        await workers_service.authenticate_worker(
                            s, worker_id=t["worker"].worker_id, token=t["token"])
                    # The credential was destroyed by revocation.
                    assert exc.value.reason in {
                        workers_service.REASON_BAD_CREDENTIAL,
                        workers_service.REASON_WORKER_REVOKED,
                    }

                    row = (await s.execute(
                        select(ScannerWorker).where(
                            ScannerWorker.worker_id == t["worker"].worker_id))).scalar_one()
                    with pytest.raises(workers_service.WorkerNotAuthorized) as exc2:
                        workers_service.assert_worker_active(row)
                    assert exc2.value.reason == workers_service.REASON_WORKER_REVOKED
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_wrong_worker_cannot_reclaim_another_tenants_recovered_scan():
    """Requirements 8 + 10: recovery does not relax tenant isolation.

    A recovered scan is `failed`, i.e. claimable -- so it is exactly the moment at which a
    weak authorization check would let the wrong worker pick it up.
    """
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    a = await _seed(s, "ta", private=True)
                    b = await _seed(s, "tb", private=True)

                    assert await _claim_scan(s, a["scan"].id, uuid.uuid4()) is True
                    await s.commit()
                    await _age_heartbeat(s, a["scan"].id, seconds=600)
                    await reap_orphaned_scans(s, timeout_seconds=3600,
                                              stale_heartbeat_seconds=300)
                    await s.commit()
                    assert (await _status_of(s, a["scan"].id))[0] == "failed"

                    # B's worker is refused A's recovered scan.
                    with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
                        workers_service.assert_worker_may_take_scan(
                            b["worker"], workspace_id=a["ws"], site_id=a["site"].id)
                    assert exc.value.reason in {
                        workers_service.REASON_WRONG_SITE,
                        workers_service.REASON_WRONG_WORKSPACE,
                    }
                    # A's own worker is still authorized for it.
                    workers_service.assert_worker_may_take_scan(
                        a["worker"], workspace_id=a["ws"], site_id=a["site"].id)
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_wrong_site_worker_cannot_reclaim_private_work():
    """Requirement 9: swapping ONLY the site (same workspace) is still refused."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    a = await _seed(s, "sa", private=True)
                    b = await _seed(s, "sb", private=True)
                    with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
                        workers_service.assert_worker_may_take_scan(
                            a["worker"], workspace_id=a["ws"], site_id=b["site"].id)
                    assert exc.value.reason == workers_service.REASON_WRONG_SITE
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_suspended_site_blocks_reclaim_of_recovered_private_work():
    """A site suspended while its scan was orphaned must not be scannable on reclaim."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                from apps.api.modules.private_sites import service as sites_service

                with tenancy.admin_bypass():
                    t = await _seed(s, "susp", private=True, site_status="suspended")
                with tenancy.workspace_scope(t["ws"]):
                    with pytest.raises(sites_service.PrivateSiteNotAuthorized) as exc:
                        await sites_service.build_scan_network_policy(
                            s, workspace_id=t["ws"], scan_id=t["scan"].id,
                            network_zone="private", site_id=t["site"].id)
                assert exc.value.reason == sites_service.REASON_SITE_SUSPENDED
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_the_reaper_never_touches_another_tenants_healthy_scan():
    """Requirement 10: the reaper is deliberately cross-tenant (it must sweep the whole
    platform), so it must be provably incapable of harming a healthy scan."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    dead = await _seed(s, "dead")
                    live = await _seed(s, "live")

                    assert await _claim_scan(s, dead["scan"].id, uuid.uuid4()) is True
                    assert await _claim_scan(s, live["scan"].id, uuid.uuid4()) is True
                    await s.commit()

                    await _age_heartbeat(s, dead["scan"].id, seconds=600)
                    await _stamp_heartbeat(s, live["scan"].id, None)  # live: beating now
                    await s.commit()

                    await reap_orphaned_scans(s, timeout_seconds=3600,
                                              stale_heartbeat_seconds=300)
                    await s.commit()

                    assert (await _status_of(s, dead["scan"].id))[0] == "failed"
                    assert (await _status_of(s, live["scan"].id))[0] == "running", (
                        "the reaper killed a healthy scan belonging to another tenant"
                    )
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_only_reaper_recovered_failures_are_re_leasable():
    """The boundary that keeps recovery from becoming an unbounded retry loop.

    `_claim_scan` treats `failed` as claimable (its retry path), so the lease query has to
    decide WHICH failures may be re-leased. Only ones the reaper recovered -- identified by
    `config.recovery` -- qualify. A scan that failed for its own reasons (bad target, tool
    crash, exhausted retries, dead-lettered) must NOT be re-leased forever: on the Celery
    path that case is bounded by autoretry + the DLQ, and re-leasing here would bypass both.
    """
    from pathlib import Path

    source = Path("apps/api/scanner_manager/app.py").read_text(encoding="utf-8")
    lease = source.split("async def lease_jobs", 1)[1].split("\n@app.", 1)[0]

    # The lease must not select `failed` unconditionally.
    assert 'Scan.status == "failed"' not in lease.replace(
        'and_(Scan.status == "failed", reaper_recovered)', ""
    ), "the lease selects failed scans without requiring reaper recovery"
    # It must gate on the recovery marker the reaper writes.
    assert "recovery" in lease, "the lease does not distinguish reaper-recovered failures"
    assert "reaper_recovered" in lease


def test_the_reaper_marks_recovery_so_the_lease_can_identify_it():
    """The two halves must agree: the reaper writes `config.recovery`, and the lease reads
    it. If the reaper ever stopped writing it, recovered scans would stop being re-leased
    -- so assert the marker is actually produced, not just consumed."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    t = await _seed(s, "marker")
                    scan_id = t["scan"].id
                    assert await _claim_scan(s, scan_id, uuid.uuid4()) is True
                    await s.commit()
                    await _age_heartbeat(s, scan_id, seconds=600)
                    assert await reap_orphaned_scans(
                        s, timeout_seconds=3600, stale_heartbeat_seconds=300) >= 1
                    await s.commit()

                    cfg = (await s.execute(
                        text("SELECT config FROM scans WHERE id = :id"),
                        {"id": str(scan_id)})).scalar()
                    blob = str(cfg)
                    assert "recovery" in blob, "the reaper did not mark the recovery"
                    assert "orphaned" in blob, "the recovery reason is not recorded"
        finally:
            await engine.dispose()

    asyncio.run(scenario())
