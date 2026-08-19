"""M4.6.2 -- atomic scan claim (F3). Verifies the conditional-UPDATE claim prevents
duplicate execution: only queued/failed scans are claimable, running/terminal are not,
and a redelivered worker skips cleanly with no side effects / no IntegrityError.

Real Postgres via a self-managed session (RLS not involved -- scans is RLS-exempt).
Scanner behavior + _run_single_tool are untouched by this milestone.
"""
import asyncio
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core.config import get_settings
from apps.api.modules.agent.models import EngagementState
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.models import ToolRun
from apps.api.scanner_engine.orchestrator import _claim_scan, run_scan


async def _seed_scan(session, status: str) -> uuid.UUID:
    user = User(email=f"claim-{uuid.uuid4()}@test.local", password_hash="x", full_name="Claim Tester")
    session.add(user)
    await session.flush()
    ws = Workspace(name="claim-ws", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    project = Project(workspace_id=ws.id, name="claim-proj", created_by=user.id)
    session.add(project)
    await session.flush()
    target = Target(project_id=project.id, type="ip_range", value="203.0.113.40", criticality="low", added_by=user.id)
    session.add(target)
    await session.flush()
    scan = Scan(
        workspace_id=ws.id, project_id=project.id, target_id=target.id, initiated_by=user.id,
        scan_type="network", status=status, config={},
    )
    session.add(scan)
    await session.commit()
    return scan.id


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


# --- 1 & 2: first worker claims a queued scan; a second cannot re-claim it ---

def test_claim_queued_then_second_claim_fails():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan_id = await _seed_scan(s, "queued")
                first = await _claim_scan(s, scan_id, uuid.uuid4())
                second = await _claim_scan(s, scan_id, uuid.uuid4())
                status = await s.scalar(select(Scan.status).where(Scan.id == scan_id))
            return first, second, status
        finally:
            await engine.dispose()

    first, second, status = asyncio.run(scenario())
    assert first is True          # (1) first worker claims the queued scan
    assert second is False        # (2) second worker cannot claim the same scan
    assert status == "running"    # status transitioned exactly once


# --- 3: a running scan cannot be claimed ---

def test_running_not_claimable():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan_id = await _seed_scan(s, "running")
                return await _claim_scan(s, scan_id, uuid.uuid4())
        finally:
            await engine.dispose()

    assert asyncio.run(scenario()) is False


# --- 4: completed / cancelled scans cannot be claimed ---

def test_terminal_not_claimable():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                completed = await _claim_scan(s, await _seed_scan(s, "completed"), uuid.uuid4())
                cancelled = await _claim_scan(s, await _seed_scan(s, "cancelled"), uuid.uuid4())
                with_errors = await _claim_scan(s, await _seed_scan(s, "completed_with_errors"), uuid.uuid4())
            return completed, cancelled, with_errors
        finally:
            await engine.dispose()

    completed, cancelled, with_errors = asyncio.run(scenario())
    assert completed is False and cancelled is False and with_errors is False


# --- 5: a failed scan can be reclaimed (retry-after-failure preserved) ---

def test_failed_is_reclaimable():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan_id = await _seed_scan(s, "failed")
                claimed = await _claim_scan(s, scan_id, uuid.uuid4())
                status = await s.scalar(select(Scan.status).where(Scan.id == scan_id))
            return claimed, status
        finally:
            await engine.dispose()

    claimed, status = asyncio.run(scenario())
    assert claimed is True and status == "running"


# --- concurrency across TWO connections: exactly one worker wins the claim ---

def test_two_connections_only_one_claims():
    async def scenario():
        e1, e2 = _engine(), _engine()
        m1 = async_sessionmaker(e1, expire_on_commit=False)
        m2 = async_sessionmaker(e2, expire_on_commit=False)
        try:
            async with m1() as s_seed:
                scan_id = await _seed_scan(s_seed, "queued")
            async with m1() as s1, m2() as s2:
                c1 = await _claim_scan(s1, scan_id, uuid.uuid4())   # connection 1
                c2 = await _claim_scan(s2, scan_id, uuid.uuid4())   # connection 2 (separate)
            return c1, c2
        finally:
            await e1.dispose()
            await e2.dispose()

    c1, c2 = asyncio.run(scenario())
    assert (c1, c2).count(True) == 1   # exactly one worker claimed; the other was rejected


# --- 6: a redelivered worker on a non-claimable scan skips with NO side effects ---

def test_run_scan_skips_non_claimable_no_integrity_error():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                # Simulate a scan already owned by another worker (status=running).
                scan_id = await _seed_scan(s, "running")
                # A redelivered task calls run_scan -> must skip BEFORE any execution.
                await run_scan(s, scan_id)   # must NOT raise (no duplicate-exec IntegrityError)
                engagements = await s.scalar(
                    select(func.count()).select_from(EngagementState).where(EngagementState.scan_id == scan_id)
                )
                tool_runs = await s.scalar(
                    select(func.count()).select_from(ToolRun).where(ToolRun.scan_id == scan_id)
                )
                status = await s.scalar(select(Scan.status).where(Scan.id == scan_id))
            return engagements, tool_runs, status
        finally:
            await engine.dispose()

    engagements, tool_runs, status = asyncio.run(scenario())
    assert engagements == 0 and tool_runs == 0   # the duplicate worker executed nothing
    assert status == "running"                    # untouched by the skipped worker
