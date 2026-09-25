"""Orphaned ToolRun reconciliation -- incident 615d0e0b, fourth defect.

A `tool_runs` row left `running` under a scan that has already finished is an impossible
lifecycle state: nothing will ever report that tool's result, because its scan is over. The
investigation of incident 615d0e0b found 14 such rows across the deployment, one of them
katana's -- which the UI faithfully rendered as a live, ticking timer for a process that had
been OOM-killed hours earlier.

Nothing in the system repaired them: the scan reaper transitions `scans` only, and
`_finalize_status` never touches `tool_runs`.

These tests exercise the real SQL against the real MySQL test database, because the whole
value of the reconciler is in the precision of its WHERE clause -- which rows it does NOT
touch matters more than which it does.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.models import ToolRun
from apps.api.scanner_engine.orchestrator import reconcile_orphaned_tool_runs

GRACE = 300


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _seed(session, *, scan_status, tool_status, scan_age_seconds, tool_name="katana"):
    """One workspace/project/target/scan plus a single tool run, with controlled ages."""
    user = User(email=f"rec-{uuid.uuid4()}@t.local", password_hash="x", full_name="rec")
    session.add(user)
    await session.flush()
    ws = Workspace(name=f"rec-{uuid.uuid4().hex[:8]}", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    project = Project(id=uuid.uuid4(), workspace_id=ws.id, name="p", created_by=user.id)
    session.add(project)
    await session.flush()
    target = Target(id=uuid.uuid4(), project_id=project.id, type="domain",
                    value=f"{uuid.uuid4().hex[:8]}.test", added_by=user.id,
                    network_zone="public")
    session.add(target)
    await session.flush()

    completed = datetime.now(timezone.utc) - timedelta(seconds=scan_age_seconds)
    scan = Scan(
        id=uuid.uuid4(), workspace_id=ws.id, project_id=project.id, target_id=target.id,
        initiated_by=user.id, scan_type="web", status=scan_status, config={},
        started_at=completed - timedelta(minutes=5),
        completed_at=completed if scan_status != "running" else None,
    )
    session.add(scan)
    await session.flush()

    run = ToolRun(
        id=uuid.uuid4(), scan_id=scan.id, tool_name=tool_name, tool_version="1.7.0",
        status=tool_status, command_hash="",
        started_at=completed - timedelta(minutes=4),
        completed_at=None if tool_status == "running" else completed,
    )
    session.add(run)
    await session.flush()
    return scan.id, run.id


def _run_case(*, scan_status, tool_status, scan_age_seconds, grace=GRACE):
    """Seed one scenario, reconcile, and return the tool run's resulting state."""
    async def go():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    _, run_id = await _seed(
                        s, scan_status=scan_status, tool_status=tool_status,
                        scan_age_seconds=scan_age_seconds,
                    )
                    await s.commit()
            async with Session() as s:
                with tenancy.admin_bypass():
                    count = await reconcile_orphaned_tool_runs(s, grace)
            async with Session() as s:
                with tenancy.admin_bypass():
                    row = (await s.execute(
                        text("SELECT status, completed_at, error_message FROM tool_runs "
                             "WHERE id = :i"),
                        {"i": str(run_id)},
                    )).fetchone()
            return count, row
        finally:
            await engine.dispose()

    return asyncio.run(go())


# =======================================================================================
# Rows that MUST be reconciled
# =======================================================================================

@pytest.mark.parametrize("scan_status", ["failed", "cancelled", "completed",
                                         "completed_with_errors"])
def test_orphan_under_every_terminal_scan_status_is_reconciled(scan_status):
    """All four terminal statuses strand a tool run equally -- the incident's scan was
    `failed`, but a cancelled or completed scan leaves an identically impossible row."""
    count, row = _run_case(scan_status=scan_status, tool_status="running",
                           scan_age_seconds=GRACE + 60)
    assert count >= 1
    assert row[0] == "failed", f"orphan under a {scan_status} scan was not reconciled"


def test_reconciled_row_gets_completed_at_so_the_ui_stops_ticking():
    """The UI renders elapsed time from started_at for as long as completed_at is NULL --
    which is why the incident showed a live timer for a dead process."""
    _, row = _run_case(scan_status="failed", tool_status="running",
                       scan_age_seconds=GRACE + 60)
    assert row[1] is not None


def test_reconciled_row_records_a_reason():
    """A status change with no stated cause is how the original incident stayed opaque."""
    _, row = _run_case(scan_status="failed", tool_status="running",
                       scan_age_seconds=GRACE + 60)
    assert row[2] and "orphaned" in row[2]


# =======================================================================================
# Rows that MUST NOT be touched -- the safety half, which matters more
# =======================================================================================

def test_a_running_scan_is_never_touched():
    """The tool is LIVE. Reconciling it would erase a genuine in-flight execution."""
    count, row = _run_case(scan_status="running", tool_status="running",
                           scan_age_seconds=GRACE + 600)
    assert row[0] == "running", "reconciler killed a tool run under a LIVE scan"
    assert count == 0


def test_a_queued_scan_is_never_touched():
    count, row = _run_case(scan_status="queued", tool_status="running",
                           scan_age_seconds=GRACE + 600)
    assert row[0] == "running"
    assert count == 0


def test_the_grace_period_protects_a_result_still_in_flight():
    """Scan finalization and a tool's result submission are separate writes, so a result
    can legitimately land just AFTER its scan goes terminal. Without the grace period the
    reconciler would race that write and fail a tool that was about to report success."""
    count, row = _run_case(scan_status="failed", tool_status="running",
                           scan_age_seconds=10)
    assert row[0] == "running", "reconciler raced a result that was still in flight"
    assert count == 0


@pytest.mark.parametrize("tool_status", ["completed", "partial", "failed",
                                         "skipped_unauthorized"])
def test_an_already_terminal_tool_run_is_never_rewritten(tool_status):
    """A tool that reported its own outcome is authoritative; the sweep must not overwrite
    it, least of all downgrade a `completed` run to `failed`."""
    count, row = _run_case(scan_status="failed", tool_status=tool_status,
                           scan_age_seconds=GRACE + 600)
    assert row[0] == tool_status
    assert count == 0


def test_an_existing_error_message_is_preserved():
    """A message the tool itself recorded is closer to the truth than the sweep's."""
    async def go():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    _, run_id = await _seed(s, scan_status="failed", tool_status="running",
                                            scan_age_seconds=GRACE + 600)
                    await s.execute(
                        text("UPDATE tool_runs SET error_message = :m WHERE id = :i"),
                        {"m": "katana: killed by SIGKILL (cgroup OOM)", "i": str(run_id)},
                    )
                    await s.commit()
            async with Session() as s:
                with tenancy.admin_bypass():
                    await reconcile_orphaned_tool_runs(s, GRACE)
            async with Session() as s:
                with tenancy.admin_bypass():
                    return (await s.execute(
                        text("SELECT status, error_message FROM tool_runs WHERE id = :i"),
                        {"i": str(run_id)},
                    )).fetchone()
        finally:
            await engine.dispose()

    row = asyncio.run(go())
    assert row[0] == "failed"
    assert row[1] == "katana: killed by SIGKILL (cgroup OOM)", (
        "the sweep overwrote the tool's own diagnosis"
    )


# =======================================================================================
# Idempotency and repeatability
# =======================================================================================

def test_reconciliation_is_idempotent():
    """The source state is `running`, so a second pass matches nothing. This is also what
    makes two reapers running concurrently safe."""
    async def go():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    _, run_id = await _seed(s, scan_status="failed", tool_status="running",
                                            scan_age_seconds=GRACE + 600)
                    await s.commit()
            counts = []
            for _ in range(3):
                async with Session() as s:
                    with tenancy.admin_bypass():
                        counts.append(await reconcile_orphaned_tool_runs(s, GRACE))
            async with Session() as s:
                with tenancy.admin_bypass():
                    row = (await s.execute(
                        text("SELECT status FROM tool_runs WHERE id = :i"),
                        {"i": str(run_id)},
                    )).fetchone()
            return counts, row
        finally:
            await engine.dispose()

    counts, row = asyncio.run(go())
    assert counts[0] >= 1
    assert counts[1] == 0, "a second pass re-matched an already-reconciled row"
    assert counts[2] == 0
    assert row[0] == "failed"


def test_a_scan_with_no_completed_at_is_still_reconcilable():
    """A scan cancelled or reaped before it ever stamped completed_at would otherwise have
    a NULL on the left of the age comparison -- never true in SQL -- making its orphans
    immortal. COALESCE(completed_at, started_at) is what prevents that."""
    async def go():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    scan_id, run_id = await _seed(
                        s, scan_status="cancelled", tool_status="running",
                        scan_age_seconds=GRACE + 600,
                    )
                    await s.execute(
                        text("UPDATE scans SET completed_at = NULL WHERE id = :i"),
                        {"i": str(scan_id)},
                    )
                    await s.commit()
            async with Session() as s:
                with tenancy.admin_bypass():
                    await reconcile_orphaned_tool_runs(s, GRACE)
            async with Session() as s:
                with tenancy.admin_bypass():
                    return (await s.execute(
                        text("SELECT status FROM tool_runs WHERE id = :i"),
                        {"i": str(run_id)},
                    )).fetchone()
        finally:
            await engine.dispose()

    assert asyncio.run(go())[0] == "failed"


def test_only_the_orphan_is_touched_when_both_kinds_exist():
    """The decisive safety test: a live scan's tool run and an orphan, reconciled in one
    pass. Exactly one must change."""
    async def go():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    _, orphan = await _seed(s, scan_status="failed", tool_status="running",
                                            scan_age_seconds=GRACE + 600)
                    _, live = await _seed(s, scan_status="running", tool_status="running",
                                          scan_age_seconds=GRACE + 600)
                    await s.commit()
            async with Session() as s:
                with tenancy.admin_bypass():
                    await reconcile_orphaned_tool_runs(s, GRACE)
            async with Session() as s:
                with tenancy.admin_bypass():
                    rows = (await s.execute(
                        text("SELECT id, status FROM tool_runs WHERE id IN (:a, :b)"),
                        {"a": str(orphan), "b": str(live)},
                    )).fetchall()
            return {str(r[0]): r[1] for r in rows}
        finally:
            await engine.dispose()

    states = asyncio.run(go())
    assert len(states) == 2
    assert sorted(states.values()) == ["failed", "running"], (
        f"expected exactly one reconciled and one untouched, got {states}"
    )
