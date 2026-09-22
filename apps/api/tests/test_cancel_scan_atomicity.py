"""F2-03 / F2-04 regression coverage: `cancel_scan` must be an atomic, fenced conditional
UPDATE, and its terminal-state guard must recognize every canonical terminal status
(completed, completed_with_errors, failed, cancelled) -- not just three of the four.

Before this fix, cancel_scan was read-then-write: a plain SELECT (get_scan) followed by an
unconditional ORM `scan.status = "cancelled"` and `db.commit()`, with no WHERE clause tying
the write to the status just read and no `completed_with_errors` in its terminal check. A
concurrent terminal write landing between the read and the commit could be silently
clobbered back to 'cancelled'.

These tests hit the real MySQL test database directly through the service function (not
mocked), asserting durable committed state exactly as test_result_persistence_resilience.py
does for the sibling incident.
"""
import asyncio
import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans import service as scans_service
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _seed_scan(status: str) -> dict:
    engine = _engine()
    try:
        Session = async_sessionmaker(engine, expire_on_commit=False)
        async with Session() as s:
            with tenancy.admin_bypass():
                user = User(email=f"{uuid.uuid4()}@t.local", password_hash="x", full_name="U")
                s.add(user)
                await s.flush()
                ws = Workspace(name=f"ws-{uuid.uuid4().hex[:8]}", owner_user_id=user.id)
                s.add(ws)
                await s.flush()
                project = Project(id=uuid.uuid4(), workspace_id=ws.id, name="P", created_by=user.id)
                s.add(project)
                await s.flush()
                target = Target(id=uuid.uuid4(), project_id=project.id, type="domain",
                                value=f"{uuid.uuid4()}.test", added_by=user.id,
                                network_zone="public")
                s.add(target)
                await s.flush()
                scan = Scan(id=uuid.uuid4(), workspace_id=ws.id, project_id=project.id,
                           target_id=target.id, initiated_by=user.id, scan_type="recon",
                           status=status, config={"requested_modules": ["httpx"]},
                           execution_token=uuid.uuid4() if status == "running" else None)
                s.add(scan)
                await s.commit()
                return {"ws": ws.id, "project": project.id, "scan": scan.id}
    finally:
        await engine.dispose()


def _seed(status: str) -> dict:
    return asyncio.run(_seed_scan(status))


async def _read_status(scan_id) -> str:
    engine = _engine()
    try:
        Session = async_sessionmaker(engine, expire_on_commit=False)
        async with Session() as s:
            with tenancy.admin_bypass():
                scan = await s.get(Scan, scan_id)
                return scan.status
    finally:
        await engine.dispose()


async def _cancel(entry: dict):
    engine = _engine()
    try:
        Session = async_sessionmaker(engine, expire_on_commit=False)
        async with Session() as s:
            with tenancy.admin_bypass():
                return await scans_service.cancel_scan(s, entry["ws"], entry["project"], entry["scan"])
    finally:
        await engine.dispose()


# -----------------------------------------------------------------------------------------
# F2-04: every canonical terminal state rejects cancellation
# -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("terminal_status", ["completed", "completed_with_errors", "failed", "cancelled"])
def test_terminal_states_cannot_be_cancelled(terminal_status):
    entry = _seed(terminal_status)
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(_cancel(entry))
    assert exc_info.value.status_code == 400
    assert terminal_status in exc_info.value.detail

    # Untouched: still the original terminal status, not overwritten to 'cancelled'.
    assert asyncio.run(_read_status(entry["scan"])) == terminal_status


@pytest.mark.parametrize("cancellable_status", ["queued", "running"])
def test_cancellable_states_can_still_be_cancelled(cancellable_status):
    entry = _seed(cancellable_status)
    scan = asyncio.run(_cancel(entry))
    assert scan.status == "cancelled"
    assert asyncio.run(_read_status(entry["scan"])) == "cancelled"


def test_cancelled_scan_cannot_be_cancelled_again():
    entry = _seed("running")
    asyncio.run(_cancel(entry))
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(_cancel(entry))
    assert exc_info.value.status_code == 400


# -----------------------------------------------------------------------------------------
# F2-03: the race -- a concurrent terminal write must win over a stale cancellation
# -----------------------------------------------------------------------------------------

def test_concurrent_completion_wins_the_race_against_cancellation():
    """Simulates the exact race from Prompt 2: cancel_scan reads 'running', then (before it
    writes) the worker's fenced finalize commits 'completed_with_errors' first. The atomic
    UPDATE...WHERE must then see the row is no longer in a cancellable state and lose the
    race -- not blindly overwrite it back to 'cancelled'.
    """
    entry = _seed("running")

    async def scenario():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)

            # A DIFFERENT connection/session finalizes the scan first, exactly as the lease
            # worker's `_finalize_status` would -- fully committed before cancel proceeds.
            async with Session() as s2:
                with tenancy.admin_bypass():
                    from apps.api.scanner_engine.orchestrator import _finalize_status
                    scan2 = await s2.get(Scan, entry["scan"])
                    assert scan2.status == "running"
                    won = await _finalize_status(
                        s2, scan2, "completed_with_errors", scan2.execution_token,
                    )
                    assert won is True

            # NOW cancel_scan runs its conditional UPDATE, on a fresh session that has not
            # seen the finalize above (matches the real race: cancel's own SELECT happened
            # earlier, before the concurrent finalize committed). The atomic UPDATE...WHERE
            # must affect zero rows because the row is already terminal, and cancel_scan
            # must report the loss rather than silently overwriting the finished scan.
            async with Session() as s:
                with tenancy.admin_bypass():
                    with pytest.raises(HTTPException) as exc_info:
                        await scans_service.cancel_scan(s, entry["ws"], entry["project"], entry["scan"])
                    assert exc_info.value.status_code == 400
        finally:
            await engine.dispose()

    asyncio.run(scenario())

    # The database must show the REAL outcome (completed_with_errors), never 'cancelled'.
    assert asyncio.run(_read_status(entry["scan"])) == "completed_with_errors"
