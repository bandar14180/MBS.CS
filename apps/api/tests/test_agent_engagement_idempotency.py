"""F3.3 -- Agent engagement get-or-create (SKIP-ON-RETRY).

A scan re-run (Celery F2 transient retry, reaper reclaim, DLQ replay) must NOT create a second
EngagementState (it's one-per-scan, uq_engagement_state_scan) nor restart the expensive AI agent
loop. First run creates the engagement and runs the loop unchanged; a re-run reuses it and skips.

Real Postgres (agent tables + tool_runs are FORCE-RLS, so the workspace GUC is set). The AI
client is injected by monkeypatching apps.api.ai_agent.agent.get_ai_client (as the e2e agent test
does); the tool subprocess boundary is never reached because the fake agent finishes immediately.
"""
import asyncio
import uuid
from types import SimpleNamespace

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core.config import get_settings
from apps.api.modules.agent.models import AgentStep, EngagementState
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.orchestrator import _run_agent_driven


class _StopClient:
    """A fake AI client whose first decision is to finish (empty candidate set + stop_reason),
    so the real agent loop runs exactly one round then terminates -- no tool subprocess needed."""

    model_version = "stop-fake/v1"

    def __init__(self):
        self.calls = 0

    def complete_json(self, system, user):
        self.calls += 1
        return {"observations": ["assessed"], "candidate_actions": [], "stop_reason": "done"}


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _set_guc(session, wid):
    await session.execute(
        text("SELECT set_config('app.current_workspace_id', :w, false)"), {"w": str(wid)}
    )


async def _seed(session):
    user = User(email=f"eng-{uuid.uuid4()}@t.local", password_hash="x", full_name="Eng Tester")
    session.add(user)
    await session.flush()
    ws = Workspace(name="eng-ws", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    await _set_guc(session, ws.id)
    proj = Project(workspace_id=ws.id, name="p", created_by=user.id)
    session.add(proj)
    await session.flush()
    tgt = Target(project_id=proj.id, type="ip_range", value="203.0.113.10", criticality="low", added_by=user.id)
    session.add(tgt)
    await session.flush()
    scan = Scan(workspace_id=ws.id, project_id=proj.id, target_id=tgt.id, initiated_by=user.id,
                scan_type="network", status="running", config={})
    session.add(scan)
    await session.commit()
    return ws.id, scan, tgt


async def _count(session, wid, table, scan_id):
    await _set_guc(session, wid)
    return int(await session.scalar(
        text(f"SELECT count(*) FROM {table} WHERE scan_id = :s"), {"s": str(scan_id)}) or 0)


def test_first_run_creates_single_engagement_and_runs_loop(monkeypatch):
    client = _StopClient()
    monkeypatch.setattr("apps.api.ai_agent.agent.get_ai_client", lambda model=None: client)

    async def scenario():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                ws, scan, tgt = await _seed(s)
                await _run_agent_driven(s, scan, tgt, SimpleNamespace(active_testing_allowed=True))
            async with async_sessionmaker(eng, expire_on_commit=False)() as v:
                return client.calls, await _count(v, ws, "engagement_state", scan.id)
        finally:
            await eng.dispose()

    calls, engagements = asyncio.run(scenario())
    assert engagements == 1     # exactly one EngagementState created
    assert calls >= 1           # the real agent loop was entered (an AI decision was made)


def test_rerun_reuses_engagement_and_skips_ai(monkeypatch):
    client = _StopClient()
    monkeypatch.setattr("apps.api.ai_agent.agent.get_ai_client", lambda model=None: client)

    async def scenario():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                ws, scan, tgt = await _seed(s)
                await _set_guc(s, ws)
                # a prior run already created the engagement
                s.add(EngagementState(workspace_id=ws, scan_id=scan.id, status="running",
                                      current_phase="reconnaissance"))
                await s.commit()

                client.calls = 0  # reset -- the re-run must make ZERO AI calls
                result = await _run_agent_driven(s, scan, tgt, SimpleNamespace(active_testing_allowed=True))
            async with async_sessionmaker(eng, expire_on_commit=False)() as v:
                return (client.calls, result,
                        await _count(v, ws, "engagement_state", scan.id),
                        await _count(v, ws, "agent_steps", scan.id))
        finally:
            await eng.dispose()

    calls, result, engagements, steps = asyncio.run(scenario())
    assert calls == 0            # AI loop NOT entered -> no LLM call on the re-run
    assert engagements == 1      # no duplicate EngagementState
    assert steps == 0            # no agent step recorded (loop skipped)
    assert isinstance(result, list)  # finalized safely (returns tool statuses)


def test_rerun_does_not_raise_integrity_error(monkeypatch):
    """Regression: before F3.3 a retry's unconditional INSERT hit uq_engagement_state_scan and
    raised IntegrityError. Now a first run then an immediate re-run completes cleanly."""
    client = _StopClient()
    monkeypatch.setattr("apps.api.ai_agent.agent.get_ai_client", lambda model=None: client)

    async def scenario():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                ws, scan, tgt = await _seed(s)
                scope = SimpleNamespace(active_testing_allowed=True)
                await _run_agent_driven(s, scan, tgt, scope)   # first run: creates + commits
                calls_after_first = client.calls
                await _run_agent_driven(s, scan, tgt, scope)   # retry: must NOT raise
                calls_after_second = client.calls
            async with async_sessionmaker(eng, expire_on_commit=False)() as v:
                return calls_after_first, calls_after_second, await _count(v, ws, "engagement_state", scan.id)
        finally:
            await eng.dispose()

    first, second, engagements = asyncio.run(scenario())
    assert engagements == 1              # still exactly one engagement
    assert second == first               # the re-run made no additional AI call
