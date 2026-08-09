"""F3.1 -- AI Planner idempotency.

A scan re-run (Celery F2 transient retry, reaper reclaim, DLQ replay) must NOT re-call the LLM
when a plan already exists: no duplicate AI charge, no duplicate ai_plans row, no ai_usage row.
Real Postgres (ai_plans is FORCE-RLS, so the workspace GUC is set), with a fake AI client that
counts calls.
"""
import asyncio
import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.ai_agent.models import AIPlan
from apps.api.ai_agent.planner import AIPlanner
from apps.api.ai_agent.providers.usage import collect_ai_usage
from apps.api.core.config import get_settings
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace


class _FakeClient:
    """A SupportsComplete stand-in that records how many times the LLM was called."""

    model_version = "fake-model-x"

    def __init__(self):
        self.calls = 0

    def complete_json(self, system, user):
        self.calls += 1
        return {"tool_sequence": ["httpx"], "reasoning_summary": "fresh-from-llm"}


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _set_ws(session, wid):
    await session.execute(
        text("SELECT set_config('app.current_workspace_id', :w, false)"), {"w": str(wid)}
    )


async def _seed_scan(session):
    user = User(email=f"plan-{uuid.uuid4()}@t.local", password_hash="x", full_name="Plan Tester")
    session.add(user)
    await session.flush()
    ws = Workspace(name="plan-ws", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    await _set_ws(session, ws.id)  # RLS bootstrap for the RLS-scoped inserts below
    proj = Project(workspace_id=ws.id, name="p", created_by=user.id)
    session.add(proj)
    await session.flush()
    tgt = Target(project_id=proj.id, type="domain", value="example.com", criticality="low", added_by=user.id)
    session.add(tgt)
    await session.flush()
    scan = Scan(workspace_id=ws.id, project_id=proj.id, target_id=tgt.id, initiated_by=user.id,
                scan_type="network", status="running", config={})
    session.add(scan)
    await session.commit()
    return ws.id, scan.id


async def _count_plans(session, scan_id):
    return int(await session.scalar(
        text("SELECT count(*) FROM ai_plans WHERE scan_id = :s"), {"s": str(scan_id)}) or 0)


def test_planner_reuses_existing_plan_without_calling_llm():
    async def scenario():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                ws, scan = await _seed_scan(s)
                await _set_ws(s, ws)
                s.add(AIPlan(scan_id=scan, tool_sequence=["nmap"], reasoning_summary="prior",
                             model_version="prior-model", prompt_version="v-prior"))
                await s.commit()

                fake = _FakeClient()
                with collect_ai_usage(agent_role="planner", workspace_id=str(ws), scan_id=str(scan)) as sink:
                    result = await AIPlanner(client=fake).plan(
                        s, scan_id=scan, target_type="domain", target_value="example.com",
                        requested_modules=["nmap", "httpx"], active_testing_allowed=False,
                    )
                plans = await _count_plans(s, scan)
                return fake.calls, result.tool_sequence, result.model_version, plans, list(sink)
        finally:
            await eng.dispose()

    calls, seq, model, plans, sink = asyncio.run(scenario())
    assert calls == 0                 # the LLM was NOT called
    assert seq == ["nmap"]            # the persisted plan was reused (not the fake's ["httpx"])
    assert model == "prior-model"     # reused verbatim from the stored plan
    assert plans == 1                 # no duplicate ai_plans row
    assert sink == []                 # no AI usage record produced on the reuse path


def test_planner_calls_llm_when_no_plan_exists():
    """First run (no prior plan) is unchanged: the LLM is called and exactly one plan persisted."""
    async def scenario():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                ws, scan = await _seed_scan(s)
                await _set_ws(s, ws)
                fake = _FakeClient()
                await AIPlanner(client=fake).plan(
                    s, scan_id=scan, target_type="domain", target_value="example.com",
                    requested_modules=["httpx"], active_testing_allowed=False,
                )
                await s.commit()
                return fake.calls, await _count_plans(s, scan)
        finally:
            await eng.dispose()

    calls, plans = asyncio.run(scenario())
    assert calls == 1     # LLM called exactly once (unchanged first-run behavior)
    assert plans == 1     # exactly one plan persisted


def test_planner_reuse_is_stable_across_two_reruns():
    """Two successive re-runs both reuse -- the LLM is never called again and no rows accrue."""
    async def scenario():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                ws, scan = await _seed_scan(s)
                await _set_ws(s, ws)
                s.add(AIPlan(scan_id=scan, tool_sequence=["httpx"], reasoning_summary="p",
                             model_version="m", prompt_version="v"))
                await s.commit()
                fake = _FakeClient()
                for _ in range(2):
                    await AIPlanner(client=fake).plan(
                        s, scan_id=scan, target_type="domain", target_value="example.com",
                        requested_modules=["httpx"], active_testing_allowed=False,
                    )
                return fake.calls, await _count_plans(s, scan)
        finally:
            await eng.dispose()

    calls, plans = asyncio.run(scenario())
    assert calls == 0     # never calls the LLM on re-runs
    assert plans == 1     # still exactly one plan
