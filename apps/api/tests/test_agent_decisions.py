"""M4.4.1 -- structured agent-decision persistence (agent_decisions table).

Verifies the additive reasoning-audit table: persistence + structured serialization,
correlation to the AgentStep audit (without modifying AgentStep), the (scan_id,
step_no) uniqueness, and FORCE-RLS workspace isolation. Uses a self-managed StaticPool
session with RLS ENABLED (GUC set, never disabled), same harness as the M4.3.x tests.
"""
import asyncio
import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.ai_agent.agent import AgentDecision, CandidateAction
from apps.api.core.config import get_settings
from apps.api.modules.agent.models import AgentDecision as AgentDecisionRow, AgentStep
from apps.api.modules.agent.repo import latest_agent_decision, persist_agent_decision
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace


async def _set_guc(session, ws_id):
    await session.execute(
        text("SELECT set_config('app.current_workspace_id', :wid, false)"), {"wid": str(ws_id)}
    )


async def _seed_scan(session):
    """Full FK chain (workspaces/users not RLS; projects/targets/scan scoped)."""
    user = User(email=f"dec-{uuid.uuid4()}@test.local", password_hash="x", full_name="Dec Tester")
    session.add(user)
    await session.flush()
    ws = Workspace(name="dec-ws", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    await _set_guc(session, ws.id)
    project = Project(workspace_id=ws.id, name="dec-proj", created_by=user.id)
    session.add(project)
    await session.flush()
    target = Target(project_id=project.id, type="ip_range", value="203.0.113.30", criticality="medium", added_by=user.id)
    session.add(target)
    await session.flush()
    scan = Scan(
        workspace_id=ws.id, project_id=project.id, target_id=target.id, initiated_by=user.id,
        scan_type="network", status="running", config={"use_agent": True},
    )
    session.add(scan)
    await session.flush()
    return ws.id, scan.id


def _decision():
    return AgentDecision(
        action="run_tool", tool="nmap", phase="reconnaissance", rationale="scan ports",
        model_version="fake/v1", prompt_version="agent/v4",
        observations=["port 80 open"], inferences=["web surface"], hypotheses=["login may exist"],
        candidates=[
            CandidateAction("nmap", 0.9, "high", "low", ["services"], "scan ports"),
            CandidateAction("httpx", 0.6, "medium", "low", ["http"], "probe http"),
        ],
        confidence=0.9, stop_reason=None,
    )


def test_persist_and_read_structured_decision():
    async def scenario():
        settings = get_settings()
        engine = create_async_engine(settings.database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                ws_id, scan_id = await _seed_scan(s)
                # A real AgentStep to correlate to (AgentStep is NOT modified).
                step = AgentStep(
                    workspace_id=ws_id, scan_id=scan_id, step_no=0, phase="reconnaissance",
                    action_type="tool_run", tool_or_module="nmap", status="completed",
                )
                s.add(step)
                await s.flush()
                await persist_agent_decision(
                    s, workspace_id=ws_id, scan_id=scan_id, step_no=0, decision=_decision(),
                    agent_step_id=step.id, budget_state={"step_no": 0, "max_steps": 40},
                )
                await s.commit()
            async with maker() as v:
                await _set_guc(v, ws_id)
                row = await latest_agent_decision(v, scan_id)
                # AgentStep row still intact + unchanged shape.
                steps = list(await v.scalars(select(AgentStep).where(AgentStep.scan_id == scan_id)))
            return row, steps, ws_id
        finally:
            await engine.dispose()

    row, steps, ws_id = asyncio.run(scenario())
    assert row is not None
    # Structured serialization + evidence tiers kept DISTINCT.
    assert row.observations == ["port 80 open"]
    assert row.inferences == ["web surface"]
    assert row.hypotheses == ["login may exist"]
    assert row.action == "run_tool" and row.selected_tool == "nmap" and row.selected_confidence == 0.9
    assert row.stop_reason is None
    assert row.model_version == "fake/v1" and row.prompt_version == "agent/v4"
    assert row.budget_state == {"step_no": 0, "max_steps": 40}
    # Candidates persisted as structured JSON with per-candidate confidence/risk/value.
    assert [c["tool"] for c in row.candidates] == ["nmap", "httpx"]
    assert row.candidates[0]["confidence"] == 0.9 and row.candidates[0]["risk"] == "low"
    assert row.candidates[1]["expected_value"] == "medium"
    # Correlated to its AgentStep, which remains a single intact audit row.
    assert len(steps) == 1
    assert row.agent_step_id == steps[0].id
    assert row.step_no == steps[0].step_no


def test_unique_scan_step_no():
    async def scenario():
        settings = get_settings()
        engine = create_async_engine(settings.database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                ws_id, scan_id = await _seed_scan(s)
                await persist_agent_decision(s, workspace_id=ws_id, scan_id=scan_id, step_no=0, decision=_decision())
                await persist_agent_decision(s, workspace_id=ws_id, scan_id=scan_id, step_no=0, decision=_decision())
                await s.commit()
        finally:
            await engine.dispose()

    with pytest.raises(IntegrityError):
        asyncio.run(scenario())


def test_agent_decisions_force_rls_configured_like_agent_steps():
    """The additive table carries the SAME workspace-isolation control as the
    accepted agent_steps / engagement_state tables: ENABLE + FORCE ROW LEVEL
    SECURITY plus a workspace_isolation policy keyed on the app.current_workspace_id
    GUC. (Runtime cross-workspace BLOCKING can't be exercised here because the dev
    DB role is a superuser, which bypasses RLS; the app layer's cross-workspace
    denial is covered by the API 403/404 tests -- see M4.4.5. This asserts the DB
    control is DEFINED correctly, identical to the platform's accepted pattern.)"""
    async def scenario():
        settings = get_settings()
        engine = create_async_engine(settings.database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                flags = (
                    await s.execute(
                        text(
                            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                            "WHERE relname = 'agent_decisions'"
                        )
                    )
                ).one()
                qual = (
                    await s.execute(
                        text(
                            "SELECT qual FROM pg_policies WHERE tablename = 'agent_decisions' "
                            "AND policyname = 'workspace_isolation'"
                        )
                    )
                ).scalar_one()
            return flags, qual
        finally:
            await engine.dispose()

    (enabled, forced), qual = asyncio.run(scenario())
    assert enabled is True and forced is True          # ENABLE + FORCE RLS
    assert "current_setting('app.current_workspace_id'" in qual
    assert "workspace_id" in qual                       # keyed on the tenant column
