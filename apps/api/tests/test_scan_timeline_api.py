"""Phase 1.3 -- read-only observability endpoints: GET /scans/{id}/timeline and
/scans/{id}/agent-decisions. Verifies authorization (401/403), cross-tenant isolation,
pagination headers, event shape, and NO sensitive-blob leakage in the decision trace.
"""
import asyncio
import uuid

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.ai_agent.agent import AgentDecision as _Decision, CandidateAction
from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.agent.models import AgentStep
from apps.api.modules.agent.repo import persist_agent_decision
from apps.api.scanner_engine.models import ToolRun
from apps.api.tests.test_scans import (
    _auth,
    _make_target,
    _register,
    _verify_target,
)


async def _seed_events(ws_id: str, scan_id: str):
    """Insert a tool run, an agent step, and a structured agent decision for the scan
    (workspace GUC set so FORCE-RLS inserts succeed)."""
    settings = get_settings()
    engine = create_async_engine(settings.database_url, poolclass=StaticPool)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as s:
            tenancy.bind_workspace(ws_id)  # Phase 0 MySQL cutover: was Postgres set_config; see apps.api.core.tenancy
            s.add(ToolRun(scan_id=uuid.UUID(scan_id), tool_name="httpx", tool_version="1", status="completed", command_hash="x"))
            step = AgentStep(workspace_id=uuid.UUID(ws_id), scan_id=uuid.UUID(scan_id), step_no=0,
                             phase="reconnaissance", action_type="tool_run", tool_or_module="httpx", status="completed")
            s.add(step)
            await s.flush()
            decision = _Decision(
                action="run_tool", tool="httpx", phase="reconnaissance", rationale="probe the web surface",
                model_version="fake/v1", prompt_version="agent/v5",
                observations=["SECRET-LOOKING internal note that must NOT leak"],
                inferences=["web exposed"], hypotheses=["login may exist"],
                candidates=[CandidateAction("httpx", 0.9, "high", "low", ["http"], "probe")],
                confidence=0.9,
            )
            await persist_agent_decision(s, workspace_id=uuid.UUID(ws_id), scan_id=uuid.UUID(scan_id),
                                         step_no=0, decision=decision, agent_step_id=step.id)
            await s.commit()
    finally:
        await engine.dispose()


def _make_scan(client, headers, ws, proj, tgt) -> str:
    r = client.post(
        f"/api/v1/workspaces/{ws}/projects/{proj}/scans", headers=headers,
        json={"target_id": tgt, "scan_type": "network", "requested_modules": ["httpx"]},
    )
    assert r.status_code in (201, 202), r.text
    return r.json()["id"]


def test_timeline_and_decisions_endpoints(client, no_celery_dispatch):
    owner = _register(client, "ObsOwner")
    headers = _auth(owner)
    ws, proj, tgt = _make_target(client, headers)
    _verify_target(client, headers, ws, proj, tgt)
    scan_id = _make_scan(client, headers, ws, proj, tgt)
    asyncio.run(_seed_events(ws, scan_id))

    tl_url = f"/api/v1/workspaces/{ws}/projects/{proj}/scans/{scan_id}/timeline"
    ad_url = f"/api/v1/workspaces/{ws}/projects/{proj}/scans/{scan_id}/agent-decisions"

    # --- timeline: authorized, has events, pagination headers ---
    r = client.get(tl_url, headers=headers)
    assert r.status_code == 200, r.text
    events = r.json()
    kinds = {e["event"] for e in events}
    assert "tool.executed" in kinds and "agent.tool_run" in kinds
    assert r.headers.get("X-Total-Count") is not None and r.headers.get("X-Has-More") is not None

    # pagination: limit=1 returns one event, headers reflect total>1
    r1 = client.get(tl_url + "?limit=1&offset=0", headers=headers)
    assert r1.status_code == 200 and len(r1.json()) == 1
    assert int(r1.headers["X-Total-Count"]) >= 2 and r1.headers["X-Has-More"] == "true"

    # --- agent-decisions: authorized, curated fields only, NO sensitive-blob leakage ---
    r = client.get(ad_url, headers=headers)
    assert r.status_code == 200, r.text
    decs = r.json()
    assert decs and decs[0]["action"] == "run_tool" and decs[0]["selected_tool"] == "httpx"
    assert decs[0]["rationale"] == "probe the web surface"     # reasoning summary exposed
    allowed = {"step_no", "phase", "action", "selected_tool", "selected_confidence", "rationale", "stop_reason", "created_at"}
    assert set(decs[0].keys()) == allowed                       # exactly the curated set
    blob = client.get(ad_url, headers=headers).text
    assert "SECRET-LOOKING" not in blob                         # observations/candidates never surfaced
    assert "candidates" not in decs[0] and "observations" not in decs[0]

    # --- cross-tenant isolation: another user cannot read either endpoint ---
    other = _auth(_register(client, "ObsIntruder"))
    assert client.get(tl_url, headers=other).status_code in (403, 404)
    assert client.get(ad_url, headers=other).status_code in (403, 404)

    # --- unauthenticated ---
    assert client.get(tl_url).status_code in (401, 403)
    assert client.get(ad_url).status_code in (401, 403)
