"""M4.3.5 -- end-to-end integration test of the REAL autonomous reasoning loop.

Unlike the pure unit tests (test_agent / test_attack_graph / test_state_projection),
this exercises the actual `orchestrator._run_agent_driven` composition against a real
Postgres (RLS enabled) with the real state-projection, attack-graph, ATT&CK-mapping,
vulnerability-ingestion and tool-execution code paths.

What is REAL here:
  * `_run_agent_driven` itself (not reimplemented), the real `RedTeamAgent`, the real
    allowlist (`available_tools`), M4.2 candidate ranking/selection, the safety gate,
    `_run_single_tool`, evidence + vulnerability ingestion, ATT&CK mapping, the
    kill-chain projection, and the incremental attack-graph rebuild + persistence.
  * Real DB rows + RLS (the workspace GUC is set; RLS is NEVER disabled).

What is MOCKED (only the external, nondeterministic boundaries):
  * The AI provider -- a deterministic *reactive* fake `SupportsComplete` that decides
    from the actual prompt it is handed (proving state evolution drives decisions, not
    a static script).
  * The two selected tools' `run()` -- returns canned stdout so the REAL parsers,
    ingestion, mapping and graph code run on deterministic input (no live nmap/nuclei).

The fake proposes an UNREGISTERED tool (metasploit) with the highest confidence on the
first turn: it must be dropped by the allowlist and the registered `httpx` selected --
proving the AI cannot execute outside the registry.
"""
import asyncio
import uuid
from types import SimpleNamespace

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core.config import get_settings
from apps.api.modules.agent.models import AgentDecision, AgentStep, EngagementState
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.users.models import User
from apps.api.modules.scans.models import Scan
from apps.api.modules.vulnerabilities.models import Vulnerability
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.models import ToolRun
from apps.api.scanner_engine.tool_runners.base import RawToolOutput
from apps.api.scanner_engine.tool_runners.httpx_runner import HttpxRunner
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner

TARGET_IP = "203.0.113.10"  # TEST-NET-3 (public, documentation range) -- never dialed (run() mocked)
WEB_URL = f"http://{TARGET_IP}"


# --- the deterministic REACTIVE fake AI provider -----------------------------------

class ScriptedClient:
    """A deterministic SupportsComplete whose decision is a function of the prompt it
    receives -- so a different decision on turn 2 PROVES the loop fed it updated state,
    rather than replaying a fixed sequence."""

    def __init__(self):
        self.calls: list[str] = []  # the user prompt handed to each decision

    @property
    def model_version(self) -> str:
        return "scripted-fake/v1"

    def complete_json(self, system: str, user: str) -> dict:
        self.calls.append(user)
        ran_httpx = "httpx ->" in user  # prior-outcome text from summarize_actions
        ran_nuclei = "nuclei ->" in user
        if ran_nuclei:
            # State shows detection is done -> legitimate stop (empty candidates).
            return {
                "observations": ["a web finding was detected and mapped"],
                "candidate_actions": [],
                "stop_reason": "attack surface sufficiently assessed",
            }
        if ran_httpx:
            # Turn 2: state changed (httpx ran, a service is in the graph). Rank a
            # weak and a strong candidate -> the strong (nuclei) must be selected.
            return {
                "observations": ["an http service is exposed"],
                "inferences": ["the web service may carry detectable weaknesses"],
                "kill_chain_phase": "delivery",
                "candidate_actions": [
                    {"tool": "naabu", "confidence": 0.4, "expected_value": "low", "risk": "low", "rationale": "more ports"},
                    {"tool": "nuclei", "confidence": 0.9, "expected_value": "high", "risk": "medium", "rationale": "probe the web service"},
                ],
            }
        # Turn 1: propose an UNREGISTERED high-confidence tool (must be rejected) plus
        # the registered httpx -> httpx must be what actually runs.
        return {
            "observations": ["target is an ip range"],
            "inferences": ["a web service may be exposed"],
            "hypotheses": ["a login surface may exist"],
            "kill_chain_phase": "reconnaissance",
            "candidate_actions": [
                {"tool": "metasploit", "confidence": 0.99, "expected_value": "high", "risk": "high", "rationale": "exploit"},
                {"tool": "httpx", "confidence": 0.7, "expected_value": "medium", "risk": "low", "rationale": "probe http"},
            ],
        }


# --- mocked tool subprocess boundary (real parsers still run on this output) --------

async def _fake_httpx_run(self, target_value, config, prior_findings):
    line = (
        f'{{"url":"{WEB_URL}","host":"{TARGET_IP}","input":"{TARGET_IP}","port":80,'
        f'"scheme":"http","status_code":200,"title":"Example","webserver":"nginx","tech":["Nginx"]}}'
    )
    return RawToolOutput(command="httpx (mock)", stdout=line + "\n", stderr="", exit_code=0)


async def _fake_nuclei_run(self, target_value, config, prior_findings):
    line = (
        f'{{"template-id":"sqli-detection","matcher-name":"","matched-at":"{WEB_URL}",'
        f'"info":{{"name":"SQL Injection","severity":"high","tags":["sqli"],'
        f'"classification":{{"cwe-id":["CWE-89"]}}}}}}'
    )
    return RawToolOutput(command="nuclei (mock)", stdout=line + "\n", stderr="", exit_code=0)


# --- helpers ------------------------------------------------------------------------

async def _set_guc(session, ws_id):
    await session.execute(
        text("SELECT set_config('app.current_workspace_id', :wid, false)"), {"wid": str(ws_id)}
    )


async def _seed(session):
    """Seed the tenant graph with RLS ENABLED (GUC set; never disabled)."""
    user = User(email=f"agent-{uuid.uuid4()}@test.local", password_hash="x", full_name="Agent Tester")
    session.add(user)
    await session.flush()

    ws = Workspace(name="agent-ws", owner_user_id=user.id)  # workspaces is not RLS-scoped
    session.add(ws)
    await session.flush()

    await _set_guc(session, ws.id)  # RLS active for everything below

    project = Project(workspace_id=ws.id, name="agent-proj", created_by=user.id)
    session.add(project)
    await session.flush()

    target = Target(project_id=project.id, type="ip_range", value=TARGET_IP, criticality="high", added_by=user.id)
    session.add(target)
    await session.flush()

    scan = Scan(
        workspace_id=ws.id, project_id=project.id, target_id=target.id, initiated_by=user.id,
        scan_type="network", status="queued", config={"use_agent": True},
    )
    session.add(scan)
    await session.commit()
    return ws.id, scan.id, target.id


async def _scenario(scripted: ScriptedClient):
    from apps.api.scanner_engine.orchestrator import _run_agent_driven

    settings = get_settings()
    engine = create_async_engine(settings.database_url, poolclass=StaticPool)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_maker() as session:
            ws_id, scan_id, target_id = await _seed(session)
            scan = await session.get(Scan, scan_id)
            target = await session.get(Target, target_id)
            scope = SimpleNamespace(active_testing_allowed=True)  # authorization is tested elsewhere

            statuses = await _run_agent_driven(session, scan, target, scope)

        # Re-open a SEPARATE session to prove the graph was PERSISTED to the DB,
        # not merely held on the in-memory state object.
        async with session_maker() as verify:
            await _set_guc(verify, ws_id)
            state = await verify.scalar(select(EngagementState).where(EngagementState.scan_id == scan_id))
            tool_runs = list(await verify.scalars(select(ToolRun).where(ToolRun.scan_id == scan_id)))
            steps = list(await verify.scalars(select(AgentStep).where(AgentStep.scan_id == scan_id)))
            vulns = list(await verify.scalars(select(Vulnerability).where(Vulnerability.last_seen_scan_id == scan_id)))
            decisions = list(await verify.scalars(
                select(AgentDecision).where(AgentDecision.scan_id == scan_id).order_by(AgentDecision.step_no)
            ))
    finally:
        await engine.dispose()

    return {
        "statuses": statuses,
        "prompts": scripted.calls,
        "engagement": state,
        "graph": state.attack_graph if state else None,
        "tool_runs": tool_runs,
        "steps": steps,
        "vulns": vulns,
        "decisions": decisions,
    }


# --- the test -----------------------------------------------------------------------

class _AlwaysHttpx:
    """Always proposes a valid available tool -- so ONLY a deterministic budget can
    stop the loop (used to prove the budget halts before the step ceiling)."""

    def __init__(self):
        self.calls: list[str] = []

    @property
    def model_version(self) -> str:
        return "always/v1"

    def complete_json(self, system, user):
        self.calls.append(user)
        return {"candidate_actions": [
            {"tool": "httpx", "confidence": 0.9, "expected_value": "high", "risk": "low", "rationale": "probe"}
        ]}


async def _budget_scenario(client):
    from apps.api.scanner_engine.orchestrator import _run_agent_driven

    settings = get_settings()
    engine = create_async_engine(settings.database_url, poolclass=StaticPool)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as s:
            ws_id, scan_id, target_id = await _seed(s)
            scan = await s.get(Scan, scan_id)
            target = await s.get(Target, target_id)
            await _run_agent_driven(s, scan, target, SimpleNamespace(active_testing_allowed=True))
        async with maker() as v:
            await _set_guc(v, ws_id)
            decisions = list(await v.scalars(
                select(AgentDecision).where(AgentDecision.scan_id == scan_id).order_by(AgentDecision.step_no)
            ))
            tool_runs = list(await v.scalars(select(ToolRun).where(ToolRun.scan_id == scan_id)))
            state = await v.scalar(select(EngagementState).where(EngagementState.scan_id == scan_id))
        return client.calls, decisions, tool_runs, state
    finally:
        await engine.dispose()


def test_agent_ai_call_budget_stops_before_ceiling(monkeypatch):
    # M4.4.3: a budget stops the loop EARLY (and before spending another AI call),
    # never approaching agent_max_steps -- the hard ceiling is untouched.
    settings = get_settings()
    monkeypatch.setattr(settings, "agent_max_ai_calls", 1)
    client = _AlwaysHttpx()
    monkeypatch.setattr("apps.api.ai_agent.agent.get_ai_client", lambda model=None: client)
    monkeypatch.setattr(HttpxRunner, "run", _fake_httpx_run)

    calls, decisions, tool_runs, state = asyncio.run(_budget_scenario(client))

    assert len(calls) == 1                 # exactly one AI call, then the budget stopped it
    assert len(tool_runs) == 1             # only the first tool ran
    assert decisions[-1].action == "finish"
    assert decisions[-1].stop_reason == "ai_call_budget_exhausted"
    assert decisions[-1].budget_state["ai_calls"] == 1
    assert decisions[-1].budget_state["max_steps"] == settings.agent_max_steps
    assert decisions[-1].budget_state["step_no"] < settings.agent_max_steps  # nowhere near the ceiling
    assert state.status == "completed"


def test_run_agent_driven_end_to_end(monkeypatch):
    scripted = ScriptedClient()
    # Inject the fake AI client into the REAL RedTeamAgent (constructed inside the loop).
    monkeypatch.setattr("apps.api.ai_agent.agent.get_ai_client", lambda model=None: scripted)
    # Mock only the tool subprocess boundary; parsers/ingestion/graph stay real.
    monkeypatch.setattr(HttpxRunner, "run", _fake_httpx_run)
    monkeypatch.setattr(NucleiRunner, "run", _fake_nuclei_run)

    r = asyncio.run(_scenario(scripted))

    prompts = r["prompts"]

    # (1) The real loop invoked the AI decision path -- once per cycle, three cycles.
    assert len(prompts) == 3, f"expected 3 AI decisions, got {len(prompts)}"

    # First decision saw an EMPTY security state (no evidence yet).
    first = prompts[0]
    assert "(none yet)" in first          # prior action outcomes empty
    assert "(no techniques mapped yet)" in first  # no ATT&CK yet
    # AI-1: untrusted evidence summaries are now wrapped in <<UNTRUSTED:...>> delimiters, so the
    # empty-state graph placeholder appears delimited. Assert the empty-state marker still shows.
    assert "(empty)" in first and "<<UNTRUSTED:graph>>" in first

    # (3) The unregistered high-confidence tool was NOT executed; (4) the registered
    # httpx went through the real execution path instead.
    ran = {tr.tool_name for tr in r["tool_runs"]}
    assert ran == {"httpx", "nuclei"}, f"unexpected tools executed: {ran}"
    assert "metasploit" not in ran        # allowlist rejected the invented tool
    assert "naabu" not in ran             # (2) lower-confidence candidate not selected

    # (5) Tool output became real evidence/state: a vulnerability was ingested.
    assert len(r["vulns"]) == 1 and r["vulns"][0].category == "CWE-89"
    assert all(tr.status == "completed" for tr in r["tool_runs"])
    assert r["statuses"] == ["completed", "completed"]

    # (9)/(13) The SECOND decision saw UPDATED state (httpx ran; a service is in the
    # graph) -- proving state evolution, not a static script.
    second = prompts[1]
    assert "httpx -> completed" in second
    assert "1 service" in second and TARGET_IP in second   # graph rebuilt & summarized into the prompt
    assert "nuclei ->" not in second                       # nuclei hasn't run yet at turn 2
    # (M4.4.2) The objective and the PRIOR cycle's persisted beliefs are carried
    # forward from the agent_decisions table into the next prompt; the turn-1
    # hypothesis is present and still marked UNVERIFIED (never promoted to fact).
    assert "Objective:" in second and "red-team assessment" in second
    assert "a login surface may exist" in second and "UNVERIFIED" in second

    # (6)/(8) The THIRD decision saw ATT&CK + kill-chain + the finding path (state
    # changed again after nuclei) -- the graph summary reached the next AI decision.
    third = prompts[2]
    assert "nuclei -> completed" in third                  # prior outcome evolved again
    assert "T1190" in third                                # MITRE technique reached reasoning
    assert "Exploitation" in third                         # kill-chain phase in context
    assert f"{WEB_URL} -> SQL Injection -> T1190" in third  # asset->finding->technique path

    # (2) M4.2 ranked selection actually flowed through: the nuclei step's audit row
    # records the ranked candidate set (nuclei chosen over naabu by confidence).
    tool_steps = [s for s in r["steps"] if s.action_type == "tool_run" and s.tool_or_module == "nuclei"]
    assert tool_steps, "no audit step recorded for the nuclei tool run"
    assert "nuclei@0.90" in tool_steps[0].rationale and "naabu@0.40" in tool_steps[0].rationale

    # (7)/(14) The attack graph was rebuilt and PERSISTED (read from a separate session).
    graph = r["graph"]
    assert graph and graph.get("nodes"), "attack graph was not persisted to EngagementState"
    node_types = {n["type"] for n in graph["nodes"]}
    assert {"asset", "service", "finding", "technique"} <= node_types
    assert any(e["rel"] == "maps_to" and e["target"] == "technique:T1190" for e in graph["edges"])
    # provenance is preserved on persisted nodes
    svc = next(n for n in graph["nodes"] if n["type"] == "service")
    assert svc["provenance"]["tool"] == "httpx" and svc["provenance"]["confidence"] == 0.9

    # (M4.4.1) Each reasoning cycle persisted ONE structured agent_decisions row,
    # correlated to its AgentStep, with the evidence tiers kept distinct.
    decisions = r["decisions"]
    assert len(decisions) == 3  # httpx, nuclei, finish
    step_ids = {s.id for s in r["steps"]}
    assert all(d.agent_step_id in step_ids for d in decisions)  # hard-linked to the audit
    d0 = decisions[0]
    assert d0.action == "run_tool" and d0.selected_tool == "httpx"
    assert d0.observations and d0.inferences and d0.hypotheses  # tiers persisted separately
    # Persisted candidates are the ALLOWLIST-VETTED set: the invented metasploit was
    # dropped before selection and never becomes a stored candidate.
    assert not any(c["tool"] == "metasploit" for c in d0.candidates)
    # The ranked set of registered candidates IS kept (turn 2: nuclei chosen over naabu).
    d1 = decisions[1]
    assert {c["tool"] for c in d1.candidates} == {"nuclei", "naabu"} and d1.selected_tool == "nuclei"
    assert decisions[-1].action == "finish" and decisions[-1].stop_reason

    # (10) Termination was a LEGITIMATE stop (explicit finish), not the step ceiling.
    assert r["engagement"].status == "completed"
    decision_steps = [s for s in r["steps"] if s.action_type == "decision"]
    assert len(decision_steps) == 1
    assert "attack surface sufficiently assessed" in decision_steps[0].rationale
    assert len(prompts) < get_settings().agent_max_steps  # did not spin to the cap
