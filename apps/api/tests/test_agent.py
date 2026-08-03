"""RedTeamAgent decision-layer tests (M2). Pure -- no DB/network. The agent may
only ever choose a tool the code already vetted (the 'never freelances' guarantee)."""
from apps.api.ai_agent.agent import RedTeamAgent
from apps.api.scanner_engine.safety import RulesOfEngagement, SafetyTier


class _Fake:
    def __init__(self, resp):
        self._resp = resp

    def complete_json(self, system, user):
        return self._resp

    @property
    def model_version(self):
        return "test-model"


def _roe(**kw):
    return RulesOfEngagement(**kw)


# --- available_tools: the allowlist ---

def test_available_tools_gates_active_testing_and_target_type():
    a = RedTeamAgent(client=_Fake({}))
    # domain, active testing NOT allowed -> nuclei (requires active) excluded
    tools = a.available_tools(target_type="domain", active_testing_allowed=False, roe=_roe(), already_run=set())
    assert "subfinder" in tools and "nuclei" not in tools
    # ip_range, active allowed -> subfinder (domain-only) excluded, nuclei included
    tools2 = a.available_tools(target_type="ip_range", active_testing_allowed=True, roe=_roe(), already_run=set())
    assert "subfinder" not in tools2 and "nuclei" in tools2


def test_available_tools_excludes_already_run():
    a = RedTeamAgent(client=_Fake({}))
    tools = a.available_tools(
        target_type="domain", active_testing_allowed=True, roe=_roe(), already_run={"subfinder", "httpx"}
    )
    assert "subfinder" not in tools and "httpx" not in tools


def test_available_tools_respects_safety_ceiling():
    a = RedTeamAgent(client=_Fake({}))
    tools = a.available_tools(
        target_type="domain", active_testing_allowed=True, roe=_roe(max_tier=SafetyTier.PASSIVE), already_run=set()
    )
    assert tools == ["subfinder"]  # only the passive tool is within a passive ceiling


# --- decide: allowlist-enforced ---

def _decide(agent, available):
    return agent.decide(
        target_type="domain", target_value="x", current_phase="reconnaissance",
        findings_summary="", tools_run_summary="", available=available,
    )


def test_decide_picks_available_tool():
    a = RedTeamAgent(client=_Fake({"action": "run_tool", "tool": "nmap", "phase": "reconnaissance", "rationale": "ports"}))
    d = _decide(a, ["nmap", "httpx"])
    assert d.action == "run_tool" and d.tool == "nmap"


def test_decide_rejects_tool_outside_allowlist():
    # model tries to run a tool that isn't available -> finish (never freelances)
    a = RedTeamAgent(client=_Fake({"action": "run_tool", "tool": "metasploit", "rationale": "pwn"}))
    d = _decide(a, ["nmap"])
    assert d.action == "finish" and d.tool is None


def test_decide_finishes_when_no_tools_available():
    a = RedTeamAgent(client=_Fake({"action": "run_tool", "tool": "nmap"}))
    d = _decide(a, [])
    assert d.action == "finish"


def test_decide_ai_failure_is_fail_soft():
    class _Boom:
        def complete_json(self, s, u):
            raise RuntimeError("provider down")

        @property
        def model_version(self):
            return "m"

    d = _decide(RedTeamAgent(client=_Boom()), ["nmap"])
    assert d.action == "finish" and "ai_unavailable" in d.rationale
