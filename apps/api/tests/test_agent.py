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


# --- decide: the enriched reasoning context reaches the prompt (M4.1) ---

class _Capture:
    """A fake client that records the user prompt it was handed."""

    def __init__(self, resp):
        self._resp = resp
        self.last_user = None

    def complete_json(self, system, user):
        self.last_user = user
        return self._resp

    @property
    def model_version(self):
        return "test-model"


def test_decide_prompt_includes_attack_and_action_context():
    client = _Capture({"action": "run_tool", "tool": "nmap", "phase": "reconnaissance", "rationale": "x"})
    RedTeamAgent(client=client).decide(
        target_type="domain",
        target_value="x",
        current_phase="reconnaissance",
        findings_summary="1 http_service(s)",
        available=["nmap"],
        attack_summary="Reconnaissance: T1595 Active Scanning",
        actions_summary="httpx -> completed (3 finding(s)); nuclei -> failed (exit 1)",
    )
    # ATT&CK/kill-chain coverage and prior outcomes are both in the model's context,
    # so they are reasoning inputs, not just report material.
    assert "T1595 Active Scanning" in client.last_user
    assert "nuclei -> failed (exit 1)" in client.last_user


def test_decide_prompt_includes_objective_and_prior_beliefs():
    # M4.4.2: the engagement objective and prior-cycle beliefs reach the reasoning
    # context, with hypotheses explicitly marked unverified.
    client = _Capture({"action": "run_tool", "tool": "nmap", "phase": "reconnaissance", "rationale": "x"})
    RedTeamAgent(client=client).decide(
        target_type="ip_range",
        target_value="10.0.0.1",
        current_phase="reconnaissance",
        findings_summary="",
        available=["nmap"],
        objective="Assess the exposed web surface",
        prior_beliefs="observed: port 80 | hypotheses (UNVERIFIED): login may exist",
    )
    assert "Assess the exposed web surface" in client.last_user
    assert "hypotheses (UNVERIFIED): login may exist" in client.last_user


def test_decide_prompt_includes_graph_summary():
    # M4.3: the attack-graph summary must reach the model's reasoning context.
    client = _Capture({"action": "run_tool", "tool": "nmap", "phase": "reconnaissance", "rationale": "x"})
    RedTeamAgent(client=client).decide(
        target_type="ip_range",
        target_value="10.0.0.1",
        current_phase="reconnaissance",
        findings_summary="1 service(s)",
        available=["nmap"],
        graph_summary="Graph: 1 asset, 1 service. Paths: 10.0.0.1:3000 -> Missing headers -> T1595.",
    )
    assert "10.0.0.1:3000 -> Missing headers -> T1595" in client.last_user


def test_decide_falls_back_to_tools_run_summary():
    # Back-compat: callers passing only the legacy tools_run_summary still work.
    client = _Capture({"action": "finish"})
    RedTeamAgent(client=client).decide(
        target_type="domain",
        target_value="x",
        current_phase="reconnaissance",
        findings_summary="",
        available=["nmap"],
        tools_run_summary="httpx, naabu",
    )
    assert "httpx, naabu" in client.last_user


# --- decide: ranked candidate_actions (M4.2) ---

def _cand(tool, conf, value="medium", risk="low"):
    return {"tool": tool, "confidence": conf, "expected_value": value, "risk": risk, "rationale": f"try {tool}"}


def test_decide_selects_highest_confidence_candidate():
    a = RedTeamAgent(client=_Fake({"candidate_actions": [_cand("httpx", 0.4), _cand("nmap", 0.9)]}))
    d = _decide(a, ["nmap", "httpx"])
    assert d.action == "run_tool" and d.tool == "nmap"
    assert d.confidence == 0.9
    # The ranked set is preserved best-first for the audit trail.
    assert [c.tool for c in d.candidates] == ["nmap", "httpx"]


def test_decide_tie_breaks_on_expected_value():
    a = RedTeamAgent(client=_Fake(
        {"candidate_actions": [_cand("httpx", 0.7, value="low"), _cand("nmap", 0.7, value="high")]}
    ))
    d = _decide(a, ["nmap", "httpx"])
    assert d.tool == "nmap"  # equal confidence -> higher expected_value wins


def test_decide_drops_candidates_outside_allowlist():
    # Highest-confidence candidate isn't available -> the next allowed one is chosen.
    a = RedTeamAgent(client=_Fake(
        {"candidate_actions": [_cand("metasploit", 0.99), _cand("nmap", 0.5)]}
    ))
    d = _decide(a, ["nmap"])
    assert d.action == "run_tool" and d.tool == "nmap"
    assert all(c.tool != "metasploit" for c in d.candidates)


def test_decide_finishes_when_all_candidates_outside_allowlist():
    a = RedTeamAgent(client=_Fake({"candidate_actions": [_cand("metasploit", 0.99), _cand("sqlmap", 0.8)]}))
    d = _decide(a, ["nmap"])
    assert d.action == "finish" and d.tool is None


def test_decide_finishes_on_empty_candidates_with_stop_reason():
    a = RedTeamAgent(client=_Fake({"candidate_actions": [], "stop_reason": "attack surface assessed"}))
    d = _decide(a, ["nmap"])
    assert d.action == "finish" and d.stop_reason == "attack surface assessed"


def test_decide_parses_evidence_tiers():
    a = RedTeamAgent(client=_Fake({
        "observations": ["port 3000 open"],
        "inferences": ["web app exposed"],
        "hypotheses": ["default creds may exist"],
        "candidate_actions": [_cand("nmap", 0.6)],
    }))
    d = _decide(a, ["nmap"])
    assert d.observations == ["port 3000 open"]
    assert d.inferences == ["web app exposed"]
    assert d.hypotheses == ["default creds may exist"]


def test_decide_clamps_confidence():
    a = RedTeamAgent(client=_Fake({"candidate_actions": [_cand("nmap", 5)]}))  # out-of-range
    d = _decide(a, ["nmap"])
    assert d.confidence == 1.0


def test_decide_risk_demotes_higher_risk_at_equal_confidence():
    # M4.4.3: equal confidence + equal expected_value -> lower risk wins (risk matters).
    a = RedTeamAgent(client=_Fake(
        {"candidate_actions": [_cand("nuclei", 0.8, risk="high"), _cand("nmap", 0.8, risk="low")]}
    ))
    d = _decide(a, ["nmap", "nuclei"])
    assert d.tool == "nmap"


def test_decide_min_confidence_floor_drops_all_and_finishes():
    a = RedTeamAgent(client=_Fake({"candidate_actions": [_cand("nmap", 0.3), _cand("httpx", 0.2)]}))
    d = a.decide(
        target_type="domain", target_value="x", current_phase="reconnaissance",
        findings_summary="", available=["nmap", "httpx"], min_confidence=0.5,
    )
    assert d.action == "finish" and d.stop_reason == "below_confidence_floor"


def test_decide_min_confidence_floor_keeps_above_floor():
    a = RedTeamAgent(client=_Fake({"candidate_actions": [_cand("nmap", 0.3), _cand("httpx", 0.8)]}))
    d = a.decide(
        target_type="domain", target_value="x", current_phase="reconnaissance",
        findings_summary="", available=["nmap", "httpx"], min_confidence=0.5,
    )
    assert d.action == "run_tool" and d.tool == "httpx"


def test_decision_summary_captures_reasoning():
    a = RedTeamAgent(client=_Fake({
        "observations": ["ssh on 22"],
        "candidate_actions": [_cand("nmap", 0.8), _cand("httpx", 0.6)],
    }))
    d = _decide(a, ["nmap", "httpx"])
    s = d.summary()
    assert "obs: ssh on 22" in s
    assert "nmap@0.80" in s and "httpx@0.60" in s
    assert "selected: nmap@0.80" in s
