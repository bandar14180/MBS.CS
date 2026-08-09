"""Pure unit tests for the agent's state-projection builders (M4.1). No DB/network.

These are what turn accumulated evidence into the compact context the RedTeamAgent
reasons over: findings, live MITRE ATT&CK / kill-chain coverage, and prior action
outcomes (a failed action is evidence -- blueprint §14/§16/§17)."""
from dataclasses import dataclass

from apps.api.scanner_engine.state_projection import (
    ActionOutcome,
    summarize_actions,
    summarize_attack_context,
    summarize_findings,
    summarize_prior_beliefs,
)


@dataclass
class _F:
    asset_type: str
    value: str


# --- summarize_findings ---

def test_summarize_findings_empty():
    assert summarize_findings([]) == "(none yet)"


def test_summarize_findings_counts_and_examples():
    out = summarize_findings([_F("http_service", "http://x:80"), _F("http_service", "http://x:443"), _F("port", "22")])
    assert "2 http_service(s)" in out and "1 port(s)" in out
    assert "http_service:http://x:80" in out


def test_summarize_findings_caps_examples():
    findings = [_F("port", str(p)) for p in range(20)]
    out = summarize_findings(findings, max_examples=3)
    assert out.count("port:") == 3  # only the first N shown, count still reflects all
    assert "20 port(s)" in out


# --- summarize_attack_context ---

def test_summarize_attack_context_empty():
    assert summarize_attack_context([]) == "(no techniques mapped yet)"


def test_summarize_attack_context_lists_phases_and_techniques():
    steps = [
        {
            "phase": "reconnaissance",
            "phase_name": "Reconnaissance",
            "techniques": [{"technique_id": "T1595", "technique_name": "Active Scanning"}],
        },
        {
            "phase": "exploitation",
            "phase_name": "Exploitation",
            "techniques": [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"}],
        },
    ]
    out = summarize_attack_context(steps)
    assert "Reconnaissance: T1595 Active Scanning" in out
    assert "Exploitation: T1190 Exploit Public-Facing Application" in out
    assert " | " in out  # phases separated


def test_summarize_attack_context_phase_without_techniques():
    out = summarize_attack_context([{"phase": "delivery", "phase_name": "Delivery", "techniques": []}])
    assert out == "Delivery"


# --- summarize_actions ---

def test_summarize_actions_empty():
    assert summarize_actions([]) == "(none yet)"


def test_summarize_actions_surfaces_failures_and_blocks():
    outcomes = [
        ActionOutcome("httpx", "completed", "3 finding(s)"),
        ActionOutcome("nuclei", "failed", "exit 1"),
        ActionOutcome("some_intrusive", "blocked", "safety_tier exceeds ceiling"),
    ]
    out = summarize_actions(outcomes)
    assert "httpx -> completed (3 finding(s))" in out
    assert "nuclei -> failed (exit 1)" in out
    assert "some_intrusive -> blocked (safety_tier exceeds ceiling)" in out


def test_summarize_actions_keeps_only_most_recent():
    outcomes = [ActionOutcome(f"t{i}", "completed") for i in range(20)]
    out = summarize_actions(outcomes, max_items=5)
    assert "t19 -> completed" in out and "t15 -> completed" in out
    assert "t14 -> completed" not in out


# --- summarize_prior_beliefs (M4.4.2 belief carry-forward) ---

def test_summarize_prior_beliefs_empty():
    assert summarize_prior_beliefs([], [], []) == "(none yet)"
    assert summarize_prior_beliefs(None, None, None) == "(none yet)"


def test_summarize_prior_beliefs_keeps_tiers_distinct_and_marks_hypotheses():
    out = summarize_prior_beliefs(["ssh open"], ["remote surface"], ["creds may exist"])
    assert "observed: ssh open" in out
    assert "inferred: remote surface" in out
    # A hypothesis is explicitly marked UNVERIFIED so it is never read as a fact.
    assert "hypotheses (UNVERIFIED): creds may exist" in out
    # The three tiers stay separated.
    assert out.index("observed:") < out.index("inferred:") < out.index("hypotheses")


def test_summarize_prior_beliefs_is_bounded():
    obs = [f"o{i}" for i in range(10)]
    out = summarize_prior_beliefs(obs, [], [], max_each=3)
    assert "o0" in out and "o2" in out and "o3" not in out
