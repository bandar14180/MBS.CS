"""AI-2.4 -- evaluation runner. Executes every suite, aggregates scores, applies thresholds, and
ties each suite to its prompt_version (AI-2.3 registry). run_all() is the CI quality gate."""
from dataclasses import dataclass

from apps.api.ai_agent.eval import evaluators as ev
from apps.api.ai_agent.eval import scenarios as sc
from apps.api.ai_agent.guards import REMEDIATION_FALLBACK_SUMMARY
from apps.api.ai_agent.prompts.registry import PROMPTS


@dataclass
class SuiteReport:
    suite: str
    results: list
    threshold: float
    prompt_version: str | None

    @property
    def score(self) -> float:
        return round(sum(r.score for r in self.results) / len(self.results), 3) if self.results else 1.0

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.results) and self.score >= self.threshold


@dataclass
class EvalReport:
    suites: list

    @property
    def passed(self) -> bool:
        return all(s.passed for s in self.suites)


def _agent_suite() -> SuiteReport:
    results = [ev.score_agent_decision(s["name"], sc.run_agent(s), s["available"], s["expected_tool"])
               for s in sc.AGENT_SCENARIOS]
    return SuiteReport("agent_tool_selection", results, 1.0, PROMPTS["agent"].version)


def _correlator_suite() -> SuiteReport:
    results = []
    for s in sc.CORRELATOR_SCENARIOS:
        input_ids = [f["id"] for f in s["findings"]]
        results.append(ev.score_correlator(s["name"], sc.run_correlator(s), input_ids, s["expected_groups"]))
    return SuiteReport("correlator_quality", results, 1.0, PROMPTS["correlator"].version)


def _remediation_suite() -> SuiteReport:
    g = sc.REMEDIATION_GROUNDED
    b = sc.REMEDIATION_BLOCKED
    results = [
        ev.score_remediation_grounded(g["name"], sc.run_remediation(g["finding"], g["response"]), g["grounding_terms"]),
        ev.score_remediation_blocked(b["name"], sc.run_remediation(b["finding"], b["response"]), REMEDIATION_FALLBACK_SUMMARY),
    ]
    return SuiteReport("remediation_quality", results, 1.0, PROMPTS["remediation"].version)


def _attack_suite() -> SuiteReport:
    results = [
        ev.score_attack_mapping(f"attack::{g['category'] or g['tags']}", sc.attack_predicted(g["category"], g["tags"]), g["expected"])
        for g in sc.ATTACK_GOLDEN
    ]
    return SuiteReport("attack_accuracy", results, 1.0, None)   # deterministic catalog -> no prompt


def _injection_suite() -> SuiteReport:
    return SuiteReport("injection_regression", sc.run_injection(), 1.0, None)


def run_all() -> EvalReport:
    return EvalReport([
        _agent_suite(),
        _correlator_suite(),
        _remediation_suite(),
        _attack_suite(),
        _injection_suite(),
    ])
