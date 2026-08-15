"""AI-2.4 -- AI quality evaluation gate (folded into the `tests` job).

Runs the offline eval harness and fails if any suite regresses below its threshold. Deterministic
(scripted fakes, no live model calls). Scenarios cover agent tool-selection, correlator quality,
remediation quality, MITRE ATT&CK accuracy, and injection regression.
"""
from apps.api.ai_agent.eval.runner import run_all
from apps.api.ai_agent.prompts.registry import PROMPTS

_REQUIRED_SUITES = {
    "agent_tool_selection",
    "correlator_quality",
    "remediation_quality",
    "attack_accuracy",
    "injection_regression",
}


def test_ai_eval_gate_passes():
    report = run_all()
    for s in report.suites:
        failing = [(r.name, r.score, r.detail) for r in s.results if not r.passed]
        assert s.passed, (
            f"AI-eval suite '{s.suite}' regressed: score={s.score} < threshold={s.threshold}; failing={failing}"
        )
    assert report.passed


def test_ai_eval_covers_required_suites():
    assert _REQUIRED_SUITES <= {s.suite for s in run_all().suites}


def test_ai_eval_ties_prompt_version():
    by = {s.suite: s.prompt_version for s in run_all().suites}
    assert by["agent_tool_selection"] == PROMPTS["agent"].version
    assert by["correlator_quality"] == PROMPTS["correlator"].version
    assert by["remediation_quality"] == PROMPTS["remediation"].version


def test_attack_accuracy_is_exact():
    suite = next(s for s in run_all().suites if s.suite == "attack_accuracy")
    assert suite.score == 1.0 and all(r.passed for r in suite.results)


def test_eval_scores_are_bounded():
    for s in run_all().suites:
        for r in s.results:
            assert 0.0 <= r.score <= 1.0
