"""Unit tests for the MITRE ATT&CK / Cyber Kill Chain mapping + the resilient
tool-run classifier. Pure -- no DB, app, or binaries."""
from types import SimpleNamespace

from apps.api.modules.attack.catalog import KillChainPhase, techniques_for
from apps.api.modules.attack.service import kill_chain_steps
from apps.api.scanner_engine.tool_runners.base import BaseToolRunner, RawToolOutput, classify_run


# --- catalog: category / tag -> technique + kill-chain phase ---

def test_cwe_maps_to_expected_technique() -> None:
    techs = techniques_for("cwe-89", None)  # SQL injection
    ids = {t[1] for t in techs}
    assert "T1190" in ids  # Exploit Public-Facing Application
    assert techs[0][3] == KillChainPhase.EXPLOITATION


def test_tags_map_and_dedupe_against_cwe() -> None:
    # cwe-78 and the "rce" tag both include T1190 + T1059 -> deduped, not doubled.
    techs = techniques_for("cwe-78", ["rce"])
    ids = [t[1] for t in techs]
    assert ids.count("T1190") == 1 and ids.count("T1059") == 1


def test_tags_accept_comma_string_and_list() -> None:
    assert techniques_for(None, "default-login") == techniques_for(None, ["default-login"])
    assert any(t[1] == "T1078" for t in techniques_for(None, "default-login"))  # Valid Accounts


def test_unknown_category_and_tag_map_to_nothing() -> None:
    assert techniques_for("cwe-99999", ["not-a-real-tag"]) == []
    assert techniques_for(None, None) == []


# --- resilient tool-run classifier ---

class _Fake(BaseToolRunner):
    name = "fake"
    version = "0"

    def __init__(self, benign=frozenset(), hard=False):
        self.benign_exit_codes = benign
        self._hard = hard

    async def run(self, target_value, config, prior_findings):  # pragma: no cover - unused
        raise NotImplementedError

    def parse(self, raw):  # pragma: no cover - unused
        return []

    def hard_failure(self, raw) -> bool:
        return self._hard


def _raw(exit_code: int, stdout: str = "") -> RawToolOutput:
    return RawToolOutput(command="x", stdout=stdout, stderr="", exit_code=exit_code)


def test_classify_exit_zero_is_completed() -> None:
    assert classify_run(_Fake(), _raw(0), produced_findings=False) == "completed"


def test_classify_benign_nonzero_is_completed() -> None:
    assert classify_run(_Fake(benign=frozenset({1})), _raw(1), produced_findings=False) == "completed"


def test_classify_nonzero_with_output_is_partial() -> None:
    assert classify_run(_Fake(), _raw(1, stdout='{"x":1}'), produced_findings=True) == "partial"
    # output present even without parsed findings still counts as partial
    assert classify_run(_Fake(), _raw(2, stdout="some text"), produced_findings=False) == "partial"


def test_classify_nonzero_no_output_is_failed() -> None:
    assert classify_run(_Fake(), _raw(1), produced_findings=False) == "failed"


def test_classify_hard_failure_overrides() -> None:
    # hard_failure wins even with a clean exit + output.
    assert classify_run(_Fake(hard=True), _raw(0, stdout="ok"), produced_findings=True) == "failed"


# --- kill-chain assembly (pure) ---

def test_kill_chain_steps_ordered_and_grouped() -> None:
    import uuid

    v1, v2 = uuid.uuid4(), uuid.uuid4()
    mappings = [
        SimpleNamespace(vulnerability_id=v1, kill_chain_phase=KillChainPhase.EXPLOITATION,
                        technique_id="T1190", technique_name="Exploit Public-Facing Application",
                        tactic_id="TA0001", tactic_name="Initial Access"),
        SimpleNamespace(vulnerability_id=v2, kill_chain_phase=KillChainPhase.RECON,
                        technique_id="T1592", technique_name="Gather Victim Host Information",
                        tactic_id="TA0043", tactic_name="Reconnaissance"),
    ]
    steps = kill_chain_steps({v1: "SQLi", v2: "Info leak"}, mappings)
    # Reconnaissance precedes Exploitation in kill-chain order regardless of input order.
    assert [s["phase"] for s in steps] == [KillChainPhase.RECON, KillChainPhase.EXPLOITATION]
    recon = steps[0]["techniques"][0]
    assert recon["technique_id"] == "T1592" and recon["findings"] == ["Info leak"]
