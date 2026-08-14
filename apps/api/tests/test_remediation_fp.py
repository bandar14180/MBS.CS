from apps.api.ai_agent.fp_reducer import FPReducer
from apps.api.ai_agent.remediation_writer import RemediationWriter


class FakeClient:
    def __init__(self, response: dict):
        self._response = response

    def complete_json(self, system: str, user: str) -> dict:
        self._last_user = user
        return self._response

    @property
    def model_version(self) -> str:
        return "test-model"


# --- Remediation writer (structure enforcement + grounding) ---

def test_remediation_structures_output() -> None:
    client = FakeClient(
        {
            "summary": "Add the missing security headers.",
            "steps": ["Set Strict-Transport-Security", "", "Set X-Frame-Options"],
            "references": [
                {"title": "OWASP Secure Headers", "url": "https://owasp.org/x"},
                {"title": "no url"},  # dropped (no url)
                "not a dict",  # ignored
            ],
        }
    )
    r = RemediationWriter(client=client).write(
        title="Missing security headers",
        severity="info",
        category="cwe-693",
        matched_at="http://10.0.0.1",
        cvss_score=0.0,
        description="Headers absent",
    )
    assert r.summary == "Add the missing security headers."
    assert r.steps == ["Set Strict-Transport-Security", "Set X-Frame-Options"]  # blank dropped
    assert r.references == [{"title": "OWASP Secure Headers", "url": "https://owasp.org/x"}]
    assert r.model_version == "test-model"
    assert r.prompt_version == "remediation/v2"


def test_remediation_grounds_prompt_in_finding() -> None:
    client = FakeClient({"summary": "s", "steps": [], "references": []})
    RemediationWriter(client=client).write(
        title="SQL Injection", severity="high", category="cwe-89",
        matched_at="http://app/login", cvss_score=8.1, description="param id",
    )
    # the finding's specifics reach the model
    assert "SQL Injection" in client._last_user
    assert "cwe-89" in client._last_user
    assert "http://app/login" in client._last_user


# --- FP reducer (suggestions only, constrained to input ids) ---

def test_fp_assessment_per_input_finding() -> None:
    client = FakeClient(
        {
            "assessments": [
                {"id": "1", "likely_false_positive": True, "confidence": "high", "reasoning": "info only"},
                {"id": "2", "likely_false_positive": False, "confidence": "medium", "reasoning": "real"},
            ]
        }
    )
    result = FPReducer(client=client).assess([{"id": "1"}, {"id": "2"}, {"id": "3"}])
    by_id = {a.finding_id: a for a in result.assessments}
    assert set(by_id) == {"1", "2", "3"}  # id 3 (unassessed) filled in
    assert by_id["1"].likely_false_positive is True and by_id["1"].confidence == "high"
    assert by_id["3"].likely_false_positive is False and by_id["3"].reasoning == "not assessed"


def test_fp_drops_unknown_ids_and_bad_confidence() -> None:
    client = FakeClient(
        {
            "assessments": [
                {"id": "99", "likely_false_positive": True, "confidence": "high", "reasoning": "x"},  # unknown
                {"id": "1", "likely_false_positive": True, "confidence": "wat", "reasoning": "y"},  # bad conf
            ]
        }
    )
    result = FPReducer(client=client).assess([{"id": "1"}])
    assert [a.finding_id for a in result.assessments] == ["1"]  # 99 dropped
    assert result.assessments[0].confidence == "low"  # invalid confidence normalized


def test_fp_empty_input() -> None:
    result = FPReducer(client=FakeClient({})).assess([])
    assert result.assessments == []
