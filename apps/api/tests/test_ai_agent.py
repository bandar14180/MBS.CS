import asyncio
import uuid

from apps.api.ai_agent.claude_client import _extract_json
from apps.api.ai_agent.correlator import AICorrelator
from apps.api.ai_agent.planner import AIPlanner, _sanitize


class FakeClient:
    """Stands in for ClaudeClient — returns canned JSON, records the last call.
    This is what makes the AI agents testable without an API key."""

    def __init__(self, response: dict):
        self._response = response
        self.calls: list[tuple[str, str]] = []

    def complete_json(self, system: str, user: str) -> dict:
        self.calls.append((system, user))
        return self._response

    @property
    def model_version(self) -> str:
        return "test-model"


class RaisingClient(FakeClient):
    def complete_json(self, system: str, user: str) -> dict:
        raise AssertionError("client should not be called")


class FakeDB:
    def __init__(self):
        self.added: list = []

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        pass

    async def scalar(self, *args, **kwargs):
        # F3.1: the planner now checks for an existing AIPlan first; a fresh scan has none,
        # so this stub returns None -> the first-run path (LLM called, plan persisted).
        return None


# --- ClaudeClient JSON extraction (pure) ---

def test_extract_json_plain() -> None:
    assert _extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_fenced() -> None:
    assert _extract_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_extract_json_embedded_in_prose() -> None:
    assert _extract_json('Here is the plan: {"a": 1} hope that helps') == {"a": 1}


# --- Planner allowlist enforcement (pure; the 'AI never freelances' guarantee) ---

def test_sanitize_drops_unknown_tools() -> None:
    # "sqlmap" and "bogus" aren't registered; only requested+registered survive
    out = _sanitize(["bogus", "httpx", "sqlmap", "naabu"], ["httpx", "naabu"], True, "domain")
    assert out == ["httpx", "naabu"]


def test_sanitize_drops_active_tool_when_not_authorized() -> None:
    out = _sanitize(["nuclei", "httpx"], ["httpx", "nuclei"], False, "domain")
    assert out == ["httpx"]  # nuclei is active-testing; not authorized -> dropped


def test_sanitize_keeps_active_tool_when_authorized() -> None:
    out = _sanitize(["nuclei", "httpx"], ["httpx", "nuclei"], True, "domain")
    assert out == ["nuclei", "httpx"]  # order preserved


def test_sanitize_respects_target_type() -> None:
    # subfinder is domain-only; on an ip_range target it's filtered out
    out = _sanitize(["subfinder", "naabu"], ["subfinder", "naabu"], True, "ip_range")
    assert out == ["naabu"]


def test_sanitize_dedupes() -> None:
    out = _sanitize(["httpx", "httpx", "naabu"], ["httpx", "naabu"], True, "domain")
    assert out == ["httpx", "naabu"]


# --- Planner.plan() full path with a fake client + fake db ---

def test_planner_plan_persists_and_sanitizes() -> None:
    client = FakeClient(
        {"tool_sequence": ["nuclei", "httpx", "bogus"], "reasoning_summary": "recon then vuln scan"}
    )
    planner = AIPlanner(client=client)
    db = FakeDB()

    result = asyncio.run(
        planner.plan(
            db,
            scan_id=uuid.uuid4(),
            target_type="domain",
            target_value="example.test",
            requested_modules=["httpx", "nuclei"],
            active_testing_allowed=True,
        )
    )

    assert result.tool_sequence == ["nuclei", "httpx"]  # bogus dropped
    assert result.reasoning_summary == "recon then vuln scan"
    assert result.model_version == "test-model"
    assert result.prompt_version == "planner/v1"
    # persisted exactly one AIPlan carrying the sanitized sequence
    assert len(db.added) == 1
    assert db.added[0].tool_sequence == ["nuclei", "httpx"]


# --- Correlator grouping (pure) ---

def test_correlator_groups_duplicates() -> None:
    client = FakeClient({"groups": [{"finding_ids": ["1", "2"], "rationale": "same header"},
                                    {"finding_ids": ["3"], "rationale": "distinct"}]})
    findings = [{"id": "1"}, {"id": "2"}, {"id": "3"}]
    result = AICorrelator(client=client).correlate(findings)
    assert [sorted(g.finding_ids) for g in result.groups] == [["1", "2"], ["3"]]


def test_correlator_drops_unknown_ids_and_fills_singletons() -> None:
    # model references a non-input id "99" and forgets "3"
    client = FakeClient({"groups": [{"finding_ids": ["1", "99"], "rationale": "x"}]})
    findings = [{"id": "1"}, {"id": "2"}, {"id": "3"}]
    result = AICorrelator(client=client).correlate(findings)
    all_ids = {i for g in result.groups for i in g.finding_ids}
    assert all_ids == {"1", "2", "3"}  # 99 dropped, 2 and 3 recovered as singletons
    # no id assigned twice
    flat = [i for g in result.groups for i in g.finding_ids]
    assert len(flat) == len(set(flat))


def test_correlator_short_circuits_single_finding() -> None:
    # one finding -> no API call at all
    result = AICorrelator(client=RaisingClient({})).correlate([{"id": "1"}])
    assert len(result.groups) == 1 and result.groups[0].finding_ids == ["1"]
