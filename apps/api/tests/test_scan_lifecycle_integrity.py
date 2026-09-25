"""PROMPT 9 -- Scan Lifecycle Integrity: adversarial regression coverage for the two
lifecycle-aggregation gaps this audit found and fixed in `scanner_worker/executor.py`.

Both gaps are variations on the SAME theme the F2-09 evidence-downgrade rule already
established: a scan's terminal status must never claim more success than what is actually
persisted (or, for the second gap, the executor must treat every control-plane VERDICT --
not just 401/403 -- as a reason to stop, not merely as an "outage" to fail open through.

GAP 1 (Invariant 7/8 -- aggregation must reflect what is actually persisted):
`execute_leased_job` aggregates its returned status from its own in-memory `statuses` list,
which is populated the moment a tool finishes RUNNING -- before that tool's result is ever
submitted to the manager. If the submission is then lost (a manager outage during
`/v1/tool-results`), the corresponding `tool_runs` row is either missing entirely or stuck
`running`, yet the executor still told `/v1/lease/complete` "completed". The fix downgrades
`completed` -> `completed_with_errors` whenever any tool result failed to persist.

GAP 2 (Invariant 6/9 -- a stale execution token must not keep acting): `_assert_execution_
token` (scanner_manager/app.py) answers a superseded execution with HTTP 409
(EXECUTION_SUPERSEDED), which is exactly as authoritative a verdict as a 401/403 -- the
fenced UPDATE behind it can never be won by a stale token. `_is_authoritative_refusal` used
to recognise only 401/403, so a 409 was misclassified as an outage: the executor kept
running further tools against the target on a token it no longer owned (harmless to
persisted state, since every subsequent write keeps losing the same fenced race, but not to
resource usage or target load). The fix adds 409 to the recognised verdict codes.
"""
import asyncio

from apps.api.scanner_engine.tool_runners.base import RawToolOutput
from apps.api.scanner_worker import executor as executor_mod
from apps.api.scanner_worker.lease_loop import REASON_AUTH_FAILED, LeaseError


def _job(config: dict | None = None, modules=("nuclei",)) -> dict:
    return {
        "scan_id": "11111111-1111-1111-1111-111111111111",
        "execution_token": "22222222-2222-2222-2222-222222222222",
        "target": {"id": "t", "type": "domain", "value": "t.example.com"},
        "requested_modules": list(modules),
        "config": config or {},
    }


def _runner(name, phase, result: RawToolOutput, findings=None):
    class _StubRunner:
        pass

    _StubRunner.name = name
    _StubRunner.phase = phase
    _StubRunner.applicable_target_types = None
    _StubRunner.benign_exit_codes = ()

    async def run(self, target_value, config, prior):
        return result

    def parse(self, raw):
        return list(findings or [])

    def hard_failure_fn(self, raw):
        return False

    _StubRunner.run = run
    _StubRunner.parse = parse
    _StubRunner.hard_failure = hard_failure_fn
    return _StubRunner


class _HTTPStatusErrorLike(Exception):
    """Minimal stand-in for httpx.HTTPStatusError -- carries a `.response.status_code`
    without requiring a live httpx.Response, matching how `_is_authoritative_refusal`
    reads the attribute (`getattr(exc, "response", None)`)."""

    class _Resp:
        def __init__(self, code):
            self.status_code = code

    def __init__(self, status_code: int):
        super().__init__(f"HTTP {status_code}")
        self.response = self._Resp(status_code)


# -----------------------------------------------------------------------------------------
# GAP 1 -- persistence-failure must downgrade a `completed` aggregate.
# -----------------------------------------------------------------------------------------

class _LossyReporter:
    """submit_tool_started/submit_evidence succeed; submit_tool_result ALWAYS raises a
    plain (non-refusal) exception -- the exact outage shape `_submit_tool_result_resilient`
    is built to survive without unwinding the tool loop (incident 615d0e0b)."""

    def __init__(self):
        self.tool_result_attempts = 0

    async def submit_tool_started(self, **kwargs):
        pass

    async def submit_tool_result(self, **kwargs):
        self.tool_result_attempts += 1
        raise RuntimeError("manager unreachable")

    async def submit_evidence(self, **kwargs):
        pass


def test_lost_tool_result_downgrades_completed_to_completed_with_errors():
    """Every tool executed cleanly, but its result never reached the manager -- the
    aggregate handed to /v1/lease/complete must not claim a clean 'completed' when
    tool_runs itself will show a missing/stuck-running row for that tool."""
    runner_cls = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0)
    )
    reporter = _LossyReporter()
    job = _job(modules=("nuclei",))

    outcome = asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=reporter, registry={"nuclei": runner_cls},
    ))

    assert reporter.tool_result_attempts == 1  # confirms the loss actually happened
    assert outcome == "completed_with_errors"
    assert outcome != "completed"


def test_no_persistence_loss_still_yields_completed():
    """Control case: the downgrade must be conditional on an ACTUAL loss, not unconditional
    -- a scan whose every submission succeeds still reports a clean 'completed'."""
    runner_cls = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0)
    )

    class _ReliableReporter:
        async def submit_tool_started(self, **kwargs):
            pass

        async def submit_tool_result(self, **kwargs):
            pass

        async def submit_evidence(self, **kwargs):
            pass

    job = _job(modules=("nuclei",))
    outcome = asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=_ReliableReporter(), registry={"nuclei": runner_cls},
    ))
    assert outcome == "completed"


def test_lost_result_alongside_a_failed_tool_stays_completed_with_errors_not_failed():
    """A persistence loss must never push the aggregate all the way to 'failed' -- the
    tools DID execute (mirrors the existing partial/failed precedent already covered by
    test_lease_execution_fidelity.py)."""
    ok_cls = _runner(
        "httpx", 20, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0)
    )
    lossy_cls = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0)
    )
    reporter = _LossyReporter()
    job = _job(modules=("httpx", "nuclei"))

    outcome = asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=reporter,
        registry={"httpx": ok_cls, "nuclei": lossy_cls},
    ))

    assert outcome == "completed_with_errors"
    assert reporter.tool_result_attempts == 2


# -----------------------------------------------------------------------------------------
# GAP 2 -- a 409 EXECUTION_SUPERSEDED must be classified as a refusal, not an outage.
# -----------------------------------------------------------------------------------------

def test_409_is_recognised_as_an_authoritative_refusal():
    exc = _HTTPStatusErrorLike(409)
    assert executor_mod._is_authoritative_refusal(exc) is True


def test_401_and_403_remain_authoritative_refusals():
    assert executor_mod._is_authoritative_refusal(_HTTPStatusErrorLike(401)) is True
    assert executor_mod._is_authoritative_refusal(_HTTPStatusErrorLike(403)) is True


def test_5xx_and_unrecognised_errors_remain_outages_not_refusals():
    assert executor_mod._is_authoritative_refusal(_HTTPStatusErrorLike(500)) is False
    assert executor_mod._is_authoritative_refusal(RuntimeError("boom")) is False


def test_lease_error_auth_failed_is_still_a_refusal():
    exc = LeaseError(REASON_AUTH_FAILED, "revoked")
    assert executor_mod._is_authoritative_refusal(exc) is True


class _SupersededReporter:
    """submit_tool_result raises a 409 (EXECUTION_SUPERSEDED) for every call -- the shape
    `_assert_execution_token` produces once a later executor has re-claimed this scan."""

    def __init__(self):
        self.calls = 0

    async def submit_tool_started(self, **kwargs):
        pass

    async def submit_tool_result(self, **kwargs):
        self.calls += 1
        raise _HTTPStatusErrorLike(409)

    async def submit_evidence(self, **kwargs):
        pass


def test_superseded_token_stops_the_loop_before_the_next_tool():
    """A worker whose execution token has been superseded must stop at the NEXT tool
    boundary rather than keep running tools against the target under a token every
    subsequent fenced write will just lose the same race against. Two runners are
    registered; only the first must actually execute."""
    first_cls = _runner(
        "httpx", 20, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0)
    )
    ran_second = {"value": False}

    class _SecondRunner:
        name = "nuclei"
        phase = 50
        applicable_target_types = None

        async def run(self, target_value, config, prior):
            ran_second["value"] = True
            return RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0)

        def parse(self, raw):
            return []

    reporter = _SupersededReporter()
    job = _job(modules=("httpx", "nuclei"))

    asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=reporter,
        registry={"httpx": first_cls, "nuclei": _SecondRunner},
    ))

    assert reporter.calls == 1          # the submission that revealed the 409
    assert ran_second["value"] is False  # the loop stopped before starting the next tool
