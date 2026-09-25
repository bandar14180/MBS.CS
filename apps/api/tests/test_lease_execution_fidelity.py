"""F2-01 / F2-02 regression coverage: the lease execution path (scanner_worker/executor.py)
must preserve tool_config through to the runner, and must not collapse the orchestrator's
existing completed/completed_with_errors/partial/failed vocabulary into a binary
completed/failed outcome.

`execute_leased_job` is exercised directly with `reporter=None` (persistence is skipped
entirely in that mode -- see executor.py), so these are pure unit tests of the aggregation
and config-handoff logic, independent of the database.
"""
import asyncio

from apps.api.core.config import get_settings
from apps.api.scanner_engine.tool_runners.base import CommonFinding, RawToolOutput
from apps.api.scanner_worker import executor as executor_mod


def _job(config: dict | None = None, modules=("nuclei",)) -> dict:
    return {
        "scan_id": "11111111-1111-1111-1111-111111111111",
        "execution_token": "22222222-2222-2222-2222-222222222222",
        "target": {"id": "t", "type": "domain", "value": "t.example.com"},
        "requested_modules": list(modules),
        "config": config or {},
    }


def _runner(name, phase, result: RawToolOutput, vuln_findings=None,
            findings=None, hard_failure=False):
    class _StubRunner:
        pass

    _StubRunner.name = name
    _StubRunner.phase = phase
    _StubRunner.applicable_target_types = None
    _StubRunner.benign_exit_codes = ()

    captured: dict = {}

    async def run(self, target_value, config, prior):
        captured["config"] = config
        captured["prior_findings"] = list(prior)
        return result

    def parse(self, raw):
        return list(findings or [])

    def hard_failure_fn(self, raw):
        return hard_failure

    _StubRunner.run = run
    _StubRunner.parse = parse
    _StubRunner.hard_failure = hard_failure_fn
    if vuln_findings is not None:
        def parse_vulnerabilities(self, raw):
            return vuln_findings
        _StubRunner.parse_vulnerabilities = parse_vulnerabilities
    return _StubRunner, captured


# -----------------------------------------------------------------------------------------
# F2-01: tool_config handoff
# -----------------------------------------------------------------------------------------

def test_non_default_tool_config_reaches_the_runner():
    """A representative non-default tool_config must arrive at runner.run() unchanged."""
    runner_cls, captured = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="", stderr="", exit_code=0)
    )
    config = {"timeout_seconds": 777, "nuclei_tags": "cve,exposure"}
    job = _job(config=config)

    outcome = asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=None, registry={"nuclei": runner_cls},
    ))

    assert outcome == "completed"
    assert captured["config"] == config


def test_default_omitted_tool_config_behaves_as_empty_dict():
    """No tool_config supplied -- the runner must see `{}`, exactly as it did before any
    tool_config was ever set on the scan, not None or a missing key."""
    runner_cls, captured = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="", stderr="", exit_code=0)
    )
    job = _job(config=None)

    asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=None, registry={"nuclei": runner_cls},
    ))

    assert captured["config"] == {}


def test_multiple_tool_configurations_all_reach_the_orchestrator():
    """Several distinct tool-config knobs (spanning different tools) must all survive
    the handoff simultaneously -- this is not just one key working by coincidence."""
    runner_cls, captured = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="", stderr="", exit_code=0)
    )
    config = {
        "timeout_seconds": 500,
        "top_ports": 250,
        "rate": 500,
        "nuclei_tags": "misconfig",
        "ffuf_rate": 10,
    }
    job = _job(config=config)

    asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=None, registry={"nuclei": runner_cls},
    ))

    for key, value in config.items():
        assert captured["config"][key] == value


# -----------------------------------------------------------------------------------------
# F2-02: status fidelity through the lease path's aggregation
# -----------------------------------------------------------------------------------------

def test_all_tools_clean_yields_completed():
    runner_cls, _ = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0)
    )
    outcome = asyncio.run(executor_mod.execute_leased_job(
        _job(), policy=None, reporter=None, registry={"nuclei": runner_cls},
    ))
    assert outcome == "completed"


def test_all_tools_failed_yields_failed():
    runner_cls, _ = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="", stderr="boom", exit_code=1)
    )
    outcome = asyncio.run(executor_mod.execute_leased_job(
        _job(), policy=None, reporter=None, registry={"nuclei": runner_cls},
    ))
    assert outcome == "failed"


def test_one_partial_tool_among_successes_yields_completed_with_errors():
    """The defect: this used to collapse to 'completed', hiding that one tool only
    produced partial output (e.g. a timeout) while another ran clean."""
    clean_cls, _ = _runner(
        "httpx", 20, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0)
    )
    partial_cls, _ = _runner(
        # non-zero exit but produced usable stdout -> classify_run marks this 'partial'
        "nuclei", 50, RawToolOutput(command="x", stdout="some findings", stderr="", exit_code=1)
    )
    job = _job(modules=("httpx", "nuclei"))
    outcome = asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=None,
        registry={"httpx": clean_cls, "nuclei": partial_cls},
    ))
    assert outcome == "completed_with_errors"


def test_one_failed_tool_among_successes_yields_completed_with_errors():
    """A hard failure on one tool alongside a clean run on another must not silently
    become 'completed' -- and must not become 'failed' either (some tools DID succeed)."""
    clean_cls, _ = _runner(
        "httpx", 20, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0)
    )
    failed_cls, _ = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="", stderr="crashed", exit_code=1)
    )
    job = _job(modules=("httpx", "nuclei"))
    outcome = asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=None,
        registry={"httpx": clean_cls, "nuclei": failed_cls},
    ))
    assert outcome == "completed_with_errors"


def test_exception_raising_tool_counts_as_failed_status_in_aggregation():
    """A runner that raises (rather than returning a non-zero RawToolOutput) is recorded
    as `failed` in `statuses` by the executor's own except-block, and must still
    participate correctly in the 3-way aggregation."""
    clean_cls, _ = _runner(
        "httpx", 20, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0)
    )

    class _RaisingRunner:
        name = "nuclei"
        phase = 50
        applicable_target_types = None

        async def run(self, target_value, config, prior):
            raise RuntimeError("boom")

        def parse(self, raw):
            return []

    job = _job(modules=("httpx", "nuclei"))
    outcome = asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=None,
        registry={"httpx": clean_cls, "nuclei": _RaisingRunner},
    ))
    assert outcome == "completed_with_errors"


# -----------------------------------------------------------------------------------------
# F2-06: classify_run must weigh parse_vulnerabilities() output, not just parse(), matching
# orchestrator.run_scan's `produced_findings = bool(findings or vuln_findings)`.
# -----------------------------------------------------------------------------------------

def test_vuln_only_output_is_partial_not_failed():
    """parse() empty + parse_vulnerabilities() non-empty + blank stdout + non-zero exit
    must classify as 'partial' -- a vuln-only tool run is not empty-handed."""
    runner_cls, _ = _runner(
        "nuclei", 50,
        RawToolOutput(command="x", stdout="", stderr="some cve found", exit_code=1),
        vuln_findings=[object()],
    )
    job = _job(modules=("nuclei",))
    outcome = asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=None, registry={"nuclei": runner_cls},
    ))
    assert outcome == "completed_with_errors"


def test_truly_empty_output_is_failed():
    """No inventory findings, no vulnerability findings, blank stdout, non-zero exit
    must still classify as 'failed'."""
    runner_cls, _ = _runner(
        "nuclei", 50,
        RawToolOutput(command="x", stdout="", stderr="crashed", exit_code=1),
        vuln_findings=[],
    )
    job = _job(modules=("nuclei",))
    outcome = asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=None, registry={"nuclei": runner_cls},
    ))
    assert outcome == "failed"


def test_successful_run_unaffected_by_vuln_signal():
    """A clean exit-0 run stays 'completed' regardless of parse_vulnerabilities() output --
    existing successful/partial execution behavior is unchanged by this fix."""
    runner_cls, _ = _runner(
        "nuclei", 50,
        RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0),
        vuln_findings=[object()],
    )
    job = _job(modules=("nuclei",))
    outcome = asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=None, registry={"nuclei": runner_cls},
    ))
    assert outcome == "completed"


# -----------------------------------------------------------------------------------------
# F2-07: a `failed`-classified run must not have its parse() findings propagated -- neither
# into `discovered` (and thus into a later tool's prior_findings) nor into the submitted
# tool-result payload. Mirrors orchestrator.py's `if status == "failed": findings = []`.
# -----------------------------------------------------------------------------------------

class _RecordingReporter:
    """Captures submit_tool_result calls so a test can inspect the findings payload.

    `evidence_fails`: when True, submit_evidence raises a plain (non-refusal) exception --
    the same fail-soft outage shape executor.py already handles for evidence loss."""

    def __init__(self, evidence_fails=False):
        self.calls = []
        self.evidence_calls = []
        self._evidence_fails = evidence_fails

    async def submit_tool_started(self, **kwargs):
        pass

    async def submit_tool_result(self, **kwargs):
        self.calls.append(kwargs)

    async def submit_evidence(self, **kwargs):
        self.evidence_calls.append(kwargs)
        if self._evidence_fails:
            raise RuntimeError("evidence storage unavailable")


def test_hard_failed_run_findings_excluded_from_discovered():
    """A hard_failure()-flagged run whose parse() still returns findings must not add
    those findings to `discovered`."""
    runner_cls, captured = _runner(
        "nuclei", 50,
        RawToolOutput(command="x", stdout="unexpected output", stderr="auth error", exit_code=1),
        findings=[CommonFinding(asset_type="url", value="https://x.example.com")],
        hard_failure=True,
    )
    job = _job(modules=("nuclei",))
    outcome = asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=None, registry={"nuclei": runner_cls},
    ))
    assert outcome == "failed"


def test_hard_failed_run_findings_excluded_from_submitted_payload():
    """Those same findings must not appear in the tool-result payload sent to the manager."""
    runner_cls, _ = _runner(
        "nuclei", 50,
        RawToolOutput(command="x", stdout="unexpected output", stderr="auth error", exit_code=1),
        findings=[CommonFinding(asset_type="url", value="https://x.example.com")],
        hard_failure=True,
    )
    reporter = _RecordingReporter()
    job = _job(modules=("nuclei",))
    asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=reporter, registry={"nuclei": runner_cls},
    ))
    assert len(reporter.calls) == 1
    assert reporter.calls[0]["status"] == "failed"
    assert reporter.calls[0]["findings"] == []


def test_downstream_tool_receives_empty_prior_findings_after_failed_upstream():
    """A tool run after a failed upstream tool must see an empty prior_findings list, even
    though the failed tool's parse() returned findings."""
    failed_cls, _ = _runner(
        "httpx", 20,
        RawToolOutput(command="x", stdout="unexpected output", stderr="auth error", exit_code=1),
        findings=[CommonFinding(asset_type="url", value="https://x.example.com")],
        hard_failure=True,
    )
    downstream_cls, downstream_captured = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0),
    )
    job = _job(modules=("httpx", "nuclei"))
    asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=None,
        registry={"httpx": failed_cls, "nuclei": downstream_cls},
    ))
    assert downstream_captured["prior_findings"] == []


def test_partial_and_completed_findings_still_propagate():
    """Existing partial/completed behavior is unchanged: findings from non-failed runs
    still reach `discovered` and a downstream tool's prior_findings.

    Uses an in-scope hostname (a subdomain of _job()'s "t.example.com" target) so this
    F2-07 assertion is unaffected by the separate F2-08 scope-enforcement gate: this test
    is about failed-status exclusion, not authorization scope."""
    partial_cls, _ = _runner(
        # non-zero exit but produced findings -> classify_run marks this 'partial'
        "httpx", 20,
        RawToolOutput(command="x", stdout="some findings", stderr="", exit_code=1),
        findings=[CommonFinding(asset_type="subdomain", value="a.t.example.com")],
        hard_failure=False,
    )
    downstream_cls, downstream_captured = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0),
    )
    job = _job(modules=("httpx", "nuclei"))
    outcome = asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=None,
        registry={"httpx": partial_cls, "nuclei": downstream_cls},
    ))
    assert outcome == "completed_with_errors"
    assert len(downstream_captured["prior_findings"]) == 1
    assert downstream_captured["prior_findings"][0].value == "a.t.example.com"


# -----------------------------------------------------------------------------------------
# F2-08: the lease path must enforce derived-scope authorization (M4.5/G9) on discovered
# hosts before handing them to a downstream active tool, mirroring
# orchestrator._run_single_tool's scope_guard.partition_in_scope() gating exactly.
#
# _job()'s target is domain "t.example.com", so:
#   - "sub.t.example.com" is in scope (subdomain of the target)
#   - "evil.attacker.com" is out of scope (unrelated domain)
# -----------------------------------------------------------------------------------------

def test_out_of_scope_host_excluded_from_downstream_prior_findings():
    upstream_cls, _ = _runner(
        "httpx", 20, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0),
        findings=[CommonFinding(asset_type="subdomain", value="evil.attacker.com")],
    )
    downstream_cls, downstream_captured = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0),
    )
    job = _job(modules=("httpx", "nuclei"))
    settings = get_settings()
    assert settings.scan_enforce_derived_scope is True  # secure default, not overridden here
    asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=None,
        registry={"httpx": upstream_cls, "nuclei": downstream_cls},
    ))
    assert downstream_captured["prior_findings"] == []


def test_deny_listed_host_excluded_from_downstream_prior_findings(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "scan_derived_scope_excludes", ["cdn.t.example.com"])
    upstream_cls, _ = _runner(
        "httpx", 20, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0),
        findings=[CommonFinding(asset_type="subdomain", value="cdn.t.example.com")],
    )
    downstream_cls, downstream_captured = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0),
    )
    job = _job(modules=("httpx", "nuclei"))
    asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=None,
        registry={"httpx": upstream_cls, "nuclei": downstream_cls},
    ))
    assert downstream_captured["prior_findings"] == []


def test_in_scope_host_reaches_downstream_prior_findings_unchanged():
    upstream_cls, _ = _runner(
        "httpx", 20, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0),
        findings=[CommonFinding(asset_type="subdomain", value="sub.t.example.com")],
    )
    downstream_cls, downstream_captured = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0),
    )
    job = _job(modules=("httpx", "nuclei"))
    asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=None,
        registry={"httpx": upstream_cls, "nuclei": downstream_cls},
    ))
    assert len(downstream_captured["prior_findings"]) == 1
    assert downstream_captured["prior_findings"][0].value == "sub.t.example.com"


def test_kill_switch_disabled_preserves_unfiltered_passthrough(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "scan_enforce_derived_scope", False)
    upstream_cls, _ = _runner(
        "httpx", 20, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0),
        findings=[CommonFinding(asset_type="subdomain", value="evil.attacker.com")],
    )
    downstream_cls, downstream_captured = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0),
    )
    job = _job(modules=("httpx", "nuclei"))
    asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=None,
        registry={"httpx": upstream_cls, "nuclei": downstream_cls},
    ))
    assert len(downstream_captured["prior_findings"]) == 1
    assert downstream_captured["prior_findings"][0].value == "evil.attacker.com"


def test_discovered_aggregation_preserved_even_when_excluded_from_probing():
    """An out-of-scope finding is still kept in the canonical `discovered` collection
    (asset ingest / F2-06 / F2-07 aggregation is unaffected) -- only the argument handed
    to the NEXT runner.run() is narrowed. Proven via the submitted tool-result payload,
    which is built from the same `findings`/`discovered` this tool contributed."""
    upstream_cls, _ = _runner(
        "httpx", 20, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0),
        findings=[
            CommonFinding(asset_type="subdomain", value="evil.attacker.com"),
            CommonFinding(asset_type="subdomain", value="sub.t.example.com"),
        ],
    )
    downstream_cls, downstream_captured = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0),
    )
    reporter = _RecordingReporter()
    job = _job(modules=("httpx", "nuclei"))
    outcome = asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=reporter,
        registry={"httpx": upstream_cls, "nuclei": downstream_cls},
    ))
    assert outcome == "completed"
    # The upstream tool's OWN submitted result still carries both findings -- exclusion from
    # active probing is not exclusion from ingestion/aggregation.
    httpx_call = next(c for c in reporter.calls if c["tool_name"] == "httpx")
    submitted_values = {f["value"] for f in httpx_call["findings"]}
    assert submitted_values == {"evil.attacker.com", "sub.t.example.com"}
    # But only the in-scope host is handed to the NEXT active tool.
    downstream_values = {f.value for f in downstream_captured["prior_findings"]}
    assert downstream_values == {"sub.t.example.com"}


# -----------------------------------------------------------------------------------------
# F2-09: a `completed` tool run must be downgraded to `partial` when raw-evidence storage
# fails, mirroring orchestrator._run_single_tool's `if storage_failed and status ==
# "completed": status = "partial"`. Evidence submission now happens before the tool-result
# submission so the reported status can reflect the storage outcome.
# -----------------------------------------------------------------------------------------

def test_evidence_failure_downgrades_completed_to_partial():
    runner_cls, _ = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0),
    )
    reporter = _RecordingReporter(evidence_fails=True)
    job = _job(modules=("nuclei",))
    asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=reporter, registry={"nuclei": runner_cls},
    ))
    assert len(reporter.calls) == 1
    assert reporter.calls[0]["status"] == "partial"
    assert reporter.calls[0]["status"] != "completed"


def test_evidence_success_preserves_completed():
    runner_cls, _ = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="ok", stderr="", exit_code=0),
    )
    reporter = _RecordingReporter(evidence_fails=False)
    job = _job(modules=("nuclei",))
    asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=reporter, registry={"nuclei": runner_cls},
    ))
    assert len(reporter.calls) == 1
    assert reporter.calls[0]["status"] == "completed"


def test_failed_status_unaffected_by_evidence_failure():
    """The downgrade rule only applies to completed -> partial; a run already classified
    `failed` (hard_failure or no usable output) must stay `failed` regardless of evidence
    submission outcome."""
    runner_cls, _ = _runner(
        "nuclei", 50,
        RawToolOutput(command="x", stdout="unexpected output", stderr="auth error", exit_code=1),
        hard_failure=True,
    )
    reporter = _RecordingReporter(evidence_fails=True)
    job = _job(modules=("nuclei",))
    asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=reporter, registry={"nuclei": runner_cls},
    ))
    assert len(reporter.calls) == 1
    assert reporter.calls[0]["status"] == "failed"


def test_partial_status_unaffected_by_evidence_failure():
    runner_cls, _ = _runner(
        "nuclei", 50,
        RawToolOutput(command="x", stdout="some findings", stderr="", exit_code=1),
        findings=[CommonFinding(asset_type="subdomain", value="a.t.example.com")],
    )
    reporter = _RecordingReporter(evidence_fails=True)
    job = _job(modules=("nuclei",))
    asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=reporter, registry={"nuclei": runner_cls},
    ))
    assert len(reporter.calls) == 1
    assert reporter.calls[0]["status"] == "partial"


def test_empty_raw_output_skips_evidence_submission_and_downgrade():
    """Blank stdout means there is nothing to submit as evidence, so no evidence call is
    made and no storage-failure downgrade can occur -- classification is untouched."""
    runner_cls, _ = _runner(
        "nuclei", 50, RawToolOutput(command="x", stdout="", stderr="", exit_code=0),
    )
    reporter = _RecordingReporter(evidence_fails=True)
    job = _job(modules=("nuclei",))
    asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=reporter, registry={"nuclei": runner_cls},
    ))
    assert reporter.evidence_calls == []
    assert len(reporter.calls) == 1
    assert reporter.calls[0]["status"] == "completed"

