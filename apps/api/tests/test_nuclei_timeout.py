"""Nuclei's OPTIONAL timeout knobs, and the no-default-timeout contract.

nuclei is routinely the longest-running tool in the pipeline (a full template set against a
real site legitimately runs for hours), so it has NO default wall-clock timeout: by default it
runs to natural completion. A cap can still be opted into per scan via
`tool_config.nuclei_timeout_seconds` (nuclei only) or the shared `tool_config.timeout_seconds`;
the nuclei-only key exists so raising it does not also raise the shared key for every other
runner -- most consequentially ffuf, whose timeout is PER TARGET. A value <= 0 means "no
timeout", same as unset.

The tests drive the real `NucleiRunner.run()` with a stubbed `create_subprocess_exec`, and
observe WHAT timeout value nuclei_runner passes to `run_with_timeout` (F2-05: the runner was
migrated from a bare `asyncio.wait_for(proc.communicate(), ...)` idiom to the shared
`run_with_timeout` helper so a timeout preserves partial output; the no-timeout contract
below -- `timeout_seconds=None` reaching `run_with_timeout` -- is unchanged by that move,
since `run_with_timeout` itself treats `None`/`<=0` as "no wall-clock cap").
"""
import asyncio

from apps.api.modules.scans.service import ALLOWED_TOOL_CONFIG_KEYS
from apps.api.scanner_engine.tool_runners import nuclei_runner
from apps.api.scanner_engine.tool_runners.base import TimedRun
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner

# Sentinel: no test here observes an actual "wait_for was never called" state any more
# (run_with_timeout is always called; it internally decides whether to apply a deadline), so
# this now just names "no timeout value was passed" for readability at call sites below.
_NO_WAIT_FOR = None


def _capture(monkeypatch) -> dict:
    """Run NucleiRunner.run() against a stub subprocess and record the `timeout` value
    nuclei_runner passed to `run_with_timeout` -- None means no wall-clock cap."""
    seen: dict = {"timeout": _NO_WAIT_FOR}

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

    async def _spy_run_with_timeout(proc, timeout, tool="", *, stdin=None):
        seen["timeout"] = timeout
        return TimedRun(stdout="", stderr="", timed_out=False, exit_code=0)

    monkeypatch.setattr(nuclei_runner.asyncio, "create_subprocess_exec", _fake_exec)
    monkeypatch.setattr(nuclei_runner, "run_with_timeout", _spy_run_with_timeout)
    return seen


def _run(monkeypatch, config: dict):
    seen = _capture(monkeypatch)
    asyncio.run(NucleiRunner().run("example.com", config, []))
    return seen["timeout"]


# --- the no-default-timeout contract -------------------------------------------------------

def test_no_config_means_no_wall_clock_timeout(monkeypatch):
    """The headline change: with nothing configured, nuclei is NOT wrapped in asyncio.wait_for
    -- it runs proc.communicate() to natural completion."""
    assert _run(monkeypatch, {}) is _NO_WAIT_FOR


def test_nuclei_timeout_seconds_applies_an_explicit_cap(monkeypatch):
    assert _run(monkeypatch, {"nuclei_timeout_seconds": 1800}) == 1800


def test_nuclei_timeout_seconds_wins_over_the_shared_key(monkeypatch):
    """Precedence: nuclei's own key beats the shared one when both are present."""
    assert _run(monkeypatch, {"nuclei_timeout_seconds": 1800, "timeout_seconds": 90}) == 1800


def test_shared_timeout_seconds_applies_when_the_nuclei_key_is_absent(monkeypatch):
    """Fallback: a config that only sets the shared `timeout_seconds` still caps nuclei."""
    assert _run(monkeypatch, {"timeout_seconds": 900}) == 900


def test_zero_or_negative_timeout_means_no_timeout(monkeypatch):
    """<= 0 is treated exactly like unset: no asyncio.wait_for, runs to completion."""
    assert _run(monkeypatch, {"nuclei_timeout_seconds": 0}) is _NO_WAIT_FOR
    assert _run(monkeypatch, {"nuclei_timeout_seconds": -5}) is _NO_WAIT_FOR
    # A <=0 nuclei key still shadows a positive shared key (the nuclei key wins, then disables).
    assert _run(monkeypatch, {"nuclei_timeout_seconds": 0, "timeout_seconds": 300}) is _NO_WAIT_FOR
    # And a <=0 shared key, with no nuclei key, also means no timeout.
    assert _run(monkeypatch, {"timeout_seconds": 0}) is _NO_WAIT_FOR


def test_a_positive_timeout_still_uses_wait_for(monkeypatch):
    """A caller who explicitly wants a cap still gets asyncio.wait_for with that exact value."""
    assert _run(monkeypatch, {"nuclei_timeout_seconds": 42}) == 42


# --- isolation from other runners ----------------------------------------------------------

def test_a_nuclei_timeout_does_not_leak_into_other_runners():
    """The nuclei-only key must be invisible to every other runner, so setting it cannot
    silently extend ffuf (per target), nmap, katana, etc. -- they read the SHARED key only."""
    from apps.api.scanner_engine.tool_runners import (
        ffuf_runner,
        katana_runner,
        nmap_runner,
        subfinder_runner,
    )

    config = {"nuclei_timeout_seconds": 10800}
    assert config.get("timeout_seconds", ffuf_runner.DEFAULT_TIMEOUT_SECONDS) == 180
    assert config.get("timeout_seconds", nmap_runner.DEFAULT_TIMEOUT_SECONDS) == 240
    assert config.get("timeout_seconds", katana_runner.DEFAULT_TIMEOUT_SECONDS) == 300
    assert config.get("timeout_seconds", subfinder_runner.DEFAULT_TIMEOUT_SECONDS) == 120


def test_nuclei_dast_is_untouched_by_the_new_key():
    """nuclei-dast keeps its own independent `dast_timeout_seconds` and its own default --
    explicitly out of scope for the nuclei no-timeout change."""
    from apps.api.scanner_engine.tool_runners import nuclei_dast_runner

    config = {"nuclei_timeout_seconds": 10800}
    assert (
        config.get("dast_timeout_seconds", nuclei_dast_runner.DEFAULT_TIMEOUT_SECONDS) == 600
    )


# --- API surface ---------------------------------------------------------------------------

def test_the_key_is_accepted_by_the_tool_config_allowlist():
    """Without this the API rejects the key with a 400 before a scan is ever created."""
    assert "nuclei_timeout_seconds" in ALLOWED_TOOL_CONFIG_KEYS
    assert "timeout_seconds" in ALLOWED_TOOL_CONFIG_KEYS
    assert "dast_timeout_seconds" in ALLOWED_TOOL_CONFIG_KEYS


def test_orchestration_and_safety_keys_are_still_not_tunable():
    """Unchanged invariant: tool_config may only tune runner behavior, never orchestration."""
    for forbidden in (
        "requested_modules", "use_agent", "use_ai_planner",
        "exploitation_enabled", "approved_hosts",
    ):
        assert forbidden not in ALLOWED_TOOL_CONFIG_KEYS


# --- cancellation + timeout termination ----------------------------------------------------

def test_cancellation_terminates_the_subprocess_and_re_raises(monkeypatch):
    """asyncio.CancelledError (scan revoke / warm shutdown) must reap the process and then
    propagate -- unchanged by the F2-05 migration to run_with_timeout, which itself
    guarantees this (see test_tool_timeouts.test_cancellation_kills_process_and_propagates);
    this test pins that NucleiRunner.run() still surfaces it end to end."""
    from apps.api.tests.test_tool_timeouts import _FakeProc

    async def _fake_exec(*_a, **_k):
        return _FakeProc([(60, b"slow\n")])

    monkeypatch.setattr(nuclei_runner.asyncio, "create_subprocess_exec", _fake_exec)

    async def _scenario():
        # No timeout configured, so run_with_timeout awaits the pumps directly; cancel it.
        task = asyncio.ensure_future(NucleiRunner().run("example.com", {}, []))
        await asyncio.sleep(0.05)
        task.cancel()
        await task

    import pytest

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(_scenario())


def test_explicit_timeout_expiry_names_the_knob_and_the_value(monkeypatch):
    """When an EXPLICIT positive timeout expires, the tool run is reported with the knob to
    raise and the value that applied -- the old bare 'timed out' said neither."""
    from apps.api.tests.test_tool_timeouts import _FakeProc

    async def _fake_exec(*_a, **_k):
        return _FakeProc([(60, b"slow\n")])

    monkeypatch.setattr(nuclei_runner.asyncio, "create_subprocess_exec", _fake_exec)

    raw = asyncio.run(NucleiRunner().run("example.com", {"nuclei_timeout_seconds": 0.2}, []))
    assert raw.exit_code == -1
    assert "timed out" in raw.stderr.lower()          # kept: existing callers match on this
    assert "0.2" in raw.stderr                        # the value that actually applied
    assert "nuclei_timeout_seconds" in raw.stderr     # the knob to raise


def test_timeout_preserves_partial_output(monkeypatch):
    """F2-05: nuclei is one of the 9 runners migrated to run_with_timeout specifically so a
    timeout no longer discards output already produced -- this is the regression the whole
    prompt exists to close for nuclei, called out by name as the most consequential case."""
    from apps.api.tests.test_tool_timeouts import _FakeProc

    async def _fake_exec(*_a, **_k):
        return _FakeProc([(0, b'{"template-id":"x"}\n'), (10, b"never\n")])

    monkeypatch.setattr(nuclei_runner.asyncio, "create_subprocess_exec", _fake_exec)

    raw = asyncio.run(NucleiRunner().run("example.com", {"nuclei_timeout_seconds": 0.2}, []))
    assert raw.exit_code == -1
    assert '"template-id":"x"' in raw.stdout
    assert "never" not in raw.stdout
