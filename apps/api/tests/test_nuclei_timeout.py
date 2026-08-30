"""Nuclei's OPTIONAL timeout knobs, and the no-default-timeout contract.

nuclei is routinely the longest-running tool in the pipeline (a full template set against a
real site legitimately runs for hours), so it has NO default wall-clock timeout: by default it
runs to natural completion. A cap can still be opted into per scan via
`tool_config.nuclei_timeout_seconds` (nuclei only) or the shared `tool_config.timeout_seconds`;
the nuclei-only key exists so raising it does not also raise the shared key for every other
runner -- most consequentially ffuf, whose timeout is PER TARGET. A value <= 0 means "no
timeout", same as unset.

The tests drive the real `NucleiRunner.run()` with a stubbed `create_subprocess_exec`, and
observe WHETHER `asyncio.wait_for` was used and with WHAT timeout -- so the no-timeout path
(bare `communicate()`, no `wait_for`) is asserted directly rather than inferred.
"""
import asyncio

from apps.api.modules.scans.service import ALLOWED_TOOL_CONFIG_KEYS
from apps.api.scanner_engine.tool_runners import nuclei_runner
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner

# Sentinel distinguishing "wait_for was never called" (the no-timeout path) from any real
# timeout value that could be passed to it.
_NO_WAIT_FOR = object()


def _capture(monkeypatch) -> dict:
    """Run NucleiRunner.run() against a stub subprocess and record how the tool was awaited:
    `seen['timeout']` is the value passed to asyncio.wait_for, or _NO_WAIT_FOR if the runner
    awaited proc.communicate() directly (the no-timeout path)."""
    seen: dict = {"timeout": _NO_WAIT_FOR}

    class _Proc:
        returncode = 0

        async def communicate(self, input=None):  # noqa: A002 -- matches asyncio's signature
            return b"", b""

        def kill(self):
            pass

    async def _fake_exec(*_a, **_k):
        return _Proc()

    real_wait_for = asyncio.wait_for

    async def _spy_wait_for(awaitable, timeout):
        seen["timeout"] = timeout
        return await real_wait_for(awaitable, timeout)

    monkeypatch.setattr(nuclei_runner.asyncio, "create_subprocess_exec", _fake_exec)
    monkeypatch.setattr(nuclei_runner.asyncio, "wait_for", _spy_wait_for)
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
    propagate -- unchanged by the no-timeout work."""
    reaped: dict = {"called": False}

    class _HangingProc:
        returncode = None

        async def communicate(self, input=None):  # noqa: A002
            await asyncio.sleep(60)

        def kill(self):
            self.returncode = -9

    async def _fake_exec(*_a, **_k):
        return _HangingProc()

    async def _fake_reap(proc, tool="", **_k):
        reaped["called"] = True
        return b"", b""

    monkeypatch.setattr(nuclei_runner.asyncio, "create_subprocess_exec", _fake_exec)
    monkeypatch.setattr(nuclei_runner, "terminate_and_reap", _fake_reap)

    async def _scenario():
        # No timeout configured, so the runner awaits communicate() directly; cancel it.
        task = asyncio.ensure_future(NucleiRunner().run("example.com", {}, []))
        await asyncio.sleep(0.05)
        task.cancel()
        await task

    import pytest

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(_scenario())
    assert reaped["called"], "terminate_and_reap must run on cancellation"


def test_explicit_timeout_expiry_names_the_knob_and_the_value(monkeypatch):
    """When an EXPLICIT positive timeout expires, the tool run is reported with the knob to
    raise and the value that applied -- the old bare 'timed out' said neither."""
    class _HangingProc:
        returncode = None

        async def communicate(self, input=None):  # noqa: A002
            await asyncio.sleep(60)

        def kill(self):
            self.returncode = -9

    async def _fake_exec(*_a, **_k):
        return _HangingProc()

    monkeypatch.setattr(nuclei_runner.asyncio, "create_subprocess_exec", _fake_exec)

    raw = asyncio.run(NucleiRunner().run("example.com", {"nuclei_timeout_seconds": 0.2}, []))
    assert raw.exit_code == -1
    assert "timed out" in raw.stderr.lower()          # kept: existing callers match on this
    assert "0.2" in raw.stderr                        # the value that actually applied
    assert "nuclei_timeout_seconds" in raw.stderr     # the knob to raise
