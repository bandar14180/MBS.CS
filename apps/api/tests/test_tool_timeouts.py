"""Scan-tool timeout budgets and partial-output preservation.

Background (measured against a live authorized target, www.lincoln.edu.my):

    tool      budget   natural runtime   result unconstrained
    whatweb   120s     152s              exit 0, full fingerprint
    katana    300s     360s              exit 0, 858 URLs
    ffuf      180s     407s              exit 0, 146 hits

Every failure was the RUNNER's wall clock, not the tool and not the network -- and because
output was collected with `communicate()`, the timeout discarded everything the tool had
already produced. Two defects: budgets that did not fit the work, and total loss of partial
results.

These tests are fully deterministic: subprocesses are faked, no network, no real tools.
"""

import asyncio

import pytest

from apps.api.scanner_engine.tool_runners import ffuf_runner, katana_runner, whatweb_runner
from apps.api.scanner_engine.tool_runners.base import run_with_timeout


# --- Fake subprocess ----------------------------------------------------------------------

class _FakeStream:
    """An asyncio-like stream that yields chunks with optional delays, then EOF."""

    def __init__(self, chunks: list[tuple[float, bytes]]):
        self._chunks = list(chunks)

    async def read(self, _n: int = -1) -> bytes:
        if not self._chunks:
            return b""
        delay, data = self._chunks.pop(0)
        if delay:
            await asyncio.sleep(delay)
        return data


class _FakeStdin:
    def __init__(self):
        self.written = b""
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _FakeProc:
    """Minimal stand-in for asyncio subprocess. Records kill()/wait() so cleanup is assertable."""

    def __init__(self, stdout_chunks, stderr_chunks=(), *, exit_after: float = 0.0, returncode=0):
        self.stdout = _FakeStream(list(stdout_chunks))
        self.stderr = _FakeStream(list(stderr_chunks))
        self.stdin = _FakeStdin()
        self._exit_after = exit_after
        self._returncode = returncode
        self.returncode = None
        self.killed = 0
        self.waited = 0

    async def wait(self):
        self.waited += 1
        if self._exit_after:
            await asyncio.sleep(self._exit_after)
        if self.returncode is None:
            self.returncode = self._returncode
        return self.returncode

    def kill(self):
        self.killed += 1
        self.returncode = -9

    async def communicate(self):
        return b"", b""


# ============================ run_with_timeout ============================================
# Driven with asyncio.run(), matching the repo's existing convention (test_nuclei_timeout.py);
# no pytest-asyncio dependency is added for this work.

def test_completed_process_returns_full_output() -> None:
    async def _scenario():
        proc = _FakeProc([(0, b"line1\n"), (0, b"line2\n")], [(0, b"warn\n")])
        result = await run_with_timeout(proc, 5, "fake")
        assert result.timed_out is False
        assert result.stdout == "line1\nline2\n"
        assert result.stderr == "warn\n"
        assert proc.killed == 0

    asyncio.run(_scenario())


def test_timeout_preserves_partial_stdout() -> None:
    """THE core regression: output produced before the deadline must survive.

    The old `wait_for(communicate())` idiom returned NOTHING here -- which is how katana's
    858 URLs and ffuf's 146 hits were lost."""

    async def _scenario():
        proc = _FakeProc([(0, b"url1\n"), (0, b"url2\n"), (10, b"never\n")])
        result = await run_with_timeout(proc, 0.25, "fake")
        assert result.timed_out is True
        assert "url1" in result.stdout and "url2" in result.stdout
        assert "never" not in result.stdout

    asyncio.run(_scenario())


def test_timeout_kills_the_process_no_orphan() -> None:
    async def _scenario():
        proc = _FakeProc([(10, b"slow\n")])
        result = await run_with_timeout(proc, 0.1, "fake")
        assert result.timed_out is True
        assert proc.killed >= 1, "timed-out process must be killed, never left running"

    asyncio.run(_scenario())


def test_no_timeout_when_budget_is_none_or_zero() -> None:
    """The nuclei policy -- no wall clock -- must remain expressible."""

    async def _scenario():
        for budget in (None, 0):
            proc = _FakeProc([(0, b"done\n")])
            result = await run_with_timeout(proc, budget, "fake")
            assert result.timed_out is False
            assert result.stdout == "done\n"

    asyncio.run(_scenario())


def test_stdin_is_written_and_closed() -> None:
    """katana receives its target list on stdin; it must see EOF or it never starts."""

    async def _scenario():
        proc = _FakeProc([(0, b"ok\n")])
        await run_with_timeout(proc, 5, "fake", stdin=b"https://a\nhttps://b")
        assert proc.stdin.written == b"https://a\nhttps://b"
        assert proc.stdin.closed is True

    asyncio.run(_scenario())


def test_stderr_is_drained_concurrently_no_deadlock() -> None:
    """Both pipes are drained at once; a chatty stderr must not block stdout (or vice versa)."""

    async def _scenario():
        proc = _FakeProc([(0.05, b"out\n")], [(0.05, b"err\n")])
        result = await asyncio.wait_for(run_with_timeout(proc, 5, "fake"), timeout=3)
        assert result.stdout == "out\n"
        assert result.stderr == "err\n"

    asyncio.run(_scenario())


def test_cancellation_kills_process_and_propagates() -> None:
    async def _scenario():
        proc = _FakeProc([(10, b"slow\n")])
        task = asyncio.create_task(run_with_timeout(proc, None, "fake"))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert proc.killed >= 1, "cancelled process must not be left running"

    asyncio.run(_scenario())


def test_partial_output_survives_even_with_empty_stderr() -> None:
    async def _scenario():
        proc = _FakeProc([(0, b"hit1\n"), (10, b"x")], [])
        result = await run_with_timeout(proc, 0.2, "fake")
        assert result.timed_out is True
        assert result.stdout.startswith("hit1")

    asyncio.run(_scenario())


# ============================ WhatWeb budget ==============================================

def test_whatweb_budget_exceeds_the_measured_runtime() -> None:
    """152s measured for 1 target at -a 3; the budget must clear it with margin."""
    budget = whatweb_runner.compute_timeout(1, 3)
    assert budget > 152, f"budget {budget}s does not fit the measured 152s run"
    assert budget >= 152 * 1.5


def test_whatweb_budget_scales_with_targets_and_aggression() -> None:
    assert whatweb_runner.compute_timeout(4, 3) > whatweb_runner.compute_timeout(1, 3)
    assert whatweb_runner.compute_timeout(1, 3) > whatweb_runner.compute_timeout(1, 1)


def test_whatweb_budget_is_clamped_both_ends() -> None:
    assert whatweb_runner.compute_timeout(0, 1) >= whatweb_runner.MIN_TIMEOUT_SECONDS
    assert whatweb_runner.compute_timeout(10_000, 4) == whatweb_runner.MAX_TIMEOUT_SECONDS


def test_whatweb_unknown_aggression_falls_back_to_default() -> None:
    assert whatweb_runner.compute_timeout(1, 99) == whatweb_runner.compute_timeout(1, 3)


# ============================ Katana budget ===============================================

def test_katana_budget_exceeds_the_measured_runtime() -> None:
    """360s measured for 1 target at depth 2 with JS crawling."""
    budget = katana_runner.compute_timeout(1, 2, js_crawl=True)
    assert budget > 360, f"budget {budget}s does not fit the measured 360s crawl"
    assert budget >= 360 * 1.5


def test_katana_budget_scales_with_depth_and_targets() -> None:
    assert katana_runner.compute_timeout(1, 3) > katana_runner.compute_timeout(1, 2)
    assert katana_runner.compute_timeout(3, 2) > katana_runner.compute_timeout(1, 2)


def test_katana_js_crawl_costs_more_than_without() -> None:
    assert katana_runner.compute_timeout(1, 2, js_crawl=True) > katana_runner.compute_timeout(
        1, 2, js_crawl=False
    )


def test_katana_budget_is_clamped_both_ends() -> None:
    assert katana_runner.compute_timeout(0, 1, False) >= katana_runner.MIN_TIMEOUT_SECONDS
    assert katana_runner.compute_timeout(10_000, 9) == katana_runner.MAX_TIMEOUT_SECONDS


# ============================ Ffuf budget =================================================

def test_ffuf_budget_is_derived_from_wordlist_and_rate() -> None:
    """The defect: a FIXED 180s cannot fit a variable wordlist. 4614/40 = 115s floor alone."""
    budget = ffuf_runner.compute_timeout(4614, 40)
    assert budget > 407, f"budget {budget}s does not fit the measured 407s run"
    floor = 4614 / 40
    assert budget >= floor * 3, "budget must leave real margin over the arithmetic floor"


def test_ffuf_budget_scales_with_wordlist_size() -> None:
    small = ffuf_runner.compute_timeout(1000, 40)
    large = ffuf_runner.compute_timeout(20000, 40)
    assert large > small


def test_ffuf_budget_scales_inversely_with_rate() -> None:
    slow = ffuf_runner.compute_timeout(10000, 10)
    fast = ffuf_runner.compute_timeout(10000, 100)
    assert slow > fast


def test_ffuf_budget_is_clamped_and_survives_absurd_input() -> None:
    assert ffuf_runner.compute_timeout(1, 10_000) == ffuf_runner.MIN_TIMEOUT_SECONDS
    assert ffuf_runner.compute_timeout(10_000_000, 1) == ffuf_runner.MAX_TIMEOUT_SECONDS
    assert ffuf_runner.compute_timeout(0, 0) >= ffuf_runner.MIN_TIMEOUT_SECONDS  # no ZeroDivisionError


def test_ffuf_wordlist_counting_is_fail_soft(tmp_path) -> None:
    wl = tmp_path / "w.txt"
    wl.write_text("a\nb\n\nc\n", encoding="utf-8")
    assert ffuf_runner.count_wordlist_entries(str(wl)) == 3          # blank line ignored
    # An unreadable path must not raise -- it falls back so the scan still runs.
    assert ffuf_runner.count_wordlist_entries(str(tmp_path / "nope.txt")) == (
        ffuf_runner.FALLBACK_WORDLIST_ENTRIES
    )


def test_ffuf_stays_per_target() -> None:
    """Concurrency and per-target execution are unchanged by the budget work."""
    assert ffuf_runner.MAX_CONCURRENT_TARGETS == 3


# ============================ No global timeout change ====================================

def test_nuclei_still_has_no_default_wall_clock_ceiling() -> None:
    """The fix must not have introduced a global cap -- nuclei runs to completion by design."""
    from apps.api.scanner_engine.tool_runners import nuclei_runner

    assert getattr(nuclei_runner, "DEFAULT_TIMEOUT_SECONDS", None) in (None, 0), (
        "nuclei must not gain a default wall-clock timeout"
    )
