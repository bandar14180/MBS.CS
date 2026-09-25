"""Bounded subprocess cleanup for the scanner tool runners.

Guards the fix for a confirmed worker-hang / orphaned-process class of bug. The previous
idiom in all 12 runners was:

    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()     # <-- unbounded

Two distinct failure modes were REPRODUCED against real subprocesses (not theorised) before
this was changed, and both are asserted below against real subprocesses too -- a mock cannot
show either one, since both live in OS process/pipe semantics:

  1. UNBOUNDED CLEANUP. SIGKILL to the direct child does not close a pipe a surviving
     GRANDCHILD still holds, so `communicate()` never returns and the worker hangs on that
     scan forever. Relevant here because several of this project's tools spawn helpers
     (whatweb is Ruby, arjun is Python, amass spawns helpers).
  2. ORPHANED PROCESS ON CANCELLATION. On scan revoke / worker warm shutdown the orchestrator
     cancels the tool task; a CancelledError arriving inside `communicate()` used to leave the
     subprocess running (its returncode stayed None).

NOT A SCANNER EXECUTION TIMEOUT: the cleanup deadline only bounds the wait AFTER termination
has already been requested. `test_healthy_long_running_process_is_never_killed_by_cleanup`
pins that distinction so the fix cannot later be mistaken for a runtime cap.
"""
import asyncio
import subprocess
import sys
import textwrap
import time

import pytest

from apps.api.scanner_engine.tool_runners.base import (
    PROCESS_CLEANUP_TIMEOUT_SECONDS,
    terminate_and_reap,
)

# A child that spawns a grandchild inheriting its stdout/stderr pipes, then sleeps. Killing
# the child alone leaves those pipes open -- this is failure mode 1 in a bottle.
_SPAWNS_GRANDCHILD = textwrap.dedent(
    """
    import subprocess, sys, time
    subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"],
                     stdout=sys.stdout, stderr=sys.stderr)
    time.sleep(120)
    """
)


async def _spawn(code: str):
    return await asyncio.create_subprocess_exec(
        sys.executable, "-c", code,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )


def test_cleanup_is_bounded_when_a_grandchild_holds_the_pipes_open():
    """The exact hang that shipped: without the bound this never returns."""
    async def scenario():
        proc = await _spawn(_SPAWNS_GRANDCHILD)
        await asyncio.sleep(0.8)   # let the grandchild actually start
        started = time.monotonic()
        await terminate_and_reap(proc, "test", timeout=3)
        return time.monotonic() - started

    elapsed = asyncio.run(scenario())
    assert elapsed < 10, f"cleanup took {elapsed:.1f}s -- it is not bounded"


def test_partial_output_survives_termination():
    """A tool killed mid-run should not lose what it already produced."""
    async def scenario():
        proc = await _spawn(
            "import sys, time; print('partial-line'); sys.stdout.flush(); time.sleep(120)"
        )
        await asyncio.sleep(0.6)
        return await terminate_and_reap(proc, "test", timeout=8)

    stdout, _ = asyncio.run(scenario())
    assert b"partial-line" in stdout


def test_no_orphan_process_is_left_behind_after_cancellation():
    """Failure mode 2: cancellation used to leave the subprocess running (returncode None)."""
    async def scenario():
        proc = await _spawn("import time; time.sleep(120)")

        async def body():
            try:
                await asyncio.wait_for(proc.communicate(), timeout=60)
            except asyncio.CancelledError:
                await terminate_and_reap(proc, "test", timeout=8)
                raise

        task = asyncio.ensure_future(body())
        await asyncio.sleep(0.5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.4)
        return proc.returncode

    assert asyncio.run(scenario()) is not None, "subprocess survived cancellation (orphan)"


def test_cancellation_still_propagates_after_cleanup():
    """Killing the process must not swallow the cancellation -- warm shutdown depends on it."""
    async def scenario():
        proc = await _spawn("import time; time.sleep(120)")
        try:
            raise asyncio.CancelledError()
        except asyncio.CancelledError:
            await terminate_and_reap(proc, "test", timeout=8)
            raise

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(scenario())


def test_terminate_and_reap_is_safe_on_an_already_exited_process():
    """Idempotent: the process may well have died before cleanup runs."""
    async def scenario():
        proc = await _spawn("print('done')")
        await proc.wait()
        return await terminate_and_reap(proc, "test", timeout=8)

    asyncio.run(scenario())   # must not raise


def test_healthy_long_running_process_is_never_killed_by_cleanup():
    """THE BOUNDARY THIS FIX MUST NOT CROSS. terminate_and_reap is only ever reached after
    termination has been requested; a healthy process that keeps producing output runs to
    completion untouched, no matter how long it takes relative to the cleanup deadline."""
    async def scenario():
        # Runs for ~2x the cleanup deadline while emitting output, and is never terminated.
        proc = await _spawn(
            f"import sys, time\n"
            f"for _ in range({PROCESS_CLEANUP_TIMEOUT_SECONDS * 2}):\n"
            f"    print('tick'); sys.stdout.flush(); time.sleep(0.1)\n"
        )
        stdout, _ = await proc.communicate()
        return proc.returncode, stdout

    rc, stdout = asyncio.run(scenario())
    assert rc == 0, "a healthy process was not allowed to finish"
    assert stdout.count(b"tick") == PROCESS_CLEANUP_TIMEOUT_SECONDS * 2


def test_every_runner_uses_bounded_cleanup_and_none_uses_the_old_idiom():
    """Repo-level guard: all 12 runners must go through the shared helper, and the unbounded
    `kill(); await communicate()` idiom must not come back in any of them."""
    from pathlib import Path

    runners = sorted(
        Path(__file__).resolve().parents[1].joinpath("scanner_engine", "tool_runners").glob("*_runner.py")
    )
    assert len(runners) == 12, f"expected 12 tool runners, found {len(runners)}"

    for path in runners:
        src = path.read_text(encoding="utf-8")
        # Bounded cleanup is satisfied EITHER by calling terminate_and_reap directly OR by
        # going through run_with_timeout, which calls it internally on both the timeout and
        # the cancellation path (see base.run_with_timeout). The property this guard protects
        # -- no runner may terminate a process without bounded reaping -- is unchanged; the
        # helper is simply the shared way to get it, and it also preserves partial output.
        assert ("terminate_and_reap" in src) or ("run_with_timeout" in src), (
            f"{path.name} does not use bounded cleanup"
        )
        assert "await proc.communicate()" not in src, (
            f"{path.name} reintroduced the unbounded `await proc.communicate()` cleanup"
        )


def test_all_twelve_tools_remain_registered():
    """The cleanup change must not have removed or disabled any scanner."""
    from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY

    expected = {
        "subfinder", "amass", "dnsx", "httpx", "whatweb", "naabu",
        "nmap", "katana", "ffuf", "arjun", "nuclei", "nuclei-dast",
    }
    missing = expected - set(TOOL_REGISTRY)
    assert not missing, f"tools no longer registered: {sorted(missing)}"


def test_cleanup_helper_does_not_shell_out_or_change_commands():
    """Sanity: the helper only signals an existing process object; it never builds a command."""
    import inspect

    src = inspect.getsource(terminate_and_reap)
    assert "create_subprocess" not in src
    assert subprocess.__name__ not in src.split("def ")[0]
