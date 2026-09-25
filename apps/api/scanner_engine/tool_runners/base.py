import asyncio
import contextlib
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

logger = logging.getLogger("mbs.scanner.cleanup")

# How often the optional RSS watchdog samples a child process, in seconds.
#
# SIZED FROM THE MEASURED GROWTH RATE, not picked for tidiness. The runaway this exists to
# contain grows at ~660 MiB/s (48 MiB -> 3695 MiB in 5.5s, measured). A sampling interval of
# `i` seconds therefore lets the process overshoot its ceiling by up to ~660*i MiB before the
# next sample sees it, so the interval and the ceiling's headroom are one decision, not two:
# at 0.25s the worst-case overshoot is ~165 MiB, which the chosen headroom absorbs many times
# over. It is also cheap -- one small /proc read per sample, four per second, against a
# process doing hundreds of MiB/s of allocation -- so it cannot materially affect a healthy
# run. A single delayed sample would be useless here: the whole runaway completes in ~6s.
RSS_SAMPLE_INTERVAL_SECONDS = 0.25


def read_process_rss_bytes(pid: int) -> int | None:
    """Resident set size of `pid` in bytes, or None when it cannot be read.

    Reads /proc/<pid>/status (VmRSS) rather than taking a psutil dependency -- the same
    approach this module's neighbours already use for cgroup files, and the only thing
    available inside the worker image.

    RETURNS None, NEVER RAISES, on every failure mode: the process exited between the caller
    deciding to sample and this read (ProcessLookupError / FileNotFoundError), /proc is not
    mounted (a non-Linux dev host), permissions, or a malformed line. None means "no
    information", and the caller MUST treat that as "do not act" -- a watchdog that killed on
    a failed read would be a worse bug than the one it guards against.
    """
    try:
        with open(f"/proc/{pid}/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    # "VmRSS:  123456 kB"
                    return int(parts[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None

# How long to wait for an ALREADY-TERMINATED process to be reaped and its pipes to close.
#
# THIS IS NOT A SCANNER EXECUTION TIMEOUT. It never limits how long a tool may RUN -- it
# only bounds the cleanup that happens AFTER termination has already been requested, so a
# worker cannot block forever collecting the corpse of a process it just killed. A healthy
# long-running scan never reaches this code path at all.
PROCESS_CLEANUP_TIMEOUT_SECONDS = 10


async def terminate_and_reap(proc, tool: str = "", *, timeout: float = PROCESS_CLEANUP_TIMEOUT_SECONDS):
    """Kill `proc` and collect whatever it already wrote, without ever blocking forever.

    WHY THIS EXISTS (both failure modes reproduced against real subprocesses, not assumed):

      1. UNBOUNDED CLEANUP. The previous idiom was `proc.kill(); await proc.communicate()`.
         `communicate()` waits for EOF on the pipes, and SIGKILL to the direct child does
         NOT close a pipe that a surviving GRANDCHILD still holds open -- so the await never
         returns and the worker hangs on that scan indefinitely. Reproduced with a child that
         spawns a grandchild inheriting stdout: cleanup blocked until the test killed it.
         This matters here because several of this project's tools do exactly that
         (whatweb is Ruby, arjun is Python, amass spawns helpers).

      2. ORPHANED PROCESSES ON CANCELLATION. When a scan is revoked or the worker warm-shuts
         down, the orchestrator cancels the tool task (see `_run_with_progress`). If that
         cancellation lands while awaiting `communicate()`, the CancelledError propagates out
         and the subprocess is simply LEFT RUNNING -- verified: the child's returncode stayed
         None after cancellation. `finally`-calling this function fixes that, and it
         deliberately re-raises CancelledError after killing so cancellation semantics are
         preserved.

    Returns (stdout, stderr) as bytes -- whatever was collected before the deadline, so
    PARTIAL RESULTS SURVIVE termination wherever the OS made them available. On a cleanup
    timeout the process is killed again and abandoned rather than awaited a second time,
    and the event is logged loudly: the worker staying responsive is worth more than the
    last unflushed bytes of a process that is already dead."""
    # The kill happens FIRST and synchronously, before any await. That ordering is what makes
    # this safe inside an `except asyncio.CancelledError:` handler: a second cancellation can
    # interrupt the await below, but the signal has already been delivered, so the process
    # cannot survive as an orphan even in that race.
    if proc.returncode is None:
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.kill()
    try:
        return await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        # The pipes did not close within the cleanup window -- almost always a surviving
        # grandchild holding them open. Do NOT await communicate() again (that is exactly
        # the unbounded wait this function exists to prevent).
        logger.error(
            "tool.cleanup_timeout tool=%s pid=%s -- process did not reap within %ss; "
            "abandoning its pipes to keep the worker responsive (a surviving grandchild "
            "may still hold them open)",
            tool or "?", getattr(proc, "pid", "?"), timeout,
            extra={"event": "tool.cleanup_timeout", "tool": tool,
                   "pid": getattr(proc, "pid", None), "timeout_s": timeout},
        )
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.kill()
        return b"", b""
    except asyncio.CancelledError:
        # Cancelled *during* cleanup. The kill above already went out; re-raise so the
        # caller's cancellation is not silently swallowed.
        raise


@dataclass
class TimedRun:
    """Result of `run_with_timeout`: output captured so far, and whether time ran out."""

    stdout: str
    stderr: str
    timed_out: bool
    exit_code: int | None
    # Whether the process was stopped because it exceeded `max_stdout_bytes`/`max_stderr_bytes`
    # rather than because its wall clock expired. This is a THIRD outcome, deliberately not
    # folded into `timed_out`: a caller that conflates them would raise a time budget that was
    # never the constraint. Defaulted False so the eleven runners that pass no output budget
    # construct and behave exactly as before.
    resource_limited: bool = False
    # Bytes actually produced on each pipe, INCLUDING anything dropped after the budget was
    # reached. `len(stdout)` alone cannot answer "how much did the tool really emit?" once a
    # cap is in play, and the reproducibility trace needs the real figure.
    stdout_bytes_seen: int = 0
    stderr_bytes_seen: int = 0
    # Complete lines seen on stdout, on the same "including what was dropped" basis.
    stdout_lines_seen: int = 0
    # WHICH budget fired, e.g. "stdout_lines", "stdout_bytes" or "rss". Empty when none did.
    # This is what lets a caller report the limit that actually bound the run instead of
    # guessing -- an operator told "output budget exceeded" cannot tell whether to raise the
    # line cap or the byte cap, and those are different decisions.
    limit_tripped: str = ""
    # Highest RSS observed for the child, in bytes, when an RSS watchdog was armed. None when
    # no watchdog ran or no sample ever succeeded -- deliberately None rather than 0, because
    # "not measured" and "measured as nothing" are different facts and a provenance record
    # must not blur them.
    peak_rss_bytes: int | None = None


async def run_with_timeout(
    proc,
    timeout: float | None,
    tool: str = "",
    *,
    stdin: bytes | None = None,
    max_stdout_bytes: int | None = None,
    max_stderr_bytes: int | None = None,
    max_stdout_lines: int | None = None,
    max_rss_bytes: int | None = None,
    # Resolved from the module constant at CALL time, not bound as a default at import time,
    # so the sampling rate is one value with one definition -- a default argument would
    # silently freeze a copy of it into this function's signature.
    rss_sample_interval: float | None = None,
) -> TimedRun:
    """Run `proc` to completion or to `timeout`, KEEPING whatever it wrote either way.

    WHY THIS EXISTS. The previous idiom in every runner was
    `await asyncio.wait_for(proc.communicate(), timeout=...)`. On timeout `wait_for` cancels
    `communicate()`, and the buffers it was assembling are discarded with it -- so a tool that
    had already produced most of its results returned NOTHING. Measured on a real authorized
    target: katana emitted 858 URLs in 360s but its 300s budget produced an EMPTY stdout, and
    ffuf's 146 hits were lost the same way. The findings existed; the timeout threw them away.

    This drains both pipes into buffers as the process writes, so a timeout keeps the partial
    output. Three properties, each of which the old idiom got wrong or only got right by luck:

      * PARTIAL OUTPUT SURVIVES. Whatever arrived before the deadline is returned.
      * NO PIPE DEADLOCK. Both stdout and stderr are drained CONCURRENTLY. A tool that fills
        the 64KB stderr pipe while the reader is blocked on stdout would otherwise hang until
        its timeout -- the classic subprocess deadlock, which `communicate()` avoids and a
        naive sequential read does not.
      * BOUNDED CLEANUP. Termination goes through the existing, tested `terminate_and_reap`,
        so there are no orphans and no unbounded waits.

    `timeout=None` (or <= 0) means no wall-clock limit -- the nuclei policy -- so this helper
    can be adopted by runners that must not be capped.

    OUTPUT BUDGET (`max_stdout_bytes` / `max_stderr_bytes` / `max_stdout_lines`). A wall clock does NOT bound
    memory: a tool that emits fast enough fills this parent's buffers long before its deadline.
    Measured on katana against a real target: one input produced 163,761 URLs (~16 MiB of
    text), and because every byte was accumulated here, joined, and then decoded to a `str`,
    the parent held several multiples of that -- for a parser that keeps 500 URLs. When a
    budget is given, the drain STOPS ACCUMULATING at the cap, terminates the process through
    the same tested `terminate_and_reap`, and returns `resource_limited=True`.

    `max_stdout_lines` is a SECOND, independent bound on the same pipe, in complete lines
    (newlines). It exists because bytes and records are different units and a caller may need
    a real guarantee in the unit its own contract is written in: katana's budget is stated in
    URLs, and a byte cap alone could not honour that -- short URLs let far more than the
    stated count through before the byte cap fires. Whichever bound is reached FIRST wins, and
    `limit_tripped` names it. Line accounting happens on chunks already read (a newline count
    over a buffer we are holding anyway), so it accumulates nothing and cannot reintroduce the
    unbounded-memory path. The line cap keeps WHOLE LINES only: truncating mid-line would emit
    a partial record that looks like a complete one.

    All three are None by default, which is byte-for-byte the previous behaviour -- the eleven
    runners that do not pass one are entirely unaffected.

    RSS BUDGET (`max_rss_bytes`). The output budgets above bound what the tool hands back to
    THIS process; they say nothing about what the tool allocates inside its own address space.
    Those are different resources with different failure modes, and the second one is not
    hypothetical: katana with `-jsluice` was measured going 48 MiB -> 3695 MiB in 5.5s
    (~660 MiB/s) while emitting ONE line of stdout, which no output cap can see. In a shared
    memory-capped container that exhausts the cgroup and the kernel OOM killer takes a victim
    of its own choosing -- which may be the worker, not the tool.

    When `max_rss_bytes` is given, a watchdog samples the CHILD PROCESS's own RSS every
    `rss_sample_interval` seconds and, if it exceeds the ceiling, stops that child through the
    same `terminate_and_reap` path as the output budgets and returns `resource_limited=True`
    with `limit_tripped="rss"`. It acts ONLY on `proc.pid` -- the exact child this call owns --
    and never on the worker, a process group, or anything it did not spawn. A failed or
    impossible RSS read (no /proc, process already gone, malformed file) is treated as "no
    information" and never as a reason to kill.

    None by default, so every existing call site is unaffected.

    What the cap does NOT do: it never discards output that was already collected (everything
    up to the cap is returned), and it never reports a capped run as a success. It is a bound
    on this process's memory, not a way to make a large crawl look small.

    Returns a TimedRun; the CALLER decides what a timeout means for its tool. This function
    never converts a failure into a success and never fabricates output.
    """
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    # Bytes SEEN per pipe, which is not the same as bytes kept once a budget is in force.
    seen = {"stdout": 0, "stderr": 0}
    # Complete LINES seen on stdout (counted as newlines). Only stdout has a line budget:
    # stderr is diagnostics, where bytes are the only meaningful unit.
    lines_seen = {"stdout": 0, "stderr": 0}
    # Which budget actually fired, for truthful reporting. A caller that cannot distinguish
    # "too many URLs" from "too many bytes" cannot tell an operator which limit to raise.
    tripped: list[str] = []
    # Set by whichever pipe hits a cap first -- or by the RSS watchdog. An asyncio.Event
    # rather than a bare flag so the waiter below is woken immediately instead of polling.
    budget_exceeded = asyncio.Event()
    # Highest RSS the watchdog observed, in bytes. Stays None when no watchdog is armed or
    # when no sample ever succeeded.
    peak_rss: dict[str, int | None] = {"bytes": None}

    async def _rss_watchdog() -> None:
        """Sample THIS child's RSS and trip the shared budget event if it exceeds the cap.

        SCOPE, deliberately narrow. The only pid it ever reads is `proc.pid`, captured from
        the process this call was handed. It does not walk children, does not touch a process
        group, and does not read the cgroup -- so it cannot select an unrelated victim even if
        /proc is lying to it, and there is no pid it could act on but this one.

        It never kills anything itself. Tripping `budget_exceeded` hands termination to the
        single existing path below (`terminate_and_reap`), so there is exactly one place in
        this module that stops a process, whatever the reason.

        MONOTONIC PACING. The loop sleeps against `time.monotonic()` deadlines rather than
        accumulating `sleep(interval)` drift, so a slow sample cannot silently stretch the
        effective interval -- which is the sampling rate the ceiling's headroom was sized
        against. A wall-clock jump cannot move it either.
        """
        pid = getattr(proc, "pid", None)
        if pid is None:
            return
        interval = (
            rss_sample_interval if rss_sample_interval is not None
            else RSS_SAMPLE_INTERVAL_SECONDS
        )
        next_at = time.monotonic()
        while True:
            next_at += interval
            await asyncio.sleep(max(0.0, next_at - time.monotonic()))
            if proc.returncode is not None:
                return  # exited on its own; nothing left to watch
            rss = read_process_rss_bytes(pid)
            if rss is None:
                # NO INFORMATION -- the process is gone, /proc is unavailable, or the read
                # failed. Keep watching (a transient read error must not silently disarm the
                # guard) but NEVER act: killing on a failed read is how a watchdog kills the
                # wrong thing.
                continue
            current_peak = peak_rss["bytes"]
            if current_peak is None or rss > current_peak:
                peak_rss["bytes"] = rss
            if max_rss_bytes is not None and rss > max_rss_bytes:
                tripped.append("rss")
                budget_exceeded.set()
                return

    async def _drain(
        stream, sink: list[bytes], which: str, cap: int | None, line_cap: int | None = None
    ) -> None:
        if stream is None:
            return
        kept = 0  # running total of bytes in `sink`, so the cap check stays O(1) per chunk
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                return
            seen[which] += len(chunk)
            if cap is None and line_cap is None:
                sink.append(chunk)
                continue

            # --- LINE budget -------------------------------------------------------------
            # Enforced while STREAMING, on chunks already read -- counting newlines in a
            # buffer we are holding anyway. Nothing is accumulated to evaluate it, so this
            # cannot reintroduce the unbounded-memory path it sits beside.
            if line_cap is not None:
                before = lines_seen[which]
                newlines = chunk.count(b"\n")
                if before + newlines >= line_cap:
                    # The cap lands INSIDE this chunk. Keep whole lines only, up to and
                    # including the one that reaches the cap -- truncating mid-line here
                    # would emit a partial URL that looks like a real one.
                    wanted = line_cap - before
                    cut = 0
                    for _ in range(wanted):
                        cut = chunk.index(b"\n", cut) + 1
                    piece = chunk[:cut]
                    if cap is not None:
                        piece = piece[: max(0, cap - kept)]
                    sink.append(piece)
                    kept += len(piece)
                    lines_seen[which] = before + newlines
                    tripped.append(f"{which}_lines")
                    budget_exceeded.set()
                    return
                lines_seen[which] = before + newlines

            # --- BYTE budget -------------------------------------------------------------
            # Keep the prefix that still fits -- PARTIAL OUTPUT UP TO THE CAP IS PRESERVED,
            # never dropped wholesale -- then stop accumulating and signal. We read nothing
            # further: the waiter terminates the process, which is what stops the writer.
            if cap is None:
                sink.append(chunk)
                kept += len(chunk)
                continue
            if kept < cap:
                piece = chunk[: cap - kept]
                sink.append(piece)
                kept += len(piece)
            if seen[which] >= cap:
                tripped.append(f"{which}_bytes")
                budget_exceeded.set()
                return

    async def _feed() -> None:
        """Write stdin (katana takes its target list this way) and close, so the tool sees EOF."""
        if stdin is None or proc.stdin is None:
            return
        try:
            proc.stdin.write(stdin)
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass  # tool exited before reading its input; its own output still tells the story
        finally:
            with contextlib.suppress(Exception):
                proc.stdin.close()

    def _decode() -> tuple[str, str]:
        return (
            b"".join(stdout_chunks).decode(errors="replace"),
            b"".join(stderr_chunks).decode(errors="replace"),
        )

    pumps = asyncio.gather(
        _feed(),
        _drain(proc.stdout, stdout_chunks, "stdout", max_stdout_bytes, max_stdout_lines),
        _drain(proc.stderr, stderr_chunks, "stderr", max_stderr_bytes),
    )

    async def _pumps_or_budget() -> None:
        """Finish when the pumps drain naturally OR when an output budget is blown.

        Without this race the budget could only be noticed AFTER the process exited on its
        own -- which is precisely the case a budget exists to prevent. `asyncio.wait` is used
        rather than a second gather so the losing task is left intact for the caller to
        cancel deterministically below."""
        if (max_stdout_bytes is None and max_stderr_bytes is None
                and max_stdout_lines is None and max_rss_bytes is None):
            await pumps
            return
        # `pumps` is passed DIRECTLY, never wrapped in a helper task. A wrapper looks
        # type-cleaner but is wrong: cancelling the wrapper propagates the cancellation into
        # the gather it awaits and kills the drain, discarding the very output this function
        # exists to preserve. VERIFIED against a real event loop -- with a wrapper, the
        # underlying worker made zero further progress after the wrapper was cancelled and
        # the gather raised CancelledError (while `gather.cancelled()` still read False,
        # which is what makes the bug easy to miss).
        #
        # Only `waiter` is cancelled in the `finally`, because it is ours and is pure
        # bookkeeping. Whether the PUMPS are cancelled or awaited is decided by the caller
        # below, which is the only place that knows which outcome occurred.
        #
        # The set is heterogeneous (Future[list[Any]] vs Task[bool]) and mypy widens it to
        # `object`, which asyncio.wait's type var rejects; the ignore is narrow and the
        # runtime behaviour is exactly what asyncio documents for a mixed awaitable set.
        waiter = asyncio.ensure_future(budget_exceeded.wait())
        # ARMED ONLY WHEN A CEILING WAS GIVEN. With max_rss_bytes None there is no watchdog
        # task at all -- not a task that samples and declines to act -- so the default path
        # costs nothing and cannot be the thing that changes a healthy run's behaviour.
        watchdog = (
            asyncio.ensure_future(_rss_watchdog()) if max_rss_bytes is not None else None
        )
        try:
            await asyncio.wait(  # type: ignore[type-var]
                {pumps, waiter}, return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            waiter.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await waiter
            # The watchdog is ours and is pure bookkeeping, so it is always torn down here --
            # on every exit from this function, including the timeout and cancellation paths
            # above. Leaving it running would keep sampling a pid that is about to be reaped
            # and, worse, could be recycled by the OS.
            if watchdog is not None:
                watchdog.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await watchdog

    try:
        if timeout is not None and timeout > 0:
            await asyncio.wait_for(asyncio.shield(_pumps_or_budget()), timeout=timeout)
        else:
            await _pumps_or_budget()

        if budget_exceeded.is_set():
            # RESOURCE LIMITED, not a timeout and not a success. Stop the pumps, terminate the
            # process through the same tested reaper (no orphans, bounded cleanup), and return
            # everything collected up to the cap.
            pumps.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await pumps
            await terminate_and_reap(proc, tool)
            out, err = _decode()
            which = tripped[0] if tripped else ""
            logger.warning(
                "tool.output_budget_exceeded tool=%s limit_tripped=%s stdout_cap=%s "
                "stdout_line_cap=%s stderr_cap=%s rss_cap=%s peak_rss=%s stdout_seen=%d "
                "stdout_lines_seen=%d stderr_seen=%d stdout_kept=%d -- process terminated",
                tool or "?", which or "?", max_stdout_bytes, max_stdout_lines,
                max_stderr_bytes, max_rss_bytes, peak_rss["bytes"],
                seen["stdout"], lines_seen["stdout"], seen["stderr"],
                len(out),
                extra={"event": "tool.output_budget_exceeded", "tool": tool,
                       "limit_tripped": which, "stdout_cap": max_stdout_bytes,
                       "stdout_line_cap": max_stdout_lines,
                       "rss_cap": max_rss_bytes, "peak_rss_bytes": peak_rss["bytes"],
                       "stdout_seen": seen["stdout"],
                       "stdout_lines_seen": lines_seen["stdout"]},
            )
            return TimedRun(
                stdout=out, stderr=err, timed_out=False, exit_code=proc.returncode,
                resource_limited=True,
                stdout_bytes_seen=seen["stdout"], stderr_bytes_seen=seen["stderr"],
                stdout_lines_seen=lines_seen["stdout"], limit_tripped=which,
                peak_rss_bytes=peak_rss["bytes"],
            )

        await proc.wait()
        out, err = _decode()
        return TimedRun(
            stdout=out, stderr=err, timed_out=False, exit_code=proc.returncode,
            stdout_bytes_seen=seen["stdout"], stderr_bytes_seen=seen["stderr"],
            stdout_lines_seen=lines_seen["stdout"], peak_rss_bytes=peak_rss["bytes"],
        )
    except asyncio.TimeoutError:
        # The deadline passed. Stop the pumps, kill the process, and RETURN WHAT WE HAVE.
        # `pumps.cancel()` then `await pumps` re-raises CancelledError, which
        # contextlib.suppress(Exception) does NOT catch (it derives from BaseException) -- so
        # awaiting it here would escape BEFORE the kill and leave the process running. Suppress
        # CancelledError explicitly.
        pumps.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await pumps
        await terminate_and_reap(proc, tool)
        out, err = _decode()
        logger.info(
            "tool.partial_output tool=%s timeout_s=%s stdout_bytes=%d stderr_bytes=%d",
            tool or "?", timeout, len(out), len(err),
            extra={"event": "tool.partial_output", "tool": tool, "timeout_s": timeout,
                   "stdout_bytes": len(out)},
        )
        return TimedRun(
            stdout=out, stderr=err, timed_out=True, exit_code=proc.returncode,
            stdout_bytes_seen=seen["stdout"], stderr_bytes_seen=seen["stderr"],
            stdout_lines_seen=lines_seen["stdout"], peak_rss_bytes=peak_rss["bytes"],
        )
    except asyncio.CancelledError:
        # Scan revoked / worker shutdown. Kill the child (otherwise it is left running --
        # verified) and re-raise so cancellation semantics are preserved.
        pumps.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await pumps
        await terminate_and_reap(proc, tool)
        raise


@dataclass
class RawToolOutput:
    command: str
    stdout: str
    stderr: str
    exit_code: int
    # Whether the tool's wall-clock budget was exceeded (Prompt 10: execution determinism &
    # trace). Every runner already computes this -- `run_with_timeout` returns it on its
    # `TimedRun` -- but until now it was discarded the moment a runner folded it into a
    # `"timed out"` string appended to stderr and an exit_code of -1. That collapsed two
    # different failure shapes (a genuine tool crash vs. a budget expiring) into the same
    # signal, so a caller could only tell them apart by string-matching stderr. Defaulted to
    # False so every existing positional/keyword `RawToolOutput(...)` construction across the
    # 12 tool runners keeps working unchanged; only the timeout branch in each runner sets it.
    timed_out: bool = False


@dataclass
class CommonFinding:
    """An inventory finding (a discovered asset). The orchestrator upserts these
    into the assets table. Adding a new tool means writing an adapter that
    produces these, nothing upstream needs to change (blueprint §4/§8)."""

    asset_type: str
    value: str
    metadata: dict = field(default_factory=dict)


@dataclass
class VulnerabilityFinding:
    """A vulnerability finding (something wrong, not just something present).
    The orchestrator feeds these to the Vulnerability Engine, which dedupes them
    across scans and links each to the tool-run evidence that produced it
    (blueprint §1: no evidence => not a finding)."""

    fingerprint: str  # stable identity for dedup across re-scans (e.g. template-id@matched-at)
    title: str
    severity: str  # info | low | medium | high | critical
    category: str | None = None  # CWE id / OWASP category / template tag
    description: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None
    matched_at: str | None = None  # URL/host:port the finding was observed at
    metadata: dict = field(default_factory=dict)


def classify_run(runner: "BaseToolRunner", raw: RawToolOutput, produced_findings: bool) -> str:
    """Classify a completed tool run as completed | partial | failed (the resilient
    pipeline's core rule; kept pure so it is unit-testable without a DB).

    - completed: exit 0, or a non-zero code the runner declares benign.
    - partial:   non-zero (non-benign) exit that still yielded usable output.
    - failed:    a hard failure the runner flags, or a non-zero exit with nothing
                 usable to keep.
    (A runner that raises/times out is handled by the caller, not here.)"""
    if runner.hard_failure(raw):
        return "failed"
    if raw.exit_code == 0 or raw.exit_code in runner.benign_exit_codes:
        return "completed"
    if produced_findings or raw.stdout.strip():
        return "partial"
    return "failed"


class BaseToolRunner(ABC):
    name: str
    version: str
    requires_active_testing: bool = False

    # The executable this runner shells out to, as passed to
    # asyncio.create_subprocess_exec (usually == `name`, but not always: the httpx
    # binary is installed as `httpx-pd` to avoid colliding with the Python httpx
    # library, and nuclei-dast drives the same `nuclei` binary as nuclei). Declared
    # here so scanner_engine.tool_preflight can answer "is this tool actually
    # installed in THIS process's PATH?" without a second, drift-prone name map --
    # a missing binary is otherwise indistinguishable, from the report alone, from
    # "ran and found nothing".
    binary: str = ""

    # The assessment CAPABILITY this tool provides (e.g. "subdomain_discovery",
    # "vulnerability_detection") -- the identity the AI decision layers
    # (AIPlanner, RedTeamAgent) reason about, independent of which binary
    # implements it. See scanner_engine.capability_registry: a future second
    # implementation of the same capability (e.g. a `massdns` runner alongside
    # `subfinder`) just registers under the same string here -- nothing in the
    # AI prompts or decision code needs to change.
    capability: str = ""

    # Position in the deterministic recon pipeline; the orchestrator runs
    # requested tools in ascending phase order regardless of request order.
    phase: int = 100

    # Cyber Kill Chain phase this tool serves (values match
    # modules.attack.catalog.KillChainPhase.*). Lets the autonomous agent pick
    # tools appropriate to the current phase and reason about progression.
    kill_chain_phase: str = "reconnaissance"

    # Safety classification (values match scanner_engine.safety.SafetyTier.*). The
    # agent may only run a tool whose tier is within the engagement's Rules of
    # Engagement. Default active_safe; passive recon tools override to "passive".
    safety_tier: str = "active_safe"

    # Target `type` values this tool applies to (None = all). The orchestrator
    # skips a requested runner when the target type doesn't match, instead of
    # running it and recording a failure (e.g. subfinder only makes sense on a
    # domain, not an ip_range).
    applicable_target_types: set[str] | None = None

    # Non-zero exit codes this tool returns on benign conditions (e.g. "host
    # down", "no results") -- the orchestrator treats these as success, not
    # failure. Empty by default; a genuine non-zero exit is then classified as
    # `partial` (parseable output was still produced) or `failed` (none), and in
    # neither case does one tool abort the whole scan (resilient pipeline).
    benign_exit_codes: frozenset[int] = frozenset()

    @abstractmethod
    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        """Execute the tool. `prior_findings` are the CommonFindings accumulated
        by earlier-phase tools in the same scan, so a runner can build on them
        (e.g. httpx probes subfinder's subdomains, nmap deep-scans naabu's
        ports). An empty list means run against `target_value` alone."""

    @abstractmethod
    def parse(self, raw: RawToolOutput) -> list[CommonFinding]:
        """Assets discovered by this tool. Recon tools implement this."""

    def parse_vulnerabilities(self, raw: RawToolOutput) -> list["VulnerabilityFinding"]:
        """Vulnerabilities found by this tool. Defaults to none so recon tools
        (which only inventory assets) don't need to implement it; vuln scanners
        like Nuclei override it."""
        return []

    def hard_failure(self, raw: RawToolOutput) -> bool:
        """Whether this raw output is a definitive tool failure regardless of any
        parseable content (override for tool-specific error signatures, e.g. an
        auth/usage error in stderr). Default False: the orchestrator then
        classifies purely on exit code + whether usable output was produced."""
        return False
