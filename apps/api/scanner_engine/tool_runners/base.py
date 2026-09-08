import asyncio
import contextlib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

logger = logging.getLogger("mbs.scanner.cleanup")

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


async def run_with_timeout(proc, timeout: float | None, tool: str = "", *, stdin: bytes | None = None) -> TimedRun:
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

    Returns a TimedRun; the CALLER decides what a timeout means for its tool. This function
    never converts a failure into a success and never fabricates output.
    """
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []

    async def _drain(stream, sink: list[bytes]) -> None:
        if stream is None:
            return
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                return
            sink.append(chunk)

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
        _drain(proc.stdout, stdout_chunks),
        _drain(proc.stderr, stderr_chunks),
    )
    try:
        if timeout is not None and timeout > 0:
            await asyncio.wait_for(asyncio.shield(pumps), timeout=timeout)
        else:
            await pumps
        await proc.wait()
        out, err = _decode()
        return TimedRun(stdout=out, stderr=err, timed_out=False, exit_code=proc.returncode)
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
        return TimedRun(stdout=out, stderr=err, timed_out=True, exit_code=proc.returncode)
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
