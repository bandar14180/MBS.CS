import asyncio
import json
import logging
import time

from apps.api.core.config import get_settings
from apps.api.scanner_engine.tool_runners._web import content_discovery_targets
from apps.api.scanner_engine.tool_runners.base import (
    BaseToolRunner,
    CommonFinding,
    RawToolOutput,
    run_with_timeout,
)

logger = logging.getLogger("mbs.scanner.ffuf")

# --- Timeout policy -----------------------------------------------------------------------
# A FIXED per-target budget cannot fit a variable wordlist. Measured on the real scan:
# 4,614 words at -rate 40 has an ARITHMETIC FLOOR of ~115s (words/rate) before a single
# millisecond of latency, against a 180s budget -- only 1.56x headroom. The observed run
# needed 407s (2.26x the budget) and exited 0 with 146 hits, all discarded on timeout.
#
# The budget is therefore DERIVED from the workload:
#     budget = (wordlist_entries / rate) * SAFETY_MARGIN
# clamped to [MIN, MAX]. The margin covers per-request latency, retries and slow targets --
# the measured 407s/115s ratio is ~3.5x, so the default margin sits above that.
#
# `-se` still bails early on a blackholing host, so a genuinely dead target does NOT sit
# here burning the full budget. This is per-target only; no global timeout changes.
# The measured run took 407s against a 115s theoretical floor -- a real-world ratio of ~3.5x.
# A 4.0 margin yields 461s, only 1.13x over the measured time, which leaves nothing for a
# slower day. 6.0 yields ~692s (1.7x over measured), matching whatweb's and katana's headroom.
# Tunable per scan via tool_config `ffuf_timeout_margin`.
SAFETY_MARGIN = 6.0
MIN_TIMEOUT_SECONDS = 120
MAX_TIMEOUT_SECONDS = 1800  # documented safety ceiling; override via tool_config
FALLBACK_WORDLIST_ENTRIES = 4600  # used only when the wordlist cannot be counted


def count_wordlist_entries(path: str) -> int:
    """Non-empty lines in the wordlist, or a conservative fallback if it cannot be read.

    Never raises: an unreadable wordlist must not stop the scan, and the fallback keeps the
    derived budget in a sane range rather than collapsing it to the minimum."""
    try:
        with open(path, "rb") as fh:
            return sum(1 for line in fh if line.strip()) or FALLBACK_WORDLIST_ENTRIES
    except OSError:
        return FALLBACK_WORDLIST_ENTRIES


def compute_timeout(wordlist_entries: int, rate: int, margin: float = SAFETY_MARGIN) -> int:
    """Per-target budget from the actual workload. Pure, so it is unit-testable.

    words/rate is the theoretical MINIMUM duration; the margin is what makes it survivable on
    a real target. Clamped so a tiny wordlist still gets a workable floor and a huge one
    cannot run unbounded."""
    rate = max(1, int(rate))
    entries = max(1, int(wordlist_entries))
    budget = (entries / rate) * max(1.0, float(margin))
    return int(max(MIN_TIMEOUT_SECONDS, min(MAX_TIMEOUT_SECONDS, budget)))


DEFAULT_TIMEOUT_SECONDS = 180  # PER TARGET, not for the whole run
# Bound how many base URLs get fuzzed so a wide recon set can't fan out unbounded.
MAX_FUZZ_TARGETS = 10
# Cap stored hits per target so a noisy wordlist can't flood the findings table.
MAX_HITS_PER_TARGET = 200
# Fuzz this many targets at once.
#
# This used to be effectively 1: the targets were fuzzed in a plain sequential loop, so
# wall time was (targets x per-target timeout). That is the single biggest reason a scan
# appears to hang -- a real scan of a host with 5 httpx-confirmed services had ffuf at
# 550s and still running (5 x 180s = 900s worst case) while every other tool in the
# pipeline had finished in 79s or less.
#
# Each target is a SEPARATE host:port, so this parallelises across hosts rather than
# piling more load onto one -- per-host request rate is still governed by `-rate`
# (ffuf_rate), which is untouched. Worst-case wall time becomes roughly
# ceil(targets / 3) x timeout instead of targets x timeout. Same bounded-concurrency
# shape the arjun runner already uses.
MAX_CONCURRENT_TARGETS = 3


class FfufRunner(BaseToolRunner):
    """Content/directory discovery (ffuf). Distinct from katana's `web_crawling`
    (which follows links the app actually exposes): ffuf brute-forces a wordlist
    against each live host to surface paths with NO inbound link at all --
    backup files, admin panels, forgotten debug endpoints. Its `url` findings
    feed the same downstream tools katana's do (arjun param discovery, nuclei /
    nuclei-dast)."""

    name = "ffuf"
    version = "2.1.0"
    binary = "ffuf"
    requires_active_testing = True  # bulk wordlist-based active probing -> gated, like arjun
    capability = "content_discovery"
    phase = 46  # after katana (45) crawls; before arjun (48) discovers params on what's found
    kill_chain_phase = "reconnaissance"
    safety_tier = "active_safe"  # GET-only wordlist probing (no state change)
    applicable_target_types = {"domain", "ip_range"}

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        targets = content_discovery_targets(target_value, prior_findings)[:MAX_FUZZ_TARGETS]
        if not targets:
            return RawToolOutput(command="ffuf (no web targets)", stdout="", stderr="no web targets", exit_code=-1)

        wordlist = config.get("ffuf_wordlist_path") or get_settings().ffuf_wordlist_path
        if not wordlist:
            return RawToolOutput(
                command="ffuf (no wordlist configured)", stdout="", stderr="no wordlist configured", exit_code=-1
            )

        rate = str(config.get("ffuf_rate", 40))
        # Explicit tool_config wins; otherwise derive the per-target budget from the ACTUAL
        # wordlist and rate rather than a constant that cannot fit a variable workload.
        entries = count_wordlist_entries(wordlist)
        per_target_timeout = config.get("timeout_seconds") or compute_timeout(
            entries, int(rate), float(config.get("ffuf_timeout_margin", SAFETY_MARGIN))
        )
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_TARGETS)
        logger.info(
            "ffuf.start targets=%d concurrency=%d per_target_timeout=%ss rate=%s "
            "wordlist=%s entries=%d",
            len(targets), MAX_CONCURRENT_TARGETS, per_target_timeout, rate, wordlist, entries,
        )

        async def _fuzz_one(index: int, target: str) -> tuple[str, str, str, int]:
            """Fuzz ONE target. Returns (command, stdout, stderr, exit_code) and never
            raises -- a crash or timeout on one host is reported, not propagated, so the
            other targets still produce results."""
            url = target.rstrip("/") + "/FUZZ"
            command = [
                "ffuf",
                "-u", url,
                "-w", wordlist,
                "-mc", "200,204,301,302,307,401,403",
                "-json",
                "-s",
                "-timeout", "10",
                "-rate", rate,
                # Bail early when the target errors on (almost) every request instead of
                # grinding the whole wordlist against a dead host. A blackholing/rate-
                # limiting target -- the single most common ffuf slowness -- otherwise
                # consumes the full per-target timeout (180s) and returns nothing;
                # measured against such a host this exits in ~57s with "Receiving spurious
                # errors, exiting." A healthy target's normal 404s are NOT spurious errors,
                # so a real scan runs the full wordlist unaffected (verified: scanme.nmap.org
                # completes every request with -se on).
                "-se",
            ]
            command_str = " ".join(command)
            async with semaphore:
                # Logged per target, as it starts and as it ends: with a wordlist of a few
                # thousand entries each of these legitimately takes minutes, and without a
                # line here the only visible state is "ffuf is running" for the whole run.
                logger.info("ffuf.target_start %d/%d url=%s", index + 1, len(targets), url)
                started = time.monotonic()
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                    )
                except OSError as exc:  # binary missing / cannot spawn
                    logger.error("ffuf.target_failed url=%s error=%s", url, exc)
                    return command_str, "", f"{target}: {type(exc).__name__}: {exc}", -1
                # Incremental capture: a timeout now KEEPS the hits found so far instead of
                # discarding them (the measured run lost all 146).
                result = await run_with_timeout(proc, per_target_timeout, "ffuf")
                if result.timed_out:
                    hits = len([ln for ln in result.stdout.splitlines() if ln.strip()])
                    logger.warning(
                        "ffuf.target_timeout %d/%d url=%s after=%ss hits_preserved=%d -- raise "
                        "tool_config timeout_seconds, or narrow the wordlist, if this target matters",
                        index + 1, len(targets), url, per_target_timeout, hits,
                    )
                    # NOT success: exit_code -1 keeps the run classified partial/failed by the
                    # existing rules, while the hits already found are preserved.
                    return (
                        command_str,
                        result.stdout,
                        f"{target}: timed out after {per_target_timeout}s; preserved {hits} hit(s)",
                        -1,
                    )

                stdout = result.stdout
                stderr = result.stderr
                hits = sum(1 for line in stdout.splitlines() if line.strip())

                # `-se` makes ffuf exit 0 even when it bailed because the target errored on
                # (almost) every request. Left as exit 0 that reads as "completed, found
                # nothing" -- indistinguishable from a clean scan of a target that genuinely
                # has no hidden paths. Detect the bail and report it as a target-side failure
                # with the reason, the same way a timeout is surfaced, so "the target
                # rejected our requests" is never silently rendered as "all clear".
                if "spurious errors" in stderr.lower() and hits == 0:
                    logger.warning(
                        "ffuf.target_unreachable %d/%d url=%s duration=%.1fs -- ffuf bailed: "
                        "the target errored on (almost) every request (timeouts/refusals). "
                        "It is likely down, rate-limiting, or blocking automated scanners.",
                        index + 1, len(targets), url, time.monotonic() - started,
                    )
                    return command_str, "", f"{target}: target errored on every request (ffuf: spurious errors)", -1

                logger.info(
                    "ffuf.target_done %d/%d url=%s exit=%s hits=%d duration=%.1fs",
                    index + 1, len(targets), url, proc.returncode, hits, time.monotonic() - started,
                )
                return command_str, stdout, stderr, proc.returncode or 0

        results = await asyncio.gather(*(_fuzz_one(i, t) for i, t in enumerate(targets)))

        commands = [r[0] for r in results]
        stdout_parts = [r[1] for r in results if r[1]]
        stderr_parts = [r[2] for r in results if r[2]]
        # Any target that failed marks the run non-zero; the orchestrator still keeps the
        # findings the successful targets produced (classify_run -> "partial").
        exit_code = next((r[3] for r in results if r[3]), 0)

        return RawToolOutput(
            command=" && ".join(commands),
            stdout="\n".join(stdout_parts),
            stderr="\n".join(stderr_parts),
            exit_code=exit_code,
        )

    def parse(self, raw: RawToolOutput) -> list[CommonFinding]:
        # ffuf's -json mode prints one JSON object per matched result (ffuf's own
        # jsonl-style line output, distinct from its `-o`/`-of json` full report).
        findings: list[CommonFinding] = []
        seen: set[str] = set()
        for line in raw.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = obj.get("url")
            if not url or url in seen:
                continue
            seen.add(url)
            findings.append(
                CommonFinding(
                    asset_type="url",
                    value=url,
                    metadata={
                        "source": "ffuf",
                        "status_code": obj.get("status"),
                        "length": obj.get("length"),
                        "has_params": "?" in url,
                    },
                )
            )
            if len(findings) >= MAX_HITS_PER_TARGET:
                break
        return findings
