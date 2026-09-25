import asyncio
import json
import logging
import os
import tempfile
import time

from apps.api.scanner_engine.tool_runners._web import param_discovery_targets
from apps.api.scanner_engine.tool_runners.base import (
    BaseToolRunner,
    CommonFinding,
    RawToolOutput,
    run_with_timeout,
)

logger = logging.getLogger("mbs.scanner.arjun")

# arjun's runtime is dominated by how many HTTP round-trips it makes to the TARGET and how long
# each one takes -- NOT by wordlist size alone. Measured extensively against a real, slow
# WordPress target (lincoln.edu.my): arjun's default `large.txt` (25,889 params) took ~575s;
# the small list (835 params) still took ~183s; and the time is erratic because that server
# responds slowly/variably and WordPress accepts many params, so arjun's per-hit binary-search
# narrowing explodes. There is no flag combo that is both fast AND accurate on such a target --
# a short per-request timeout (`-T 3`) finished in ~33s but found nothing (the server didn't
# answer in time), while `-T 5+` let the narrowing run for minutes. So the defaults below aim
# for "works and stays out of the way," and EVERY knob is overridable via tool_config for a
# caller who wants to trade accuracy for speed (or vice-versa) on a specific engagement.
DEFAULT_WORDLIST = "small"     # 835 common params -- covers the high-value injectable names that
# param discovery actually needs to feed the fuzzer. Opt up via tool_config arjun_wordlist.
_WORDLIST_NAMES = ("small", "medium", "large")
DEFAULT_THREADS = 15           # up from arjun's own default of 5 -- a safe parallelism boost that
# helps without hurting accuracy. Overridable via tool_config arjun_threads.
DEFAULT_REQUEST_TIMEOUT = 10   # arjun's `-T` (per-HTTP-request timeout). 10s is accurate on a slow
# server; lower it (arjun_request_timeout) for speed at the cost of missing params on slow hosts.

DEFAULT_TIMEOUT_SECONDS = 300  # OVERALL per-target cap. Enough for arjun to actually COMPLETE on a
# moderately slow host (~183s observed) and produce findings, rather than always timing out with
# nothing. On timeout the tool is killed and the scan continues (resilient) -- arjun never blocks
# the pipeline. Overridable via tool_config param_discovery_timeout_seconds.
MAX_CONCURRENT_TARGETS = 3     # run this many arjun subprocesses at once. Sequential would make
# a full param_discovery_max=10 batch take up to 10x DEFAULT_TIMEOUT_SECONDS in the worst case;
# bounding concurrency keeps worst-case wall time close to one DEFAULT_TIMEOUT_SECONDS window
# regardless of how many endpoints there are to probe.
MAX_PARAMS_PER_URL = 15        # cap so a synthesised URL doesn't get absurdly long


def _resolve_wordlist(name_or_path: str) -> str | None:
    """Map a wordlist selector to an on-disk arjun wordlist path. Accepts a short name
    ("small"/"medium"/"large") resolved against arjun's own bundled `db/` dir, or an absolute
    path used as-is. Returns None if it can't be resolved (caller then omits `-w`, so arjun
    falls back to its own default -- never a crash)."""
    if not name_or_path:
        return None
    if os.path.isabs(name_or_path) and os.path.exists(name_or_path):
        return name_or_path
    name = str(name_or_path).strip().lower()
    if name not in _WORDLIST_NAMES:
        return None
    try:
        import arjun  # arjun bundles its wordlists next to its package
    except ImportError:
        return None
    path = os.path.join(os.path.dirname(arjun.__file__), "db", f"{name}.txt")
    return path if os.path.exists(path) else None


class ArjunRunner(BaseToolRunner):
    """HTTP parameter discovery (arjun). The crawler finds endpoint *paths*, but a
    JSON API's parameter *names* (e.g. ?q=, ?file=, ?id=) live in JS that builds
    the request dynamically, so a plain crawl misses them -- and a fuzzer with no
    parameter has nothing to inject. arjun brute-forces valid parameter names per
    endpoint, and we emit `url` findings carrying those params so nuclei-dast can
    then fuzz them. This is what turns discovered API paths into fuzzable targets."""

    name = "arjun"
    version = "2.2.7"
    binary = "arjun"
    requires_active_testing = True  # actively probes endpoints with a param wordlist -> gated
    capability = "parameter_discovery"
    phase = 48  # after katana (45) has the endpoints, before nuclei-dast (55) fuzzes them
    kill_chain_phase = "reconnaissance"
    safety_tier = "active_safe"  # benign GET probes to enumerate params (no state change)
    applicable_target_types = {"domain", "ip_range"}

    async def _probe_one(
        self, url: str, timeout: float, wordlist: str | None, threads: int, request_timeout: int
    ) -> tuple[str, dict, str | None, bool, bool]:
        """Run arjun against a SINGLE url. Returns (command_str, found_params, error_or_None,
        clean, timed_out). Never raises -- a crash/timeout on this one url is this function's
        problem to report, not the caller's to catch. `timed_out` is reported as a structured
        boolean (not inferred later by matching the word "timed out" in `error`) so the
        aggregate RawToolOutput can carry a real timeout signal (Prompt 10)."""
        out_fd, out_path = tempfile.mkstemp(suffix=".json")
        os.close(out_fd)
        os.remove(out_path)  # arjun writes this path itself; just need a fresh unique name

        command = ["arjun", "-u", url, "-oJ", out_path, "-m", "GET", "-T", str(request_timeout), "-t", str(threads)]
        if wordlist:
            command += ["-w", wordlist]
        command_str = " ".join(command)
        logger.info("arjun.target_start url=%s timeout=%ss", url, timeout)
        started = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            # arjun writes its findings to `out_path` (-oJ), not stdout, so the incremental
            # stdout/stderr capture run_with_timeout provides is not what preserves partial
            # results here -- the file is. What WAS missing on timeout: the out_path read
            # below was skipped entirely, so params arjun had already flushed to disk before
            # being killed were discarded. Now the file is read whether or not it timed out.
            result = await run_with_timeout(proc, timeout, "arjun")
            if result.timed_out:
                found: dict = {}
                if os.path.exists(out_path):
                    try:
                        with open(out_path, encoding="utf-8", errors="replace") as f:
                            data = json.load(f)
                        if isinstance(data, dict):
                            found = data
                    except (OSError, json.JSONDecodeError):
                        pass
                logger.warning(
                    "arjun.target_timeout url=%s after=%ss params_recovered=%d -- raise "
                    "tool_config param_discovery_timeout_seconds, or lower "
                    "arjun_request_timeout, if this endpoint matters",
                    url, timeout, len(found),
                )
                return command_str, found, f"{url}: timed out", False, True

            found = {}
            if os.path.exists(out_path):
                try:
                    with open(out_path, encoding="utf-8", errors="replace") as f:
                        data = json.load(f)
                    if isinstance(data, dict):
                        found = data
                except (OSError, json.JSONDecodeError):
                    pass

            if result.exit_code == 0:
                logger.info(
                    "arjun.target_done url=%s params=%d duration=%.1fs",
                    url, len(found), time.monotonic() - started,
                )
                return command_str, found, None, True, False
            err_tail = result.stderr.strip()[-300:]
            return (
                command_str, found,
                f"{url}: exit {result.exit_code}" + (f": {err_tail}" if err_tail else ""),
                False, False,
            )
        finally:
            try:
                os.remove(out_path)
            except OSError:
                pass

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        targets = param_discovery_targets(prior_findings, config.get("param_discovery_max", 10))
        if not targets:
            return RawToolOutput(command="arjun (no endpoints to probe)", stdout="", stderr="no endpoints", exit_code=0)

        # ONE URL AT A TIME via `-u`, not a single `-i <file>` batch call. arjun's own batch
        # code path (upstream bug, arjun==2.2.7 __main__.py's initialize()) crashes with
        # `AttributeError: 'dict' object has no attribute 'status_code'` when ANY url in the
        # batch returns a "bad" HTTP status -- and because it's one process for the whole
        # batch, that one crash discards every other url's results too. `-u` takes a
        # different code path that doesn't hit this bug, and isolating each url means a
        # crash/timeout on one endpoint no longer kills discovery for the rest (same
        # resilience principle as naabu/nmap/httpx resolving each host independently).
        #
        # Run up to MAX_CONCURRENT_TARGETS of these at once (each probe can legitimately take
        # minutes -- see DEFAULT_TIMEOUT_SECONDS) so worst-case wall time is bounded by ONE
        # timeout window, not (number of endpoints * timeout).
        per_target_timeout = config.get("param_discovery_timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
        wordlist = _resolve_wordlist(config.get("arjun_wordlist", DEFAULT_WORDLIST))
        threads = config.get("arjun_threads", DEFAULT_THREADS)
        request_timeout = config.get("arjun_request_timeout", DEFAULT_REQUEST_TIMEOUT)
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_TARGETS)
        logger.info(
            "arjun.start targets=%d concurrency=%d per_target_timeout=%ss wordlist=%s threads=%s",
            len(targets), MAX_CONCURRENT_TARGETS, per_target_timeout, wordlist, threads,
        )

        async def _bounded(url: str):
            async with semaphore:
                return await self._probe_one(url, per_target_timeout, wordlist, threads, request_timeout)

        results = await asyncio.gather(*(_bounded(url) for url in targets))

        merged: dict = {}
        stderr_parts: list[str] = []
        commands: list[str] = []
        clean_runs = 0  # count of urls that finished with exit 0 -- "ran fine, maybe found nothing"
        any_timed_out = False
        for command_str, found, error, clean, timed_out in results:
            commands.append(command_str)
            merged.update(found)
            if clean:
                clean_runs += 1
            if error:
                stderr_parts.append(error)
            any_timed_out = any_timed_out or timed_out

        return RawToolOutput(
            command=" && ".join(commands) + f"  (probed {len(targets)} endpoint(s), "
            f"{MAX_CONCURRENT_TARGETS} concurrent)",
            # Empty string (not "{}") when nothing succeeded, so classify_run's non-zero-exit
            # fallback (produced_findings or stdout.strip()) doesn't mistake a genuinely failed
            # run for "partial" just because an empty JSON object happens to be truthy text.
            stdout=json.dumps(merged) if merged else "",
            stderr="; ".join(stderr_parts)[-1000:],
            # 0 iff at least one url completed cleanly (even with zero params found -- that's a
            # legitimate "ran fine, nothing interesting here" outcome, same as single-call batch
            # mode before). Every url crashing/timing out must NOT read as a clean success.
            exit_code=0 if clean_runs > 0 else (1 if commands else -1),
            # True iff AT LEAST ONE of the fanned-out per-endpoint probes hit its budget. A
            # multi-target tool's timeout is inherently a per-target fact; "any" is the
            # conservative aggregate for a trace consumer asking "did a timeout affect this
            # run at all" -- the per-target detail already lives in the aggregated `error`
            # text a few lines above, unaffected by this.
            timed_out=any_timed_out,
        )

    def parse(self, raw: RawToolOutput) -> list[CommonFinding]:
        """Turn arjun's {url: {params: [...]}} into parameterised `url` findings
        (url?p1=1&p2=1...) that the DAST runner will fuzz.

        Prompt 17 (Parameter Intelligence) hardening of how the synthesised query is BUILT --
        the discovered param NAMES are unchanged, only the URL construction is made correct:

          * DUPLICATE names are collapsed (order-preserving). arjun can legitimately report a
            name twice; emitting `?q=1&q=1` is parameter pollution WE inject, which is noise
            the DAST fuzzer would then waste budget on and which makes the synthesised URL
            nondeterministic in length.
          * Each name is PERCENT-ENCODED before it goes into the query. Without this a param
            name containing `&`, `=` or a space corrupts the query string -- a name like
            `x&y` split into a PHANTOM parameter `y` the target never exposed (a fabricated
            attack surface), and a name with a space produced an invalid URL. Encoding keeps
            the synthesised URL faithful to exactly the names arjun discovered.
          * Names that are empty after stripping are dropped -- they cannot be a real param.

        The `params` METADATA still records the raw discovered names (deduped) for provenance,
        so the finding never detaches from what arjun actually reported."""
        from urllib.parse import quote

        if not raw.stdout.strip():
            return []
        try:
            data = json.loads(raw.stdout)
        except json.JSONDecodeError:
            return []

        findings: list[CommonFinding] = []
        for url, info in (data.items() if isinstance(data, dict) else []):
            params = (info or {}).get("params") if isinstance(info, dict) else None
            if not params:
                continue
            # Order-preserving de-dup of non-empty names, then cap.
            seen: set[str] = set()
            names: list[str] = []
            for p in params:
                name = str(p).strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                names.append(name)
                if len(names) >= MAX_PARAMS_PER_URL:
                    break
            if not names:
                continue
            # Encode each name so a `&`/`=`/space in a discovered name cannot fabricate or
            # corrupt a parameter. `safe=""` encodes the query-delimiter characters too.
            query = "&".join(f"{quote(name, safe='')}=1" for name in names)
            sep = "&" if "?" in url else "?"
            findings.append(
                CommonFinding(
                    asset_type="url",
                    value=f"{url}{sep}{query}",
                    metadata={"has_params": True, "source": "arjun", "params": names},
                )
            )
        return findings
