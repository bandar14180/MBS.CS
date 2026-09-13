import asyncio
import logging
import os
import time

from apps.api.scanner_engine.tool_runners._web import web_targets
from apps.api.scanner_engine.tool_runners.base import (
    BaseToolRunner,
    CommonFinding,
    RawToolOutput,
    run_with_timeout,
)

logger = logging.getLogger("mbs.scanner.katana")

# --- Go heap policy ------------------------------------------------------------------------
# katana is a Go binary, and Go's garbage collector sizes itself from what it believes the
# machine has -- it does NOT read the cgroup limit this process is confined to. Inside a
# memory-limited container those two numbers disagree badly: /proc/meminfo reports the whole
# VM (measured here: 7792 MiB) while cgroup v2 memory.max is 2048 MiB. The GC therefore lets
# the heap grow toward a multi-GiB target that the cgroup will never allow, and the kernel
# OOM-kills the process before a serious collection ever runs.
#
# That is not a theory. Observed directly: katana runs that had been completing in ~500-660s
# started dying at 14-17s with exit code -9 (SIGKILL, NOT the -1 this runner returns on its
# own timeout) the moment a 2 GiB cgroup limit was introduced, while its wall-clock budget was
# 585s and untouched. The cgroup's memory.events oom_kill counter incremented once per failed
# run, and the partial stdout captured before each kill contained valid crawled URLs -- the
# crawl was working and was killed mid-flight, purely on memory.
#
# GOMEMLIMIT is Go's soft heap ceiling: above it the GC runs continuously instead of letting
# the heap grow. Pointing it at a fraction of the REAL cgroup limit makes katana collect
# aggressively while it still has headroom, instead of being killed. It is a soft limit by
# design -- Go will exceed it rather than deadlock if live data genuinely requires more -- so
# it degrades into slower crawling, never into a hang.
#
# WHY A FRACTION, NOT THE WHOLE LIMIT: GOMEMLIMIT governs the Go heap only. The cgroup also
# has to hold katana's non-heap memory (stacks, the Go runtime itself, OS page cache for the
# binary) plus everything else in the container -- the worker's own Python process and any
# Playwright/Chromium instance started for screenshot evidence. The headroom below is what
# keeps the SUM under the wall, not just the heap.
#
# MEASURED, not guessed. At 0.6 (1228 MiB of a 2048 MiB cgroup) a real crawl of a large
# WordPress target still died: the cgroup climbed 1188 -> 1793 -> 2025 MiB and was OOM-killed
# at 42s. GOMEMLIMIT is a SOFT ceiling -- Go exceeds it rather than stall when live data grows
# faster than the GC reclaims -- so the ceiling has to sit far enough below the wall that the
# overshoot still fits. 0.35 (716 MiB of 2048 MiB) leaves ~1.3 GiB of absorption for that
# overshoot plus non-heap, Python and any Chromium screenshot instance.
_GOMEMLIMIT_FRACTION = 0.35
# Floor/ceiling so a pathologically small or an unlimited cgroup both yield something sane.
_GOMEMLIMIT_MIN_MIB = 256
_GOMEMLIMIT_MAX_MIB = 4096


def _cgroup_memory_max_bytes() -> int | None:
    """The cgroup v2 memory ceiling this process is confined to, or None when unlimited.

    Reads memory.max directly rather than trusting /proc/meminfo, which reports the host/VM
    and is exactly the number Go gets wrong. Returns None for the literal "max" (no limit)
    and on any read error, so a non-containerised or cgroup-v1 host simply opts out.
    """
    try:
        with open("/sys/fs/cgroup/memory.max") as fh:
            raw = fh.read().strip()
    except OSError:
        return None
    if raw == "max":
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def compute_gomemlimit_mib(cgroup_max_bytes: int | None) -> int | None:
    """GOMEMLIMIT (in MiB) to hand katana, or None to leave Go's default alone.

    Pure, so the sizing rule is unit-testable without a container. None means "no cgroup
    limit" -- there is nothing to protect against, and forcing a ceiling would only make an
    unconstrained crawl slower for no benefit.
    """
    if cgroup_max_bytes is None:
        return None
    mib = int((cgroup_max_bytes / (1024 * 1024)) * _GOMEMLIMIT_FRACTION)
    return max(_GOMEMLIMIT_MIN_MIB, min(_GOMEMLIMIT_MAX_MIB, mib))


def _katana_env() -> dict[str, str]:
    """Process environment for katana: inherited, plus GOMEMLIMIT when a cgroup cap applies.

    GOGC is deliberately NOT set. GOMEMLIMIT alone makes the GC pace itself against the real
    ceiling; pinning GOGC as well would force constant collection even when the heap is small
    and would cost crawl throughput for nothing.
    """
    env = dict(os.environ)
    limit_mib = compute_gomemlimit_mib(_cgroup_memory_max_bytes())
    if limit_mib is not None:
        env["GOMEMLIMIT"] = f"{limit_mib}MiB"
    return env

# --- Timeout policy -----------------------------------------------------------------------
# 300s was itself already a raise from 180s for exactly this reason, and it was STILL short:
# measured against a live authorized target (www.lincoln.edu.my, depth 2, -js-crawl -jsluice)
# katana needed 360s to exit 0 with 858 URLs. The 300s ceiling killed it 60s from the end and
# -- because output was collected with communicate() -- discarded all 858.
#
# Two independent fixes, because these were two independent defects:
#   A) the budget now scales with what actually drives crawl time (targets x depth), and
#   B) output is captured incrementally, so a timeout keeps the URLs already crawled.
#
# whatweb/ffuf/nuclei budgets are untouched by this; there is no global timeout change.
# 240 would yield 390s for the measured 360s crawl -- a 1.08x margin, which is not a margin
# at all on a live target whose latency varies run to run. 360 yields ~585s (1.6x), matching
# the headroom whatweb and ffuf get.
BASE_PER_TARGET_SECONDS = 360
DEPTH_FACTOR_PER_LEVEL = 1.25   # each extra depth level multiplies the frontier
JS_CRAWL_FACTOR = 1.3           # -js-crawl/-jsluice fetch and parse every script
MIN_TIMEOUT_SECONDS = 180
MAX_TIMEOUT_SECONDS = 3600

# --- Per-target process isolation -----------------------------------------------------------
# Each target now gets its OWN katana process (see run()). That changes what a "timeout" is,
# so the budget is split into two DIFFERENT quantities that the previous single-process model
# conflated -- they were indistinguishable only because there was always exactly one process.
#
# WHY THE SPLIT EXISTS. katana's `-crawl-duration` is documented as "maximum duration to crawl
# THE TARGET for" -- it is a PER-INPUT bound, not a process-wide one. With N targets in one
# process the real worst case was therefore N x crawl-duration, while the runner's budget was
# clamped at MAX_TIMEOUT_SECONDS (3600s). At 44 targets those two numbers disagree by ~6x, so
# the budget could expire with most targets never crawled. One process per target makes the
# per-input bound and the per-process bound the SAME thing again.
#
# The safety factor is the ONLY free parameter, and it is derived from CRAWL_DURATION_SECONDS
# rather than written as a separate magic number: katana is supposed to stop itself at
# -crawl-duration and exit 0, so the runner's own deadline only has to cover that plus startup,
# DNS, and the drain of the final responses. 1.6 is the same headroom whatweb and ffuf get (see
# the 585s figure above, which is 360 x 1.625).
PER_TARGET_SAFETY_FACTOR = 1.6
# Floor for a single target, so a pathologically small configured crawl-duration cannot
# produce a deadline katana could never meet even on a fast host.
MIN_PER_TARGET_SECONDS = 60


def compute_per_target_timeout(crawl_duration_seconds: int | None = None) -> int:
    """Wall-clock budget for ONE target's katana process. Pure, so it is unit-testable.

    Derived from the crawl-duration katana is told to honour, NOT from the target count:
    every target gets an identical, independent process, so its budget cannot depend on how
    many OTHER targets are in the list. That independence is the whole point -- it is what
    stops a large target list from squeezing the per-target deadline.

    `crawl_duration_seconds` defaults to CRAWL_DURATION_SECONDS (defined below, next to the
    flag it feeds); pass the per-scan override so the deadline tracks the duration katana was
    ACTUALLY given rather than the module default."""
    duration = CRAWL_DURATION_SECONDS if crawl_duration_seconds is None else int(crawl_duration_seconds)
    return max(MIN_PER_TARGET_SECONDS, int(duration * PER_TARGET_SAFETY_FACTOR))


def compute_total_budget(target_count: int, per_target_timeout: int) -> int:
    """Total wall-clock the whole katana tool run may consume, across ALL target processes.

    DERIVED (count x per-target), never a fixed ceiling. A fixed ceiling is exactly what would
    silently drop the tail of a long target list: at 44 targets a 3600s cap covers only ~7 of
    them, and the other 37 would go uncrawled -- a coverage reduction disguised as a timeout.
    Nothing above the runner imposes a competing deadline: the scan Celery task runs with no
    time limit and the orchestrator only heartbeats around the tool, so the reaper keys on
    executor LIVENESS (a heartbeat every ~30s) rather than on runtime."""
    return max(1, int(target_count)) * int(per_target_timeout)


def compute_timeout(target_count: int, depth: int = 2, js_crawl: bool = True) -> int:
    """Wall-clock budget for one katana invocation. Pure, so it is unit-testable.

    RETAINED for the explicit `tool_config.timeout_seconds` override path and for callers that
    ask "how long may this tool take": with per-target processes the TOTAL is computed by
    compute_total_budget() instead. Kept because a scan may still pin a total via config.

    Targets share ONE invocation (they are fed on stdin), so the budget scales with their
    count; depth compounds because each level multiplies the crawl frontier. Clamped at both
    ends so a large target list cannot become effectively unbounded."""
    budget = float(BASE_PER_TARGET_SECONDS * max(1, target_count))
    budget *= DEPTH_FACTOR_PER_LEVEL ** max(0, depth - 1)
    if js_crawl:
        budget *= JS_CRAWL_FACTOR
    return int(max(MIN_TIMEOUT_SECONDS, min(MAX_TIMEOUT_SECONDS, budget)))


DEFAULT_TIMEOUT_SECONDS = 300  # was 180 -- observed timing out on a real, authorized live
# target (same pattern as nuclei's default bump). Still overridable per-scan via
# tool_config.timeout_seconds.
# Cap stored URLs so a large site can't flood the findings table; the DAST runner
# fuzzes parameterised URLs first anyway.
MAX_URLS = 500

# Tell KATANA ITSELF to stop once it has crawled roughly what the parser will keep, instead
# of crawling until the wall clock runs out and throwing almost all of it away.
#
# MEASURED: with the memory problem fixed, a real run against the live target no longer hit
# any OOM (oom_kill stayed 0, peak 2539 MiB inside the 4096 MiB cap) -- it ran the FULL 585s
# budget, emitted 29,828 URLs, and exited -1 on the runner's own timeout. The parser then
# kept the first MAX_URLS (500) and discarded the other ~29,300, so 99.8% of that crawl time
# bought nothing. The site is simply larger than any sane wall-clock budget; raising the
# timeout would only postpone the same truncation.
#
# -max-domain-pages is set as a first bound, but it is NOT sufficient on its own and must not
# be relied on alone -- MEASURED: with -max-domain-pages 2000 the same target still emitted
# 109,214 URLs and hit the runner's timeout again. Two reasons, both verified from the
# captured output: the limit is per DOMAIN and the crawl legitimately spans 40 of them
# (www/online/posts/hostel.lincoln.edu.my and third-party hosts referenced by the pages), and
# even the single target host alone produced 73,524 lines, so the 2000 bound was not
# honoured the way "pages" maps to emitted URLs here. Kept as a cheap upper bound.
MAX_DOMAIN_PAGES = MAX_URLS * 4

# THE bound that actually terminates the crawl cleanly. -crawl-duration makes katana stop by
# itself and exit 0, which is exactly the outcome the pipeline needs: a `completed` tool run
# instead of a `partial` one truncated by the runner's own wall clock.
#
# It must stay comfortably BELOW the deadline the runner gives that process so katana finishes
# on its own terms first; if it were >= the deadline, run_with_timeout would still fire and we
# would be back to exit -1. That relationship is now STRUCTURAL rather than coincidental:
# compute_per_target_timeout() derives the deadline from THIS constant
# (x PER_TARGET_SAFETY_FACTOR), so the margin holds automatically even when a scan overrides
# the duration via tool_config.crawl_duration_seconds.
#
# This is a PER-INPUT bound in katana ("maximum duration to crawl the target for"), which is
# precisely why one process per target is the right unit: with N targets sharing a process the
# real worst case was N x this value, against a budget clamped at MAX_TIMEOUT_SECONDS.
#
# At the ~50 URL/s crawl rate measured on a real target, 300s yields far more raw output than
# the MAX_URLS=500 the parser keeps -- so nothing the platform stores is lost.
CRAWL_DURATION_SECONDS = 300

# Concurrent INPUTS (targets) katana processes at once -- katana's `-parallelism`, which is a
# different axis from `-concurrency` (fetchers WITHIN one input) and was the actual cause of
# the cgroup OOM kill.
#
# The flag was previously omitted, so katana silently used its own default of 10. Tuning only
# `-concurrency 3` therefore bounded memory per target while leaving TEN independent crawls
# running simultaneously -- ten frontiers, ten visited-sets and ~30 in-flight responses, each
# body fed to -jsluice (which katana documents as "memory intensive") and expanded into a
# parse tree several times its size. That live data is REACHABLE, so GOMEMLIMIT cannot
# reclaim it: the Go heap overshoots its soft ceiling and the kernel kills the process.
#
# CORRECTION, from a controlled runtime test: lowering this was NOT sufficient, and the
# concurrency theory above is NOT the root cause. With -parallelism 2 verifiably in the
# command, the same 44-target workload was OOM-killed again -- exit -9, oom_kill 0 -> 1,
# memory.peak 4,294,987,776 B against a 4,294,967,296 B cap. A 5x cut in concurrent inputs
# bought 112.6s -> 132.2s, i.e. 1.18x, not the ~5x the concurrency model predicts.
#
# Two measurements explain why. First, -rate-limit is GLOBAL (katana has separate -hrl/-hrlm
# for per-host), so total request throughput -- and therefore the rate at which state
# accumulates -- barely changes when parallelism drops. Second, the memory trace shows the GC
# working normally for ~60s (13 reclaims totalling 2,696 MiB, net +75 MiB) and then failing to
# reclaim at all (1 reclaim, net +3,834 MiB): the live set became genuinely unreachable-free,
# which is retention, not concurrency.
#
# The real cause is CUMULATIVE state held for the lifetime of one process, addressed by running
# one process per target (see run()). This flag is KEPT at 2 because it is directionally right
# and costs nothing -- with a single target per process it now bounds in-process input overlap
# at a value the measured-safe 1-target runs never exceeded.
#
# NOTHING is skipped: every target is still crawled, at full depth, with -js-crawl and -jsluice
# both on.
PARALLELISM = 2


class KatanaRunner(BaseToolRunner):
    """Crawler (ProjectDiscovery katana). The missing link for app-layer testing:
    httpx/nuclei only see the entry page, so custom endpoints and their query
    parameters are invisible. katana walks the app (links + JS) and emits every
    URL it finds -- especially parameterised ones, which are what the DAST runner
    then fuzzes for SQLi/XSS/etc."""

    name = "katana"
    # Matches ARG KATANA_VERSION in infra/docker/Dockerfile.worker, which is what is actually
    # installed. This said 1.1.2 while the image shipped 1.7.0; the string is reported as tool
    # metadata on findings, so the drift put a wrong version in reports. Every flag this runner
    # passes was verified present in the installed binary's -h output.
    version = "1.7.0"
    binary = "katana"
    requires_active_testing = False  # benign GET crawling -- recon, like httpx
    capability = "web_crawling"
    phase = 45  # after nmap (40) so it can crawl services on discovered ports; before nuclei (50)
    kill_chain_phase = "reconnaissance"
    safety_tier = "active_safe"  # sends only benign navigation requests (no state change)
    applicable_target_types = {"domain", "ip_range"}

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        targets = web_targets(target_value, prior_findings)
        if not targets:
            return RawToolOutput(command="katana (no web targets)", stdout="", stderr="no web targets", exit_code=-1)

        depth_value = int(config.get("crawl_depth", 2))
        depth = str(depth_value)
        crawl_duration = int(config.get("crawl_duration_seconds", CRAWL_DURATION_SECONDS))
        # PER-TARGET, not per-invocation: every target gets its own process, so its deadline
        # is derived from the crawl-duration that process is given -- never from how many
        # other targets happen to be in the list.
        per_target_timeout = compute_per_target_timeout(crawl_duration)
        # Explicit tool_config wins (a scan may still pin one total); otherwise the total is
        # DERIVED as count x per-target so the tail of a long list is never silently dropped.
        total_budget = config.get("timeout_seconds") or compute_total_budget(
            len(targets), per_target_timeout
        )
        logger.info(
            "katana.start targets=%d depth=%s per_target_timeout=%ss total_budget=%ss "
            "crawl_duration=%ss gomemlimit=%s",
            len(targets), depth, per_target_timeout, total_budget, crawl_duration,
            compute_gomemlimit_mib(_cgroup_memory_max_bytes()) or "unset",
        )
        command = [
            "katana",
            "-silent",
            "-no-color",
            "-depth", depth,
            "-js-crawl",              # follow endpoints linked from JS files
            "-jsluice",               # extract API endpoints embedded in JS (fetch/XHR paths a
                                      # plain crawl misses -- e.g. /api/products?, /api/files/view?file=);
                                      # this is what surfaces a JSON API for the DAST runner to fuzz
            "-field-scope", "fqdn",   # stay on the exact target host (no wandering off-target)
            # Concurrency is the real memory multiplier for a -jsluice crawl, and it is what
            # finally made katana survive a capped container. MEASURED at -concurrency 10 on
            # the live target: the cgroup went 415 -> 2002 MiB in ~7s (~226 MiB/s) and was
            # OOM-killed at 37s. That is not a GC failure -- GOMEMLIMIT was working (a 2002 ->
            # 1264 MiB collection is visible in the same trace) -- it is simply that nothing
            # can reclaim faster than ten concurrent jsluice parses allocate. Each in-flight
            # response is a body plus a parse tree several times its size, so peak memory
            # scales with this number far more sharply than with -max-response-size.
            #
            # 3 keeps the crawl comfortably inside the budget. Nothing is skipped: every URL
            # and every JS file is still fetched and parsed (-js-crawl and -jsluice are both
            # untouched), just fewer at a time -- a throughput trade, not a coverage one, and
            # the runner's timeout budget already scales with targets x depth to absorb it.
            "-concurrency", str(config.get("crawl_concurrency", 3)),
            # Concurrent INPUTS, the other half of the pair above. Must be set EXPLICITLY:
            # omitting it leaves katana on its default of 10, which is what OOM-killed the
            # 44-target run. See PARALLELISM for the measurement.
            "-parallelism", str(config.get("crawl_parallelism", PARALLELISM)),
            "-rate-limit", str(config.get("crawl_rate", 150)),
            "-timeout", "10",
            # Cap a single response at 1 MiB (katana's own default is 4 MiB). This attacks the
            # memory problem at its SOURCE rather than only reacting to it via GOMEMLIMIT:
            # -jsluice is documented BY KATANA ITSELF as "memory intensive" because it reads
            # and parses whole JavaScript files, and with -concurrency 10 up to ten of those
            # bodies are resident at once -- 40 MiB of in-flight bodies at the default, before
            # any parse allocations. 1 MiB comfortably covers real-world bundles (the
            # measured target's largest were well under it), so this trims worst-case
            # blow-ups from a handful of pathological assets WITHOUT reducing crawl coverage:
            # -js-crawl and -jsluice both stay on and every discovered URL is still followed.
            "-max-response-size", str(config.get("max_response_bytes", 1024 * 1024)),
            # Terminate the crawl on katana's own terms (exit 0) once it has enough for the
            # MAX_URLS the parser keeps -- see MAX_DOMAIN_PAGES / CRAWL_DURATION_SECONDS above.
            "-max-domain-pages", str(config.get("max_domain_pages", MAX_DOMAIN_PAGES)),
            "-crawl-duration", f"{int(config.get('crawl_duration_seconds', CRAWL_DURATION_SECONDS))}s",
        ]

        env = _katana_env()

        # ONE PROCESS PER TARGET. This is the memory fix, and it is the only mechanism that
        # actually bounds it.
        #
        # MEASURED: feeding all N targets to ONE katana process OOM-killed the container at
        # 29 and 44 targets (exit -9, memory.peak == memory.max == 4096 MiB, oom_kill +1),
        # while every 1-target run at the same 4096 MiB limit survived -- including runs that
        # crawled 109,214 URLs over 585s, three times the output of the 44-target run that
        # died. So the discriminator is NOT output volume and NOT the container limit: it is
        # how long ONE process accumulates crawl state.
        #
        # WHY PROCESS EXIT IS THE RELEASE POINT. katana's dedup state -- filters.Simple
        # (UniqueURL + UniqueContent) hanging off types.CrawlerOptions, plus common.Shared and
        # its DomainCounter -- is built ONCE per process and reachable for that process's whole
        # life. The installed binary (v1.7.0) exposes no Reset/Clear/Purge on any of them, only
        # Close(), which runs at process teardown. Nothing inside katana frees this between
        # inputs, so the live set grows with CUMULATIVE crawl volume and GOMEMLIMIT cannot help:
        # a soft heap ceiling only makes the GC work harder, and it cannot reclaim what is still
        # reachable. Exiting the process is what hands the pages back to the kernel.
        #
        # The peak live set is therefore bounded by ONE target's crawl -- the shape that has
        # seven measured runs at this limit with zero OOM kills -- instead of by the sum over
        # all of them. Nothing is skipped: every target is still crawled, at full depth, with
        # -js-crawl and -jsluice on, and every flag below is identical for each process.
        chunks: list[str] = []
        summaries: list[str] = []
        completed = partial = killed = 0
        started = time.monotonic()
        attempted = 0

        for idx, target in enumerate(targets, start=1):
            elapsed = time.monotonic() - started
            remaining = total_budget - elapsed
            # The FIRST target always gets its attempt, however small the configured total.
            # Bailing out before launching anything would turn an explicit (if unrealistic)
            # `tool_config.timeout_seconds` into a run that crawled nothing at all -- strictly
            # worse than letting it try and time out, which at least preserves partial output.
            if attempted and remaining < MIN_PER_TARGET_SECONDS:
                # Out of budget. The remaining targets are NAMED rather than silently dropped:
                # an invisible truncation would be a coverage reduction disguised as a timeout.
                skipped = targets[idx - 1:]
                summaries.append(
                    f"  [--] {len(skipped)} target(s) not attempted -- total budget "
                    f"{total_budget}s exhausted after {elapsed:.0f}s: {', '.join(skipped)}"
                )
                logger.warning(
                    "katana.budget_exhausted attempted=%d skipped=%d after=%.0fs budget=%ss",
                    attempted, len(skipped), elapsed, total_budget,
                )
                break

            attempted += 1
            # The per-target deadline never exceeds what is left of the total, so the tool as
            # a whole cannot overrun its derived budget. It is never <= 0: run_with_timeout
            # reads that as "no wall-clock limit", which would hang this target forever -- the
            # opposite of what an exhausted budget should do.
            target_timeout = max(0.01, min(float(per_target_timeout), remaining))
            t0 = time.monotonic()
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            # EXACTLY ONE target on this process's stdin. Sending more than one is what the
            # whole change exists to prevent.
            result = await run_with_timeout(
                proc, target_timeout, "katana", stdin=target.encode()
            )
            took = time.monotonic() - t0

            if result.stdout:
                chunks.append(result.stdout)
                # katana writes one URL per line, but a process killed mid-write can leave a
                # chunk without its trailing newline -- which would glue its last URL to the
                # next target's first one and corrupt BOTH for the parser.
                if not result.stdout.endswith("\n"):
                    chunks.append("\n")

            crawled = len([ln for ln in result.stdout.splitlines() if ln.strip()])
            exit_code = proc.returncode if proc.returncode is not None else -1

            if result.timed_out:
                # NOT success. The URLs crawled before the deadline are preserved, and this
                # target is reported as partial -- the coverage limitation stays visible.
                partial += 1
                summaries.append(
                    f"  [{idx:02d}] {target} exit=-1 {took:.0f}s {crawled} URL(s) -- "
                    f"timed out after {target_timeout:.0f}s"
                )
                logger.warning(
                    "katana.target_timeout idx=%d/%d url=%s after=%.0fs urls_preserved=%d",
                    idx, len(targets), target, target_timeout, crawled,
                )
            elif exit_code == -9:
                # SIGKILL is NOT this runner's own timeout -- that path returns -1 above. A -9
                # means something OUTSIDE the process killed it, and in a memory-capped
                # container that is overwhelmingly the cgroup OOM killer. With one process per
                # target this now costs ONE target instead of the entire crawl, and the next
                # target starts from a clean baseline because this process's state died with it.
                killed += 1
                summaries.append(
                    f"  [{idx:02d}] {target} exit=-9 {took:.0f}s {crawled} URL(s) -- "
                    f"killed by SIGKILL (cgroup OOM killer in a memory-capped container)"
                )
                logger.warning(
                    "katana.target_sigkill idx=%d/%d url=%s urls_preserved=%d gomemlimit=%s",
                    idx, len(targets), target, crawled,
                    compute_gomemlimit_mib(_cgroup_memory_max_bytes()) or "unset",
                )
            elif exit_code == 0:
                completed += 1
                summaries.append(
                    f"  [{idx:02d}] {target} exit=0 {took:.0f}s {crawled} URL(s)"
                )
            else:
                partial += 1
                summaries.append(
                    f"  [{idx:02d}] {target} exit={exit_code} {took:.0f}s {crawled} URL(s)"
                )
                logger.warning(
                    "katana.target_failed idx=%d/%d url=%s exit=%s urls_preserved=%d",
                    idx, len(targets), target, exit_code, crawled,
                )

        # ONE join at the end -- not inside the loop, which would make the copying quadratic.
        stdout = "".join(chunks)
        skipped_count = len(targets) - attempted
        header = (
            f"katana: {len(targets)} target(s), one process each; "
            f"{completed} completed, {partial} partial, {killed} killed, "
            f"{skipped_count} not attempted"
        )
        stderr = "\n".join([header, *summaries])

        # AGGREGATE exit code. 0 only when EVERY target succeeded; otherwise -1, which lets
        # classify_run mark the run `partial` when any URLs survived and `failed` only when
        # nothing usable was produced -- the existing rule, unchanged. Deliberately NOT -9:
        # that code means "this process was killed from outside" and no longer describes the
        # tool run as a whole once each target has its own process. A per-target kill stays
        # fully visible in the summary above and in katana.target_sigkill.
        aggregate_exit = 0 if (completed == len(targets) and targets) else -1

        logger.info(
            "katana.summary targets=%d attempted=%d completed=%d partial=%d killed=%d "
            "skipped=%d urls=%d elapsed=%.0fs",
            len(targets), attempted, completed, partial, killed, skipped_count,
            len([ln for ln in stdout.splitlines() if ln.strip()]),
            time.monotonic() - started,
        )

        return RawToolOutput(
            command=" ".join(command) + f"  (one process per target; {len(targets)} target(s): "
                                        f"{', '.join(targets)})",
            stdout=stdout,
            stderr=stderr,
            exit_code=aggregate_exit,
        )

    def parse(self, raw: RawToolOutput) -> list[CommonFinding]:
        findings: list[CommonFinding] = []
        seen: set[str] = set()
        for line in raw.stdout.splitlines():
            url = line.strip()
            if not url or not url.lower().startswith(("http://", "https://")):
                continue
            if url in seen:
                continue
            seen.add(url)
            findings.append(
                CommonFinding(
                    asset_type="url",
                    value=url,
                    metadata={"has_params": "?" in url, "source": "katana"},
                )
            )
            if len(findings) >= MAX_URLS:
                break
        return findings
