import asyncio
import logging
import os
import time

from apps.api.scanner_engine.tool_runners._web import web_targets
from apps.api.scanner_engine.tool_runners.base import (
    RSS_SAMPLE_INTERVAL_SECONDS,
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
# NOTHING is skipped: every target is still crawled, at full depth, with -js-crawl on
# (-jsluice is opt-in -- see JSLUICE_DEFAULT).
PARALLELISM = 2

# --- Per-target OUTPUT budget ---------------------------------------------------------------
# THE bound this module was missing. Everything above limits how LONG one target may crawl
# (-crawl-duration, the runner deadline) or how much memory KATANA may use (GOMEMLIMIT,
# -concurrency, -max-response-size). None of them bounds how MUCH OUTPUT a single target may
# hand back, and that is a separate resource path with its own ceiling: the PARENT's.
#
# MEASURED, from the 29-target run this constant exists to fix: one target emitted 163,761
# URLs. At ~100 bytes per line that is ~16 MiB on the wire, and the parent held far more than
# 16 MiB of it -- base.run_with_timeout accumulated every chunk in a list, `b"".join()`
# materialised a second full copy, `.decode()` a third as a Python str, and the runner then
# appended that str to `chunks` where it stayed RESIDENT FOR THE REST OF THE 29-TARGET LOOP.
# Several targets doing that concurrently in a 4 GiB cgroup is the exit=-9 path, and it is in
# the WORKER, not in katana: katana's own per-process memory was already bounded.
#
# The waste is total. parse() keeps MAX_URLS (500) and discards the rest, so 163,261 of those
# URLs were carried through the whole loop only to be thrown away.
#
# TWO INDEPENDENT LIMITS, BOTH REALLY ENFORCED. This used to be ONE setting
# (`max_urls_per_target`) that was silently converted into a byte cap (urls x 512) and never
# enforced as a URL count at all. That was a lie in the configuration: a run with
# `max_urls_per_target=10000` was observed stopping at 74,364 URLs, because real URLs are far
# shorter than 512 bytes so the BYTE cap always fired first. An operator reading the setting
# would reasonably expect 10,000.
#
# Both units now exist because both matter, and neither substitutes for the other:
#   * BYTES bound MEMORY. This is the control that prevents the worker-cgroup OOM, and it is
#     the one that must never be removed. Line length is attacker-influenced, so a URL count
#     alone gives NO memory guarantee -- 10,000 pathological 1 MiB lines is 10 GiB.
#   * URLS bound RECORDS. This is the unit the tool emits, the unit parse() consumes, and the
#     unit an operator reasons about. A byte cap alone cannot honour a stated URL count.
#
# Whichever is reached FIRST stops the crawl, and the summary names which one it was, so the
# operator raises the limit that actually bound the run.
#
# SIZING. 10,000 URLs is 20x the MAX_URLS (500) that parse() keeps, leaving a large margin for
# dedup: parse() canonicalises and dedupes, so 500 kept URLs may legitimately require several
# times 500 raw lines. 5 MiB is the measured-safe memory bound (the runtime validation held
# peak parent RSS to ~57-83 MiB across flooding targets, with no cgroup OOM kill), and it is
# deliberately UNCHANGED from the value that validation exercised.
MAX_URLS_PER_TARGET = 10_000
MAX_STDOUT_BYTES_PER_TARGET = 5 * 1024 * 1024  # 5 MiB -- the hard memory boundary

# --- -jsluice: DEFAULT OFF, because on real targets it destroys both memory AND coverage ----
# This is the cause of the "target burns the full per-target timeout and yields nothing" class
# of run, and it is NOT a time problem -- it is an allocation problem that ends in a SIGKILL.
#
# MEASURED on this worker, same binary (v1.7.0), same flags, same live authorized targets,
# sampling RSS every 500 ms. Only -jsluice differs between the two columns:
#
#   target                             -js-crawl -jsluice   -js-crawl only
#   ---------------------------------  ------------------   ---------------
#   cpanel.brightvision-og.com         3601 MiB,     1 URL    73 MiB, 2465 URLs
#   webmail.brightvision-og.com        3838 MiB,     1 URL    77 MiB, 2464 URLs
#   www.brightvision-og.com            3740 MiB,     1 URL    53 MiB,    1 URL
#
# The growth curve is ~48 MiB -> 3695 MiB in 5.5s (~660 MiB/s) while stdout stays at ONE line,
# after which the cgroup OOM killer takes the process (exit 137). So the flag does not merely
# cost memory for extra coverage: on these targets it produces 1 URL instead of 2465. Turning
# it off is a 50x memory reduction AND a ~2465x COVERAGE INCREASE. There is no trade here.
#
# WHY THIS LOOKED LIKE A TIMEOUT. The production symptom was `katana.target_timeout ...
# urls_preserved=1` -- 30 of 30 timing-out targets preserved exactly ONE URL. A genuinely slow
# crawl emits thousands of lines before its deadline; one line means the process never got
# past the seed. What actually happened is that jsluice-driven allocation drove the SHARED
# 4 GiB worker cgroup to ~100% (measured: memory.pressure full avg10=78.97, i.e. every process
# in the container stalled ~79% of wall-clock waiting on memory). Under that pressure even
# `katana -version` -- no network, no crawl -- took 52,000-301,000 ms against 48-138 ms on an
# unpressured worker. The runner's own deadline then fired on a process that had been starved,
# not on a crawl that was making progress.
#
# WHAT IS LOST, STATED HONESTLY. -jsluice extracts API endpoints embedded in JS bundles
# (fetch/XHR paths such as /api/files/view?file=) that a link crawl does not see. That is real
# capability, so this is a DEFAULT, not a removal: a scan can set `jsluice=True` in tool_config
# to re-enable it for a target known to tolerate it. -js-crawl stays ON unconditionally, so JS
# files are still fetched and the URLs they LINK to are still followed and crawled -- which is
# where the measured 2465 URLs come from. Depth, scope and every other coverage control are
# untouched.
JSLUICE_DEFAULT = False

# --- -jsluice RSS ceiling: per-target containment for the runs that DO opt in --------------
# JSLUICE_DEFAULT = False keeps the runaway off the default path, but it is a DEFAULT, not a
# removal -- a scan may still set `jsluice=True`, and on the measured targets that run reaches
# ~4082 MiB against a ~4096 MiB worker cgroup and is OOM-killed (memory.events oom 0->2,
# oom_kill 0->1; Docker reports OOMKilled=true). The kernel's OOM killer chooses its own
# victim inside that cgroup, so the cost of one opt-in target is a risk to the WHOLE worker.
# This ceiling makes the cost of an opt-in target land on that target and nowhere else.
#
# WHY 1 GiB. Three numbers fix it, and all three are measured:
#
#   1. THE WALL is the worker cgroup at ~4096 MiB, SHARED. The Python worker, its Redis/Celery
#      client state, any Chromium screenshot instance, the other per-target buffers and the
#      kernel's own page accounting all live under the same wall. katana's share is not 4 GiB;
#      it is whatever is left, and the ceiling has to be a share, not the wall.
#   2. THE OVERSHOOT is set by the growth rate, ~660 MiB/s (48 -> 3695 MiB in 5.5s). At the
#      0.25s sampling interval the process can add ~165 MiB between the last sample below the
#      ceiling and the one that trips it, and more while the SIGKILL is delivered and the
#      pages are returned. So the real worst case is the ceiling plus a few hundred MiB.
#   3. WHAT A HEALTHY RUN NEEDS is ~75 MiB (measured peak, jsluice=False). A LEGITIMATE
#      jsluice crawl of a JS-heavy target needs more than that, but nothing in the measured
#      data suggests it needs a gigabyte: the 4 GiB runs were producing ONE URL, i.e. they
#      were not doing useful work with the memory.
#
# 1 GiB sits ~13x above a healthy run (so it does not truncate real crawls) and ~4x below the
# wall (so even a ceiling-plus-overshoot peak of ~1.3 GiB leaves ~2.7 GiB for everything else
# in the container). A ceiling near 4 GiB would be no ceiling at all -- it would trip at the
# same moment the kernel does, which is the failure this exists to prevent.
JSLUICE_MAX_RSS_BYTES = 1024 * 1024 * 1024  # 1 GiB
# Reason recorded when THIS ceiling stops a run. Distinct from the stdout/URL budgets, because
# they call for different operator responses: an output budget is a coverage trade, and this
# is a statement that the target cannot be crawled with -jsluice inside the worker's memory.
JSLUICE_RSS_LIMIT_REASON = "jsluice_rss"
# katana's stderr is diagnostics only (the runner builds its own summary), so it gets a small,
# fixed cap. Unbounded stderr is the same memory path as unbounded stdout.
MAX_STDERR_BYTES = 1024 * 1024


class KatanaBudgetError(ValueError):
    """An invalid per-target output budget. Raised BEFORE any process is spawned."""


def _validate_budget(name: str, value: int) -> int:
    """Validate one per-target budget. Pure, so it is unit-testable.

    VALIDATED, not clamped. A budget is a safety control, and silently repairing a nonsensical
    one is how a control becomes decorative -- a configured 0 or -1 would otherwise be read as
    "unlimited" by the very code meant to impose a limit, which is the exact failure this
    function exists to make impossible. Raising instead means a misconfigured scan fails
    loudly, before a process is spawned, rather than running unbounded."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise KatanaBudgetError(f"katana {name} must be an int, got {value!r}")
    if value < 1:
        raise KatanaBudgetError(
            f"katana {name} must be >= 1, got {value} -- a non-positive budget would "
            "disable the bound entirely"
        )
    return value


def resolve_output_budgets(config: dict) -> tuple[int, int]:
    """(max_urls, max_stdout_bytes) for ONE target, both validated. Pure and unit-testable.

    Returns BOTH because both are enforced; a caller cannot be given one number and told it
    means the other."""
    return (
        _validate_budget("max_urls_per_target", int(config.get("max_urls_per_target", MAX_URLS_PER_TARGET))),
        _validate_budget(
            "max_stdout_bytes_per_target",
            int(config.get("max_stdout_bytes_per_target", MAX_STDOUT_BYTES_PER_TARGET)),
        ),
    )


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
        # VALIDATED BEFORE ANY PROCESS IS SPAWNED. resolve_output_budgets raises on a
        # non-positive or non-integer budget rather than falling back to "unlimited", so a
        # misconfigured scan cannot quietly run without the bound. This sits ahead of the
        # loop deliberately: failing after spawning 28 of 29 processes would be no protection
        # at all. BOTH budgets are resolved here; neither is derived from the other.
        max_urls_per_target, stdout_budget_bytes = resolve_output_budgets(config)
        # DEFAULT OFF. `bool(...)` so a JSON-sourced "true"/1 behaves, and so an absent key can
        # never be read as "on" -- the failure this default exists to prevent is an OOM kill,
        # and it must not be reachable by omission.
        jsluice_enabled = bool(config.get("jsluice", JSLUICE_DEFAULT))
        # ARMED ONLY FOR -jsluice. None means no watchdog task is created at all, so the
        # default path (jsluice=False, measured 75 MiB peak) is byte-for-byte what it was --
        # this guard exists for the opt-in runaway and must not become a tax on the healthy
        # case. Validated like the output budgets, and for the same reason: a configured 0
        # would otherwise be read as "unlimited" by the control meant to impose the limit.
        jsluice_max_rss = (
            _validate_budget(
                "jsluice_max_rss_bytes",
                int(config.get("jsluice_max_rss_bytes", JSLUICE_MAX_RSS_BYTES)),
            )
            if jsluice_enabled
            else None
        )
        # Explicit tool_config wins (a scan may still pin one total); otherwise the total is
        # DERIVED as count x per-target so the tail of a long list is never silently dropped.
        total_budget = config.get("timeout_seconds") or compute_total_budget(
            len(targets), per_target_timeout
        )
        logger.info(
            "katana.start targets=%d depth=%s per_target_timeout=%ss total_budget=%ss "
            "crawl_duration=%ss gomemlimit=%s max_urls_per_target=%d stdout_budget_bytes=%d "
            "jsluice=%s jsluice_max_rss_bytes=%s",
            len(targets), depth, per_target_timeout, total_budget, crawl_duration,
            compute_gomemlimit_mib(_cgroup_memory_max_bytes()) or "unset",
            max_urls_per_target, stdout_budget_bytes, jsluice_enabled,
            jsluice_max_rss if jsluice_max_rss is not None else "disarmed",
        )
        command = [
            "katana",
            "-silent",
            "-no-color",
            "-depth", depth,
            "-js-crawl",              # follow endpoints linked from JS files. UNCONDITIONAL:
                                      # measured at 72 MiB peak for 2580 URLs, i.e. it is both
                                      # cheap and the main source of crawl coverage here.
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
            # and every JS file is still fetched and parsed (-js-crawl is untouched; -jsluice
            # is opt-in, see JSLUICE_DEFAULT), just fewer at a time -- a throughput trade, not a
            # coverage one, and
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
            # -js-crawl stays on and every discovered URL is still followed.
            "-max-response-size", str(config.get("max_response_bytes", 1024 * 1024)),
            # Terminate the crawl on katana's own terms (exit 0) once it has enough for the
            # MAX_URLS the parser keeps -- see MAX_DOMAIN_PAGES / CRAWL_DURATION_SECONDS above.
            "-max-domain-pages", str(config.get("max_domain_pages", MAX_DOMAIN_PAGES)),
            "-crawl-duration", f"{int(config.get('crawl_duration_seconds', CRAWL_DURATION_SECONDS))}s",
        ]
        # OPT-IN, never on by default -- see JSLUICE_DEFAULT for the measurements. Appended
        # rather than written inline so the default command contains no trace of it: a flag
        # that is off must be ABSENT from argv, not passed with a falsy value, because argv is
        # what orchestrator.py hashes into ToolRun.command_hash and stores as the effective
        # command. An operator reading that record has to be able to see, from the argv alone,
        # whether the run carried the expensive parser.
        if jsluice_enabled:
            command.append("-jsluice")

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
        # -js-crawl on (-jsluice only when explicitly enabled), and every flag below is
        # identical for each process.
        chunks: list[str] = []
        summaries: list[str] = []
        completed = partial = killed = resource_limited = 0
        # Counted separately from `resource_limited` so the run-level line can name the
        # -jsluice memory ceiling specifically -- it is the one cause here whose remedy is to
        # turn a FLAG off rather than to raise a number.
        rss_limited = 0
        peak_rss_seen: int | None = None
        any_timed_out = False  # at least one per-target process hit its own deadline
        any_resource_limited = False  # at least one per-target process blew its output budget
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
            # The output budget is enforced PER PROCESS, so one pathological target cannot
            # spend another target's share -- the same independence the per-target deadline
            # already has.
            result = await run_with_timeout(
                proc, target_timeout, "katana", stdin=target.encode(),
                max_stdout_bytes=stdout_budget_bytes,
                max_stderr_bytes=MAX_STDERR_BYTES,
                max_stdout_lines=max_urls_per_target,
                # PER-TARGET, like every other bound here: the watchdog watches THIS process
                # and stops THIS process. None when jsluice is off, so no watchdog is armed.
                max_rss_bytes=jsluice_max_rss,
            )
            took = time.monotonic() - t0
            # Highest RSS observed across every process in this run, so the provenance record
            # carries one number an operator can compare against the ceiling. None stays None
            # when nothing was ever sampled -- "not measured" is not "measured as zero".
            if result.peak_rss_bytes is not None and (
                peak_rss_seen is None or result.peak_rss_bytes > peak_rss_seen
            ):
                peak_rss_seen = result.peak_rss_bytes

            if result.stdout:
                chunks.append(result.stdout)
                # katana writes one URL per line, but a process killed mid-write can leave a
                # chunk without its trailing newline -- which would glue its last URL to the
                # next target's first one and corrupt BOTH for the parser.
                if not result.stdout.endswith("\n"):
                    chunks.append("\n")

            crawled = len([ln for ln in result.stdout.splitlines() if ln.strip()])
            exit_code = proc.returncode if proc.returncode is not None else -1

            if result.resource_limited:
                # RESOURCE LIMITED. A DISTINCT outcome from a timeout: the crawl was stopped
                # because it produced more than this target's share of memory allowed, not
                # because its clock ran out. Kept separate so an operator does not raise a
                # time budget that was never the constraint.
                #
                # NOT SUCCESS, even though katana was working correctly when it was stopped.
                # `partial` is incremented so the aggregate exit code cannot be 0, which is
                # what keeps classify_run from reporting this run as `completed`. The URLs
                # collected before the cap are preserved in `chunks` above.
                partial += 1
                resource_limited += 1
                any_resource_limited = True
                # NAME THE LIMIT THAT ACTUALLY FIRED. "output budget exceeded" alone leaves an
                # operator guessing which of the two to raise, and they are different
                # decisions -- the URL cap is a coverage trade, the byte cap is the memory
                # boundary that must not move.
                # The RSS ceiling is reported under its OWN reason, `jsluice_rss`, not as a
                # generic output budget: the two say different things to an operator. An
                # output budget means "this target produced more than its share of results";
                # jsluice_rss means "-jsluice cannot crawl this target inside the worker's
                # memory", for which the answer is to drop -jsluice for that target, not to
                # raise a cap. It is also NOT a timeout -- the deadline was nowhere near.
                rss_tripped = result.limit_tripped == "rss"
                if rss_tripped:
                    rss_limited += 1
                    limit_reason = JSLUICE_RSS_LIMIT_REASON
                else:
                    limit_reason = result.limit_tripped or "unknown"
                which = {
                    "stdout_lines": f"URL limit ({max_urls_per_target} URL(s))",
                    "stdout_bytes": f"output byte limit ({stdout_budget_bytes} bytes)",
                    "rss": f"-jsluice memory ceiling ({jsluice_max_rss} bytes RSS)",
                }.get(result.limit_tripped, f"output budget ({result.limit_tripped or 'unknown'})")
                peak_note = (
                    f" peak RSS {result.peak_rss_bytes} byte(s)."
                    if result.peak_rss_bytes is not None else ""
                )
                summaries.append(
                    f"  [{idx:02d}] {target} exit=resource_limited reason={limit_reason} "
                    f"{took:.0f}s {crawled} URL(s) "
                    f"-- stopped by the per-target {which}; "
                    f"{result.stdout_lines_seen} URL(s) / {result.stdout_bytes_seen} byte(s) "
                    f"seen.{peak_note} Crawl INCOMPLETE: the remaining attack surface was not "
                    f"enumerated and is NOT proven absent."
                )
                logger.warning(
                    "katana.target_resource_limited idx=%d/%d url=%s urls_preserved=%d "
                    "limit_tripped=%s reason=%s budget_urls=%d budget_bytes=%d urls_seen=%d "
                    "bytes_seen=%d rss_cap=%s peak_rss=%s",
                    idx, len(targets), target, crawled, result.limit_tripped or "?",
                    limit_reason,
                    max_urls_per_target, stdout_budget_bytes, result.stdout_lines_seen,
                    result.stdout_bytes_seen,
                    jsluice_max_rss if jsluice_max_rss is not None else "disarmed",
                    result.peak_rss_bytes,
                )
            elif result.timed_out:
                # NOT success. The URLs crawled before the deadline are preserved, and this
                # target is reported as partial -- the coverage limitation stays visible.
                partial += 1
                any_timed_out = True
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
            f"{completed} completed, {partial} partial "
            # The "(N resource_limited)" tally keeps its existing shape -- consumers and
            # tests key on it -- and the jsluice-memory tally is APPENDED as its own clause
            # rather than folded into it, because it names a different remedy.
            f"({resource_limited} resource_limited"
            f"{f', {rss_limited} {JSLUICE_RSS_LIMIT_REASON}' if rss_limited else ''}), "
            f"{killed} killed, "
            f"{skipped_count} not attempted"
        )
        # A RUN-LEVEL outcome line, so a consumer does not have to parse per-target lines to
        # learn that coverage was bounded. The two causes stay separate here for the same
        # reason they are separate per target: they call for different operator responses (a
        # larger output budget vs. a longer deadline), and collapsing them sends operators to
        # the wrong knob.
        if any_resource_limited or any_timed_out:
            causes = []
            if any_resource_limited:
                output_limited = resource_limited - rss_limited
                if output_limited:
                    causes.append(
                        f"{output_limited} target(s) hit a per-target output limit "
                        f"({max_urls_per_target} URL(s) or {stdout_budget_bytes} bytes, "
                        f"whichever came first)"
                    )
                if rss_limited:
                    # NAMED SEPARATELY, with the remedy implied: this is not a budget to
                    # raise, it is a flag that this target cannot afford.
                    causes.append(
                        f"{rss_limited} target(s) hit the -jsluice memory ceiling "
                        f"({jsluice_max_rss} bytes RSS, reason "
                        f"{JSLUICE_RSS_LIMIT_REASON}) -- -jsluice cannot crawl those targets "
                        f"within the worker's memory; re-run them without it"
                    )
            if any_timed_out:
                causes.append("at least one target hit its wall-clock deadline")
            summaries.append(
                "  [!!] CRAWL INCOMPLETE -- " + "; ".join(causes) + ". The URLs above are "
                "what was observed, NOT a complete enumeration: endpoints beyond the bound "
                "were never requested and are NOT proven absent."
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
            "katana.summary targets=%d attempted=%d completed=%d partial=%d "
            "resource_limited=%d rss_limited=%d killed=%d skipped=%d urls=%d "
            "peak_rss=%s elapsed=%.0fs",
            len(targets), attempted, completed, partial, resource_limited, rss_limited,
            killed, skipped_count,
            len([ln for ln in stdout.splitlines() if ln.strip()]),
            peak_rss_seen,
            time.monotonic() - started,
        )

        # REPRODUCIBILITY (Prompt 10). `command` is what orchestrator.py hashes into
        # ToolRun.command_hash and stores verbatim as ToolRun.effective_command, so the
        # EFFECTIVE resource controls belong here -- the argv alone does not record the
        # runner-side bounds (deadline, output budget, Go heap ceiling), and without them a
        # `resource_limited` run could not be reproduced or even explained after the fact.
        #
        # gomemlimit is reported as "unavailable" when there is no cgroup v2 limit to read,
        # rather than substituting a plausible number: an invented limit in a provenance
        # record is worse than an absent one.
        gomemlimit_mib = compute_gomemlimit_mib(_cgroup_memory_max_bytes())
        controls = (
            f"katana_version={self.version} "
            f"per_target_timeout_s={per_target_timeout} "
            f"total_budget_s={total_budget} "
            f"crawl_duration_s={crawl_duration} "
            f"crawl_depth={depth} "
            # BOTH limits, because both are enforced and either may be the one that bound the
            # run. Recording only one would make the trace unreproducible in exactly the case
            # that matters -- a resource_limited run.
            f"max_urls_per_target={max_urls_per_target} "
            f"max_stdout_bytes_per_target={stdout_budget_bytes} "
            f"stderr_budget_bytes={MAX_STDERR_BYTES} "
            f"parallelism={config.get('crawl_parallelism', PARALLELISM)} "
            f"concurrency={config.get('crawl_concurrency', 3)} "
            # The single biggest determinant of whether a target OOMs (3.7 GiB vs 73 MiB on
            # the measured targets), so it belongs in the reproducibility record alongside the
            # other effective resource controls.
            f"jsluice={jsluice_enabled} "
            # THE RSS GUARD, in full, because a `jsluice_rss` run is unreproducible without
            # it: whether the guard was armed at all, at what ceiling, whether it fired, and
            # the highest RSS actually observed. All four are separate facts -- a run that was
            # armed and did not trip is not the same evidence as one that was never armed.
            # `peak_rss_bytes` is reported as "unmeasured" rather than 0 when no sample ever
            # succeeded, for the same reason gomemlimit says "unavailable": an invented number
            # in a provenance record is worse than an absent one.
            f"jsluice_rss_limit_enabled={jsluice_max_rss is not None} "
            f"jsluice_max_rss_bytes={jsluice_max_rss if jsluice_max_rss is not None else 'disarmed'} "
            f"jsluice_rss_limit_tripped={rss_limited > 0} "
            f"jsluice_rss_limited_targets={rss_limited} "
            f"jsluice_rss_reason={JSLUICE_RSS_LIMIT_REASON if rss_limited else 'none'} "
            f"rss_sample_interval_s={RSS_SAMPLE_INTERVAL_SECONDS} "
            f"peak_rss_bytes={peak_rss_seen if peak_rss_seen is not None else 'unmeasured'} "
            f"gomemlimit_mib={gomemlimit_mib if gomemlimit_mib is not None else 'unavailable'}"
        )
        return RawToolOutput(
            command=" ".join(command) + f"  (one process per target; {len(targets)} target(s): "
                                        f"{', '.join(targets)}; effective controls: {controls})",
            stdout=stdout,
            stderr=stderr,
            exit_code=aggregate_exit,
            # True iff at least one per-target process hit its own deadline (Prompt 10). A
            # target killed by the OOM killer (exit -9) is a DIFFERENT failure mode and is
            # deliberately not folded into this flag -- it is already fully visible via
            # `killed`/`katana.target_sigkill` and conflating the two would make an operator
            # raise a timeout budget that was never the actual problem.
            timed_out=any_timed_out,
        )

    def parse(self, raw: RawToolOutput) -> list[CommonFinding]:
        # Prompt 16 (Endpoint Intelligence): CANONICALIZE each crawled URL before dedup, so two
        # spellings of ONE endpoint (host case, default :80/:443, empty path, #fragment,
        # percent-encoding case) collapse to a single endpoint asset instead of N. Without this
        # katana emitted `http://a/x`, `http://A/x`, `http://a:80/x` and `http://a/x#frag` as
        # four distinct `url` assets -- four rows, and four downstream param-discovery / DAST
        # targets for the same endpoint, wasting the (expensive) per-URL arjun/nuclei-dast
        # budget and fracturing coverage across identical surfaces.
        #
        # It reuses location_normalize.normalize_location -- the SAME canonicalizer nuclei's
        # fingerprinting already uses -- so endpoint identity here and vulnerability identity
        # downstream agree on what "the same endpoint" means (a prerequisite for correlating a
        # DAST finding back to the crawled endpoint that produced it). The normalizer only
        # folds representational differences; it never touches path segments or query values,
        # which are semantically load-bearing (see that module's rule table).
        #
        # PROVENANCE PRESERVED: the exact raw URL katana emitted is kept in metadata
        # (`raw_url`) whenever normalization changed it, so the canonical value never detaches
        # the finding from what the tool actually reported.
        from apps.api.scanner_engine.api_intel import classify_api
        from apps.api.scanner_engine.location_normalize import normalize_location

        findings: list[CommonFinding] = []
        seen: set[str] = set()
        for line in raw.stdout.splitlines():
            url = line.strip()
            if not url or not url.lower().startswith(("http://", "https://")):
                continue
            canonical = normalize_location(url) or url
            if canonical in seen:
                continue
            seen.add(canonical)
            metadata = {"has_params": "?" in canonical, "source": "katana"}
            if canonical != url:
                metadata["raw_url"] = url  # preserve exactly what the tool emitted
            # Prompt 18: tag the endpoint's API characteristics (is_api / kind / version) so
            # the API surface is recorded on the asset and reasoned about downstream. A hint
            # from the URL shape only -- never a claim the endpoint is reachable/complete.
            metadata.update(classify_api(canonical).as_metadata())
            findings.append(CommonFinding(asset_type="url", value=canonical, metadata=metadata))
            if len(findings) >= MAX_URLS:
                break
        return findings
