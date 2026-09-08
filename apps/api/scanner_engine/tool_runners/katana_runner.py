import asyncio
import logging

from apps.api.scanner_engine.tool_runners._web import web_targets
from apps.api.scanner_engine.tool_runners.base import (
    BaseToolRunner,
    CommonFinding,
    RawToolOutput,
    run_with_timeout,
)

logger = logging.getLogger("mbs.scanner.katana")

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


def compute_timeout(target_count: int, depth: int = 2, js_crawl: bool = True) -> int:
    """Wall-clock budget for one katana invocation. Pure, so it is unit-testable.

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


class KatanaRunner(BaseToolRunner):
    """Crawler (ProjectDiscovery katana). The missing link for app-layer testing:
    httpx/nuclei only see the entry page, so custom endpoints and their query
    parameters are invisible. katana walks the app (links + JS) and emits every
    URL it finds -- especially parameterised ones, which are what the DAST runner
    then fuzzes for SQLi/XSS/etc."""

    name = "katana"
    version = "1.1.2"
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
        # Explicit tool_config wins; otherwise derive the budget from targets x depth x JS
        # crawling -- the three things that actually determine how long a crawl takes.
        timeout = config.get("timeout_seconds") or compute_timeout(len(targets), depth_value, js_crawl=True)
        logger.info(
            "katana.start targets=%d depth=%s timeout=%ss", len(targets), depth, timeout
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
            "-concurrency", "10",
            "-rate-limit", str(config.get("crawl_rate", 150)),
            "-timeout", "10",
        ]

        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        # Incremental capture. The previous `communicate()` call discarded everything on
        # timeout -- the comment below it claimed partial output was kept, but `stdout=""`
        # was returned, so 858 crawled URLs were thrown away on the measured run.
        result = await run_with_timeout(proc, timeout, "katana", stdin="\n".join(targets).encode())
        if result.timed_out:
            # NOT success. The URLs crawled before the deadline are preserved, and the
            # non-zero exit lets classify_run mark this `partial` (usable output) rather than
            # `completed` -- the coverage limitation stays visible.
            crawled = len([ln for ln in result.stdout.splitlines() if ln.strip()])
            logger.warning(
                "katana.timeout targets=%d after=%ss urls_preserved=%d",
                len(targets), timeout, crawled,
            )
            note = f"timed out after {timeout}s; preserved {crawled} crawled URL(s)"
            return RawToolOutput(
                command=" ".join(command),
                stdout=result.stdout,
                stderr=(result.stderr + "\n" + note).strip(),
                exit_code=-1,
            )
        stdout, stderr = result.stdout, result.stderr

        return RawToolOutput(
            command=" ".join(command) + f"  (stdin: {', '.join(targets)})",
            stdout=stdout,
            stderr=stderr,
            exit_code=proc.returncode if proc.returncode is not None else -1,
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
