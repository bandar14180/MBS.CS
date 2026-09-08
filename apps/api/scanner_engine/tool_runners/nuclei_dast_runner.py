import asyncio
import logging

from apps.api.core.config import get_settings
from apps.api.scanner_engine.tool_runners._web import crawled_urls, web_targets
from apps.api.scanner_engine.tool_runners.base import CommonFinding, RawToolOutput, terminate_and_reap
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner

logger = logging.getLogger("mbs.scanner.nuclei_dast")

DEFAULT_TIMEOUT_SECONDS = 600  # fuzzing many params is slower than a signature scan
# Bound how many URLs we fuzz so a big crawl can't run unbounded.
MAX_FUZZ_URLS = 200


class NucleiDastRunner(NucleiRunner):
    """nuclei in DAST (fuzzing) mode. Where the signature nuclei run checks for
    known issues on the entry page, this fuzzes the *parameters* katana
    discovered -- injecting SQLi / XSS / SSTI / command-injection / LFI probes
    and detecting them from the response. This is what closes the gap on custom
    app-logic bugs the signature scan can't see.

    Reuses NucleiRunner.parse_vulnerabilities (identical JSONL schema); only the
    target selection and the command (adds `-dast`) differ."""

    name = "nuclei-dast"
    binary = "nuclei"  # same binary as NucleiRunner, driven with -dast
    requires_active_testing = True  # sends injection payloads to app inputs -> gated on active testing
    capability = "dast_fuzzing"
    phase = 55  # after katana (45) has crawled and after the signature nuclei (50)
    kill_chain_phase = "delivery"   # delivers fuzzing probes, like nuclei
    safety_tier = "active_safe"     # DETECTION fuzzing (benign markers); no exploitation

    def coverage_state(self, target_value: str, prior_findings: list[CommonFinding]) -> str:
        """How much of the app this DAST run can actually reach: crawled | fallback_root_only | none.

        WHY THIS IS REPORTED. `_target_urls` falls back to the bare entry point when the
        crawler produced nothing -- which is the right behaviour (fuzzing the root is better
        than fuzzing nothing) but it made a degraded run indistinguishable from a full one.
        Observed on a real scan: katana timed out and returned zero URLs, DAST then "succeeded"
        in 12.3s having fuzzed only the homepage, and the scan reported a clean DAST pass.

        This states the difference so the run's coverage is legible. It changes NO
        vulnerability semantics: the same URLs are fuzzed, the same findings are produced, and
        nothing is reclassified -- only the stderr note and this label are new."""
        if crawled_urls(prior_findings):
            return "crawled"
        try:
            fallback = web_targets(target_value, prior_findings)
        except Exception:
            # web_targets resolves the host through the SSRF guard, which RAISES for an
            # unresolvable/blocked target rather than returning an empty list. A coverage
            # LABEL must never be the thing that fails a run, so an unusable target simply
            # reports "none" -- run() then returns the existing no-targets error.
            return "none"
        return "fallback_root_only" if fallback else "none"

    def _target_urls(self, target_value: str, prior_findings: list[CommonFinding]) -> list[str]:
        """Fuzz the URLs katana crawled (parameterised ones first -- those are
        what -dast actually injects into). Fall back to the plain web targets if
        the crawler produced nothing."""
        urls = crawled_urls(prior_findings)
        if not urls:
            urls = web_targets(target_value, prior_findings)
        return urls[:MAX_FUZZ_URLS]

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        urls = self._target_urls(target_value, prior_findings)
        coverage = self.coverage_state(target_value, prior_findings)
        if not urls:
            return RawToolOutput(
                command="nuclei -dast (no targets)", stdout="",
                stderr="no targets; coverage=none", exit_code=-1,
            )
        if coverage == "fallback_root_only":
            # The crawler produced nothing, so this run can only fuzz the entry point. Said
            # plainly here so a 12s "success" is not read as full application coverage.
            logger.warning(
                "nuclei_dast.degraded_coverage urls=%d coverage=%s -- no crawled URLs "
                "available (upstream crawl produced none); fuzzing entry point only",
                len(urls), coverage,
            )

        command = ["nuclei", "-dast", "-jsonl", "-silent", "-disable-update-check", "-no-color"]
        templates_dir = get_settings().nuclei_templates_dir
        if templates_dir:
            command += ["-templates", templates_dir]

        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input="\n".join(urls).encode()),
                timeout=config.get("dast_timeout_seconds", DEFAULT_TIMEOUT_SECONDS),
            )
        except asyncio.CancelledError:
            # Scan revoked / worker warm shutdown. Without this the subprocess is
            # LEFT RUNNING (verified: returncode stays None) -- kill it, then re-raise
            # so cancellation still propagates.
            await terminate_and_reap(proc, "nuclei-dast")
            raise
        except asyncio.TimeoutError:
            await terminate_and_reap(proc, "nuclei-dast")
            return RawToolOutput(command=" ".join(command), stdout="", stderr="timed out", exit_code=-1)

        return RawToolOutput(
            command=" ".join(command) + f"  (fuzzed {len(urls)} url(s), coverage={coverage})",
            stdout=stdout.decode(errors="replace"),
            # Coverage is appended to stderr so it reaches the stored evidence and is visible
            # to anyone reading the run, without changing findings or their classification.
            stderr=(stderr.decode(errors="replace") + f"\ncoverage={coverage}").strip(),
            exit_code=proc.returncode if proc.returncode is not None else -1,
        )
