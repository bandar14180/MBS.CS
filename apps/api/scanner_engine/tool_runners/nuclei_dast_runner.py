import asyncio

from apps.api.core.config import get_settings
from apps.api.scanner_engine.tool_runners._web import crawled_urls, web_targets
from apps.api.scanner_engine.tool_runners.base import CommonFinding, RawToolOutput
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner

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
    requires_active_testing = True  # sends injection payloads to app inputs -> gated on active testing
    phase = 55  # after katana (45) has crawled and after the signature nuclei (50)
    kill_chain_phase = "delivery"   # delivers fuzzing probes, like nuclei
    safety_tier = "active_safe"     # DETECTION fuzzing (benign markers); no exploitation

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
        if not urls:
            return RawToolOutput(command="nuclei -dast (no targets)", stdout="", stderr="no targets", exit_code=-1)

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
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return RawToolOutput(command=" ".join(command), stdout="", stderr="timed out", exit_code=-1)

        return RawToolOutput(
            command=" ".join(command) + f"  (fuzzed {len(urls)} url(s))",
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            exit_code=proc.returncode if proc.returncode is not None else -1,
        )
