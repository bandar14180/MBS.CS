import asyncio

from apps.api.scanner_engine.tool_runners._web import web_targets
from apps.api.scanner_engine.tool_runners.base import BaseToolRunner, CommonFinding, RawToolOutput

DEFAULT_TIMEOUT_SECONDS = 180
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
    requires_active_testing = False  # benign GET crawling -- recon, like httpx
    phase = 45  # after nmap (40) so it can crawl services on discovered ports; before nuclei (50)
    kill_chain_phase = "reconnaissance"
    safety_tier = "active_safe"  # sends only benign navigation requests (no state change)
    applicable_target_types = {"domain", "ip_range"}

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        targets = web_targets(target_value, prior_findings)
        if not targets:
            return RawToolOutput(command="katana (no web targets)", stdout="", stderr="no web targets", exit_code=-1)

        depth = str(config.get("crawl_depth", 2))
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
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input="\n".join(targets).encode()),
                timeout=config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS),
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            # A crawl that ran out of time still produced useful URLs on stdout; the
            # orchestrator keeps partial output rather than discarding the run.
            return RawToolOutput(command=" ".join(command), stdout="", stderr="timed out", exit_code=-1)

        return RawToolOutput(
            command=" ".join(command) + f"  (stdin: {', '.join(targets)})",
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
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
