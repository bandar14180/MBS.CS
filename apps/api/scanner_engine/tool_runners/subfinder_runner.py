import asyncio
import json

from apps.api.scanner_engine.tool_runners.base import BaseToolRunner, CommonFinding, RawToolOutput

DEFAULT_TIMEOUT_SECONDS = 120


class SubfinderRunner(BaseToolRunner):
    name = "subfinder"
    version = "2.14.0"
    requires_active_testing = False  # passive enumeration from public sources
    phase = 10  # first in the recon pipeline
    applicable_target_types = {"domain"}  # subdomain enumeration only makes sense for a domain

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        # Passive: subfinder queries external data sources for subdomains of the
        # domain; no host resolution needed here (unlike naabu/httpx).
        command = ["subfinder", "-d", target_value, "-json", "-silent"]

        proc = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return RawToolOutput(command=" ".join(command), stdout="", stderr="timed out", exit_code=-1)

        return RawToolOutput(
            command=" ".join(command),
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            exit_code=proc.returncode if proc.returncode is not None else -1,
        )

    def parse(self, raw: RawToolOutput) -> list[CommonFinding]:
        findings: list[CommonFinding] = []
        for line in raw.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = obj.get("host")
            if not host:
                continue

            findings.append(
                CommonFinding(
                    asset_type="subdomain",
                    value=host,
                    metadata={"source": obj.get("source")},
                )
            )
        return findings
