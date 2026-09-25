import asyncio
import json

from apps.api.scanner_engine.tool_runners.base import (
    BaseToolRunner,
    CommonFinding,
    RawToolOutput,
    run_with_timeout,
)

DEFAULT_TIMEOUT_SECONDS = 120


class SubfinderRunner(BaseToolRunner):
    name = "subfinder"
    version = "2.14.0"
    binary = "subfinder"
    requires_active_testing = False  # passive enumeration from public sources
    capability = "subdomain_discovery"
    phase = 10  # first in the recon pipeline
    kill_chain_phase = "reconnaissance"
    safety_tier = "passive"  # queries public sources; no packets to the target
    applicable_target_types = {"domain"}  # subdomain enumeration only makes sense for a domain

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        # Passive: subfinder queries external data sources for subdomains of the
        # domain; no host resolution needed here (unlike naabu/httpx).
        command = ["subfinder", "-d", target_value, "-json", "-silent"]

        proc = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        # Incremental capture: a timeout now KEEPS whatever subfinder already found
        # instead of discarding it (see base.run_with_timeout).
        result = await run_with_timeout(
            proc, config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS), "subfinder"
        )
        if result.timed_out:
            return RawToolOutput(
                command=" ".join(command),
                stdout=result.stdout,
                stderr=(result.stderr + "\ntimed out").strip(),
                exit_code=-1,
                timed_out=True,
            )

        return RawToolOutput(
            command=" ".join(command),
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code if result.exit_code is not None else -1,
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
