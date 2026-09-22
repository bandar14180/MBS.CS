import asyncio
import json

from apps.api.scanner_engine.tool_runners.base import (
    BaseToolRunner,
    CommonFinding,
    RawToolOutput,
    run_with_timeout,
)

DEFAULT_TIMEOUT_SECONDS = 90


class DnsxRunner(BaseToolRunner):
    """DNS resolution/validation (ProjectDiscovery dnsx). A second, independent
    implementation of `subdomain_discovery` alongside subfinder/amass: resolves
    the target plus every subdomain those tools found and keeps only the ones
    that actually have live DNS records, so downstream tools (httpx/naabu) never
    waste a probe on a stale/dead name. Demonstrates the capability registry's
    "more than one tool can serve a capability" case -- the orchestrator/agent
    still just ask for `subdomain_discovery`."""

    name = "dnsx"
    version = "1.2.1"
    binary = "dnsx"
    requires_active_testing = False  # standard DNS resolution -- no traffic to the target's services
    capability = "subdomain_discovery"
    phase = 15  # after subfinder/amass (10/11) discover names, before httpx (20) probes them
    kill_chain_phase = "reconnaissance"
    safety_tier = "passive"  # DNS queries to resolvers, same class as subfinder's public-source lookups
    applicable_target_types = {"domain"}

    def _host_set(self, target_value: str, prior_findings: list[CommonFinding]) -> list[str]:
        hosts = [target_value]
        hosts.extend(f.value for f in prior_findings if f.asset_type == "subdomain")
        seen: set[str] = set()
        return [h for h in hosts if not (h in seen or seen.add(h))]

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        hosts = self._host_set(target_value, prior_findings)

        command = ["dnsx", "-json", "-silent", "-a", "-resp"]

        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        timeout_seconds = config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
        # Incremental capture: a timeout now KEEPS whatever dnsx already resolved instead
        # of discarding it (see base.run_with_timeout).
        result = await run_with_timeout(
            proc, timeout_seconds, "dnsx", stdin="\n".join(hosts).encode()
        )
        if result.timed_out:
            return RawToolOutput(
                command=" ".join(command) + f"  (stdin: {', '.join(hosts)})",
                stdout=result.stdout,
                stderr=(result.stderr + "\ntimed out").strip(),
                exit_code=-1,
                timed_out=True,
            )

        return RawToolOutput(
            command=" ".join(command) + f"  (stdin: {', '.join(hosts)})",
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code if result.exit_code is not None else -1,
        )

    def parse(self, raw: RawToolOutput) -> list[CommonFinding]:
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

            host = obj.get("host")
            if not host or host in seen:
                continue
            a_records = obj.get("a") or []
            if not a_records:
                continue  # no live A record -> not a resolvable subdomain, drop it
            seen.add(host)
            findings.append(
                CommonFinding(
                    asset_type="subdomain",
                    value=host,
                    metadata={"source": "dnsx", "a_records": a_records},
                )
            )
        return findings
