import asyncio
import json
import socket

from apps.api.scanner_engine.tool_runners._net import resolve_scan_host
from apps.api.scanner_engine.tool_runners.base import (
    BaseToolRunner,
    CommonFinding,
    RawToolOutput,
    run_with_timeout,
)

DEFAULT_TIMEOUT_SECONDS = 90


class NaabuRunner(BaseToolRunner):
    name = "naabu"
    version = "2.6.1"
    binary = "naabu"
    requires_active_testing = False  # passive/recon per blueprint §7 -- gated on verified only
    capability = "port_discovery"
    phase = 30  # after subfinder (10) + httpx (20), before nmap (40)
    kill_chain_phase = "reconnaissance"
    safety_tier = "active_safe"  # connect-scan port discovery (no state change)

    def _host_set(self, target_value: str, prior_findings: list[CommonFinding]) -> list[str]:
        """Original target plus any live hosts httpx confirmed, else any
        subdomains subfinder discovered. Deduped, original always included."""
        hosts = [target_value]
        for f in prior_findings:
            if f.asset_type == "http_service":
                host = f.metadata.get("host")
                if host:
                    hosts.append(host)
        if len(hosts) == 1:  # no httpx findings -> fall back to subfinder subdomains
            hosts.extend(f.value for f in prior_findings if f.asset_type == "subdomain")
        # dedupe preserving order
        seen: set[str] = set()
        return [h for h in hosts if not (h in seen or seen.add(h))]

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        top_ports = str(config.get("top_ports", 100))
        rate = str(config.get("rate", 200))

        # Resolve each host independently (matches httpx_runner): a recon-discovered host that
        # no longer resolves (a common, expected outcome -- e.g. a stale subdomain subfinder
        # found, or an httpx-confirmed host whose DNS changed since) must only drop THAT host,
        # not abort the whole scan. The previous all-or-nothing list comprehension aborted every
        # host in the batch on the first unresolvable one.
        resolved: list[str] = []
        resolve_errors: list[str] = []
        for h in self._host_set(target_value, prior_findings):
            try:
                resolved.append(resolve_scan_host(h))
            except (socket.gaierror, IndexError) as exc:
                resolve_errors.append(f"{h}: {type(exc).__name__}: {exc}")
                continue
        if not resolved:
            return RawToolOutput(
                command=f"naabu -host {target_value} (no resolvable hosts)",
                stdout="",
                stderr="no resolvable hosts -- " + "; ".join(resolve_errors),
                exit_code=-1,
            )

        command = [
            "naabu",
            "-host", ",".join(resolved),
            "-scan-type", "connect",  # no raw sockets/root needed, unlike -scan-type syn
            "-top-ports", top_ports,
            "-rate", rate,
            "-json",
            "-silent",
        ]

        proc = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        # Incremental capture: a timeout now KEEPS whatever naabu already found instead
        # of discarding it (see base.run_with_timeout).
        result = await run_with_timeout(
            proc, config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS), "naabu"
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

            port = obj.get("port")
            host = obj.get("host") or obj.get("ip")
            if port is None or host is None:
                continue

            findings.append(
                CommonFinding(
                    asset_type="port",
                    value=f"{host}:{port}",
                    metadata={
                        "host": host,
                        "ip": obj.get("ip"),
                        "port": port,
                        "protocol": obj.get("protocol", "tcp"),
                    },
                )
            )
        return findings
