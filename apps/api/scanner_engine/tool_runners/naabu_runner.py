import asyncio
import json
import socket

from apps.api.scanner_engine.tool_runners._net import resolve_scan_host
from apps.api.scanner_engine.tool_runners.base import BaseToolRunner, CommonFinding, RawToolOutput

DEFAULT_TIMEOUT_SECONDS = 90


class NaabuRunner(BaseToolRunner):
    name = "naabu"
    version = "2.6.1"
    requires_active_testing = False  # passive/recon per blueprint §7 -- gated on verified only
    phase = 30  # after subfinder (10) + httpx (20), before nmap (40)

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

        try:
            resolved = [resolve_scan_host(h) for h in self._host_set(target_value, prior_findings)]
        except (socket.gaierror, IndexError) as exc:
            return RawToolOutput(
                command=f"naabu -host {target_value}",
                stdout="",
                stderr=f"DNS resolution failed: {exc}",
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
