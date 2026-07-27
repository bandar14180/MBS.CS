import asyncio
import json
import socket

from apps.api.scanner_engine.tool_runners._net import resolve_scan_host
from apps.api.scanner_engine.tool_runners.base import BaseToolRunner, CommonFinding, RawToolOutput

DEFAULT_TIMEOUT_SECONDS = 120

# The ProjectDiscovery httpx binary is installed as `httpx-pd` in the worker
# image to avoid colliding with the Python `httpx` library on PATH.
HTTPX_BIN = "httpx-pd"


class HttpxRunner(BaseToolRunner):
    name = "httpx"
    version = "1.10.0"
    requires_active_testing = False  # HTTP probing/fingerprinting -- passive recon
    phase = 20  # after subfinder (10), before naabu (30)

    def _host_set(self, target_value: str, prior_findings: list[CommonFinding]) -> list[str]:
        """Probe the original target plus any subdomains subfinder discovered."""
        hosts = [target_value]
        hosts.extend(f.value for f in prior_findings if f.asset_type == "subdomain")
        seen: set[str] = set()
        return [h for h in hosts if not (h in seen or seen.add(h))]

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        resolved: list[str] = []
        for host in self._host_set(target_value, prior_findings):
            try:
                resolved.append(resolve_scan_host(host))
            except (socket.gaierror, IndexError):
                continue  # skip hosts that don't resolve; others still get probed

        if not resolved:
            return RawToolOutput(
                command=f"{HTTPX_BIN} (no resolvable hosts)", stdout="", stderr="no resolvable hosts", exit_code=-1
            )

        command = [
            HTTPX_BIN,
            "-json",
            "-silent",
            "-no-color",
            "-tech-detect",
            "-status-code",
            "-title",
        ]

        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input="\n".join(resolved).encode()),
                timeout=config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS),
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return RawToolOutput(command=" ".join(command), stdout="", stderr="timed out", exit_code=-1)

        return RawToolOutput(
            command=" ".join(command) + f"  (stdin: {', '.join(resolved)})",
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

            url = obj.get("url")
            if not url:
                continue

            findings.append(
                CommonFinding(
                    asset_type="http_service",
                    value=url,
                    metadata={
                        "host": obj.get("host") or obj.get("input"),
                        "port": obj.get("port"),
                        "scheme": obj.get("scheme"),
                        "status_code": obj.get("status_code"),
                        "title": obj.get("title"),
                        "webserver": obj.get("webserver"),
                        "tech": obj.get("tech") or obj.get("technologies"),
                    },
                )
            )
        return findings
