import asyncio
import ipaddress
import json
import socket

from apps.api.scanner_engine.tool_runners.base import BaseToolRunner, CommonFinding, RawToolOutput

DEFAULT_TIMEOUT_SECONDS = 90


def _resolve_scan_host(target_value: str) -> str:
    """Naabu uses its own bundled DNS resolvers, which bypass the OS resolver
    (so Docker-internal names -- and any split-horizon/internal DNS -- fail).
    Resolve via the OS here and hand naabu an IP. IPs and CIDR ranges pass
    through untouched."""
    try:
        ipaddress.ip_network(target_value, strict=False)
        return target_value  # already an IP or CIDR
    except ValueError:
        pass
    # getaddrinfo uses the OS resolver; take the first A/AAAA record.
    infos = socket.getaddrinfo(target_value, None)
    return infos[0][4][0]


class NaabuRunner(BaseToolRunner):
    name = "naabu"
    version = "2.6.1"
    requires_active_testing = False  # passive/recon per blueprint §7 -- gated on verified only

    async def run(self, target_value: str, config: dict) -> RawToolOutput:
        top_ports = str(config.get("top_ports", 100))
        rate = str(config.get("rate", 200))

        try:
            scan_host = await asyncio.get_running_loop().run_in_executor(
                None, _resolve_scan_host, target_value
            )
        except (socket.gaierror, IndexError) as exc:
            return RawToolOutput(
                command=f"naabu -host {target_value}",
                stdout="",
                stderr=f"DNS resolution failed for {target_value}: {exc}",
                exit_code=-1,
            )

        command = [
            "naabu",
            "-host", scan_host,
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
