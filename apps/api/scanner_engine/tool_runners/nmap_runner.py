import asyncio
import socket
import xml.etree.ElementTree as ET

from apps.api.scanner_engine.tool_runners._net import resolve_scan_host
from apps.api.scanner_engine.tool_runners.base import BaseToolRunner, CommonFinding, RawToolOutput

DEFAULT_TIMEOUT_SECONDS = 240


class NmapRunner(BaseToolRunner):
    name = "nmap"
    version = "7"  # apt-provided; major line pinned, exact patch varies by base image
    requires_active_testing = False  # service/version detection -- recon
    phase = 40  # last: deep-scans the ports naabu found
    kill_chain_phase = "reconnaissance"
    safety_tier = "active_safe"  # connect + version detection (no state change)

    def _targets_and_ports(
        self, target_value: str, prior_findings: list[CommonFinding]
    ) -> tuple[list[str], list[str] | None]:
        """Blueprint §8: 'deep scan on Naabu-discovered ports only'. If naabu
        produced port findings, scan exactly those hosts/ports; otherwise fall
        back to a top-ports service scan of the original target."""
        hosts: list[str] = []
        ports: set[str] = set()
        for f in prior_findings:
            if f.asset_type == "port":
                ip = f.metadata.get("ip") or f.metadata.get("host")
                port = f.metadata.get("port")
                if ip:
                    hosts.append(str(ip))
                if port is not None:
                    ports.add(str(port))

        if hosts and ports:
            seen: set[str] = set()
            uniq_hosts = [h for h in hosts if not (h in seen or seen.add(h))]
            return uniq_hosts, sorted(ports, key=int)
        return [target_value], None  # fallback

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        hosts, ports = self._targets_and_ports(target_value, prior_findings)

        try:
            resolved = [resolve_scan_host(h) for h in hosts]
        except (socket.gaierror, IndexError) as exc:
            return RawToolOutput(
                command=f"nmap {' '.join(hosts)}", stdout="", stderr=f"DNS resolution failed: {exc}", exit_code=-1
            )

        # -sT connect scan (no root), -sV version detection, -Pn skip host
        # discovery (containers often drop ping), -oX - XML to stdout.
        command = ["nmap", "-sT", "-sV", "-Pn", "-T4"]
        if ports is not None:
            command += ["-p", ",".join(ports)]
        else:
            command += ["--top-ports", str(config.get("top_ports", 100))]
        command += ["-oX", "-", *resolved]

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
        if not raw.stdout.strip():
            return findings
        try:
            root = ET.fromstring(raw.stdout)
        except ET.ParseError:
            return findings

        for host in root.findall("host"):
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host.find("address")
            ip = addr_el.get("addr") if addr_el is not None else None
            if ip is None:
                continue
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = port.get("portid")
                svc = port.find("service")
                findings.append(
                    CommonFinding(
                        asset_type="service",
                        value=f"{ip}:{portid}",
                        metadata={
                            "ip": ip,
                            "port": int(portid) if portid and portid.isdigit() else portid,
                            "protocol": port.get("protocol", "tcp"),
                            "service": svc.get("name") if svc is not None else None,
                            "product": svc.get("product") if svc is not None else None,
                            "version": svc.get("version") if svc is not None else None,
                        },
                    )
                )
        return findings
