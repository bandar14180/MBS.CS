import asyncio
import socket
import xml.etree.ElementTree as ET

from apps.api.scanner_engine.tool_runners._net import resolve_scan_host
from apps.api.scanner_engine.tool_runners.base import (
    BaseToolRunner,
    CommonFinding,
    RawToolOutput,
    run_with_timeout,
)

DEFAULT_TIMEOUT_SECONDS = 240


class NmapRunner(BaseToolRunner):
    name = "nmap"
    version = "7"  # apt-provided; major line pinned, exact patch varies by base image
    binary = "nmap"
    requires_active_testing = False  # service/version detection -- recon
    capability = "service_fingerprinting"
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

        # Resolve each host independently (matches httpx_runner/naabu_runner): a
        # naabu-discovered host that no longer resolves must only drop THAT host, not abort
        # the whole scan on the first unresolvable one (the previous all-or-nothing list
        # comprehension did exactly that).
        resolved: list[str] = []
        resolve_errors: list[str] = []
        for h in hosts:
            try:
                resolved.append(resolve_scan_host(h))
            except (socket.gaierror, IndexError) as exc:
                resolve_errors.append(f"{h}: {type(exc).__name__}: {exc}")
                continue
        if not resolved:
            return RawToolOutput(
                command=f"nmap {' '.join(hosts)} (no resolvable hosts)",
                stdout="",
                stderr="no resolvable hosts -- " + "; ".join(resolve_errors),
                exit_code=-1,
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
        # Incremental capture: a timeout now KEEPS whatever nmap already streamed to its
        # -oX - XML output instead of discarding it (see base.run_with_timeout). The XML
        # will typically be truncated/unclosed in that case; parse() already tolerates
        # that via its existing ET.ParseError guard, returning no findings rather than
        # raising.
        result = await run_with_timeout(
            proc, config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS), "nmap"
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
