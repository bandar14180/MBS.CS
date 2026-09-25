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

DEFAULT_TIMEOUT_SECONDS = 120

# The ProjectDiscovery httpx binary is installed as `httpx-pd` in the worker
# image to avoid colliding with the Python `httpx` library on PATH.
HTTPX_BIN = "httpx-pd"


class HttpxRunner(BaseToolRunner):
    name = "httpx"
    version = "1.10.0"
    binary = HTTPX_BIN
    requires_active_testing = False  # HTTP probing/fingerprinting -- passive recon
    capability = "web_service_discovery"
    phase = 20  # after subfinder (10), before naabu (30)
    kill_chain_phase = "reconnaissance"
    safety_tier = "active_safe"  # sends benign HTTP probes (no state change)

    def _host_set(self, target_value: str, prior_findings: list[CommonFinding]) -> list[str]:
        """Probe the original target plus any subdomains subfinder discovered."""
        hosts = [target_value]
        hosts.extend(f.value for f in prior_findings if f.asset_type == "subdomain")
        seen: set[str] = set()
        return [h for h in hosts if not (h in seen or seen.add(h))]

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        # Validate (SSRF/DNS-rebinding) but feed httpx-pd the ORIGINAL HOSTNAME, not the
        # resolved IP. Unlike naabu/nmap (raw TCP; no concept of virtual hosting), httpx
        # speaks HTTP(S): the Host header and TLS SNI are the hostname, and the overwhelming
        # majority of real-world sites are on shared IPs / CDNs (Vercel, Netlify, Cloudflare,
        # ...) that route purely on that value. Feeding a bare IP silently probes whatever
        # default/unrelated site that IP's edge answers with instead of the actual target --
        # found by httpx returning a 308 to https://vercel.com/ for a real production domain,
        # not a timeout or an error, so nothing about the run LOOKED broken. Every downstream
        # HTTP-layer tool (nuclei, katana, arjun, nuclei-dast) inherits this fix for free: they
        # all key off httpx's own `http_service` finding, never resolving independently.
        resolved: list[str] = []
        resolve_errors: list[str] = []
        for host in self._host_set(target_value, prior_findings):
            try:
                resolve_scan_host(host)
            except (socket.gaierror, IndexError) as exc:
                # Keep the REAL reason, not just "didn't resolve" -- the UI's error/reason
                # field surfaces this stderr directly, so a DNS-side failure is diagnosable
                # from the scan itself instead of requiring a container-log lookup.
                resolve_errors.append(f"{host}: {type(exc).__name__}: {exc}")
                continue  # skip hosts that don't resolve; others still get probed
            resolved.append(host)

        if not resolved:
            return RawToolOutput(
                command=f"{HTTPX_BIN} (no resolvable hosts)",
                stdout="",
                stderr="no resolvable hosts -- " + "; ".join(resolve_errors),
                exit_code=-1,
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
        timeout_seconds = config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
        # Incremental capture: a timeout now KEEPS whatever httpx already probed instead
        # of discarding it (see base.run_with_timeout).
        result = await run_with_timeout(
            proc, timeout_seconds, "httpx", stdin="\n".join(resolved).encode()
        )
        if result.timed_out:
            return RawToolOutput(
                command=" ".join(command) + f"  (stdin: {', '.join(resolved)})",
                stdout=result.stdout,
                stderr=(result.stderr + "\ntimed out").strip(),
                exit_code=-1,
                timed_out=True,
            )

        return RawToolOutput(
            command=" ".join(command) + f"  (stdin: {', '.join(resolved)})",
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

            url = obj.get("url")
            if not url:
                continue

            metadata = {
                "host": obj.get("host") or obj.get("input"),
                "port": obj.get("port"),
                "scheme": obj.get("scheme"),
                "status_code": obj.get("status_code"),
                "title": obj.get("title"),
                "webserver": obj.get("webserver"),
                "tech": obj.get("tech") or obj.get("technologies"),
            }
            # Prompt 20 (Authenticated Surface Intelligence): derive the auth state from what
            # httpx observed (status code + redirect location + title) WITHOUT authenticating.
            # A 401/403 is `protected`, a login bounce is `login_redirect` -- surface the
            # unauthenticated scan did not cross, which the coverage model then names as a
            # requires_auth gap rather than treating "no finding" as "nothing there".
            from apps.api.scanner_engine.auth_state import auth_metadata

            metadata.update(
                auth_metadata(
                    obj.get("status_code"),
                    location=obj.get("location") or obj.get("final_url"),
                    title=obj.get("title"),
                )
            )
            findings.append(CommonFinding(asset_type="http_service", value=url, metadata=metadata))
        return findings
