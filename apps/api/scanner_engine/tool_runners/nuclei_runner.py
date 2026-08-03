import asyncio
import json

from apps.api.core.config import get_settings
from apps.api.scanner_engine.tool_runners._net import resolve_scan_host
from apps.api.scanner_engine.tool_runners.base import (
    BaseToolRunner,
    CommonFinding,
    RawToolOutput,
    VulnerabilityFinding,
)

DEFAULT_TIMEOUT_SECONDS = 300
# A broader-but-still-safe default template set for a professional web pentest:
# common misconfigurations, known CVEs, sensitive exposures, default credentials,
# subdomain takeovers, and tech fingerprinting. All are gated by
# `requires_active_testing` (they send payloads). Override per-scan via
# config["nuclei_tags"]; the richer classifications (CWE/CVE/tags) also drive the
# ATT&CK / kill-chain mapping downstream.
DEFAULT_TAGS = "misconfig,cve,exposure,default-login,takeover,tech"


class NucleiRunner(BaseToolRunner):
    name = "nuclei"
    version = "3.11.0"
    requires_active_testing = True  # sends template payloads -> gated on active_testing_allowed (§7)
    phase = 50  # last: runs against http services discovered earlier in the pipeline
    kill_chain_phase = "delivery"      # delivers detection probes/payloads
    safety_tier = "active_safe"        # DETECTION templates only (no exploitation)

    # Bound the fan-out when we probe discovered ports (a top-ports sweep can
    # return many): each endpoint becomes two URLs (http + https).
    _MAX_DISCOVERED_ENDPOINTS = 50

    def _target_urls(self, target_value: str, prior_findings: list[CommonFinding]) -> list[str]:
        """Pick what nuclei scans, in priority order:

        1. The HTTP services httpx confirmed (`http_service` findings) -- the
           happy path when the web app is on a default port httpx probed.
        2. If httpx confirmed none (e.g. the app listens on a non-standard port
           like :3000 that httpx's default 80/443 probe never saw), fall back to
           the open ports naabu (`port`) and nmap (`service`) discovered, probing
           http+https on each. Without httpx we can't know the scheme, so we try
           both; nuclei's HTTP templates simply no-op on a port that doesn't
           speak (that) HTTP. This is what stops a web app on an odd port from
           being invisible to the vuln scan.
        3. Only if nothing was discovered at all, http(s) on the bare target.
        """
        urls = [f.value for f in prior_findings if f.asset_type == "http_service" and f.value]
        if urls:
            seen: set[str] = set()
            return [u for u in urls if not (u in seen or seen.add(u))]

        # Derive endpoints from discovered ports/services (same target host, so
        # already net_guard-validated; a port doesn't change the host).
        endpoints: list[str] = []
        seen_ep: set[str] = set()
        for f in prior_findings:
            if f.asset_type not in ("service", "port"):
                continue
            host = f.metadata.get("ip") or f.metadata.get("host")
            port = f.metadata.get("port")
            if not host or port is None:
                continue
            ep = f"{host}:{port}"
            if ep not in seen_ep:
                seen_ep.add(ep)
                endpoints.append(ep)
        if endpoints:
            probed: list[str] = []
            for ep in endpoints[: self._MAX_DISCOVERED_ENDPOINTS]:
                probed.append(f"http://{ep}")
                probed.append(f"https://{ep}")
            return probed

        try:
            ip = resolve_scan_host(target_value)
        except Exception:
            ip = target_value
        return [f"http://{ip}", f"https://{ip}"]

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        urls = self._target_urls(target_value, prior_findings)
        tags = config.get("nuclei_tags", DEFAULT_TAGS)

        command = ["nuclei", "-jsonl", "-silent", "-disable-update-check", "-no-color"]
        # Point nuclei at the baked-in template set explicitly (see
        # Dockerfile.worker) so discovery never depends on the ambient $HOME.
        templates_dir = get_settings().nuclei_templates_dir
        if templates_dir:
            command += ["-templates", templates_dir]
        if tags:
            command += ["-tags", tags]

        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input="\n".join(urls).encode()),
                timeout=config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS),
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return RawToolOutput(command=" ".join(command), stdout="", stderr="timed out", exit_code=-1)

        return RawToolOutput(
            command=" ".join(command) + f"  (stdin: {', '.join(urls)})",
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            exit_code=proc.returncode if proc.returncode is not None else -1,
        )

    def parse(self, raw: RawToolOutput) -> list[CommonFinding]:
        # Nuclei produces vulnerabilities, not inventory assets.
        return []

    def parse_vulnerabilities(self, raw: RawToolOutput) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        for line in raw.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            template_id = obj.get("template-id") or obj.get("templateID")
            info = obj.get("info", {})
            matched_at = obj.get("matched-at") or obj.get("matched_at") or obj.get("host")
            matcher = obj.get("matcher-name") or ""
            if not template_id or not matched_at:
                continue

            classification = info.get("classification") or {}
            cwe = classification.get("cwe-id")
            cve = classification.get("cve-id")
            category = None
            if cwe:
                category = cwe[0] if isinstance(cwe, list) else cwe

            findings.append(
                VulnerabilityFinding(
                    fingerprint=f"{template_id}|{matcher}|{matched_at}",
                    title=info.get("name") or template_id,
                    severity=(info.get("severity") or "info").lower(),
                    category=category,
                    description=info.get("description"),
                    cvss_vector=classification.get("cvss-metrics"),
                    cvss_score=classification.get("cvss-score"),
                    matched_at=matched_at,
                    metadata={
                        "template_id": template_id,
                        "matcher_name": matcher or None,
                        "cve": cve,
                        "type": obj.get("type"),
                        "tags": info.get("tags"),
                    },
                )
            )
        return findings
