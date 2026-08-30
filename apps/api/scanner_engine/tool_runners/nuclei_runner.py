import asyncio
import json

from apps.api.core.config import get_settings
from apps.api.scanner_engine.tool_runners._web import web_targets
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

    def _target_urls(self, target_value: str, prior_findings: list[CommonFinding]) -> list[str]:
        """What nuclei scans: httpx-confirmed HTTP services, else the open ports
        naabu/nmap discovered (so a web app on a non-standard port like :3000 --
        which httpx's default 80/443 probe never sees -- is still scanned), else
        http(s) on the bare target. See tool_runners._web.web_targets."""
        return web_targets(target_value, prior_findings)

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
        # Dedupe by fingerprint WITHIN a single tool run. nuclei -- and especially
        # NucleiDastRunner, which inherits this parser -- can emit the same
        # template|matcher|matched-at more than once (DAST re-hits one template against one
        # URL while fuzzing its parameters). Every finding in a run shares that run's single
        # evidence row, so two identical fingerprints dedupe to the same vulnerability and
        # then both tried to link (vuln, evidence), raising a duplicate-key IntegrityError in
        # ingest. Collapsing them here (defence in depth alongside the idempotent link in
        # vulnerabilities/service.py) keeps one finding per distinct fingerprint per run. The
        # fingerprint format is unchanged.
        seen_fingerprints: set[str] = set()
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

            fingerprint = f"{template_id}|{matcher}|{matched_at}"
            if fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(fingerprint)

            classification = info.get("classification") or {}
            cwe = classification.get("cwe-id")
            cve = classification.get("cve-id")
            category = None
            if cwe:
                category = cwe[0] if isinstance(cwe, list) else cwe

            findings.append(
                VulnerabilityFinding(
                    fingerprint=fingerprint,
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
