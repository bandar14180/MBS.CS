import asyncio
import json

from apps.api.core.config import get_settings
from apps.api.scanner_engine.tool_runners._web import web_targets
from apps.api.scanner_engine.tool_runners.base import (
    terminate_and_reap,
    BaseToolRunner,
    CommonFinding,
    RawToolOutput,
    VulnerabilityFinding,
)

# NO DEFAULT WALL-CLOCK TIMEOUT. nuclei is routinely the longest-running tool in the
# pipeline (a full template set against a real site legitimately runs for hours), so a fixed
# ceiling necessarily either kills healthy long scans or is a meaningless large number. By
# default nuclei runs to natural completion; the reaper (heartbeat-based) recovers a genuinely
# dead worker, and cancellation still terminates the subprocess (see run()). An optional
# per-scan cap is still honored via tool_config.nuclei_timeout_seconds (nuclei only) or the
# shared tool_config.timeout_seconds; a value <= 0 also means no timeout.
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
    binary = "nuclei"
    requires_active_testing = True  # sends template payloads -> gated on active_testing_allowed (§7)
    capability = "vulnerability_detection"
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
        # Optional timeout precedence: nuclei's own key wins, else the shared key, else NONE.
        # `nuclei_timeout_seconds` is nuclei-only because raising the SHARED `timeout_seconds`
        # to accommodate nuclei also raises it for every other runner -- including ffuf, whose
        # timeout is PER TARGET. When NEITHER key is set (the default), nuclei is NOT bounded
        # by a wall clock at all: it runs to natural completion, and liveness/cancellation are
        # handled elsewhere (the heartbeat reaper; the CancelledError branch below). A value
        # <= 0 is treated the same as unset -- explicitly "no timeout".
        timeout_seconds = config.get("nuclei_timeout_seconds", config.get("timeout_seconds"))
        if timeout_seconds is not None and timeout_seconds <= 0:
            timeout_seconds = None

        stdin_bytes = "\n".join(urls).encode()
        try:
            if timeout_seconds is None:
                # No wall-clock cap: let nuclei finish on its own.
                stdout, stderr = await proc.communicate(input=stdin_bytes)
            else:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=stdin_bytes),
                    timeout=timeout_seconds,
                )
        except asyncio.CancelledError:
            # Scan revoked / worker warm shutdown. Without this the subprocess is
            # LEFT RUNNING (verified: returncode stays None) -- kill it, then re-raise
            # so cancellation still propagates.
            await terminate_and_reap(proc, "nuclei")
            raise
        except asyncio.TimeoutError:
            # Only reachable when a caller explicitly set a positive timeout.
            await terminate_and_reap(proc, "nuclei")
            return RawToolOutput(
                command=" ".join(command),
                stdout="",
                # Name the knob and the value that actually applied: the previous bare
                # "timed out" left an operator guessing which of the two keys to raise.
                stderr=(
                    f"timed out after {timeout_seconds}s -- raise "
                    f"tool_config.nuclei_timeout_seconds (nuclei only) if this target matters"
                ),
                exit_code=-1,
            )

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
