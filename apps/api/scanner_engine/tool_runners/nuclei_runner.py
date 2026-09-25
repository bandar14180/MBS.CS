import asyncio
import json

from apps.api.core.config import get_settings
from apps.api.modules.vulnerabilities.taxonomy import canonical_cve, canonical_cwe
from apps.api.scanner_engine.location_normalize import normalize_location
from apps.api.scanner_engine.tool_runners._dast_context import extract_dast_context
from apps.api.scanner_engine.tool_runners._web import web_targets
from apps.api.scanner_engine.tool_runners.base import (
    run_with_timeout,
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


def _text(value: object) -> str:
    """A string field from nuclei's JSON, or "" when it was absent or not a string.

    Prompt 24 (Requirement E). Every consumer of these fields -- `.lower()` on severity, the
    DB's string columns, the report renderer -- assumes a string because nuclei's schema says
    so. A single line where one is null/list/number used to raise out of
    `parse_vulnerabilities` and cost the run EVERY finding (see the shape guard in the loop).

    Deliberately returns "" rather than `str(value)` for a non-string: stringifying would put
    `"['high']"` or `"None"` into a security report as though nuclei had said it. Absent is
    truthful; a coerced repr is not."""
    return value if isinstance(value, str) else ""


def _opt_text(value: object) -> str | None:
    """`_text` for columns that are nullable -- absent stays None rather than becoming ""."""
    return value if isinstance(value, str) else None


def _cvss_score(value: object) -> float | None:
    """nuclei's `cvss-score` as a float, or None.

    `VulnerabilityFinding.cvss_score` is typed `float | None` and flows through
    `vulnerabilities.service._score_for` into a NUMERIC column, so a string that got this far
    reached the DB as text. nuclei normally emits a number, but a string ("9.8") is a real
    spelling in the wild, so it is parsed rather than discarded.

    A bool is rejected explicitly: `isinstance(True, int)` is True in Python, and `True` is
    not a CVSS score. Anything unparseable returns None -- no score is ever DERIVED from the
    severity here (that decision belongs to `_score_for`, which documents why the floor is
    applied there and not invented at parse time)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


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

    @staticmethod
    def _timeout_seconds(config: dict) -> float | None:
        """The effective wall-clock cap for this run, or None for "run to completion".

        Prompt 24 (Requirements A and C/D). `tool_config` is key-allowlisted by scans.service
        but its VALUES are unvalidated (`tool_config: dict` in the schema), so both
        `nuclei_timeout_seconds` and the shared `timeout_seconds` arrive as arbitrary JSON.
        This is the same defect class already closed for `nuclei_tags` here and for
        `dast_timeout_seconds` in NucleiDastRunner -- nuclei itself was simply never given the
        same treatment, and it failed WORSE than either of those:

          * The value used to be read AFTER `create_subprocess_exec`, and the bare
            `timeout_seconds <= 0` comparison raises `TypeError: '<=' not supported between
            instances of 'str' and 'int'` for a string/list/dict. REPRODUCED: the exception
            escapes `run()` with the nuclei process ALREADY SPAWNED and never killed
            (`proc.kill()` is never reached, and there is no try/finally around the spawn), so
            the orchestrator records an opaque failed tool run AND leaks a live nuclei that
            keeps sending payloads at the target. That is an orphaned active-testing process
            created by a config typo -- the exact outcome Requirement D forbids.
          * `True` was silently ACCEPTED. `isinstance(True, int)` is True in Python, so a bool
            flowed into `asyncio.wait_for(timeout=True)` and became a ONE-SECOND cap on a tool
            whose whole documented policy is that it may run for hours. The scan then reported
            a timeout that no operator had configured.

        Validating BEFORE the spawn turns both into a clear config error naming the key, with
        no process created. A value <= 0 still means "no wall-clock cap" -- unchanged, and the
        same convention NucleiDastRunner uses. Refusing rather than falling back to the other
        key or to no-timeout is deliberate: silently substituting a budget the operator did not
        ask for is how a truncated scan comes to be reported as a clean one."""
        for key in ("nuclei_timeout_seconds", "timeout_seconds"):
            if key not in config:
                continue
            value = config[key]
            if value is None:
                # Explicit null == unset, so fall through to the next key (and ultimately to
                # the no-timeout default). Matches NucleiDastRunner's handling of a null.
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(
                    f"tool_config.{key} must be a number of seconds, got "
                    f"{type(value).__name__}: {value!r}"
                )
            return float(value) if value > 0 else None
        return None

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        # Validate the configured budget BEFORE spawning nuclei (see _timeout_seconds): a bad
        # value must be a clear config error, never an opaque mid-run TypeError with a live
        # active-testing subprocess left behind.
        timeout_seconds = self._timeout_seconds(config)
        urls = self._target_urls(target_value, prior_findings)
        tags = config.get("nuclei_tags", DEFAULT_TAGS)

        command = ["nuclei", "-jsonl", "-silent", "-disable-update-check", "-no-color"]
        # Point nuclei at the baked-in template set explicitly (see
        # Dockerfile.worker) so discovery never depends on the ambient $HOME.
        templates_dir = get_settings().nuclei_templates_dir
        if templates_dir:
            command += ["-templates", str(templates_dir)]
        # Prompt 24 (Requirement A). `tool_config` is key-allowlisted by scans.service but its
        # VALUES are unvalidated (`tool_config: dict` in the schema), so `nuclei_tags` arrives
        # as arbitrary JSON. There is NO shell here -- create_subprocess_exec takes an argv
        # list -- so a string, however hostile, is one argument to `-tags` and cannot inject a
        # flag; that property is unchanged and is what makes this safe rather than merely
        # tidy. The real defect was a non-STRING value: `command += ["-tags", ["--proxy", ...]]`
        # appends a LIST as one argv element, which create_subprocess_exec rejects with a bare
        # `TypeError: expected str, bytes or os.PathLike` -- recorded by the orchestrator as an
        # opaque failed tool run with no indication that the config was at fault. Coercing to
        # text keeps argv well-typed and keeps the single-argument property explicit at the
        # point where the guarantee is made.
        if tags and isinstance(tags, str):
            command += ["-tags", tags]
        elif tags:
            # Not a string: refuse the value rather than stringify it into a tag selector that
            # silently means something other than what was configured. Falling back to
            # DEFAULT_TAGS would ALSO be wrong -- it would run a template set the operator did
            # not ask for while reporting success.
            raise ValueError(
                f"tool_config.nuclei_tags must be a comma-separated string, got "
                f"{type(tags).__name__}: {tags!r}"
            )

        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        # Optional timeout precedence (resolved above, BEFORE the spawn): nuclei's own key
        # wins, else the shared key, else NONE. `nuclei_timeout_seconds` is nuclei-only
        # because raising the SHARED `timeout_seconds` to accommodate nuclei also raises it
        # for every other runner -- including ffuf, whose timeout is PER TARGET. When NEITHER
        # key is set (the default), nuclei is NOT bounded by a wall clock at all: it runs to
        # natural completion, and liveness/cancellation are handled elsewhere (the heartbeat
        # reaper; the CancelledError branch below). A value <= 0 is treated the same as unset
        # -- explicitly "no timeout". See _timeout_seconds for why the value is now validated
        # before the process exists rather than compared after it.
        stdin_bytes = "\n".join(urls).encode()
        # Incremental capture: a timeout now KEEPS whatever nuclei already reported instead
        # of discarding it (see base.run_with_timeout). `timeout_seconds=None` is handled
        # natively by run_with_timeout as "no wall-clock cap", preserving the exact
        # let-it-finish semantics above.
        result = await run_with_timeout(proc, timeout_seconds, "nuclei", stdin=stdin_bytes)
        if result.timed_out:
            # Only reachable when a caller explicitly set a positive timeout.
            return RawToolOutput(
                command=" ".join(command),
                stdout=result.stdout,
                # Name the knob and the value that actually applied: the previous bare
                # "timed out" left an operator guessing which of the two keys to raise.
                stderr=(
                    result.stderr + "\n"
                    f"timed out after {timeout_seconds}s -- raise "
                    f"tool_config.nuclei_timeout_seconds (nuclei only) if this target matters"
                ).strip(),
                exit_code=-1,
                timed_out=True,
            )

        return RawToolOutput(
            command=" ".join(command) + f"  (stdin: {', '.join(urls)})",
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code if result.exit_code is not None else -1,
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
            # SHAPE guard (Prompt 24, Requirement E). `json.loads` succeeding only means the
            # line was valid JSON -- NOT that it was a JSON *object* with the fields below.
            # A JSONL line that is a list/string/number (a nuclei error payload, a proxy or
            # wrapper injecting a line, a future schema change) previously reached
            # `obj.get(...)` and raised AttributeError/TypeError out of this whole method.
            # The orchestrator catches that (parse_vuln_failed) but then substitutes
            # `vuln_findings = []` for the ENTIRE run -- so ONE anomalous line discarded every
            # good finding beside it, and with exit 0 the run still classified as `completed`.
            # MEASURED: a critical RCE on line 1 was dropped and the scan read as clean. That
            # is the silent-false-negative direction this prompt exists to close, so a
            # non-object line is skipped like a malformed one instead of poisoning the batch.
            if not isinstance(obj, dict):
                continue

            template_id = obj.get("template-id") or obj.get("templateID")
            # ABSENT vs WRONG-TYPED `info` are deliberately different cases, because they mean
            # different things and the original `obj.get("info", {})` conflated them:
            #
            #   * ABSENT  -- normal. Some nuclei records legitimately carry no `info` block,
            #     and the code below already degrades correctly (title falls back to the
            #     template id, severity to nuclei's own "info" default). Kept working exactly
            #     as before: dropping these would LOSE real findings.
            #   * WRONG-TYPED (null / scalar / list) -- malformed. The record claims an `info`
            #     block and it is unreadable, so the fields below cannot be trusted; treating
            #     it as {} would silently label it "info" severity with a template-id title,
            #     manufacturing a clean-looking finding out of a record we could not parse.
            info = obj.get("info", {})
            if info is None:
                info = {}          # explicit null == absent; same benign degradation
            elif not isinstance(info, dict):
                continue           # present but unreadable == malformed record
            matched_at = obj.get("matched-at") or obj.get("matched_at") or obj.get("host")
            matcher = obj.get("matcher-name") or ""
            # Identity must be STRINGS: both feed the fingerprint, and a non-string there
            # would either raise (normalize_location does a substring test) or produce an
            # unstable identity that cannot dedupe or be traced back. No identity => dropped,
            # never guessed -- the existing rule below, extended to cover type as well as
            # absence.
            if not isinstance(template_id, str) or not isinstance(matched_at, str):
                continue
            if not isinstance(matcher, str):
                matcher = ""
            if not template_id or not matched_at:
                continue

            # Normalize ONLY the fingerprint's identity input (Prompt 13, Finding #1) --
            # `matched_at` itself (below, on the finding) stays the exact raw string nuclei
            # reported, so evidence/report display is unaffected. This does not change the
            # fingerprint FORMAT (still template_id|matcher|matched_at) or retroactively touch
            # any already-persisted fingerprint -- see location_normalize.py's module docstring.
            fingerprint = f"{template_id}|{matcher}|{normalize_location(matched_at)}"
            if fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(fingerprint)

            # Same shape rule one level down: nuclei's `classification` is an object, but a
            # non-object value here would raise on `.get` and take the whole batch with it.
            # An unreadable classification means "no CWE/CVE reported" -- the honest reading,
            # and canonical_cwe/canonical_cve already return None for anything unparseable.
            classification = info.get("classification")
            if not isinstance(classification, dict):
                classification = {}
            cwe = classification.get("cwe-id")
            cve = classification.get("cve-id")
            # Prompt 23: canonicalise the identifiers nuclei reports, and preserve exactly what
            # it said. `cwe-id`/`cve-id` may be a list or a scalar; the first entry is the
            # primary classification. Neither id is ever INVENTED -- an absent or malformed
            # value stays absent (canonical_* return None), and nothing is derived from the
            # severity, the title or the other identifier.
            raw_cwe = (cwe[0] if isinstance(cwe, list) else cwe) if cwe else None
            raw_cve = (cve[0] if isinstance(cve, list) else cve) if cve else None
            category = canonical_cwe(raw_cwe)
            cve = canonical_cve(raw_cve)

            # Prompt 13, Finding #7: parameter/method/header context nuclei-dast's fuzzing
            # actually left in its own JSON output, when present. Never invents a value nuclei
            # did not report -- see _dast_context.py's module docstring for exactly what each
            # key means and where it comes from. Merged into the SAME metadata dict (not a
            # separate field) so existing consumers reading VulnerabilityFinding.metadata see
            # one flat namespace, unchanged in shape from before this addition.
            metadata = {
                "template_id": template_id,
                "matcher_name": matcher or None,
                "cve": cve,
                "type": obj.get("type"),
                "tags": info.get("tags"),
            }
            # Scanner-native provenance (Prompt 23): keep what nuclei ACTUALLY emitted whenever
            # canonicalisation changed or rejected it, so normalising is never lossy and an
            # analyst can always trace a canonical id back to the tool's own words. Recorded
            # only when it differs, so the common (already-canonical) case adds no noise.
            if raw_cwe is not None and raw_cwe != category:
                metadata["cwe_reported"] = raw_cwe
            if raw_cve is not None and raw_cve != cve:
                metadata["cve_reported"] = raw_cve
            metadata.update(extract_dast_context(obj, matched_at))

            findings.append(
                VulnerabilityFinding(
                    fingerprint=fingerprint,
                    title=_text(info.get("name")) or template_id,
                    # `.lower()` on a non-string severity (a list/int nuclei should never emit,
                    # but which a wrapper or a schema change can produce) raised out of the
                    # whole batch. Coerced to text first; the AUTHORITATIVE normalisation is
                    # still the single one at the ingest boundary
                    # (vulnerabilities.service -> taxonomy.normalize_severity), which this does
                    # not duplicate or pre-empt -- an unrecognised word is passed through
                    # unchanged, exactly as before, for that boundary to rule on.
                    severity=_text(info.get("severity")).lower() or "info",
                    category=category,
                    description=_opt_text(info.get("description")),
                    cvss_vector=_opt_text(classification.get("cvss-metrics")),
                    # cvss_score is typed float|None. A string score ("9.8") is a real nuclei
                    # spelling and is converted; anything non-numeric becomes None rather than
                    # reaching the numeric column as text. Never derived from the severity.
                    cvss_score=_cvss_score(classification.get("cvss-score")),
                    matched_at=matched_at,
                    metadata=metadata,
                )
            )
        return findings
