import asyncio
import logging
import os

from apps.api.core.config import get_settings
from apps.api.scanner_engine.tool_runners._web import crawled_urls, web_targets
from apps.api.scanner_engine.tool_runners.base import CommonFinding, RawToolOutput, run_with_timeout
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner

logger = logging.getLogger("mbs.scanner.nuclei_dast")

DEFAULT_TIMEOUT_SECONDS = 600  # fuzzing many params is slower than a signature scan
# Bound how many URLs we fuzz so a big crawl can't run unbounded.
MAX_FUZZ_URLS = 200
# How many fuzzed URLs are written verbatim into the recorded command (reproducibility). The
# list is already capped at MAX_FUZZ_URLS; this second bound keeps a 200-URL run's evidence
# header readable, and the elision states how many were omitted rather than hiding them.
_COMMAND_URLS_RECORDED = 25


def _template_provenance(templates_dir: str | None) -> str:
    """Which nuclei template set actually ran, as an OBSERVED fact about the checkout on disk.

    Reads, in order of preference, the two files nuclei's own template repository ships:
    `.checksum` (the template-set digest nuclei maintains) and `.version`. Only the FIRST
    line is used and it is truncated -- this is a provenance label destined for stderr, not
    a file dump.

    NEVER INVENTS. An unset/missing/unreadable directory yields "unknown" rather than a
    plausible-looking version, because a fabricated template version is worse than an absent
    one: it would make two materially different runs look identical in the audit trail. This
    is a LABEL only -- it changes no finding, no severity and no classification, and it can
    never fail the run (every filesystem error degrades to "unknown")."""
    if not templates_dir:
        return "unknown"
    for marker in (".checksum", ".version"):
        path = os.path.join(str(templates_dir), marker)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                value = fh.readline().strip()
        except OSError:
            continue
        if value:
            return f"{marker.lstrip('.')}:{value[:64]}"
    return "unknown"


class NucleiDastRunner(NucleiRunner):
    """nuclei in DAST (fuzzing) mode. Where the signature nuclei run checks for
    known issues on the entry page, this fuzzes the *parameters* katana
    discovered -- injecting SQLi / XSS / SSTI / command-injection / LFI probes
    and detecting them from the response. This is what closes the gap on custom
    app-logic bugs the signature scan can't see.

    Reuses NucleiRunner.parse_vulnerabilities (identical JSONL schema); only the
    target selection and the command (adds `-dast`) differ."""

    name = "nuclei-dast"
    binary = "nuclei"  # same binary as NucleiRunner, driven with -dast
    requires_active_testing = True  # sends injection payloads to app inputs -> gated on active testing
    capability = "dast_fuzzing"
    phase = 55  # after katana (45) has crawled and after the signature nuclei (50)
    kill_chain_phase = "delivery"   # delivers fuzzing probes, like nuclei
    safety_tier = "active_safe"     # DETECTION fuzzing (benign markers); no exploitation

    def coverage_state(self, target_value: str, prior_findings: list[CommonFinding]) -> str:
        """How much of the app this DAST run can actually reach: crawled | fallback_root_only | none.

        WHY THIS IS REPORTED. `_target_urls` falls back to the bare entry point when the
        crawler produced nothing -- which is the right behaviour (fuzzing the root is better
        than fuzzing nothing) but it made a degraded run indistinguishable from a full one.
        Observed on a real scan: katana timed out and returned zero URLs, DAST then "succeeded"
        in 12.3s having fuzzed only the homepage, and the scan reported a clean DAST pass.

        This states the difference so the run's coverage is legible. It changes NO
        vulnerability semantics: the same URLs are fuzzed, the same findings are produced, and
        nothing is reclassified -- only the stderr note and this label are new."""
        if crawled_urls(prior_findings):
            return "crawled"
        try:
            fallback = web_targets(target_value, prior_findings)
        except Exception:
            # web_targets resolves the host through the SSRF guard, which RAISES for an
            # unresolvable/blocked target rather than returning an empty list. A coverage
            # LABEL must never be the thing that fails a run, so an unusable target simply
            # reports "none" -- run() then returns the existing no-targets error.
            return "none"
        return "fallback_root_only" if fallback else "none"

    def _available_urls(self, target_value: str, prior_findings: list[CommonFinding]) -> list[str]:
        """Every URL this run COULD fuzz, before MAX_FUZZ_URLS is applied.

        Split out from `_target_urls` so run() can compare "selected" against "available" and
        report what the cap left untested. Selection itself is unchanged."""
        urls = crawled_urls(prior_findings)
        if not urls:
            urls = web_targets(target_value, prior_findings)
        return urls

    def _target_urls(self, target_value: str, prior_findings: list[CommonFinding]) -> list[str]:
        """Fuzz the URLs katana crawled (parameterised ones first -- those are
        what -dast actually injects into). Fall back to the plain web targets if
        the crawler produced nothing."""
        return self._available_urls(target_value, prior_findings)[:MAX_FUZZ_URLS]

    def _selected_urls(self, target_value: str, prior_findings: list[CommonFinding]) -> tuple[list[str], int]:
        """(urls actually fuzzed, urls available before the cap).

        Goes through `_target_urls` for the SELECTION so that subclasses and tests overriding
        that method keep working exactly as before -- the pre-cap count is an additional
        observation, never a second selection path that could disagree with it. `available` is
        floored at the selected count so a stubbed/overridden `_target_urls` can never report
        a nonsensical negative truncation."""
        urls = self._target_urls(target_value, prior_findings)
        try:
            available = len(self._available_urls(target_value, prior_findings))
        except Exception:
            # `_available_urls` resolves the host through the SSRF guard, which RAISES for a
            # blocked/unresolvable target. This value is a REPORTING detail (how much surface
            # the cap hid), so it must never be the thing that fails a run that selection
            # already succeeded at -- exactly the rule coverage_state() follows above. The
            # selected list is authoritative; fall back to it and report no truncation.
            available = len(urls)
        return urls, max(available, len(urls))

    @staticmethod
    def _timeout_seconds(config: dict) -> float | None:
        """The effective wall-clock cap for this DAST run.

        `tool_config` is key-allowlisted by scans.service but its VALUES are unvalidated
        (`tool_config: dict` in the schema), so `dast_timeout_seconds` arrives as arbitrary
        JSON -- exactly the class of defect already closed for `nuclei_tags` in
        NucleiRunner.run(). A non-numeric value (a string, list or dict) previously flowed
        straight into `run_with_timeout`, where `asyncio.wait_for` raises an opaque TypeError
        AFTER the subprocess has already been spawned: the orchestrator records a failed tool
        run with no indication the config was at fault, and the spawned nuclei process is left
        to be cleaned up on the error path rather than never started.

        A bool is rejected explicitly (`isinstance(True, int)` is True in Python, and `True`
        is not a duration). Consistent with NucleiRunner's timeout policy, a value <= 0 means
        "no wall-clock cap" rather than an instant timeout. Refusing the value is deliberate:
        silently falling back to DEFAULT_TIMEOUT_SECONDS would run under a budget the operator
        did not ask for while reporting success."""
        if "dast_timeout_seconds" not in config:
            return DEFAULT_TIMEOUT_SECONDS
        value = config["dast_timeout_seconds"]
        if value is None:
            return DEFAULT_TIMEOUT_SECONDS
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(
                f"tool_config.dast_timeout_seconds must be a number of seconds, got "
                f"{type(value).__name__}: {value!r}"
            )
        return float(value) if value > 0 else None

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        # Validate the configured budget BEFORE spawning nuclei, so a bad value is a clear
        # config error rather than an opaque mid-run failure with a live subprocess attached.
        timeout_seconds = self._timeout_seconds(config)
        urls, available = self._selected_urls(target_value, prior_findings)
        coverage = self.coverage_state(target_value, prior_findings)
        if not urls:
            return RawToolOutput(
                command="nuclei -dast (no targets)", stdout="",
                stderr="no targets; coverage=none", exit_code=-1,
            )
        if coverage == "fallback_root_only":
            # The crawler produced nothing, so this run can only fuzz the entry point. Said
            # plainly here so a 12s "success" is not read as full application coverage.
            logger.warning(
                "nuclei_dast.degraded_coverage urls=%d coverage=%s -- no crawled URLs "
                "available (upstream crawl produced none); fuzzing entry point only",
                len(urls), coverage,
            )

        command = ["nuclei", "-dast", "-jsonl", "-silent", "-disable-update-check", "-no-color"]
        templates_dir = get_settings().nuclei_templates_dir
        if templates_dir:
            command += ["-templates", str(templates_dir)]
        # TEMPLATE PROVENANCE. `-templates <dir>` names WHERE the templates came from but not
        # WHICH set ran, and nuclei's JSONL findings carry only a template-id. Without this, a
        # finding could not be tied to the template revision that produced it: two runs of the
        # same nuclei version against the same target can legitimately differ purely because
        # the template set moved underneath them, and nothing recorded that. The provenance is
        # OBSERVED from the checkout on disk (see _template_provenance) -- never guessed, and
        # absent when it cannot be read. It is reported alongside the existing coverage note,
        # so it reaches stored evidence without changing any finding or its classification.
        provenance = _template_provenance(templates_dir)

        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        # Incremental capture: a timeout now KEEPS whatever nuclei-dast already reported
        # instead of discarding it (see base.run_with_timeout).
        result = await run_with_timeout(
            proc, timeout_seconds, "nuclei-dast", stdin="\n".join(urls).encode()
        )
        # REPRODUCIBILITY (Prompt 25). The fuzzed URLs arrive on STDIN, so `" ".join(command)`
        # alone cannot answer "what did this run actually test?" -- and `ToolRun.command_hash`
        # is computed over this string, so two runs fuzzing completely different URL sets
        # hashed IDENTICALLY. NucleiRunner already records `(stdin: ...)` for exactly this
        # reason; the DAST runner recorded only a COUNT. Bounded (the list is already capped at
        # MAX_FUZZ_URLS, and long lists are elided) so evidence stays readable.
        shown = ", ".join(urls[:_COMMAND_URLS_RECORDED])
        if len(urls) > _COMMAND_URLS_RECORDED:
            shown += f", ... (+{len(urls) - _COMMAND_URLS_RECORDED} more)"
        annotated_command = (
            " ".join(command)
            + f"  (fuzzed {len(urls)} of {available} url(s), coverage={coverage}, "
            + f"templates={provenance}, max_fuzz_urls={MAX_FUZZ_URLS})"
            + f"  (stdin: {shown})"
        )
        # SILENT TRUNCATION (Prompt 25). `_target_urls` caps the fuzz list at MAX_FUZZ_URLS and
        # said nothing about it. A crawl that found 5,000 URLs therefore fuzzed 200 and
        # reported a clean DAST pass -- 96% of the discovered surface was never tested, and
        # nothing in the run recorded that. Same class as the `fallback_root_only` coverage
        # defect already fixed above, and the same remedy: state it plainly. katana words its
        # equivalent cap the same way ("NOT proven absent"), because a bounded test finding
        # nothing is not evidence that nothing is there.
        truncated = available > len(urls)
        if truncated:
            logger.warning(
                "nuclei_dast.fuzz_targets_truncated fuzzed=%d available=%d cap=%d -- the "
                "remaining URLs were NOT fuzzed and are not proven clean",
                len(urls), available, MAX_FUZZ_URLS,
            )
        truncation_note = (
            f"\nfuzz_targets_truncated: fuzzed {len(urls)} of {available} discovered URL(s) "
            f"(cap max_fuzz_urls={MAX_FUZZ_URLS}); the remaining "
            f"{available - len(urls)} URL(s) were NOT fuzzed and are NOT proven clean"
            if truncated else ""
        )
        if result.timed_out:
            return RawToolOutput(
                command=annotated_command,
                stdout=result.stdout,
                stderr=(
                    result.stderr
                    + f"\ntimed out after {timeout_seconds}s -- raise "
                    f"tool_config.dast_timeout_seconds if this target matters"
                    f"\ncoverage={coverage}\nnuclei_templates={provenance}"
                    + truncation_note
                ).strip(),
                exit_code=-1,
                timed_out=True,
            )

        return RawToolOutput(
            command=annotated_command,
            stdout=result.stdout,
            # Coverage and template provenance are appended to stderr so they reach the stored
            # evidence and are visible to anyone reading the run, without changing findings or
            # their classification.
            stderr=(
                result.stderr + f"\ncoverage={coverage}\nnuclei_templates={provenance}"
                + truncation_note
            ).strip(),
            exit_code=result.exit_code if result.exit_code is not None else -1,
        )
