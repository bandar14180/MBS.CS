"""Nuclei / Nuclei-DAST detection-vs-verification boundary (Prompts C and D).

These lock in behaviour the audit found ALREADY CORRECT, so it cannot regress silently. The
boundary they guard is the core MBS.SC principle: nuclei output is a DETECTION, never proof.

Specifically:
  * a timeout or crash must never look like a clean result (Global Requirement 7);
  * a partial run must stay partial;
  * nuclei findings enter the lifecycle as `open`, never `confirmed`;
  * DAST must report degraded coverage rather than presenting entry-point-only fuzzing as
    full application coverage.
"""

import json

from apps.api.scanner_engine.tool_runners.base import CommonFinding, RawToolOutput, classify_run
from apps.api.scanner_engine.tool_runners.nuclei_dast_runner import NucleiDastRunner
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner

_FINDING_LINE = json.dumps({
    "template-id": "acme-rce", "matched-at": "https://x.test/a",
    "info": {"name": "RCE", "severity": "high"},
})


# --- C. Failure semantics: nothing broken is ever "clean" -----------------------------------

def test_timeout_with_partial_output_is_partial_not_completed():
    r = NucleiRunner()
    raw = RawToolOutput(command="nuclei", stdout=_FINDING_LINE, stderr="timed out",
                        exit_code=-1, timed_out=True)
    findings = r.parse_vulnerabilities(raw)
    assert len(findings) == 1                                  # partial output is kept
    assert classify_run(r, raw, bool(findings)) == "partial"   # never "completed"
    assert raw.timed_out is True                               # and the reason survives


def test_timeout_with_no_output_is_failed():
    r = NucleiRunner()
    raw = RawToolOutput(command="nuclei", stdout="", stderr="timed out",
                        exit_code=-1, timed_out=True)
    assert classify_run(r, raw, False) == "failed"


def test_crash_with_no_output_is_failed_not_clean():
    r = NucleiRunner()
    raw = RawToolOutput(command="nuclei", stdout="", stderr="boom", exit_code=1)
    assert classify_run(r, raw, False) == "failed"


def test_clean_run_with_zero_findings_is_completed():
    """The one case that legitimately means 'nothing found' -- exit 0, no error."""
    r = NucleiRunner()
    raw = RawToolOutput(command="nuclei", stdout="", stderr="", exit_code=0)
    assert classify_run(r, raw, False) == "completed"


def test_malformed_jsonl_lines_are_skipped_not_fatal():
    r = NucleiRunner()
    raw = RawToolOutput(command="nuclei", stdout="{not json\n" + _FINDING_LINE + "\n\n",
                        stderr="", exit_code=0)
    assert len(r.parse_vulnerabilities(raw)) == 1


def test_finding_without_template_or_location_is_dropped():
    """No identity => no fingerprint => it cannot be deduped or traced. Dropped, not guessed."""
    r = NucleiRunner()
    no_tid = json.dumps({"matched-at": "https://x.test/", "info": {"severity": "high"}})
    no_loc = json.dumps({"template-id": "t", "info": {"severity": "high"}})
    raw = RawToolOutput(command="nuclei", stdout=no_tid + "\n" + no_loc, stderr="", exit_code=0)
    assert r.parse_vulnerabilities(raw) == []


def test_duplicate_findings_dedupe_within_a_run():
    """Duplicates must not create misleading confidence (Global Requirement 8)."""
    r = NucleiRunner()
    raw = RawToolOutput(command="nuclei", stdout="\n".join([_FINDING_LINE] * 5),
                        stderr="", exit_code=0)
    assert len(r.parse_vulnerabilities(raw)) == 1


# --- C. Nuclei detections are not self-certifying -------------------------------------------

def test_nuclei_runners_are_detection_tier_not_exploitation():
    """Both runners declare `active_safe` -- detection templates only. A finding from them is
    therefore an observation, and no code path may treat it as demonstrated exploitation."""
    assert NucleiRunner.safety_tier == "active_safe"
    assert NucleiDastRunner.safety_tier == "active_safe"


def test_dast_inherits_the_signature_parser():
    """D: identical JSONL schema, so the taxonomy/dedup guarantees above apply to DAST too."""
    assert NucleiDastRunner.parse_vulnerabilities is NucleiRunner.parse_vulnerabilities


# --- D. DAST coverage is never overstated ---------------------------------------------------

def test_dast_reports_crawled_coverage_when_urls_were_crawled():
    d = NucleiDastRunner()
    prior = [CommonFinding(asset_type="url", value="https://x.test/a?id=1",
                           metadata={"source": "katana", "has_params": True})]
    assert d.coverage_state("x.test", prior) == "crawled"


def test_dast_degraded_coverage_is_not_reported_as_full():
    """The observed real-world failure: katana timed out, DAST fuzzed only the homepage in
    12s, and the scan read as a clean full DAST pass."""
    d = NucleiDastRunner()
    assert d.coverage_state("x.test", []) in ("fallback_root_only", "none")


def test_dast_fuzz_targets_are_bounded():
    """Boundedness: a large crawl cannot produce unbounded fan-out."""
    from apps.api.scanner_engine.tool_runners.nuclei_dast_runner import MAX_FUZZ_URLS

    d = NucleiDastRunner()
    prior = [
        CommonFinding(asset_type="url", value=f"https://x.test/p{i}?id=1",
                      metadata={"source": "katana", "has_params": True})
        for i in range(MAX_FUZZ_URLS + 50)
    ]
    assert len(d._target_urls("x.test", prior)) <= MAX_FUZZ_URLS
