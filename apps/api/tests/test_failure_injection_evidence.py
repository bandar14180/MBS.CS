"""Prompt 32 -- failure injection: an evidence-upload failure must never corroborate a finding.

THE DEFECT THIS PINS (found by injecting the failure, fixed in verification.py)
-------------------------------------------------------------------------------
Object storage being down must not fail an otherwise-successful scan, so
`orchestrator._run_single_tool` catches the storage error and records a SENTINEL evidence row:

    storage_uri = "unavailable://evidence-storage-failed/<tool_run_id>",  checksum = ""

That keeps the vulnerability -> evidence linkage intact for debuggability. But the row points
at NOTHING: no bytes were stored and none can ever be retrieved.

`classify_verification` decided "were artefacts captured?" with `len(evidence_uris)`. The
sentinel is a non-empty string, so it COUNTED. Consequences, both of them real:

  * a finding whose evidence upload failed was graded PARTIALLY_VERIFIED -- "captured tool
    output corroborates the match" -- when nothing was captured;
  * with a screenshot alongside it, that reached VERIFIED, whose rendered note reads
    "Exploitation corroborated by captured evidence."

So a MinIO outage could upgrade an ordinary scanner pattern match into a claim of demonstrated
exploitation. That is exactly the "partial execution promoted to VERIFIED" failure this
batch forbids, and the "generic evidence becoming verification" failure Prompt 29 forbids --
reached through infrastructure failure rather than through any finding's own data.

THE FIX
-------
`_is_real_artefact` / `_count_artefacts` in verification.py: an artefact counts only when its
reference actually points at a stored object. A failed capture is the ABSENCE of evidence and
now reads exactly like it. This is not a new evidence concept -- retention/service.py and
evidence_integrity.py already filter the same sentinel for the same reason; the rule was simply
missing at this one site.

WHAT IS DELIBERATELY UNCHANGED
------------------------------
The fail-soft ingest behaviour itself. The sentinel row is still written, the scan still
completes, and the tool run still aggregates to completed_with_errors. Only the REPORT's
reading of that row changes: it is no longer evidence of anything.
"""

import uuid

from apps.api.modules.reports.data import VulnRow
from apps.api.modules.reports.verification import (
    PARTIALLY_VERIFIED,
    REASON_NO_ARTEFACTS,
    REASON_RESPONSE_CAPTURED,
    REASON_SCREENSHOT_CAPTURED,
    UNVERIFIED,
    VERIFIED,
    classify_verification,
    classify_verification_row,
    verification_reasons,
)

SENTINEL = "unavailable://evidence-storage-failed/7f3a2c71-0000-4000-8000-000000000001"
REAL_LOG = "s3://mbs-evidence/tool-runs/abc/raw-output.txt"
REAL_SHOT = ("s3://mbs-evidence/vulnerabilities/v/screenshot-0011.png", "a" * 64)
FAILED_SHOT = (SENTINEL, "")

# A specific, non-generic, non-inference match -- the only class that can reach VERIFIED at
# all. Using anything weaker would mask the defect behind an unrelated ceiling.
SPECIFIC = dict(template_id="sqli-error-based", matcher_name="word")


# === the injected failure ====================================================================

def test_a_failed_evidence_upload_is_not_a_captured_artefact():
    """THE defect. A sentinel alone must read exactly like no evidence at all."""
    assert classify_verification(evidence_uris=[SENTINEL], **SPECIFIC)[0] == UNVERIFIED
    assert classify_verification(**SPECIFIC)[0] == UNVERIFIED


def test_a_failed_upload_plus_a_screenshot_never_reaches_verified():
    """The escalation path: one real artefact + one FAILED capture is not two artefacts.

    VERIFIED requires corroboration from two INDEPENDENT directions. A failed upload supplies
    no direction at all, so this must stop at the single-artefact ceiling."""
    state, _ = classify_verification(
        evidence_uris=[SENTINEL], screenshots=[REAL_SHOT], **SPECIFIC
    )
    assert state == PARTIALLY_VERIFIED


def test_a_failed_screenshot_capture_is_also_not_an_artefact():
    """The same rule applies to the screenshot axis, which carries (uri, checksum) tuples."""
    state, _ = classify_verification(
        evidence_uris=[REAL_LOG], screenshots=[FAILED_SHOT], **SPECIFIC
    )
    assert state == PARTIALLY_VERIFIED


def test_two_failed_captures_are_not_verified():
    assert classify_verification(
        evidence_uris=[SENTINEL], screenshots=[FAILED_SHOT], **SPECIFIC
    )[0] == UNVERIFIED


def test_empty_and_whitespace_uris_are_not_artefacts():
    """A blank string is not a reference to anything either."""
    assert classify_verification(evidence_uris=["", "   "], **SPECIFIC)[0] == UNVERIFIED


# === the legitimate path is untouched (the control) ==========================================

def test_real_artefacts_still_reach_verified():
    """POSITIVE control. If this ever fails, the fix has over-reached and is hiding real proof."""
    assert classify_verification(
        evidence_uris=[REAL_LOG], screenshots=[REAL_SHOT], **SPECIFIC
    )[0] == VERIFIED


def test_a_real_artefact_alongside_a_failed_one_still_counts_once():
    """Mixed list: the real artefact is not discarded just because a sibling upload failed."""
    assert classify_verification(evidence_uris=[SENTINEL, REAL_LOG], **SPECIFIC)[0] == PARTIALLY_VERIFIED


def test_real_artefacts_are_counted_per_axis_not_pooled():
    """Two REAL logs and no screenshot is still one direction of corroboration, not two."""
    assert classify_verification(
        evidence_uris=[REAL_LOG, REAL_LOG + ".2"], **SPECIFIC
    )[0] == PARTIALLY_VERIFIED


# === the reason trace tells the same story ===================================================

def test_the_reason_trace_reports_no_artefacts_for_a_failed_upload():
    """The audit trail must not claim a response was captured when the capture failed."""
    reasons = verification_reasons(evidence_uris=[SENTINEL], **SPECIFIC)
    assert REASON_NO_ARTEFACTS in reasons
    assert REASON_RESPONSE_CAPTURED not in reasons


def test_the_reason_trace_still_reports_real_captures():
    reasons = verification_reasons(evidence_uris=[REAL_LOG], screenshots=[REAL_SHOT], **SPECIFIC)
    assert REASON_RESPONSE_CAPTURED in reasons
    assert REASON_SCREENSHOT_CAPTURED in reasons
    assert REASON_NO_ARTEFACTS not in reasons


# === the row-level entry point behaves identically ===========================================

def test_the_row_classifier_applies_the_same_rule():
    """`classify_verification_row` is what gather_report_data actually calls."""
    row = VulnRow(
        id=uuid.uuid4(), title="SQL Injection", severity="high", status="open",
        category="cwe-89", cvss_score=8.6, cvss_vector=None, final_risk_score=None,
        risk_rationale=None, compliance=[], evidence_uris=[SENTINEL],
        screenshots=[REAL_SHOT], template_id="sqli-error-based", matcher_name="word",
        matched_at="https://h/a?id=1",
    )
    assert classify_verification_row(row)[0] == PARTIALLY_VERIFIED


# === fail-soft ingest itself is unchanged ====================================================

def test_the_sentinel_shape_this_depends_on_is_the_one_the_orchestrator_writes():
    """Pins the coupling. If the orchestrator ever changes its sentinel scheme, the filter
    above would silently stop matching and the defect would return unnoticed -- so the shape
    is asserted against the producing code path's own literal, not just assumed here."""
    import inspect

    from apps.api.scanner_engine import orchestrator

    source = inspect.getsource(orchestrator)
    assert "unavailable://evidence-storage-failed/" in source
