"""§5 follow-up -- exhaustive EDGE-CASE coverage for reports/verification.py.

These tests pin the CURRENT semantics; none of them changed behaviour. They exist so that a
future edit to the classifier cannot silently move a verification state, and so the safety
properties (never falsely Verified, independent of CVSS/risk/ai_confidence) are asserted from
many directions rather than trusted.

Companion to test_verification.py, which covers the six primary cases. This file covers the
combinatorial surface: evidence combinations, detection/inference/CVE semantics, independence,
and malformed input.
"""

import uuid

from apps.api.modules.reports.data import VulnRow
from apps.api.modules.reports.verification import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    PARTIALLY_VERIFIED,
    UNVERIFIED,
    VERIFIED,
    classify_verification,
    classify_verification_row,
)

# A template with NO generic marker and NO inference marker -- the only shape that can ever
# reach VERIFIED. Kept as a constant so each test states its intent rather than its spelling.
SPECIFIC = "apache-path-traversal-2021"
GENERIC = "unix-command-injection"      # generic comes from the MATCHER, not this name
LOG = ["s3://mbs-evidence/tool-runs/abc/raw-output.txt"]
SHOT = [("s3://mbs-evidence/shots/abc.png", "sha256:aa")]


def _row(**kw):
    base = dict(
        id=uuid.uuid4(), title="T", severity="high", status="open", category="cwe-78",
        cvss_score=9.8, cvss_vector=None, final_risk_score=10.0, risk_rationale=None,
        compliance=[], evidence_uris=[], screenshots=[], template_id=SPECIFIC,
        matcher_name="status", matched_at="https://e.com/a",
    )
    base.update(kw)
    return VulnRow(**base)


# ============================ 1-8: evidence combinations ==================================

def test_01_no_evidence() -> None:
    assert classify_verification(template_id=SPECIFIC, matcher_name="status") == (
        UNVERIFIED, CONFIDENCE_MEDIUM
    )


def test_02_screenshot_only() -> None:
    state, conf = classify_verification(template_id=SPECIFIC, matcher_name="status", screenshots=SHOT)
    assert state == PARTIALLY_VERIFIED      # one artefact corroborates, never proves
    assert conf == CONFIDENCE_HIGH


def test_03_log_only() -> None:
    state, conf = classify_verification(template_id=SPECIFIC, matcher_name="status", evidence_uris=LOG)
    assert state == PARTIALLY_VERIFIED
    assert conf == CONFIDENCE_HIGH


def test_04_screenshot_plus_log_is_the_only_verified_path() -> None:
    state, conf = classify_verification(
        template_id=SPECIFIC, matcher_name="status", evidence_uris=LOG, screenshots=SHOT
    )
    assert state == VERIFIED
    assert conf == CONFIDENCE_HIGH


def test_05_multiple_screenshots_without_logs_stay_partial() -> None:
    """Quantity of ONE artefact kind is not a substitute for two independent kinds."""
    shots = [("s3://a.png", "h1"), ("s3://b.png", "h2"), ("s3://c.png", "h3")]
    state, _ = classify_verification(template_id=SPECIFIC, matcher_name="status", screenshots=shots)
    assert state == PARTIALLY_VERIFIED


def test_06_multiple_logs_without_screenshots_stay_partial() -> None:
    logs = ["s3://a.txt", "s3://b.txt", "s3://c.txt"]
    state, _ = classify_verification(template_id=SPECIFIC, matcher_name="status", evidence_uris=logs)
    assert state == PARTIALLY_VERIFIED


def test_07_mixed_evidence_types_reach_verified_on_a_specific_match() -> None:
    state, _ = classify_verification(
        template_id=SPECIFIC, matcher_name="status",
        evidence_uris=["s3://a.txt", "s3://b.har"], screenshots=SHOT,
    )
    assert state == VERIFIED


def test_08_unknown_evidence_type_is_still_an_artefact() -> None:
    """The classifier counts ARTEFACTS; it does not gate on the type string, so an unfamiliar
    evidence type still corroborates rather than being silently ignored."""
    state, _ = classify_verification(
        template_id=SPECIFIC, matcher_name="status", evidence_uris=["s3://unknown.blob"]
    )
    assert state == PARTIALLY_VERIFIED


# ============================ 9-14: detection semantics ===================================

def test_09_generic_matcher_defaults_to_unverified_medium() -> None:
    assert classify_verification(template_id=GENERIC, matcher_name="generic") == (
        UNVERIFIED, CONFIDENCE_MEDIUM
    )


def test_10_generic_scanner_detection_template_is_never_verified() -> None:
    for tid in ("waf-detect", "tech-detect", "fingerprinthub-web-fingerprints", "x-detection"):
        state, _ = classify_verification(
            template_id=tid, matcher_name="m", evidence_uris=LOG, screenshots=SHOT
        )
        assert state == PARTIALLY_VERIFIED, f"{tid} reached {state}"


def test_10b_detection_templates_agree_between_classification_and_verification() -> None:
    """REGRESSION: the two modules must agree on what a detection template is.

    `fingerprinthub-web-fingerprints`, `nginx-version`, `apache-eol`, `tech-*` and `waf-*` are
    DETECTIONS to classification.py, but verification.py's own marker list did not recognise
    them -- so with both artefact kinds present they reached VERIFIED and the report could
    state that a technology fingerprint or WAF banner was verified exploitation. Live reports
    were shielded only because gather_report_data passes `classification` first; the public
    classifier failed OPEN for every other caller.

    Asserted WITHOUT passing `classification`, which is exactly the unshielded path."""
    from apps.api.modules.reports.classification import DETECTION, classify

    for tid in (
        "fingerprinthub-web-fingerprints", "nginx-version", "apache-eol",
        "tech-something", "waf-cloudflare", "x-detect", "x-detection",
    ):
        assert classify(template_id=tid, cvss_score=None) == DETECTION, f"{tid} not a detection"
        state, _ = classify_verification(
            template_id=tid, matcher_name="m", evidence_uris=LOG, screenshots=SHOT
        )
        assert state != VERIFIED, f"{tid} reached VERIFIED despite being a detection"


def test_11_specific_non_generic_finding_without_evidence_is_unverified() -> None:
    state, _ = classify_verification(template_id=SPECIFIC, matcher_name="status")
    assert state == UNVERIFIED


def test_12_specific_plus_screenshot() -> None:
    state, _ = classify_verification(template_id=SPECIFIC, matcher_name="status", screenshots=SHOT)
    assert state == PARTIALLY_VERIFIED


def test_13_specific_plus_log() -> None:
    state, _ = classify_verification(template_id=SPECIFIC, matcher_name="status", evidence_uris=LOG)
    assert state == PARTIALLY_VERIFIED


def test_14_specific_plus_both() -> None:
    state, _ = classify_verification(
        template_id=SPECIFIC, matcher_name="status", evidence_uris=LOG, screenshots=SHOT
    )
    assert state == VERIFIED


def test_classification_detection_outranks_full_evidence() -> None:
    """An explicit DETECTION classification caps the state even with both artefact kinds."""
    state, _ = classify_verification(
        template_id=SPECIFIC, matcher_name="status", evidence_uris=LOG, screenshots=SHOT,
        classification="detection",
    )
    assert state == PARTIALLY_VERIFIED


# ============================ 15-19: inference semantics ==================================

def test_15_to_18_inference_markers_are_never_verified_and_are_low_confidence() -> None:
    """time-based / blind / timing / OOB: the tool INFERRED the condition from a side channel.

    Asserted with FULL evidence present -- the strongest input -- so this proves the inference
    cap holds even when artefacts would otherwise reach VERIFIED."""
    for marker in ("time-based", "time_based", "blind", "timing", "out-of-band", "oob"):
        state, conf = classify_verification(
            template_id=SPECIFIC, matcher_name=marker, evidence_uris=LOG, screenshots=SHOT
        )
        assert state != VERIFIED, f"{marker} reached VERIFIED"
        assert state == PARTIALLY_VERIFIED
        assert conf == CONFIDENCE_LOW, f"{marker} was not Low confidence"


def test_15b_inference_markers_without_evidence_are_unverified_low() -> None:
    for marker in ("time-based", "blind", "timing", "oob"):
        assert classify_verification(template_id=SPECIFIC, matcher_name=marker) == (
            UNVERIFIED, CONFIDENCE_LOW
        )


def test_19_callback_is_not_currently_an_inference_marker() -> None:
    """Documents ACTUAL behaviour, not aspiration: "callback" is NOT in _INFERENCE_MARKERS, so
    it does not lower confidence. Pinned deliberately -- if it is ever added to the marker list
    this test fails and forces the change to be conscious rather than incidental.

    Safety is unaffected: without evidence the state is still UNVERIFIED."""
    state, conf = classify_verification(template_id=SPECIFIC, matcher_name="callback")
    assert state == UNVERIFIED
    assert conf == CONFIDENCE_MEDIUM  # not Low -- "callback" is not a recognised marker


def test_inference_marker_detected_in_template_id_too() -> None:
    """The marker is matched across template AND matcher, so a time-based TEMPLATE also counts."""
    state, conf = classify_verification(template_id="time-based-sqli", matcher_name="m")
    assert (state, conf) == (UNVERIFIED, CONFIDENCE_LOW)


# ============================ 20-22: CVE semantics ========================================

def test_20_specific_cve_with_full_evidence_is_verified_high() -> None:
    state, conf = classify_verification(
        template_id="CVE-2021-41773-path-traversal", matcher_name="status",
        evidence_uris=LOG, screenshots=SHOT, cve="CVE-2021-41773",
    )
    assert (state, conf) == (VERIFIED, CONFIDENCE_HIGH)


def test_21_cve_looking_text_on_a_generic_template_does_not_verify() -> None:
    """A CVE id raises CONFIDENCE only when the template is not generic; it NEVER verifies."""
    state, conf = classify_verification(
        template_id="cve-2021-41773-detect", matcher_name="m", cve="CVE-2021-41773"
    )
    assert state == UNVERIFIED
    assert conf == CONFIDENCE_MEDIUM  # generic suppresses the CVE confidence boost


def test_22_cve_plus_generic_detection_with_evidence_stays_partial() -> None:
    state, _ = classify_verification(
        template_id="cve-2021-41773-detect", matcher_name="generic",
        evidence_uris=LOG, screenshots=SHOT, cve="CVE-2021-41773",
    )
    assert state == PARTIALLY_VERIFIED


def test_cve_alone_raises_confidence_but_not_verification() -> None:
    state, conf = classify_verification(template_id=SPECIFIC, matcher_name="m", cve="CVE-2021-41773")
    assert state == UNVERIFIED
    assert conf == CONFIDENCE_HIGH


# ============================ 23-25: independence ==========================================

def test_23_verification_ignores_ai_confidence() -> None:
    """ai_confidence is the AI triage model's rating of its OWN output. Setting it to any value
    -- including 1.0 -- must not move verification or confidence."""
    base = classify_verification_row(_row())
    for value in (0.0, 0.5, 1.0, None):
        row = _row()
        row.ai_confidence = value  # attribute the classifier must never read
        assert classify_verification_row(row) == base


def test_24_verification_ignores_cvss() -> None:
    results = {classify_verification_row(_row(cvss_score=c)) for c in (None, 0.0, 5.5, 9.8, 10.0)}
    assert len(results) == 1, f"CVSS changed verification: {results}"


def test_25_verification_ignores_risk_and_severity() -> None:
    results = {
        classify_verification_row(_row(final_risk_score=r, severity=s))
        for r in (None, 0.0, 5.0, 10.0)
        for s in ("info", "low", "medium", "high", "critical")
    }
    assert len(results) == 1, f"risk/severity changed verification: {results}"


def test_verification_ignores_status_and_category() -> None:
    results = {
        classify_verification_row(_row(status=st, category=cat))
        for st in ("open", "confirmed", "reopened", "fixed", "false_positive")
        for cat in (None, "cwe-78", "cwe-79")
    }
    assert len(results) == 1


# ============================ 26-30: safety / malformed input ==============================

def test_26_empty_evidence_containers_are_treated_as_absent() -> None:
    # Annotated because the literal list mixes an empty list, an empty tuple and None, which
    # mypy cannot infer a common element type for (the CI gate rejects an unannotated binding).
    empties: list[object] = [[], (), None]
    for empty in empties:
        state, _ = classify_verification(
            template_id=SPECIFIC, matcher_name="m", evidence_uris=empty, screenshots=empty
        )
        assert state == UNVERIFIED


def test_27_malformed_metadata_does_not_raise() -> None:
    """None/empty/odd template and matcher values must classify, not explode."""
    for tid in (None, "", "   ", "???", "a" * 500):
        for matcher in (None, "", "   ", "???"):
            state, conf = classify_verification(template_id=tid, matcher_name=matcher)
            assert state in (UNVERIFIED, PARTIALLY_VERIFIED, VERIFIED)
            assert conf in (CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH)


def test_28_missing_location_does_not_affect_verification() -> None:
    """matched_at is not a verification signal -- an unlocated finding classifies identically."""
    assert classify_verification_row(_row(matched_at=None)) == classify_verification_row(_row())


def test_29_duplicate_evidence_does_not_upgrade_state() -> None:
    """The same artefact listed twice is still ONE kind of artefact -- it must not fake the
    two-independent-artefacts condition that VERIFIED requires."""
    state, _ = classify_verification(
        template_id=SPECIFIC, matcher_name="status", evidence_uris=["s3://same.txt", "s3://same.txt"]
    )
    assert state == PARTIALLY_VERIFIED
    assert state != VERIFIED


def test_30_unknown_matcher_and_template_default_safely() -> None:
    state, conf = classify_verification(template_id="totally-unknown-xyz", matcher_name="unknown-zzz")
    assert state == UNVERIFIED
    assert conf == CONFIDENCE_MEDIUM


def test_row_missing_every_attribute_is_safe() -> None:
    class Bare:
        pass

    assert classify_verification_row(Bare()) == (UNVERIFIED, CONFIDENCE_MEDIUM)


def test_classifier_is_pure_and_does_not_mutate_the_row() -> None:
    row = _row(evidence_uris=list(LOG), screenshots=list(SHOT))
    before = (row.cvss_score, row.final_risk_score, row.severity, row.status,
              list(row.evidence_uris), list(row.screenshots), row.classification)
    classify_verification_row(row)
    after = (row.cvss_score, row.final_risk_score, row.severity, row.status,
             list(row.evidence_uris), list(row.screenshots), row.classification)
    assert before == after


def test_repeated_classification_is_deterministic() -> None:
    row = _row(evidence_uris=list(LOG), screenshots=list(SHOT))
    first = classify_verification_row(row)
    assert all(classify_verification_row(row) == first for _ in range(20))
