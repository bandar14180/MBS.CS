"""§5 -- verification state and confidence (modules/reports/verification.py).

A scanner MATCH is not a PROOF. These tests pin two things:

  1. the classifier fails toward UNVERIFIED -- VERIFIED is reachable only from explicit
     evidence, never from a template name, a severity or a CVSS;
  2. verification is INERT with respect to risk -- it must not change cvss_score,
     final_risk_score, severity or the security score. Those invariance tests are the
     load-bearing ones: the whole design depends on verification being reporting metadata
     rather than a back-door severity modifier.
"""

import uuid

from apps.api.modules.reports.data import VulnRow
from apps.api.modules.reports.scoring import compute_security_score
from apps.api.modules.reports.verification import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    PARTIALLY_VERIFIED,
    UNVERIFIED,
    VERIFIED,
    classify_verification,
    classify_verification_row,
    confidence_label,
    verification_label,
    verification_note,
)


def _row(
    template_id="unix-command-injection",
    matcher_name="generic",
    severity="high",
    cvss=9.8,
    risk=10.0,
    evidence=(),
    shots=(),
    classification="vulnerability",
    status="open",
):
    return VulnRow(
        id=uuid.uuid4(),
        title="Unix Command Injection - Generic Detection",
        severity=severity,
        status=status,
        category="cwe-78",
        cvss_score=cvss,
        cvss_vector=None,
        final_risk_score=risk,
        risk_rationale=None,
        compliance=[],
        evidence_uris=list(evidence),
        screenshots=list(shots),
        template_id=template_id,
        matcher_name=matcher_name,
        matched_at="https://example.com/a",
        classification=classification,
    )


# --- Case 1: generic/time-based command-injection detection -------------------------------

def test_generic_command_injection_defaults_to_unverified_medium() -> None:
    """THE required default: a generic scanner detection is Unverified / Medium."""
    state, conf = classify_verification(
        template_id="unix-command-injection", matcher_name="generic"
    )
    assert state == UNVERIFIED
    assert conf == CONFIDENCE_MEDIUM


def test_windows_command_injection_generic_also_unverified_medium() -> None:
    state, conf = classify_verification(
        template_id="windows-command-injection", matcher_name="generic"
    )
    assert (state, conf) == (UNVERIFIED, CONFIDENCE_MEDIUM)


def test_time_based_inference_lowers_confidence_not_verification() -> None:
    """Timing/blind inference is the weakest signal class -> Low confidence, still Unverified."""
    state, conf = classify_verification(
        template_id="time-based-sqli", matcher_name="time-based"
    )
    assert state == UNVERIFIED
    assert conf == CONFIDENCE_LOW


# --- Case 2: confirmed evidence reaches a higher state ------------------------------------

def test_specific_match_with_both_artefacts_is_verified() -> None:
    """The ONLY path to VERIFIED: a specific (non-generic, non-inferred) match corroborated by
    BOTH a captured response and a visual capture."""
    state, conf = classify_verification(
        template_id="CVE-2021-41773-path-traversal",
        matcher_name="status",
        evidence_uris=["s3://mbs-evidence/log"],
        screenshots=[("s3://mbs-evidence/shot", "sha256")],
        cve="CVE-2021-41773",
    )
    assert state == VERIFIED
    assert conf == CONFIDENCE_HIGH


def test_single_artefact_is_only_partially_verified() -> None:
    """One artefact corroborates; it does not prove exploitation."""
    state, _ = classify_verification(
        template_id="apache-rce", matcher_name="word", evidence_uris=["s3://e"]
    )
    assert state == PARTIALLY_VERIFIED


# --- Case 3: insufficient evidence is NEVER falsely Verified ------------------------------

def test_no_evidence_is_never_verified_however_severe() -> None:
    """Severity and CVSS must not buy a verification upgrade."""
    for sev, cvss in [("critical", 10.0), ("high", 9.8), ("medium", 5.5), ("low", 2.0)]:
        state, _ = classify_verification_row(_row(severity=sev, cvss=cvss))
        assert state == UNVERIFIED, f"{sev}/{cvss} was not Unverified"


def test_generic_template_with_full_evidence_still_not_verified() -> None:
    """Evidence on a GENERIC match corroborates but cannot prove -- capped at partial."""
    state, _ = classify_verification(
        template_id="unix-command-injection",
        matcher_name="generic",
        evidence_uris=["s3://e"],
        screenshots=[("a", "b")],
    )
    assert state == PARTIALLY_VERIFIED
    assert state != VERIFIED


def test_detection_is_never_verified_even_with_evidence() -> None:
    """'Verified exploitation' is not a meaningful claim about a technology detection."""
    state, _ = classify_verification(
        template_id="waf-detect",
        matcher_name="waf",
        evidence_uris=["s3://e"],
        screenshots=[("a", "b")],
        classification="detection",
    )
    assert state == PARTIALLY_VERIFIED
    assert state != VERIFIED


def test_cve_alone_does_not_verify() -> None:
    """A CVE id raises CONFIDENCE, never VERIFICATION -- they are independent axes."""
    state, conf = classify_verification(
        template_id="CVE-2021-41773-traversal", matcher_name="status", cve="CVE-2021-41773"
    )
    assert state == UNVERIFIED
    assert conf == CONFIDENCE_HIGH


# --- Case 4: verification does NOT modify CVSS --------------------------------------------

def test_verification_does_not_modify_cvss() -> None:
    """An unverified CVSS 9.8 stays a CVSS 9.8. Downgrading unproven findings would hide risk."""
    row = _row(cvss=9.8)
    before = row.cvss_score
    state, _ = classify_verification_row(row)
    assert state == UNVERIFIED
    assert row.cvss_score == before == 9.8
    assert row.severity == "high"


# --- Case 5: verification does NOT modify final_risk_score --------------------------------

def test_verification_does_not_modify_final_risk_score() -> None:
    row = _row(risk=10.0)
    before = row.final_risk_score
    classify_verification_row(row)
    assert row.final_risk_score == before == 10.0


# --- Case 6: verification does NOT modify the Security Score ------------------------------

def test_verification_does_not_change_security_score() -> None:
    """Identical findings differing ONLY in evidence (hence verification) must score the same.

    scoring.py reads status/severity/classification/cvss/risk -- deliberately NOT verification.
    This test fails loudly if verification ever leaks into the scoring path."""
    unverified = [_row(evidence=(), shots=())]
    verified = [
        _row(
            template_id="CVE-2021-41773-path-traversal",
            matcher_name="status",
            evidence=["s3://e"],
            shots=[("a", "b")],
        )
    ]
    # Precondition: the two rows really do differ in verification state.
    assert classify_verification_row(unverified[0])[0] == UNVERIFIED
    assert classify_verification_row(verified[0])[0] == VERIFIED
    # ...yet the score is identical, because only severity/cvss/risk/status/classification count.
    assert compute_security_score(unverified) == compute_security_score(verified)


def test_scoring_module_does_not_consult_verification() -> None:
    """Structural guard: scoring must not IMPORT the verification module or READ either field.

    Asserted against imports/attribute reads rather than the bare word, because scoring.py
    legitimately uses "manual verification" in prose -- the invariant is the dependency, not
    the vocabulary."""
    from pathlib import Path

    import apps.api.modules.reports.scoring as scoring_mod

    source = Path(scoring_mod.__file__).read_text(encoding="utf-8")
    assert "import verification" not in source
    assert "reports.verification" not in source
    assert "classify_verification" not in source
    for read in ('"verification"', "'verification'", ".verification", '"confidence"', ".confidence"):
        assert read not in source, f"scoring.py reads {read}"


# --- VulnRow wiring + defaults ------------------------------------------------------------

def test_vulnrow_defaults_are_the_safe_values() -> None:
    """Any VulnRow built without the new fields (legacy call sites, test doubles) must default
    to the conservative pair rather than to a verified claim."""
    row = _row()
    assert row.verification == UNVERIFIED
    assert row.confidence == CONFIDENCE_MEDIUM


def test_row_classifier_tolerates_missing_attributes() -> None:
    """A row-like object lacking the metadata still classifies, mirroring classify_row."""

    class Bare:
        pass

    assert classify_verification_row(Bare()) == (UNVERIFIED, CONFIDENCE_MEDIUM)


# --- Labels / notes -----------------------------------------------------------------------

def test_labels_and_note_are_human_readable_and_default_safely() -> None:
    assert verification_label(VERIFIED) == "Verified"
    assert verification_label(PARTIALLY_VERIFIED) == "Partially Verified"
    assert verification_label(UNVERIFIED) == "Unverified"
    assert verification_label(None) == "Unverified"  # unknown -> safest label
    assert confidence_label(CONFIDENCE_HIGH) == "High"
    assert confidence_label(None) == "Medium"
    assert "manual validation" in verification_note(UNVERIFIED).lower()
    assert "corroborated" in verification_note(VERIFIED).lower()


def test_verification_is_distinct_from_ai_confidence() -> None:
    """§5: ai_confidence must not be the source of this value.

    ai_confidence is the AI triage model's rating of its OWN output; verification/confidence
    are evidence-derived. The module must not read it under any name."""
    from pathlib import Path

    import apps.api.modules.reports.verification as ver_mod

    source = Path(ver_mod.__file__).read_text(encoding="utf-8")
    # Mentioned only in the prose explaining why it is NOT used; never read as an attribute.
    assert 'getattr(row, "ai_confidence"' not in source
    assert "row.ai_confidence" not in source
