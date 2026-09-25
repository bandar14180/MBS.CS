"""Exposed reasoning behind the verification state (Prompt B).

`classify_verification` computed four signals internally (artefacts / generic / inference /
detection) and returned only the 2-tuple, discarding WHY. The report layer then re-derived one
of them -- `render._is_inference_match` reaches into the private `_has_inference_marker` -- so
the analyst-facing explanation was both duplicated and incomplete: it explained inference, but
not why something was generic, was a detection, had no artefacts, or earned `high` from a CVE.

These cover the reason codes as an audit trail that CANNOT disagree with the decision, because
both are computed from the same private predicates.
"""

from apps.api.modules.reports.verification import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    PARTIALLY_VERIFIED,
    REASON_CORROBORATED_BOTH,
    REASON_CVE_BACKED,
    REASON_DETECTION_CLASS,
    REASON_GENERIC_MATCH,
    REASON_INFERENCE_MATCH,
    REASON_NO_ARTEFACTS,
    REASON_RESPONSE_CAPTURED,
    REASON_SCREENSHOT_CAPTURED,
    UNVERIFIED,
    VERIFIED,
    classify_verification,
    reason_note,
    verification_reasons,
    verification_reasons_row,
)

SPECIFIC = "acme-specific-rce"
GENERIC = "unix-command-injection-generic"
LOG = ["s3://bucket/log"]
SHOT = [("s3://bucket/shot.png", "checksum")]


# --- A. Reasons agree with the state the classifier returned --------------------------------

def test_no_artefacts_is_explained():
    kw = dict(template_id=SPECIFIC, matcher_name="status")
    assert classify_verification(**kw)[0] == UNVERIFIED
    assert REASON_NO_ARTEFACTS in verification_reasons(**kw)


def test_verified_state_is_explained_by_both_artefacts():
    kw = dict(template_id=SPECIFIC, matcher_name="status", evidence_uris=LOG, screenshots=SHOT)
    assert classify_verification(**kw)[0] == VERIFIED
    reasons = verification_reasons(**kw)
    assert REASON_CORROBORATED_BOTH in reasons
    assert REASON_RESPONSE_CAPTURED in reasons
    assert REASON_SCREENSHOT_CAPTURED in reasons
    assert REASON_NO_ARTEFACTS not in reasons


def test_generic_downgrade_is_explained():
    kw = dict(template_id=GENERIC, matcher_name="body", evidence_uris=LOG, screenshots=SHOT)
    assert classify_verification(**kw)[0] == PARTIALLY_VERIFIED
    assert REASON_GENERIC_MATCH in verification_reasons(**kw)


def test_inference_downgrade_is_explained():
    kw = dict(template_id=SPECIFIC, matcher_name="time-based", evidence_uris=LOG, screenshots=SHOT)
    state, conf = classify_verification(**kw)
    assert (state, conf) == (PARTIALLY_VERIFIED, CONFIDENCE_LOW)
    assert REASON_INFERENCE_MATCH in verification_reasons(**kw)


def test_detection_class_is_explained():
    kw = dict(template_id="tech-detect", matcher_name="body", classification="detection",
              evidence_uris=LOG, screenshots=SHOT)
    assert classify_verification(**kw)[0] == PARTIALLY_VERIFIED
    assert REASON_DETECTION_CLASS in verification_reasons(**kw)


def test_cve_backed_high_confidence_is_explained():
    """Two different inputs both return `high`; only the reasons distinguish them."""
    cve_kw = dict(template_id="CVE-2021-41773", cve="CVE-2021-41773")
    art_kw = dict(template_id=SPECIFIC, matcher_name="status", evidence_uris=LOG, screenshots=SHOT)
    assert classify_verification(**cve_kw)[1] == CONFIDENCE_HIGH
    assert classify_verification(**art_kw)[1] == CONFIDENCE_HIGH
    assert REASON_CVE_BACKED in verification_reasons(**cve_kw)
    assert REASON_CVE_BACKED not in verification_reasons(**art_kw)


# --- B. The audit trail cannot contradict the decision --------------------------------------

def test_no_artefacts_reason_iff_unverified_for_artefact_reasons():
    """`REASON_NO_ARTEFACTS` appears exactly when the classifier saw no artefacts."""
    for uris, shots in ((None, None), (LOG, None), (None, SHOT), (LOG, SHOT)):
        kw = dict(template_id=SPECIFIC, matcher_name="status", evidence_uris=uris, screenshots=shots)
        has_artefacts = bool(uris or shots)
        assert (REASON_NO_ARTEFACTS in verification_reasons(**kw)) is (not has_artefacts)
        if not has_artefacts:
            assert classify_verification(**kw)[0] == UNVERIFIED


def test_corroborated_both_never_claims_exploitation():
    """Evidence separation: two artefacts is a statement about ARTEFACTS, not exploitability.
    A generic match with both artefacts is corroborated but still NOT verified."""
    kw = dict(template_id=GENERIC, matcher_name="body", evidence_uris=LOG, screenshots=SHOT)
    assert REASON_CORROBORATED_BOTH in verification_reasons(**kw)
    assert classify_verification(**kw)[0] != VERIFIED


# --- C. Determinism -------------------------------------------------------------------------

def test_reasons_are_deterministic_and_stably_ordered():
    kw = dict(template_id=GENERIC, matcher_name="time-based", evidence_uris=LOG, screenshots=SHOT)
    first = verification_reasons(**kw)
    for _ in range(50):
        assert verification_reasons(**kw) == first      # identical list, identical order


def test_reasons_row_matches_keyword_form():
    class _Row:
        template_id = GENERIC
        matcher_name = "time-based"
        evidence_uris = LOG
        screenshots = SHOT
        classification = None
        cve = None

    assert verification_reasons_row(_Row()) == verification_reasons(
        template_id=GENERIC, matcher_name="time-based", evidence_uris=LOG, screenshots=SHOT,
    )


def test_row_form_tolerates_missing_attributes():
    class _Bare:
        pass

    assert verification_reasons_row(_Bare()) == [REASON_NO_ARTEFACTS]


def test_reason_notes_exist_for_every_code_and_unknown_is_empty():
    for code in (REASON_NO_ARTEFACTS, REASON_GENERIC_MATCH, REASON_INFERENCE_MATCH,
                 REASON_DETECTION_CLASS, REASON_RESPONSE_CAPTURED, REASON_SCREENSHOT_CAPTURED,
                 REASON_CORROBORATED_BOTH, REASON_CVE_BACKED):
        assert reason_note(code)
    assert reason_note("not-a-real-code") == ""
    assert reason_note(None) == ""


# --- D. Reasons do not alter the decision ---------------------------------------------------

def test_exposing_reasons_changed_no_classification():
    """Regression guard: the documented state/confidence matrix is untouched by Prompt B."""
    assert classify_verification(template_id=SPECIFIC, matcher_name="status") == (UNVERIFIED, "medium")
    assert classify_verification(template_id=SPECIFIC, matcher_name="status",
                                 evidence_uris=LOG, screenshots=SHOT) == (VERIFIED, CONFIDENCE_HIGH)
    assert classify_verification(template_id=GENERIC, matcher_name="generic") == (UNVERIFIED, "medium")
