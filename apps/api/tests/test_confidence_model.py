"""Prompt 22 -- the Confidence Model as a first-class, separately-testable axis.

WHY THIS FILE EXISTS ALONGSIDE test_verification*.py. Those files pin the CLASSIFIER: given
metadata, what state comes out. This file pins the MODEL: that "confidence" means exactly one
thing, is produced by exactly one deterministic path, cannot be set by an AI, and never implies
verification. The six scenarios Prompt 22 names are asserted here by name so a future edit
cannot quietly drop one.

The audit that preceded this file found the classifier itself already correct (Prompts A-E).
Nothing here re-tests that work; these are the gaps it left: conflicting evidence, the explicit
"high confidence is not proof" invariant, and the structural AI-bypass guard.
"""

import uuid

import pytest

from apps.api.modules.reports.data import VulnRow
from apps.api.modules.reports.verification import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_SOURCE_AI,
    CONFIDENCE_SOURCE_EVIDENCE,
    PARTIALLY_VERIFIED,
    UNVERIFIED,
    VERIFIED,
    ConfidenceProvenanceError,
    classify_verification,
    classify_verification_row,
    normalize_confidence,
)

SPECIFIC = "apache-path-traversal-2021"
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


# ===================== the six required regression scenarios ==============================

def test_scenario_1_low_confidence_detection() -> None:
    """Timing/blind inference is the weakest signal: LOW, and never verified."""
    state, conf = classify_verification(template_id="sqli-time-based", matcher_name="time-based")
    assert (state, conf) == (UNVERIFIED, CONFIDENCE_LOW)


def test_scenario_2_high_confidence_without_proof() -> None:
    """THE CENTRAL INVARIANT: confidence and verification are independent axes.

    A CVE-backed specific template earns HIGH confidence on signal quality alone -- with zero
    evidence artefacts. It must remain UNVERIFIED. If a refactor ever let confidence imply
    verification, this is the test that fails."""
    state, conf = classify_verification(template_id=SPECIFIC, cve="CVE-2021-41773")
    assert conf == CONFIDENCE_HIGH, "a specific CVE-backed template is a high-quality signal"
    assert state == UNVERIFIED, "HIGH confidence must NEVER imply verification"


def test_scenario_3_verified_finding() -> None:
    """Both artefact kinds on a specific match -- the only route to VERIFIED."""
    state, conf = classify_verification(
        template_id=SPECIFIC, matcher_name="status", evidence_uris=LOG, screenshots=SHOT
    )
    assert (state, conf) == (VERIFIED, CONFIDENCE_HIGH)


def test_scenario_4_conflicting_evidence() -> None:
    """Artefacts present (pointing toward proof) while the match is generic/inferred (pointing
    away from it). The conflict must resolve CONSERVATIVELY on BOTH axes: corroborated but not
    proven, and the weaker confidence wins. Resolving a conflict optimistically is how a
    generic pattern match would acquire the authority of a demonstrated exploit."""
    state, conf = classify_verification(
        template_id="unix-command-injection",
        matcher_name="time-based",          # inference conflicts with the artefacts below
        evidence_uris=LOG,
        screenshots=SHOT,
    )
    assert state == PARTIALLY_VERIFIED, "full artefacts must not override a weak match"
    assert conf == CONFIDENCE_LOW, "the conflict resolves to the WEAKER confidence"


def test_scenario_5_missing_evidence() -> None:
    """No artefacts at all: UNVERIFIED regardless of how severe the finding is."""
    state, _ = classify_verification_row(_row(cvss_score=10.0, severity="critical"))
    assert state == UNVERIFIED


def test_scenario_6_ai_confidence_without_independent_proof() -> None:
    """An AI rating -- at maximum certainty -- moves neither axis, and cannot be admitted as
    evidence confidence at all. This is the bypass the guard exists to stop."""
    baseline = classify_verification_row(_row())
    row = _row()
    row.ai_confidence = 1.0
    assert classify_verification_row(row) == baseline, "AI rating must not move the axes"

    with pytest.raises(ConfidenceProvenanceError):
        normalize_confidence("high", source=CONFIDENCE_SOURCE_AI)


# ===================== normalisation of inconsistent representations ======================

def test_band_spellings_converge_on_one_representation() -> None:
    for spelling in ("HIGH", " high ", "High", "hIgH"):
        assert normalize_confidence(spelling) == CONFIDENCE_HIGH


def test_missing_confidence_defaults_to_the_documented_safe_band() -> None:
    assert normalize_confidence(None) == CONFIDENCE_MEDIUM


@pytest.mark.parametrize("numeric", [0.0, 0.5, 0.95, 1.0, 1, 0, True, False])
def test_numeric_confidence_is_refused_not_silently_mapped(numeric) -> None:
    """The float vocabularies (ai_confidence, attack-graph, agent scoring) grade different
    questions. Any mapping onto these bands would be invented, so none exists."""
    with pytest.raises(ConfidenceProvenanceError):
        normalize_confidence(numeric)


@pytest.mark.parametrize("bogus", ["very-high", "unknown", "", "verified", "critical"])
def test_unknown_bands_are_refused(bogus) -> None:
    with pytest.raises(ConfidenceProvenanceError):
        normalize_confidence(bogus)


def test_every_classifier_output_is_admissible_by_the_guard() -> None:
    """The guard and the classifier must agree: nothing the classifier can emit may be refused
    by the admission point, or a legitimate finding would fail to render."""
    cases = [
        dict(template_id=SPECIFIC),
        dict(template_id=SPECIFIC, cve="CVE-2021-41773"),
        dict(template_id=SPECIFIC, evidence_uris=LOG, screenshots=SHOT),
        dict(template_id="unix-command-injection", matcher_name="time-based"),
        dict(template_id="tech-detect", evidence_uris=LOG),
    ]
    for kw in cases:
        _, conf = classify_verification(**kw)
        assert normalize_confidence(conf, source=CONFIDENCE_SOURCE_EVIDENCE) == conf


# ===================== separation from the other axes =====================================

def test_confidence_is_not_severity_or_cvss() -> None:
    """Confidence must not move when severity/CVSS/risk move."""
    seen = {
        classify_verification_row(_row(severity=s, cvss_score=c, final_risk_score=r))[1]
        for s, c, r in (("low", 0.0, 0.0), ("critical", 10.0, 10.0), ("info", 3.1, 2.0))
    }
    assert len(seen) == 1, f"confidence tracked severity/CVSS: {seen}"


def test_confidence_is_deterministic_for_identical_input() -> None:
    kw = dict(template_id=SPECIFIC, matcher_name="status", evidence_uris=LOG, screenshots=SHOT)
    assert len({classify_verification(**kw) for _ in range(25)}) == 1
