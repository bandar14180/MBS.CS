"""Phase 4.1 -- verification / confidence / evidence presented as three separate axes.

THE PRESENTATION GAP THIS PINS
------------------------------
Verification and confidence were collapsed into ONE plain-text fact-card row
("Partially Verified · Low confidence"), rendered in the same grey as Status, Asset and
Matcher. Beside a bold CVSS 9.8 and Business risk 10.0 the two numbers carried all the visual
authority, and the qualifier that should temper them was the quietest line on the page -- so a
PARTIALLY VERIFIED finding could reasonably be read as confirmed exploitation.

WHAT PHASE 4.1 CHANGED
----------------------
PRESENTATION ONLY. Three chips on three palettes, plus a state-gated caption. No classifier,
threshold, score or stored value was touched; `verification.py` is byte-identical.

THE THREE AXES, WHICH MUST NEVER MERGE
--------------------------------------
  * Verification -- was it demonstrated?          (evidence-derived)
  * Confidence   -- how much is the signal worth? (independent of the above)
  * Evidence     -- what artefacts exist?         (a COUNT, never a judgement)

AND THE ONE THAT IS NOT AN AXIS
-------------------------------
`vulnerabilities.ai_confidence` is the AI triage model's rating of its OWN output. It is NULL
on every row in the live dataset, has no production writer, and is never read by the report.
The tests at the bottom assert it stays that way: it must never reach a chip, and must never
influence verification or confidence.
"""

import collections
import hashlib
import re
import uuid
from datetime import datetime, timezone

import pytest

from apps.api.modules.reports import _branding as B
from apps.api.modules.reports.data import EvidenceRecord, ReportData, VulnRow
from apps.api.modules.reports.render import (
    _assurance_caption,
    _finding_groups,
    render_technical,
)
from apps.api.modules.reports.scoring import compute_security_score
from apps.api.modules.reports.verification import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    PARTIALLY_VERIFIED,
    UNVERIFIED,
    VERIFIED,
    classify_verification_row,
)
from apps.api.tests.test_report_layout import _pdf_text

DIGEST = hashlib.sha256(b"evidence").hexdigest()
CAPTURED = datetime(2026, 9, 8, 14, 23, 51, tzinfo=timezone.utc)


def _rec(etype="log_excerpt", uri="s3://mbs-evidence/tool-runs/a/raw-output.txt"):
    return EvidenceRecord(uuid.uuid4(), etype, uri, DIGEST, CAPTURED)


def _row(matcher="status", evidence=(), shots=(), **kw):
    evidence, shots = list(evidence), list(shots)
    return VulnRow(
        id=uuid.uuid4(), title=kw.pop("title", "Command Injection"),
        severity=kw.pop("severity", "critical"), status=kw.pop("status", "open"),
        category="cwe-78", cvss_score=kw.pop("cvss_score", 9.8), cvss_vector=None,
        final_risk_score=kw.pop("final_risk_score", 10.0), risk_rationale=None, compliance=[],
        evidence_uris=[r.storage_uri for r in evidence],
        evidence_items=[(r.evidence_type, r.storage_uri) for r in evidence],
        evidence_records=evidence + shots,
        screenshots=[(s.storage_uri, s.checksum) for s in shots],
        template_id=kw.pop("template_id", "cmd-inj"), matcher_name=matcher,
        matched_at=kw.pop("matched_at", "https://h/a"),
    )


def _data(rows):
    sev = dict(collections.Counter(r.severity for r in rows))
    return ReportData(
        project_name="ChipProj", security_score=compute_security_score(rows),
        severity_counts=sev, total_vulns=len(rows), active_vulns=len(rows),
        active_severity_counts=sev, vulns=rows,
    )


def _text(pdf: bytes) -> str:
    return re.sub(r"\s+", " ", _pdf_text(pdf))


def _group(row) -> dict:
    return _finding_groups([row])[0]


# --- the three chips are present and separate ----------------------------------------------

def test_all_three_axes_are_labelled_separately() -> None:
    text = _text(render_technical(_data([_row(evidence=[_rec()])])))
    for caption in ("VERIFICATION", "CONFIDENCE", "EVIDENCE"):
        assert caption in text, f"missing chip caption: {caption}"


def test_verification_and_confidence_are_no_longer_one_collapsed_row() -> None:
    """The old single fact-card row read "<state> · <level> confidence". It must be gone."""
    text = _text(render_technical(_data([_row(matcher="time-based", evidence=[_rec()])])))
    assert "Partially Verified · Low confidence" not in text
    assert "Partially Verified" in text
    assert "Low" in text


def test_evidence_chip_states_a_count_not_a_judgement() -> None:
    text = _text(render_technical(_data([_row(evidence=[_rec()])])))
    assert "1 artefact(s)" in text
    # It must never assert the artefacts prove anything.
    assert "evidence verified" not in text.lower()
    assert "proven by evidence" not in text.lower()


def test_absence_of_evidence_is_stated_plainly() -> None:
    text = _text(render_technical(_data([_row()])))
    assert "No artefacts" in text


def test_screenshots_are_counted_separately_in_the_evidence_chip() -> None:
    text = _text(render_technical(
        _data([_row(evidence=[_rec()], shots=[_rec("screenshot", "s3://e/s.png")])])
    ))
    assert "screenshot(s)" in text


# --- the three palettes are distinct -------------------------------------------------------

def test_verification_palette_is_not_the_severity_palette() -> None:
    """Painting verification in severity colours would imply a relationship that does not
    exist -- the classifier never reads severity, CVSS or risk."""
    assert set(B.VERIFICATION_COLORS.values()).isdisjoint(set(B.SEVERITY_COLORS.values()))


def test_confidence_palette_is_distinct_from_severity_and_verification() -> None:
    """Three axes, three palettes. A shared hex would let two independent facts read as one
    escalating signal."""
    conf = set(B.CONFIDENCE_COLORS.values())
    assert conf.isdisjoint(set(B.VERIFICATION_COLORS.values()))
    assert conf.isdisjoint(set(B.SEVERITY_COLORS.values()))


def test_no_real_state_collides_with_the_unknown_fallback() -> None:
    """MUTED is reserved for an UNRECOGNISED state. If a real state also rendered as MUTED, the
    "unknown never looks like a known state" guarantee would be unobservable."""
    assert B.MUTED not in set(B.VERIFICATION_COLORS.values())
    assert B.MUTED not in set(B.CONFIDENCE_COLORS.values())


def test_only_verified_gets_a_confirmatory_colour() -> None:
    """VERIFIED is the only state backed by two independent artefact kinds, so it is the only
    one that earns a positive (green) colour. The others must stay neutral."""
    assert B.verification_color(VERIFIED) == "#15803d"
    assert B.verification_color(PARTIALLY_VERIFIED) != B.verification_color(VERIFIED)
    assert B.verification_color(UNVERIFIED) != B.verification_color(VERIFIED)


def test_every_verification_state_has_a_colour() -> None:
    for state in (VERIFIED, PARTIALLY_VERIFIED, UNVERIFIED):
        assert B.verification_color(state) != B.MUTED, f"{state} falls through to MUTED"
        assert state in B.VERIFICATION_BG


def test_every_confidence_level_has_a_colour() -> None:
    for level in (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW):
        assert B.confidence_color(level) != B.MUTED, f"{level} falls through to MUTED"


def test_unknown_states_fail_to_neutral_never_to_confirmatory() -> None:
    """Fails the same direction verification.py does: an unrecognised state must never be
    painted as demonstrated."""
    for bogus in (None, "", "   ", "proven", "definitely"):
        assert B.verification_color(bogus) == B.MUTED
        assert B.verification_color(bogus) != B.verification_color(VERIFIED)
        assert B.confidence_color(bogus) == B.MUTED
        assert B.verification_bg(bogus) == B.BAND


# --- the caption is gated on the actual state -----------------------------------------------

def test_partially_verified_caption_denies_confirmed_exploitation() -> None:
    """THE audit §8 scenario: CVSS 9.8 + risk 10.0 + PARTIALLY VERIFIED / LOW."""
    g = _group(_row(matcher="time-based", evidence=[_rec()]))
    assert (g["verification"], g["confidence"]) == (PARTIALLY_VERIFIED, CONFIDENCE_LOW)
    caption = _assurance_caption(g)
    assert "NOT independently demonstrated" in caption
    assert "not a confirmed compromise" in caption


def test_unverified_caption_says_not_demonstrated() -> None:
    caption = _assurance_caption(_group(_row()))
    assert "NOT been demonstrated" in caption
    assert "manual validation" in caption


def test_only_verified_caption_uses_confirmatory_language() -> None:
    g = _group(_row(evidence=[_rec()], shots=[_rec("screenshot", "s3://e/s.png")]))
    assert g["verification"] == VERIFIED
    caption = _assurance_caption(g)
    assert "corroborated by captured evidence" in caption
    assert "NOT" not in caption.replace("NOT been", "").replace("NOT independently", "")


def test_caption_separates_evidence_presence_from_proof() -> None:
    """The exact confusion requirement 7 names: evidence present != evidence verified."""
    caption = _assurance_caption(_group(_row(matcher="time-based", evidence=[_rec()])))
    assert "not itself proof of exploitation" in caption


def test_caption_states_severity_independence() -> None:
    caption = _assurance_caption(_group(_row()))
    assert "independent of all three measures" in caption
    assert "not reduced when a finding is unverified" in caption


def test_caption_does_not_repeat_fact_card_value_labels() -> None:
    """The finding block states each assessed value exactly once (see
    test_report_narrative.py::test_finding_id_and_severity_are_not_duplicated_in_the_block).
    The caption must make its point without reusing those labels as prose."""
    caption = _assurance_caption(_group(_row()))
    assert "Severity" not in caption
    assert "CVSS" not in caption


def test_caption_always_names_the_three_axes_as_separate() -> None:
    for row in (_row(), _row(evidence=[_rec()]),
                _row(evidence=[_rec()], shots=[_rec("screenshot", "s3://e/s.png")])):
        assert "three separate measures" in _assurance_caption(_group(row))


# --- ai_confidence must never become a chip or influence one -------------------------------

def test_ai_confidence_never_reaches_the_rendered_report() -> None:
    """It is the AI's rating of its OWN output, not an evidence statement. Surfacing it beside
    verification would invite exactly the conflation requirement 5 forbids."""
    row = _row(evidence=[_rec()])
    row.ai_confidence = 0.99
    text = _text(render_technical(_data([row])))
    assert "0.99" not in text
    assert "AI confidence" not in text
    assert "ai_confidence" not in text


def test_ai_confidence_does_not_move_verification_or_the_chips() -> None:
    base = classify_verification_row(_row(evidence=[_rec()]))
    for value in (0.0, 0.5, 1.0, None):
        row = _row(evidence=[_rec()])
        row.ai_confidence = value
        assert classify_verification_row(row) == base
        g = _group(row)
        assert (g["verification"], g["confidence"]) == base


def test_ai_confidence_is_absent_from_the_report_row_contract() -> None:
    """VulnRow deliberately carries no ai_confidence field; the report never loads it."""
    assert "ai_confidence" not in {f.name for f in __import__("dataclasses").fields(VulnRow)}


# --- verification semantics are untouched ---------------------------------------------------

def test_verification_module_semantics_are_unchanged() -> None:
    """Phase 4.1 is presentation. The classifier's own outputs must be exactly as before."""
    assert classify_verification_row(_row())[0] == UNVERIFIED
    assert classify_verification_row(_row(evidence=[_rec()]))[0] == PARTIALLY_VERIFIED
    assert classify_verification_row(
        _row(evidence=[_rec()], shots=[_rec("screenshot", "s3://e/s.png")])
    )[0] == VERIFIED
    # A generic/inference match with artefacts is corroborated, never proven.
    assert classify_verification_row(
        _row(matcher="time-based", evidence=[_rec()],
             shots=[_rec("screenshot", "s3://e/s.png")])
    )[0] == PARTIALLY_VERIFIED


@pytest.mark.parametrize("severity", ["info", "low", "medium", "high", "critical"])
def test_chips_do_not_vary_with_severity(severity: str) -> None:
    """Verification is independent of severity; the chip must reflect that."""
    g = _group(_row(severity=severity, evidence=[_rec()]))
    assert g["verification"] == PARTIALLY_VERIFIED


@pytest.mark.parametrize("cvss", [None, 0.0, 5.5, 9.8, 10.0])
def test_chips_do_not_vary_with_cvss(cvss) -> None:
    g = _group(_row(cvss_score=cvss, evidence=[_rec()]))
    assert g["verification"] == PARTIALLY_VERIFIED


def test_presentation_does_not_alter_any_assessed_value() -> None:
    rows = [_row(evidence=[_rec()])]
    before = [(r.severity, r.cvss_score, r.final_risk_score, r.status) for r in rows]
    render_technical(_data(rows))
    assert [(r.severity, r.cvss_score, r.final_risk_score, r.status) for r in rows] == before


# --- earlier phases intact -------------------------------------------------------------------

def test_r01_r02_r03_r04_intact() -> None:
    from apps.api.modules.reports.render import _score_band, render_executive

    rows = [_row(evidence=[_rec()], matched_at=f"https://h/p{i}") for i in range(7)]
    data = _data(rows)
    # R-01
    assert data.total_issue_count() == 1 and data.total_vulns == 7
    assert "1 unique issue across 7 affected locations" in _text(render_executive(data))
    # R-02
    assert data.compliance_coverage() == []
    # R-03
    assert data.is_scan_scoped() is False
    # R-04
    assert B.score_band_color(_score_band(data.security_score)) != B.MUTED


def test_phase_32_evidence_integrity_still_rendered() -> None:
    text = _text(render_technical(_data([_row(evidence=[_rec()])])))
    assert "Evidence manifest" in text
    assert "2026-09-08 14:23:51 UTC" in text
