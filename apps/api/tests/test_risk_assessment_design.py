"""Phase 4.5 -- Risk Assessment design system + MBS.SC branding removal.

WHAT THE TRACE FOUND
--------------------
`render_risk_assessment` built through a bare `SimpleDocTemplate`: no cover, no Table of
Contents, no running header/footer, no page numbers, no PDF outline -- and its H1 read
"MBS.SC — Client Risk Assessment", branding retired everywhere else in the suite. Measured on a
real render: MBS.SC present, MBS.PT absent, no contact details, no TOC, no page numbers, no
bookmarks. One of three report types looked like a different product.

WHAT PHASE 4.5 CHANGED
----------------------
Presentation and branding ONLY. The renderer now builds through the SAME
`_cover_story`/`_toc_story`/`_section`/`_build_document` path as the Executive and Technical
reports, so it inherits the canonical logo, cover, classification, contacts, header/footer,
"Page N of M" (Phase 4.4) and outline. No second branding or chrome implementation exists.

THE INVARIANT THAT MATTERS MOST
-------------------------------
Every figure still comes from `assessment.summary` -- the snapshot frozen at issue time -- and
NOTHING is recomputed from live findings. A re-render of a March assessment in June must still
say what it said in March. The tests below pin that explicitly by rendering a snapshot whose
numbers deliberately disagree with the live ReportData handed alongside it.
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
    _score_band,
    render_executive,
    render_risk_assessment,
    render_technical,
)
from apps.api.modules.reports.scoring import compute_security_score
from apps.api.tests.test_report_layout import _page_count, _pdf_text

DIGEST = hashlib.sha256(b"evidence").hexdigest()
CAPTURED = datetime(2026, 9, 8, 14, 0, 0, tzinfo=timezone.utc)


class _Assessment:
    """An ISSUED assessment whose frozen summary deliberately disagrees with live data."""

    title = "Q3 2026 Client Risk Assessment"
    period_start = datetime(2026, 7, 1, tzinfo=timezone.utc)
    period_end = datetime(2026, 9, 30, tzinfo=timezone.utc)
    issued_at = datetime(2026, 10, 1, 9, 30, tzinfo=timezone.utc)
    narrative = ("Posture improved this quarter.\n"
                 "Two critical issues remain outstanding.")
    summary = {
        "security_score": 58,
        "score_band": "Weak",
        "active_findings": 12,
        "unresolved_issue_count": 4,
        "affected_assets": ["app.test", "api.test"],
        "affected_endpoint_count": 7,
        "active_severity_counts": {"critical": 2, "high": 3, "medium": 5, "low": 2, "info": 0},
        "top_risks": [
            {"title": "SQL Injection", "severity": "critical", "max_risk": 10.0,
             "max_cvss": 9.8, "endpoint_count": 3},
            {"title": "Reflected XSS", "severity": "high", "max_risk": 8.0,
             "max_cvss": 7.4, "endpoint_count": 2},
            {"title": "Unscored Finding", "severity": "medium", "max_risk": None,
             "max_cvss": None, "endpoint_count": 1},
        ],
        "remediation_progress": {
            "total": 10, "proposed": 2, "accepted": 1, "in_progress": 3,
            "awaiting_verification": 1, "verified": 2, "closed": 1, "risk_accepted": 0,
            "overdue": 2, "completion_percent": 30, "resolved": 3,
        },
    }


def _row(template_id="sql-injection", severity="critical", matched_at="https://app.test/a"):
    record = EvidenceRecord(uuid.uuid4(), "log_excerpt", f"s3://e/{uuid.uuid4()}.txt",
                            DIGEST, CAPTURED)
    return VulnRow(
        id=uuid.uuid4(), title=template_id.replace("-", " ").title(), severity=severity,
        status="open", category="cwe-89", cvss_score=9.8, cvss_vector="CVSS:3.1/AV:N",
        final_risk_score=9.0, risk_rationale=None,
        compliance=[("owasp", "A03:2021", "Injection")],
        evidence_uris=[record.storage_uri],
        evidence_items=[(record.evidence_type, record.storage_uri)],
        evidence_records=[record], template_id=template_id, matcher_name="status",
        matched_at=matched_at, asset_value="app.test", description="A condition was detected.",
    )


def _data(rows=None):
    rows = [_row(), _row("xss-reflected", "high", "https://app.test/b")] if rows is None else rows
    active = [r for r in rows if r.status in ("open", "confirmed", "reopened")]
    return ReportData(
        project_name="Northwind Retail", security_score=compute_security_score(rows),
        severity_counts=dict(collections.Counter(r.severity for r in rows)),
        total_vulns=len(rows), active_vulns=len(active),
        active_severity_counts=dict(collections.Counter(r.severity for r in active)),
        vulns=rows,
    )


def _pdf():
    return render_risk_assessment(_data(), _Assessment())


def _text(pdf: bytes) -> str:
    return re.sub(r"\s+", " ", _pdf_text(pdf))


# --- 1.-3. MBS.PT branding present, MBS.SC gone ---------------------------------------------

def test_mbs_pt_branding_is_present() -> None:
    text = _text(_pdf())
    assert B.BRAND_NAME in text
    assert B.REPORT_SUITE in text


def test_mbs_sc_branding_is_absent_from_the_risk_assessment() -> None:
    """THE defect: the H1 read "MBS.SC — Client Risk Assessment"."""
    assert "MBS.SC" not in _text(_pdf())


def test_no_mbs_sc_string_can_be_rendered_by_any_report() -> None:
    """No report may EMIT the retired brand.

    Checked against rendered output rather than source text: the renderer still carries a
    comment naming "MBS.SC" to record the defect that was removed, which is documentation, not
    branding. What matters is that no reader can ever see it."""
    data = _data()
    for pdf in (render_executive(data), render_technical(data),
                render_risk_assessment(data, _Assessment())):
        assert "MBS.SC" not in _text(pdf)


def test_no_mbs_sc_remains_in_executable_code() -> None:
    """Source-level guard, excluding comments: a literal would mean the brand can still be
    printed under some code path."""
    import pathlib

    offenders = []
    for path in pathlib.Path("apps/api/modules/reports").glob("*.py"):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("#", 1)[0]
            if "MBS.SC" in code:
                offenders.append(f"{path}:{lineno}")
    assert offenders == [], f"MBS.SC in executable code: {offenders}"


def test_approved_contact_details_are_correct() -> None:
    text = _text(_pdf())
    assert B.CONTACT_EMAIL in text
    assert B.CONTACT_PHONE in text
    assert "bandaraodh@gmail.com" in text
    assert "+966578121147" in text


def test_branding_comes_from_the_canonical_module_not_a_literal() -> None:
    """No second branding implementation: the identity strings are _branding's."""
    assert B.BRAND_NAME == "MBS.PT"
    assert _text(_pdf()).count(B.BRAND_NAME) >= 2  # cover + footer


# --- 4.-7. canonical design tokens ------------------------------------------------------------

def test_score_band_palette_is_the_canonical_one() -> None:
    assert B.score_band_color("Weak") == B.SCORE_BAND_COLORS["Weak"]
    assert B.score_band_color(_Assessment.summary["score_band"]) != B.MUTED


def test_fair_remains_the_canonical_score_band_key() -> None:
    """R-04 contract, unchanged by this phase."""
    assert "Fair" in B.SCORE_BAND_COLORS
    assert "Moderate" not in B.SCORE_BAND_COLORS
    assert _score_band(80) == "Fair"


def test_severity_colors_remain_canonical() -> None:
    for sev in ("critical", "high", "medium", "low", "info"):
        assert B.severity_color(sev) == B.SEVERITY_COLORS[sev]


def test_no_duplicate_colour_constants_were_introduced() -> None:
    """Phase 4.5 must reuse tokens, not define a parallel palette."""
    import pathlib

    source = pathlib.Path("apps/api/modules/reports/render.py").read_text(encoding="utf-8")
    risk_block = source[source.index("def render_risk_assessment"):]
    risk_block = risk_block[:risk_block.index("\ndef render(")]
    hex_literals = set(re.findall(r"#[0-9a-fA-F]{6}", risk_block))
    assert hex_literals <= {"#ffffff"}, f"hard-coded colours in the risk renderer: {hex_literals}"


def test_verification_confidence_language_is_untouched() -> None:
    """Phase 4.1 owns this vocabulary; the Risk Assessment must not fork it."""
    assert set(B.VERIFICATION_COLORS) == {"verified", "partially_verified", "unverified"}
    assert set(B.CONFIDENCE_COLORS) == {"high", "medium", "low"}
    assert set(B.VERIFICATION_COLORS.values()).isdisjoint(set(B.SEVERITY_COLORS.values()))


def test_risk_assessment_does_not_introduce_ai_confidence() -> None:
    text = _text(_pdf())
    assert "AI confidence" not in text
    assert "ai_confidence" not in text


def test_risk_assessment_makes_no_confirmed_compromise_claim() -> None:
    text = _text(_pdf()).lower()
    for phrase in ("confirmed compromise", "successfully exploited", "proven exploitation"):
        assert phrase not in text
    assert "not all confirmed vulnerabilities" in text


# --- 8.-9. frozen values are preserved, never recomputed -------------------------------------

def test_security_score_comes_from_the_frozen_snapshot() -> None:
    """The live ReportData scores differently; the snapshot value must win."""
    data = _data()
    assert data.security_score != _Assessment.summary["security_score"]
    text = _text(render_risk_assessment(data, _Assessment()))
    assert "58/100" in text
    assert f"{data.security_score}/100" not in text


def test_frozen_counts_are_printed_not_live_ones() -> None:
    data = _data()
    assert data.total_vulns != _Assessment.summary["active_findings"]
    text = _text(render_risk_assessment(data, _Assessment()))
    assert "12 recorded finding(s)" in text          # snapshot
    assert "7 endpoint(s)" in text                    # snapshot


def test_score_band_thresholds_are_unchanged() -> None:
    for score, band in ((95, "Strong"), (80, "Fair"), (50, "Weak"), (20, "Critical")):
        assert _score_band(score) == band


def test_snapshot_band_is_preferred_over_recomputation() -> None:
    """If the snapshot recorded a band, that band is what a re-render must state."""
    band = _Assessment.summary["score_band"]
    # summary is a heterogeneous dict (ints + strs), so mypy widens lookups to `object`.
    assert isinstance(band, str)
    assert band in _text(_pdf())


def test_unscored_risk_renders_as_na_not_zero() -> None:
    """"not scored" and "scored zero" stay distinct, exactly as everywhere else."""
    assert "N/A" in _text(_pdf())


def test_all_frozen_figures_survive_the_redesign() -> None:
    text = _text(_pdf())
    for probe in ("58/100", "Weak", "12 recorded finding(s)", "7 endpoint(s)",
                  "app.test", "SQL Injection", "10.0", "9.8", "30%"):
        assert probe in text, f"lost frozen figure: {probe}"


def test_issued_narrative_is_rendered_verbatim() -> None:
    text = _text(_pdf())
    assert "Posture improved this quarter." in text
    assert "Two critical issues remain outstanding." in text


# --- 10.-13. R-01 / R-02 / R-03 / R-04 intact ------------------------------------------------

def test_r01_unit_vocabulary_is_used() -> None:
    text = _text(_pdf())
    assert "UNIQUE ISSUES" in text
    assert "recorded finding(s)" in text
    assert "remediated once" in text


def test_r01_semantics_intact_in_the_other_reports() -> None:
    rows = [_row("one-issue", matched_at=f"https://h/p{i}") for i in range(7)]
    data = _data(rows)
    assert data.total_issue_count() == 1 and data.total_vulns == 7
    assert "1 unique issue across 7 affected locations" in _text(render_executive(data))


def test_r02_compliance_semantics_intact() -> None:
    from apps.api.modules.reports.scoring import is_scorable

    data = _data()
    contributing = {
        fid for _fw, controls in data.compliance_coverage()
        for _cid, _d, ids in controls for fid in ids
    }
    assert contributing <= {v.finding_id for v in data.vulns if is_scorable(v)}


def test_r03_scan_scope_semantics_intact() -> None:
    assert _data().is_scan_scoped() is False


def test_r04_band_colour_resolves_for_every_band() -> None:
    for band in ("Strong", "Fair", "Weak", "Critical"):
        assert B.score_band_color(band) != B.MUTED


# --- 14.-17. earlier phases intact ------------------------------------------------------------

def test_phase_32_evidence_manifest_intact() -> None:
    text = _text(render_technical(_data()))
    assert "Evidence manifest" in text


def test_phase_41_assurance_chips_intact() -> None:
    text = _text(render_technical(_data()))
    for caption in ("VERIFICATION", "CONFIDENCE", "EVIDENCE"):
        assert caption in text


def test_phase_42_layout_protection_intact() -> None:
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, Paragraph, Table, TableStyle

    from apps.api.modules.reports.render import _finding_block, _finding_groups, _styles

    styles = _styles(getSampleStyleSheet, ParagraphStyle, colors)
    g = _finding_groups(_data().vulns)[0]
    out = _finding_block(1, g, styles, colors, Paragraph, Table, TableStyle, mm)
    assert isinstance(out, list) and isinstance(out[0], KeepTogether)


# --- 18.-19. PDF rendering and navigation ------------------------------------------------------

def test_risk_assessment_pdf_renders() -> None:
    pdf = _pdf()
    assert pdf[:4] == b"%PDF"
    assert _page_count(pdf) >= 1


def test_risk_assessment_has_a_cover_and_toc() -> None:
    text = _text(_pdf())
    assert "Table of Contents" in text
    assert "Classification" in text
    assert "Client Risk Assessment" in text


def test_risk_assessment_has_page_n_of_m() -> None:
    """Phase 4.4 numbering, inherited by building through _build_document."""
    pdf = _pdf()
    pairs = re.findall(r"Page (\d+) of (\d+)", _text(pdf))
    assert pairs, "no 'Page N of M' in the Risk Assessment footer"
    totals = {int(t) for _n, t in pairs}
    assert len(totals) == 1
    assert totals.pop() == _page_count(pdf) - 1


def test_risk_assessment_has_pdf_bookmarks() -> None:
    assert b"/Outlines" in _pdf()


def test_risk_assessment_navigation_has_no_dangling_destinations() -> None:
    from apps.api.modules.reports import _page_furniture as PF

    base = PF.numbered_canvas_factory()
    bookmarks: dict[str, int] = {}
    outline: list[tuple[str, str]] = []

    class _Probe(base):  # type: ignore[misc, valid-type]
        def bookmarkPage(self, key, *a, **k):
            bookmarks[key] = self.getPageNumber()
            return super().bookmarkPage(key, *a, **k)

        def addOutlineEntry(self, title, key, *a, **k):
            outline.append((title, key))
            return super().addOutlineEntry(title, key, *a, **k)

    original = PF.numbered_canvas_factory
    PF.numbered_canvas_factory = lambda: _Probe
    try:
        pdf = _pdf()
    finally:
        PF.numbered_canvas_factory = original

    assert outline, "no outline entries"
    assert [k for _t, k in outline if k not in bookmarks] == []
    pages = _page_count(pdf)
    assert all(1 <= bookmarks[k] <= pages for _t, k in outline)


def test_all_sections_are_present() -> None:
    text = _text(_pdf())
    for heading in ("Assessment Details", "Security Posture", "Severity Distribution",
                    "Affected Assets", "Key Risks", "Remediation Progress",
                    "Management Summary"):
        assert heading in text, f"missing section: {heading}"


def test_the_three_reports_share_one_chrome() -> None:
    """Brand, suite name and contacts appear in all three documents."""
    data = _data()
    for pdf in (render_executive(data), render_technical(data),
                render_risk_assessment(data, _Assessment())):
        text = _text(pdf)
        assert B.BRAND_NAME in text
        assert B.CONTACT_EMAIL in text
        assert re.search(r"Page \d+ of \d+", text)


@pytest.mark.parametrize("summary", [{}, {"security_score": None}])
def test_degenerate_snapshots_still_render(summary) -> None:
    class _Empty:
        title = "Empty"
        period_start = period_end = issued_at = None
        narrative = None

    _Empty.summary = summary
    pdf = render_risk_assessment(_data(), _Empty())
    assert pdf[:4] == b"%PDF"


def test_redesign_alters_no_assessed_value() -> None:
    rows = [_row(), _row("xss-reflected", "high", "https://app.test/b")]
    before = [(r.severity, r.cvss_score, r.final_risk_score, r.status) for r in rows]
    render_risk_assessment(_data(rows), _Assessment())
    assert [(r.severity, r.cvss_score, r.final_risk_score, r.status) for r in rows] == before
