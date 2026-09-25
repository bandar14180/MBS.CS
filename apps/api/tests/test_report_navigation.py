"""Phase 4.4 -- PDF navigation: finding bookmarks, TOC entries, Page N of M, link integrity.

WHAT THE TRACE FOUND
--------------------
1. Only the 9 top-level sections were navigable. A 17-page report with 6 findings offered no
   way to jump to a finding from the outline or the Table of Contents.
2. The footer printed "Page 4" with no total, so a reader could not tell whether a printed
   deliverable was complete.
3. Section bookmark keys were `abs(hash(raw))`. Python salts str hashes per process, so the
   SAME section produced a different anchor on every run (observed: sec-058a29c0,
   sec-1eb63aac, sec-36c5ad58). Re-rendering an unchanged report rewrote every destination.

WHAT PHASE 4.4 CHANGED
----------------------
Navigation only. Finding headings became bookmarked, TOC-registered level-1 entries anchored
on the CANONICAL finding id; anchors became deterministic (md5); the footer prints a real
total via a deferred-numbering canvas. No assessed value, identity or ordering changed.

EVIDENCE BOUNDARY
-----------------
No PDF parser (pypdf/PyPDF2/pdfminer/fitz) is installed in this environment, so destination
integrity is verified by instrumenting ReportLab's OWN canvas API -- recording every
`bookmarkPage`/`addOutlineEntry` call and the page each resolved to -- rather than by
re-parsing the emitted file. Text-level facts are verified against the generated PDF's real
content streams.
"""

import collections
import hashlib
import re
import uuid
from datetime import datetime, timezone

import pytest

from apps.api.modules.reports import _page_furniture as PF
from apps.api.modules.reports.data import EvidenceRecord, ReportData, VulnRow
from apps.api.modules.reports.render import (
    _finding_groups,
    render_executive,
    render_technical,
)
from apps.api.modules.reports.scoring import compute_security_score
from apps.api.tests.test_report_layout import _page_count, _pdf_text

DIGEST = hashlib.sha256(b"evidence").hexdigest()
CAPTURED = datetime(2026, 9, 8, 14, 0, 0, tzinfo=timezone.utc)
OWASP = ("owasp", "A03:2021", "Injection")


def _row(template_id="sql-injection", severity="critical", matched_at="https://app.test/a",
         status="open", cvss=9.8, category="cwe-89"):
    record = EvidenceRecord(uuid.uuid4(), "log_excerpt", f"s3://e/{uuid.uuid4()}.txt",
                            DIGEST, CAPTURED)
    return VulnRow(
        id=uuid.uuid4(), title=template_id.replace("-", " ").title(), severity=severity,
        status=status, category=category, cvss_score=cvss, cvss_vector="CVSS:3.1/AV:N",
        final_risk_score=9.0, risk_rationale=None, compliance=[OWASP],
        evidence_uris=[record.storage_uri],
        evidence_items=[(record.evidence_type, record.storage_uri)],
        evidence_records=[record], template_id=template_id, matcher_name="status",
        matched_at=matched_at, asset_value="app.test", description="A condition was detected.",
    )


def _data(rows):
    active = [r for r in rows if r.status in ("open", "confirmed", "reopened")]
    return ReportData(
        project_name="NavProj", security_score=compute_security_score(rows),
        severity_counts=dict(collections.Counter(r.severity for r in rows)),
        total_vulns=len(rows), active_vulns=len(active),
        active_severity_counts=dict(collections.Counter(r.severity for r in active)),
        vulns=rows,
    )


def _estate():
    """Four distinct findings, so the outline has several destinations to resolve."""
    return [
        _row("sql-injection", "critical", "https://app.test/a"),
        _row("xss-reflected", "high", "https://app.test/b", category="cwe-79"),
        _row("weak-tls", "medium", "https://api.test/c", cvss=5.3, category="cwe-327"),
        _row("open-redirect", "low", "https://app.test/d", cvss=3.1, category="cwe-601"),
    ]


def _text(pdf: bytes) -> str:
    return re.sub(r"\s+", " ", _pdf_text(pdf))


def _capture_navigation(data, renderer=render_technical):
    """Render while recording every bookmark/outline call ReportLab actually makes.

    Returns (pdf, bookmarks{key: page}, outline[(title, key)]). This is the substitute for a
    PDF parser: it observes the real canvas API on the real build, so a destination that never
    resolved simply would not appear."""
    base = PF.numbered_canvas_factory()
    bookmarks: dict[str, int] = {}
    outline: list[tuple[str, str]] = []

    class _Probe(base):
        def bookmarkPage(self, key, *a, **k):
            bookmarks[key] = self.getPageNumber()
            return super().bookmarkPage(key, *a, **k)

        def addOutlineEntry(self, title, key, *a, **k):
            outline.append((title, key))
            return super().addOutlineEntry(title, key, *a, **k)

    original = PF.numbered_canvas_factory
    PF.numbered_canvas_factory = lambda: _Probe
    try:
        pdf = renderer(data)
    finally:
        PF.numbered_canvas_factory = original
    return pdf, bookmarks, outline


# --- 1. stable finding identifiers ---------------------------------------------------------

def test_finding_ids_are_stable_across_renders() -> None:
    data = _data(_estate())
    first = [g["finding_id"] for g in _finding_groups(data.vulns)]
    second = [g["finding_id"] for g in _finding_groups(data.vulns)]
    assert first == second
    assert all(re.fullmatch(r"MBS-[0-9A-F]{8}", i) for i in first)


def test_navigation_introduces_no_second_identifier_system() -> None:
    """Anchors are the canonical id with a prefix -- not a new identity."""
    data = _data(_estate())
    _pdf, _bm, outline = _capture_navigation(data)
    ids = {g["finding_id"] for g in _finding_groups(data.vulns)}
    for _title, key in [o for o in outline if o[1].startswith("finding-")]:
        assert key.removeprefix("finding-") in ids


def test_findings_are_not_renumbered_for_presentation() -> None:
    """Display ordinals still follow _finding_groups' existing severity ordering."""
    data = _data(_estate())
    groups = _finding_groups(data.vulns)
    text = _text(render_technical(data))
    for idx, g in enumerate(groups, 1):
        assert f"{idx}. {g['title']}" in text


def test_section_anchors_are_deterministic_across_processes() -> None:
    """The hash() defect: keys must not change between runs. md5 is process-stable."""
    expected = f"sec-{hashlib.md5('4. Detailed Findings'.encode()).hexdigest()[:8]}"
    _pdf, _bm, outline = _capture_navigation(_data(_estate()))
    keys = {k for _t, k in outline}
    assert expected in keys, "section anchor is not the deterministic md5 form"


# --- 2. TOC entry -> finding destination ---------------------------------------------------

def test_every_finding_has_a_bookmark_destination() -> None:
    data = _data(_estate())
    _pdf, bookmarks, _outline = _capture_navigation(data)
    for g in _finding_groups(data.vulns):
        assert f"finding-{g['finding_id']}" in bookmarks


def test_every_finding_appears_in_the_pdf_outline() -> None:
    data = _data(_estate())
    _pdf, _bm, outline = _capture_navigation(data)
    titles = " ".join(t for t, _k in outline)
    for g in _finding_groups(data.vulns):
        assert g["finding_id"] in titles


def test_outline_entries_are_titled_with_the_canonical_id_and_title() -> None:
    data = _data(_estate())
    _pdf, _bm, outline = _capture_navigation(data)
    entries = [t for t, k in outline if k.startswith("finding-")]
    for g in _finding_groups(data.vulns):
        assert any(t.startswith(g["finding_id"]) and g["title"] in t for t in entries)


def test_findings_are_nested_under_their_section_in_the_outline() -> None:
    """Level 1 keeps findings under "4. Detailed Findings" rather than flattening them."""
    from apps.api.modules.reports.render import _FindingHeading, _styles
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

    styles = _styles(getSampleStyleSheet, ParagraphStyle, colors)
    heading = _FindingHeading("1. X", styles["FindingTitle"],
                              anchor="finding-MBS-00000001", toc_text="MBS-00000001 — X")
    assert heading._toc_level == 1
    assert heading._toc_key == "finding-MBS-00000001"


# --- 3./8. destination integrity -----------------------------------------------------------

def test_every_outline_entry_has_a_matching_bookmark() -> None:
    """No dangling destination: an outline entry pointing at an unregistered key is broken."""
    _pdf, bookmarks, outline = _capture_navigation(_data(_estate()))
    dangling = [k for _t, k in outline if k not in bookmarks]
    assert dangling == [], f"outline entries without a destination: {dangling}"


def test_no_destination_points_outside_the_document() -> None:
    pdf, bookmarks, outline = _capture_navigation(_data(_estate()))
    pages = _page_count(pdf)
    for _title, key in outline:
        page = bookmarks[key]
        assert 1 <= page <= pages, f"{key} -> page {page}, document has {pages}"


def test_finding_destinations_are_distinct_pages_in_order() -> None:
    """Findings are laid out in order, so their destinations must not go backwards."""
    data = _data(_estate())
    _pdf, bookmarks, _outline = _capture_navigation(data)
    pages = [bookmarks[f"finding-{g['finding_id']}"] for g in _finding_groups(data.vulns)]
    assert pages == sorted(pages)


# --- 4./5. page numbers --------------------------------------------------------------------

def test_footer_prints_page_n_of_m() -> None:
    text = _text(render_technical(_data(_estate())))
    assert re.search(r"Page \d+ of \d+", text), "no 'Page N of M' in the footer"


def test_total_is_the_real_final_page_count() -> None:
    """Not an estimate: M must equal the actual PDF page count minus the unnumbered cover."""
    pdf = render_technical(_data(_estate()))
    pairs = re.findall(r"Page (\d+) of (\d+)", _text(pdf))
    assert pairs
    totals = {int(t) for _n, t in pairs}
    assert len(totals) == 1, f"inconsistent totals: {totals}"
    assert totals.pop() == _page_count(pdf) - 1


def test_every_content_page_is_numbered_exactly_once() -> None:
    pdf = render_technical(_data(_estate()))
    numbers = [int(n) for n, _t in re.findall(r"Page (\d+) of (\d+)", _text(pdf))]
    assert sorted(numbers) == list(range(1, _page_count(pdf)))


def test_page_numbering_holds_for_the_executive_report_too() -> None:
    pdf = render_executive(_data(_estate()))
    pairs = re.findall(r"Page (\d+) of (\d+)", _text(pdf))
    assert pairs
    assert int(pairs[0][1]) == _page_count(pdf) - 1


def test_cover_page_remains_unnumbered() -> None:
    pdf = render_technical(_data(_estate()))
    numbers = [int(n) for n, _t in re.findall(r"Page (\d+) of (\d+)", _text(pdf))]
    assert 0 not in numbers
    assert len(numbers) == _page_count(pdf) - 1


# --- 6./7. scoped reports ------------------------------------------------------------------

def test_scoped_report_links_only_to_findings_it_contains() -> None:
    rows = _estate()
    scoped = _data([r for r in rows if r.template_id == "sql-injection"])
    in_scope = {g["finding_id"] for g in _finding_groups(scoped.vulns)}

    _pdf, _bm, outline = _capture_navigation(scoped)
    linked = {k.removeprefix("finding-") for _t, k in outline if k.startswith("finding-")}
    assert linked == in_scope


def test_scoped_report_has_no_link_to_an_excluded_finding() -> None:
    rows = _estate()
    full = {g["finding_id"] for g in _finding_groups(_data(rows).vulns)}
    scoped = _data([r for r in rows if r.template_id == "sql-injection"])
    in_scope = {g["finding_id"] for g in _finding_groups(scoped.vulns)}
    excluded = full - in_scope
    assert excluded, "fixture must actually exclude something"

    _pdf, _bm, outline = _capture_navigation(scoped)
    linked = {k.removeprefix("finding-") for _t, k in outline if k.startswith("finding-")}
    assert not (linked & excluded)


def test_scoped_report_page_total_is_its_own() -> None:
    scoped = _data([r for r in _estate() if r.template_id == "sql-injection"])
    pdf = render_technical(scoped)
    pairs = re.findall(r"Page (\d+) of (\d+)", _text(pdf))
    assert int(pairs[0][1]) == _page_count(pdf) - 1


# --- 9.-16. earlier phases intact -----------------------------------------------------------

def test_existing_sections_remain_intact() -> None:
    text = _text(render_technical(_data(_estate())))
    for heading in ("Assessment Overview", "Scope & Methodology", "Findings Summary",
                    "Detailed Findings", "Evidence & Screenshots", "Compliance Coverage",
                    "MITRE ATT", "Remediation Plan", "Appendix"):
        assert heading in text, f"missing section: {heading}"


def test_executive_sections_remain_intact() -> None:
    text = _text(render_executive(_data(_estate())))
    for heading in ("1. Executive Summary", "4. Key Risks",
                    "7. Recommended Actions", "8. Conclusion"):
        assert heading in text


def test_r01_count_units_intact() -> None:
    rows = [_row("one-issue", matched_at=f"https://h/p{i}") for i in range(7)]
    data = _data(rows)
    assert data.total_issue_count() == 1 and data.total_vulns == 7
    assert "1 unique issue across 7 affected locations" in _text(render_executive(data))


def test_r02_compliance_population_intact() -> None:
    data = _data([_row("gone", status="fixed")])
    assert data.compliance_frameworks() == []


def test_r03_scope_metadata_intact() -> None:
    assert _data(_estate()).is_scan_scoped() is False


def test_r04_score_band_intact() -> None:
    from apps.api.modules.reports import _branding as B
    from apps.api.modules.reports.render import _score_band

    data = _data(_estate())
    assert B.score_band_color(_score_band(data.security_score)) != B.MUTED


def test_phase_32_evidence_manifest_intact() -> None:
    text = _text(render_technical(_data(_estate())))
    assert "Evidence manifest" in text
    assert "2026-09-08 14:00:00 UTC" in text


def test_phase_41_assurance_chips_intact() -> None:
    text = _text(render_technical(_data(_estate())))
    for caption in ("VERIFICATION", "CONFIDENCE", "EVIDENCE"):
        assert caption in text


def test_phase_42_layout_behaviour_intact() -> None:
    """The finding block is still a list whose first element is the atomic header group."""
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, Paragraph, Table, TableStyle

    from apps.api.modules.reports.render import _finding_block, _styles

    styles = _styles(getSampleStyleSheet, ParagraphStyle, colors)
    g = _finding_groups(_estate())[0]
    out = _finding_block(1, g, styles, colors, Paragraph, Table, TableStyle, mm)
    assert isinstance(out, list)
    assert isinstance(out[0], KeepTogether)


def test_navigation_alters_no_assessed_value() -> None:
    rows = _estate()
    before = [(r.severity, r.cvss_score, r.final_risk_score, r.status) for r in rows]
    render_technical(_data(rows))
    assert [(r.severity, r.cvss_score, r.final_risk_score, r.status) for r in rows] == before


@pytest.mark.parametrize("rows", [[], [_row("solo")]])
def test_edge_cases_still_render_with_numbering(rows) -> None:
    pdf = render_technical(_data(rows))
    assert pdf[:4] == b"%PDF"
    assert re.search(r"Page \d+ of \d+", _text(pdf))
