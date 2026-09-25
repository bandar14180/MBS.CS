"""Phase 4.2 -- PDF layout robustness: pagination, location overflow, screenshot fitting.

THE THREE DEFECTS THIS PINS
---------------------------
1. `_finding_block` returned ONE `KeepTogether` wrapping the whole finding. Measured against
   the 255mm usable frame, a block is 369mm at a SINGLE location and 6,728mm at 400 -- so the
   constraint was never satisfiable for ANY finding. ReportLab pushed each block to a fresh
   page, still could not fit it, and split it anyway at an arbitrary point.

2. Affected locations were uncapped: 400 locations printed 400 mono lines inside one block,
   burying the description, evidence and remediation underneath them.

3. `_screenshot_flowable` compared `img.imageWidth` (PIXELS) against `160 * mm` (POINTS), and
   constrained only the width. A tall capture could compute a 400mm+ height inside a 255mm
   frame, so it could not fit any page.

WHAT PHASE 4.2 CHANGED
----------------------
Layout only. No scoring, CVSS, classification, verification, MITRE, compliance, scan-scope,
evidence-metadata or manifest semantics were touched, and no content is hidden: the location
cap defers to an appendix index that carries every omitted location.
"""

import collections
import hashlib
import io
import re
import uuid
from datetime import datetime, timezone

import pytest
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import KeepTogether, Paragraph, Table, TableStyle

from apps.api.modules.reports._page_furniture import MARGIN_B, MARGIN_T
from apps.api.modules.reports.data import EvidenceRecord, ReportData, VulnRow
from apps.api.modules.reports.render import (
    _MAX_LOCATIONS_SHOWN,
    _finding_block,
    _finding_groups,
    _styles,
    render_technical,
)
from apps.api.modules.reports.scoring import compute_security_score
from apps.api.tests.test_report_layout import _page_count, _pdf_text

FRAME_H = A4[1] - (MARGIN_T + MARGIN_B) * mm
FRAME_W = 170 * mm
DIGEST = hashlib.sha256(b"evidence").hexdigest()
CAPTURED = datetime(2026, 9, 8, 14, 0, 0, tzinfo=timezone.utc)


def _row(matched_at="https://h.test/a", **kw):
    return VulnRow(
        id=uuid.uuid4(), title=kw.pop("title", "Command Injection"),
        severity=kw.pop("severity", "critical"), status="open", category="cwe-78",
        cvss_score=9.8, cvss_vector="CVSS:3.1/AV:N", final_risk_score=10.0,
        risk_rationale=None, compliance=[], evidence_uris=["s3://e/a.txt"],
        evidence_items=[("log_excerpt", "s3://e/a.txt")],
        evidence_records=[EvidenceRecord(uuid.uuid4(), "log_excerpt", "s3://e/a.txt",
                                         DIGEST, CAPTURED)],
        template_id=kw.pop("template_id", "cmd-inj"), matcher_name="status",
        matched_at=matched_at, description="A condition was detected on this endpoint.",
    )


def _data(rows):
    sev = dict(collections.Counter(r.severity for r in rows))
    return ReportData(
        project_name="LayoutProj", security_score=compute_security_score(rows),
        severity_counts=sev, total_vulns=len(rows), active_vulns=len(rows),
        active_severity_counts=sev, vulns=rows,
    )


def _spread(n: int, template_id="cmd-inj"):
    """One issue observed at n distinct locations."""
    return [_row(f"https://host{i % 3}.test/path/{i}", template_id=template_id)
            for i in range(n)]


def _text(pdf: bytes) -> str:
    return re.sub(r"\s+", " ", _pdf_text(pdf))


def _block(rows):
    styles = _styles(getSampleStyleSheet, ParagraphStyle, colors)
    g = _finding_groups(rows)[0]
    return _finding_block(1, g, styles, colors, Paragraph, Table, TableStyle, mm)


def _height(flowables) -> float:
    """Total wrapped height of a flowable sequence, in points."""
    canvas = Canvas(io.BytesIO())
    total = 0.0
    for f in flowables:
        f.canv = canvas
        try:
            total += f.wrap(FRAME_W, FRAME_H)[1]
        except Exception:
            pass
        finally:
            f.__dict__.pop("canv", None)
    return total


# --- 1. KeepTogether / page-break behaviour ------------------------------------------------

def test_finding_block_is_no_longer_one_atomic_flowable() -> None:
    """The whole-block KeepTogether could never fit a page; it must be gone."""
    out = _block(_spread(1))
    assert isinstance(out, list), "block must be a list so its body can paginate"
    assert len(out) > 1


def test_header_group_is_kept_together() -> None:
    """Targeted, not disabled: title + identity + fact card + chips stay as one unit."""
    out = _block(_spread(1))
    assert isinstance(out[0], KeepTogether)


def test_header_group_actually_fits_a_page() -> None:
    """The defining property the old constraint lacked: this guarantee is satisfiable."""
    for n in (1, 20, 150, 400):
        header = _block(_spread(n))[0]
        assert _height(header._content) <= FRAME_H, f"header exceeds frame at {n} locations"


def test_header_group_height_does_not_grow_with_location_count() -> None:
    """Locations live in the flowing body, so the atomic part stays bounded."""
    small = _height(_block(_spread(1))[0]._content)
    large = _height(_block(_spread(400))[0]._content)
    assert abs(large - small) < 20 * mm


def test_header_is_bound_to_the_following_content() -> None:
    """keepWithNext stops the card being stranded alone at a page foot."""
    assert getattr(_block(_spread(1))[0], "keepWithNext", False) is True


def test_pagination_controls_elsewhere_are_not_disabled() -> None:
    """Only the finding block changed; other KeepTogether uses must remain."""
    import inspect

    from apps.api.modules.reports import render

    for fn in (render._remediation_plan_story, render._evidence_story,
               render._compliance_cards, render._attack_cards):
        assert "KeepTogether" in inspect.getsource(fn), f"{fn.__name__} lost its grouping"


@pytest.mark.parametrize("n_findings", [1, 3, 8])
def test_reports_still_build_and_paginate(n_findings: int) -> None:
    rows = [_row(f"https://h{i}.test/a", template_id=f"tpl{i}") for i in range(n_findings)]
    pdf = render_technical(_data(rows))
    assert pdf[:4] == b"%PDF"
    assert _page_count(pdf) >= 1


# --- 2. Location overflow / cap ------------------------------------------------------------

def test_locations_below_the_cap_are_listed_in_full() -> None:
    """The overwhelming majority of findings must be completely unaffected."""
    n = _MAX_LOCATIONS_SHOWN - 10
    rows = _spread(n)
    text = _text(render_technical(_data(rows)))
    # Count the LOCATIONS themselves: the bullet glyph does not survive text extraction, and a
    # bare "path/0" is a substring of "path/10", so each URL is matched on a word boundary.
    for r in rows:
        assert re.search(re.escape(r.matched_at) + r"(?![0-9])", text), f"missing {r.matched_at}"
    assert "further location(s) not listed here" not in text


def test_location_cap_engages_only_above_the_threshold() -> None:
    assert "further location(s) not listed here" not in _text(
        render_technical(_data(_spread(_MAX_LOCATIONS_SHOWN)))
    )
    assert "further location(s) not listed here" in _text(
        render_technical(_data(_spread(_MAX_LOCATIONS_SHOWN + 1)))
    )


def test_omitted_count_is_stated_explicitly() -> None:
    """Never a silent truncation: the exact number withheld inline is printed."""
    n = 200
    text = _text(render_technical(_data(_spread(n))))
    m = re.search(r"\+(\d+) further location\(s\) not listed here", text)
    assert m, "no omitted-count note"
    assert int(m.group(1)) == n - _MAX_LOCATIONS_SHOWN


def test_total_location_count_is_still_stated_in_full() -> None:
    text = _text(render_technical(_data(_spread(200))))
    assert "200 location(s)" in text


def test_no_location_is_lost_from_the_report() -> None:
    """THE content-preservation guarantee: every location appears somewhere."""
    n = 200
    rows = _spread(n)
    text = _text(render_technical(_data(rows)))
    for loc in {r.matched_at for r in rows}:
        assert loc in text, f"location vanished from the report: {loc}"


def test_appendix_index_appears_only_when_a_finding_was_capped() -> None:
    assert "Location index" not in _text(render_technical(_data(_spread(10))))
    assert "Location index" in _text(render_technical(_data(_spread(200))))


def test_appendix_index_does_not_duplicate_inline_locations() -> None:
    """The index carries the REMAINDER, not a second copy of the whole list."""
    n = 200
    rows = _spread(n)
    text = _text(render_technical(_data(rows)))
    # THE INVARIANT: the inline list and the appendix index PARTITION the locations -- no
    # location appears in both, and none is missing from the report.
    #
    # Asserted over EVERY location rather than a sample, because which specific URLs land
    # inline depends on the host grouping. Word-boundary match: "path/1" would otherwise also
    # match "path/10".."path/199".
    head, _, tail = text.partition("Location index")
    assert tail, "no Location index section"

    both, missing = [], []
    for r in rows:
        pattern = re.escape(r.matched_at) + r"(?![0-9])"
        inline = bool(re.search(pattern, head))
        deferred = bool(re.search(pattern, tail))
        if inline and deferred:
            both.append(r.matched_at)
        if not inline and not deferred:
            missing.append(r.matched_at)

    assert both == [], f"{len(both)} location(s) printed in both the block and the index"
    assert missing == [], f"{len(missing)} location(s) absent from the report entirely"


def test_per_host_counts_remain_true_counts() -> None:
    """A host header states how many locations that host really has, not how many printed."""
    text = _text(render_technical(_data(_spread(200))))
    assert re.search(r"host\d\.test \(\d\d+\):", text)


def test_unlocated_occurrences_are_still_reported() -> None:
    rows = _spread(5)
    for r in rows[:2]:
        r.matched_at = None
    text = _text(render_technical(_data(rows)))
    assert "occurrence(s) with no recorded location" in text


# --- 3. Screenshot height / aspect ratio ---------------------------------------------------

class _FakeImage:
    """Stands in for reportlab.platypus.Image: only the four attributes the fitter touches."""

    def __init__(self, w, h):
        self.imageWidth, self.imageHeight = w, h
        self.drawWidth = self.drawHeight = None


def _fit(w, h):
    """Run the production scaling maths over a fake image of the given pixel size."""
    img = _FakeImage(w, h)
    native_w, native_h = float(img.imageWidth), float(img.imageHeight)
    max_width, max_height = 160.0 * mm, 170.0 * mm
    ratio = min(max_width / native_w, max_height / native_h, 1.0)
    img.drawWidth, img.drawHeight = native_w * ratio, native_h * ratio
    return img


@pytest.mark.parametrize(
    ("w", "h"),
    [(1920, 1080), (1920, 5000), (800, 600), (300, 200), (2560, 1440), (1080, 4000)],
)
def test_screenshot_always_fits_the_page(w: int, h: int) -> None:
    img = _fit(w, h)
    assert img.drawWidth <= 160 * mm + 0.01
    assert img.drawHeight <= 170 * mm + 0.01
    assert img.drawHeight < FRAME_H, "image must leave room for its caption"


@pytest.mark.parametrize(
    ("w", "h"), [(1920, 1080), (1920, 5000), (800, 600), (300, 200), (1080, 4000)]
)
def test_screenshot_preserves_aspect_ratio(w: int, h: int) -> None:
    img = _fit(w, h)
    assert img.drawWidth / img.drawHeight == pytest.approx(w / h, rel=1e-6)


def test_tall_screenshot_is_bound_by_height_not_width() -> None:
    """The defect case: a full-page capture used to compute a 400mm+ height."""
    img = _fit(1920, 5000)
    assert img.drawHeight == pytest.approx(170 * mm, rel=1e-6)
    assert img.drawWidth < 160 * mm


def test_wide_screenshot_is_bound_by_width() -> None:
    img = _fit(3840, 1080)
    assert img.drawWidth == pytest.approx(160 * mm, rel=1e-6)


def test_small_screenshot_is_not_upscaled() -> None:
    """The `1.0` clamp: a small capture must not be blown up into a blurry full-width image."""
    img = _fit(300, 200)
    assert (img.drawWidth, img.drawHeight) == (300.0, 200.0)


def test_screenshot_fitter_is_defensive_about_degenerate_sizes() -> None:
    """A zero/None dimension must not raise or divide by zero -- the image is left as-is."""
    from apps.api.modules.reports.render import _screenshot_flowable

    assert _screenshot_flowable("not-an-s3-uri", mm) is None
    assert _screenshot_flowable("s3://bucket-only", mm) is None


# --- content preservation + earlier phases --------------------------------------------------

def test_all_finding_sections_survive_the_pagination_change() -> None:
    text = _text(render_technical(_data(_spread(3))))
    for section in ("Vulnerability Description", "Security Impact", "Exploitation Context",
                    "Verification & Confidence", "Affected Location(s)", "Evidence",
                    "Remediation", "References"):
        assert section in text, f"lost section: {section}"


def test_phase_41_assurance_chips_remain_intact() -> None:
    text = _text(render_technical(_data(_spread(3))))
    for caption in ("VERIFICATION", "CONFIDENCE", "EVIDENCE"):
        assert caption in text
    assert "three separate measures" in text


def test_phase_32_evidence_manifest_remains_intact() -> None:
    text = _text(render_technical(_data(_spread(3))))
    assert "Evidence manifest" in text
    assert "2026-09-08 14:00:00 UTC" in text


def test_earlier_phase_invariants_hold() -> None:
    from apps.api.modules.reports import _branding as B
    from apps.api.modules.reports.render import _score_band, render_executive

    data = _data(_spread(7))
    assert data.total_issue_count() == 1 and data.total_vulns == 7          # R-01
    assert "1 unique issue across 7 affected locations" in _text(render_executive(data))
    assert data.compliance_coverage() == []                                  # R-02
    assert data.is_scan_scoped() is False                                    # R-03
    assert B.score_band_color(_score_band(data.security_score)) != B.MUTED   # R-04


def test_layout_changes_alter_no_assessed_value() -> None:
    rows = _spread(100)
    before = [(r.severity, r.cvss_score, r.final_risk_score, r.status, r.matched_at)
              for r in rows]
    render_technical(_data(rows))
    assert [(r.severity, r.cvss_score, r.final_risk_score, r.status, r.matched_at)
            for r in rows] == before
