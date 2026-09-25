import uuid

import pytest

from apps.api.modules.reports import render
from apps.api.modules.reports.data import (
    ReportData,
    VulnRow,
    _parse_fingerprint,
    compute_security_score,
)
from apps.api.modules.reports.render import _findings_summary


# --- Security score (pure) ---
# compute_security_score now takes FINDINGS, not severity counts: the score is computed
# over distinct underlying issues rather than per-row severity tallies. The model itself
# is exercised in test_security_score.py; these keep the report-layer contract honest.

def _row(severity: str, status: str = "open", template_id: str = "tpl", matched_at: str = "u", **kw) -> VulnRow:
    """A minimal VulnRow, to confirm the scorer reads the report's own row type."""
    return VulnRow(
        id=uuid.uuid4(),
        title=kw.pop("title", f"{severity} finding"),
        severity=severity,
        status=status,
        category=None,
        cvss_score=kw.pop("cvss_score", None),
        cvss_vector=None,
        final_risk_score=kw.pop("final_risk_score", None),
        risk_rationale=None,
        compliance=[],
        evidence_uris=[],
        template_id=template_id,
        matched_at=matched_at,
    )


def test_score_perfect_when_no_active() -> None:
    assert compute_security_score([]) == 100
    assert compute_security_score([_row("critical", status="fixed")]) == 100


def test_score_penalizes_by_severity() -> None:
    """Ordering, not magic numbers: higher severity => lower score."""
    critical = compute_security_score([_row("critical", template_id="c")])
    high = compute_security_score([_row("high", template_id="h")])
    medium = compute_security_score([_row("medium", template_id="m")])
    low = compute_security_score([_row("low", template_id="l")])
    assert critical < high < medium < low < 100


def test_score_ignores_informational_findings() -> None:
    assert compute_security_score([_row("info", template_id=f"i{i}") for i in range(5)]) == 100


def test_score_groups_one_issue_across_many_endpoints() -> None:
    """Regression for the old per-row model: 10 endpoints of one issue is not 10 issues."""
    spread = compute_security_score(
        [_row("high", template_id="same", matched_at=f"u{i}") for i in range(10)]
    )
    distinct = compute_security_score(
        [_row("high", template_id=f"t{i}", matched_at="u") for i in range(10)]
    )
    assert spread > distinct
    assert spread > 0  # breadth alone can never floor the score


def test_score_stays_within_bounds() -> None:
    score = compute_security_score(
        [_row("critical", template_id=f"t{i}", cvss_score=10.0, final_risk_score=10.0) for i in range(100)]
    )
    assert 0 <= score <= 100


# --- PDF rendering (needs reportlab; smoke that output is a valid PDF) ---

def _sample_data(n_vulns: int = 2) -> ReportData:
    vulns = [
        VulnRow(
            id=uuid.uuid4(),
            title=f"Finding {i}",
            severity="high" if i == 0 else "medium",
            status="open",
            category="cwe-693",
            cvss_score=7.5 if i == 0 else 5.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L",
            final_risk_score=9.0 if i == 0 else 5.0,
            risk_rationale="CVSS x criticality",
            compliance=[("owasp", "A05:2021", "Security Misconfiguration")],
            evidence_uris=[f"s3://mbs-evidence/tool-runs/{uuid.uuid4()}/raw-output.txt"],
        )
        for i in range(n_vulns)
    ]
    return ReportData(
        project_name="Acme <Test> Project",  # ampersand/angle-bracket to exercise escaping
        security_score=71,
        severity_counts={"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
        total_vulns=n_vulns,
        active_vulns=n_vulns,
        vulns=vulns,
    )


def test_executive_report_is_pdf() -> None:
    out = render.render("executive", _sample_data())
    assert out[:5] == b"%PDF-"
    assert len(out) > 800


def test_executive_report_renders_attack_graph_section() -> None:
    # M4.4.6: the report renders the autonomous attack-graph section when an agent
    # engagement exists, including confirmed access. The default (empty attack_graph)
    # is exercised by test_executive_report_is_pdf -> proves fail-soft/back-compat.
    data = _sample_data()
    data.attack_graph = {
        "has_data": True,
        "engagement_count": 1,
        "node_counts": {"asset": 1, "service": 1, "finding": 1, "technique": 1, "access": 1},
        "confirmed_access": [{"target": "203.0.113.7", "access_state": "access_obtained", "module": "known_cve"}],
    }
    out = render.render("executive", data)
    assert out[:5] == b"%PDF-"
    # A larger document than the same report without the populated section.
    assert len(out) > len(render.render("executive", _sample_data()))


def test_technical_report_is_pdf() -> None:
    out = render.render("technical", _sample_data(3))
    assert out[:5] == b"%PDF-"


def test_technical_report_handles_no_findings() -> None:
    empty = ReportData(
        project_name="Empty", security_score=100,
        severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        total_vulns=0, active_vulns=0, vulns=[],
    )
    assert render.render("technical", empty)[:5] == b"%PDF-"


def test_unknown_report_type_raises() -> None:
    with pytest.raises(ValueError):
        render.render("marketing", _sample_data())


# --- Phase 1: finding location (template / matcher / matched_at) in the report ------------
# The report must distinguish findings that share a title/severity/evidence but hit different
# URLs -- the nuclei-dast case where one template fires on many fuzzed URLs. matched_at is
# recovered from the EXISTING fingerprint (no schema change), and the fingerprint's LAST field
# can itself contain '|' (an injection payload like `?lang=|dir`), so parsing must not split it.


def test_parse_fingerprint_extracts_the_three_parts():
    assert _parse_fingerprint("template-id|matcher-name|https://example.com/test?id=1") == (
        "template-id", "matcher-name", "https://example.com/test?id=1"
    )


def test_parse_fingerprint_keeps_a_pipe_inside_the_matched_at_url():
    # Real fingerprint: the payload puts a '|' in the URL. matched_at must stay whole.
    fp = "windows-command-injection|time-based|https://h.example.com/?lang=|dir"
    assert _parse_fingerprint(fp) == (
        "windows-command-injection", "time-based", "https://h.example.com/?lang=|dir"
    )
    # even multiple pipes in the URL survive
    assert _parse_fingerprint("t|m|https://h/?a=|b|c")[2] == "https://h/?a=|b|c"


def test_parse_fingerprint_is_defensive_on_missing_or_malformed_input():
    assert _parse_fingerprint(None) == (None, None, None)
    assert _parse_fingerprint("") == (None, None, None)
    assert _parse_fingerprint("just-a-hash") == ("just-a-hash", None, None)      # no pipes
    assert _parse_fingerprint("template|matcher") == ("template", "matcher", None)  # no url
    # trailing-empty segments become None, not "" -> renderer shows N/A
    assert _parse_fingerprint("template||") == ("template", None, None)


def _finding_block_text(v: VulnRow) -> str:
    """Extract the rendered TEXT of a finding's report block (not just 'is it a PDF').

    Calls the real `render._finding_block` with the same reportlab objects the renderer uses,
    then walks the returned KeepTogether's flowables pulling each Paragraph's plain text. No
    PDF-text-extraction dependency (none is installed) and NO production change -- it asserts
    the exact strings the report will draw. The project has no pypdf/pdfminer, and reportlab
    compresses its content streams, so searching the PDF bytes would not work."""
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Table, TableStyle

    styles = render._styles(getSampleStyleSheet, ParagraphStyle, colors)
    # _finding_block now takes a GROUP (one vulnerability, many locations), so build the
    # group the same way the renderer does rather than passing the row straight through.
    (group,) = render._finding_groups([v])
    block = render._finding_block(1, group, styles, colors, Paragraph, Table, TableStyle, mm)

    texts: list[str] = []

    def _collect(node, sink: list[str]):
        """Append a flowable's plain text (recursing into nested cards) into `sink`."""
        if node is None:
            return
        content = getattr(node, "_content", None)
        if content is not None:
            for child in content:
                _collect(child, sink)
            return
        cells = getattr(node, "_cellvalues", None)
        if cells is not None:
            for row in cells:
                for cell in row:
                    _collect(cell, sink)
            return
        if hasattr(node, "getPlainText"):
            sink.append(node.getPlainText())
        elif isinstance(node, str):
            sink.append(node)

    def _walk(flowable):
        content = getattr(flowable, "_content", None)
        if content is not None:
            for child in content:
                _walk(child)
            return
        # Finding metadata is now laid out in label/value CARDS (Tables) rather than a run of
        # loose Paragraphs, so the walk must descend into table cells too -- otherwise this
        # helper silently returns less text than the block actually renders and every
        # assertion built on it becomes vacuous.
        cellvalues = getattr(flowable, "_cellvalues", None)
        if cellvalues is not None:
            for row in cellvalues:
                # A card row is (label, value). Re-joined as "Label: value" so the text reads
                # the way it did when these facts were loose Paragraphs -- the layout changed,
                # the content did not, and existing assertions stay meaningful.
                cells = []
                for cell in row:
                    sub: list[str] = []
                    if isinstance(cell, (list, tuple)):
                        for item in cell:
                            _collect(item, sub)
                    else:
                        _collect(cell, sub)
                    cells.append(" ".join(x for x in sub if x))
                cells = [c for c in cells if c]
                if len(cells) == 2:
                    texts.append(f"{cells[0]}: {cells[1]}")
                elif cells:
                    texts.append(" ".join(cells))
            return
        if hasattr(flowable, "getPlainText"):
            texts.append(flowable.getPlainText())

    # Phase 4.2: _finding_block returns a LIST (an atomic header group + flowing body) rather
    # than one oversized KeepTogether that could never fit a page. Walk each top-level flowable.
    for _flowable in (block if isinstance(block, list) else [block]):
        _walk(_flowable)
    return "\n".join(texts)


def _group_block_text(group: dict) -> str:
    """Rendered text of one GROUPED finding block (see _finding_block_text)."""
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Table, TableStyle

    styles = render._styles(getSampleStyleSheet, ParagraphStyle, colors)
    block = render._finding_block(1, group, styles, colors, Paragraph, Table, TableStyle, mm)

    texts: list[str] = []

    def _collect(node, sink: list[str]):
        """Append a flowable's plain text (recursing into nested cards) into `sink`."""
        if node is None:
            return
        content = getattr(node, "_content", None)
        if content is not None:
            for child in content:
                _collect(child, sink)
            return
        cells = getattr(node, "_cellvalues", None)
        if cells is not None:
            for row in cells:
                for cell in row:
                    _collect(cell, sink)
            return
        if hasattr(node, "getPlainText"):
            sink.append(node.getPlainText())
        elif isinstance(node, str):
            sink.append(node)

    def _walk(flowable):
        content = getattr(flowable, "_content", None)
        if content is not None:
            for child in content:
                _walk(child)
            return
        # Metadata is laid out in label/value CARDS (Tables); re-joined as "Label: value" so
        # this helper reports what the block renders rather than silently dropping the card.
        cellvalues = getattr(flowable, "_cellvalues", None)
        if cellvalues is not None:
            for row in cellvalues:
                cells = []
                for cell in row:
                    sub: list[str] = []
                    _collect(cell, sub)
                    cells.append(" ".join(x for x in sub if x))
                cells = [c for c in cells if c]
                if len(cells) == 2:
                    texts.append(f"{cells[0]}: {cells[1]}")
                elif cells:
                    texts.append(" ".join(cells))
            return
        text = getattr(flowable, "text", None)
        if text is not None:
            texts.append(str(text))

    # Phase 4.2: _finding_block returns a LIST (an atomic header group + flowing body) rather
    # than one oversized KeepTogether that could never fit a page. Walk each top-level flowable.
    for _flowable in (block if isinstance(block, list) else [block]):
        _walk(_flowable)
    return "\n".join(texts)


def _vuln_row_with_fingerprint(fp: str, **over):
    """A VulnRow whose location fields are parsed from `fp`, mirroring build_report_data."""
    tid, matcher, matched = _parse_fingerprint(fp)
    base = dict(
        id=uuid.uuid4(), title="Unix Command Injection - Generic Detection", severity="high",
        status="open", category="cwe-77", cvss_score=9.8, cvss_vector=None,
        final_risk_score=10.0, risk_rationale=None, compliance=[], evidence_uris=[],
        template_id=tid, matcher_name=matcher, matched_at=matched,
    )
    base.update(over)
    return VulnRow(**base)


def test_vuln_row_carries_the_extracted_location():
    row = _vuln_row_with_fingerprint("unix-command-injection|time-based|https://x/a?p=1")
    assert row.template_id == "unix-command-injection"
    assert row.matcher_name == "time-based"
    assert row.matched_at == "https://x/a?p=1"


def test_technical_report_shows_template_matcher_matched_at_and_status():
    row = _vuln_row_with_fingerprint("unix-command-injection|time-based|https://x/a?p=1")
    text = _finding_block_text(row)
    # The four Phase-1 lines are rendered with their real values.
    assert "Template: unix-command-injection" in text
    assert "Matcher: time-based" in text
    # One location -> listed under "Affected Location(s)", still showing the full URL.
    assert "Affected Location(s)" in text and "1 location(s):" in text
    assert "https://x/a?p=1" in text
    assert "Status: open" in text
    # And the whole report still renders to a valid PDF.
    data = ReportData(
        project_name="P", security_score=0,
        severity_counts={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        total_vulns=1, active_vulns=1, vulns=[row],
    )
    assert render.render("technical", data)[:5] == b"%PDF-"


def test_two_locations_of_one_vulnerability_are_one_block_listing_both_urls():
    """Two rows sharing title/severity/template/matcher but DIFFERENT URLs are ONE
    vulnerability observed twice -- a single block listing both locations, not two blocks."""
    a = _vuln_row_with_fingerprint("unix-command-injection|time-based|https://x/a?p=1")
    b = _vuln_row_with_fingerprint("unix-command-injection|time-based|https://x/b?p=2")
    # Same on every axis except the URL.
    assert (a.title, a.severity, a.template_id, a.matcher_name) == \
           (b.title, b.severity, b.template_id, b.matcher_name)
    assert a.matched_at != b.matched_at

    groups = render._finding_groups([a, b])
    assert len(groups) == 1, "same template at two URLs must be ONE finding"
    text = _group_block_text(groups[0])
    # The single block lists BOTH urls, and the shared metadata appears only once.
    assert "Affected Location(s)" in text and "2 location(s):" in text
    assert "https://x/a?p=1" in text and "https://x/b?p=2" in text
    assert text.count("Template: unix-command-injection") == 1

    data = ReportData(
        project_name="P", security_score=0,
        severity_counts={"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0},
        total_vulns=2, active_vulns=2, vulns=[a, b],
    )
    assert render.render("technical", data)[:5] == b"%PDF-"


def test_report_matched_at_keeps_a_pipe_url_whole_not_just_the_payload():
    """The incident fingerprint has a '|' in the URL. The report must show the FULL URL,
    never the trailing 'dir' the payload ends with."""
    fp = ("windows-command-injection|time-based|"
          "https://universities.brightvision-og.com/university/nilai-university/?lang=|dir")
    row = _vuln_row_with_fingerprint(fp)
    text = _finding_block_text(row)
    assert ("https://universities.brightvision-og.com/university/"
            "nilai-university/?lang=|dir") in text
    assert "• dir" not in text                    # never the mangled tail alone
    assert "Template: windows-command-injection" in text
    assert "Matcher: time-based" in text


def test_report_renders_na_when_location_is_unavailable():
    """A finding with no parseable fingerprint (older/non-nuclei) must render N/A, not crash."""
    row = _vuln_row_with_fingerprint("legacy-hash-only")   # -> matcher/matched None
    assert row.matcher_name is None and row.matched_at is None
    text = _finding_block_text(row)
    assert "Template: legacy-hash-only" in text    # the one part it could recover
    assert "Matcher: N/A" in text
    assert "No specific location was recorded" in text
    data = ReportData(
        project_name="P", security_score=85,
        severity_counts={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        total_vulns=1, active_vulns=1, vulns=[row],
    )
    assert render.render("technical", data)[:5] == b"%PDF-"


def test_report_renders_na_for_a_completely_empty_fingerprint():
    """None/empty fingerprint -> all three N/A, no crash (backward compatibility)."""
    for fp in ("", None):
        tid, matcher, matched = _parse_fingerprint(fp)
        row = VulnRow(
            id=uuid.uuid4(), title="Legacy", severity="low", status="open", category=None,
            cvss_score=None, cvss_vector=None, final_risk_score=None, risk_rationale=None,
            compliance=[], evidence_uris=[],
            template_id=tid, matcher_name=matcher, matched_at=matched,
        )
        text = _finding_block_text(row)
        assert "Template: N/A" in text
        assert "Matcher: N/A" in text
        assert "No specific location was recorded" in text


# --- P0 #1: CVSS 0.0 vs N/A must stay distinguishable in the report -----------------------
# A genuine CVSS of 0.0 is a real score and must render its value; a missing score (None)
# must render "N/A". Truthiness logic (`x or 0.0`, `if not x`) would wrongly collapse
# 0.0 into a fallback -- these pin the explicit-None behaviour instead. Reuses the existing
# _finding_block_text / _vuln_row_with_fingerprint helpers (no PDF-text dependency).
#
# The fact card states the score once as "CVSS: <score> (<band>)" -- the value and its CVSS
# v3.1 band together -- so 0.0 reads "CVSS: 0.0 (None)" and a missing score "CVSS: N/A". The
# INVARIANT under test is unchanged: the two must never be rendered alike.

_FP = "unix-command-injection|time-based|https://x/a?p=1"


def test_genuine_zero_cvss_renders_as_0_not_na():
    text = _finding_block_text(_vuln_row_with_fingerprint(_FP, cvss_score=0.0))
    assert "CVSS: 0.0" in text
    assert "CVSS: N/A" not in text         # 0.0 must NOT be shown as missing


def test_missing_cvss_renders_as_na_not_zero():
    text = _finding_block_text(_vuln_row_with_fingerprint(_FP, cvss_score=None))
    assert "CVSS: N/A" in text
    assert "CVSS: 0.0" not in text         # missing must NOT be shown as 0.0


def test_normal_cvss_still_renders_its_value():
    text = _finding_block_text(_vuln_row_with_fingerprint(_FP, cvss_score=9.8))
    assert "CVSS: 9.8" in text


def test_zero_and_none_are_distinguishable_in_the_same_report():
    a = _vuln_row_with_fingerprint("t|m|https://x/zero", cvss_score=0.0)
    b = _vuln_row_with_fingerprint("t|m|https://x/none", cvss_score=None)
    text_a = _finding_block_text(a)
    text_b = _finding_block_text(b)
    assert "CVSS: 0.0" in text_a and "CVSS: N/A" not in text_a
    assert "CVSS: N/A" in text_b and "CVSS: 0.0" not in text_b
    # And the full technical report still renders both together as a valid PDF.
    data = ReportData(
        project_name="P", security_score=0,
        severity_counts={"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0},
        total_vulns=2, active_vulns=2, vulns=[a, b],
    )
    assert render.render("technical", data)[:5] == b"%PDF-"


def test_data_layer_passes_cvss_through_without_defaulting():
    """build_report_data must not convert a stored 0.0 or None with `or 0.0`-style logic --
    VulnRow carries the exact value. (Data-layer guard, complementing the render tests.)"""
    assert VulnRow(
        id=uuid.uuid4(), title="T", severity="low", status="open", category=None,
        cvss_score=0.0, cvss_vector=None, final_risk_score=None, risk_rationale=None,
        compliance=[], evidence_uris=[],
    ).cvss_score == 0.0
    assert VulnRow(
        id=uuid.uuid4(), title="T", severity="low", status="open", category=None,
        cvss_score=None, cvss_vector=None, final_risk_score=None, risk_rationale=None,
        compliance=[], evidence_uris=[],
    ).cvss_score is None


# --- P0 #2: 100/100 with Info-only findings must not read as "0 findings" or "N vulns" ----
# Info findings carry zero score penalty (data._SEVERITY_PENALTY["info"] == 0), so 19 Info ->
# 100/100 is CORRECT scoring, not a bug. This is a report-CLARITY fix: the summary sentence
# must reconcile the score with the finding count. Tests assert the actual rendered summary
# (via the pure _findings_summary helper + the full report text), never touching the scoring.


def _exec_summary_text(data: ReportData) -> str:
    """Plain text of the Executive report's story flowables (dependency-free, like the Phase-1
    finding-block helper). Renders to a BytesIO doc while capturing the Paragraph texts."""
    import reportlab.platypus as platypus

    captured: list[str] = []

    def _grab(flowables):
        for f in flowables or ():
            if hasattr(f, "getPlainText"):
                captured.append(f.getPlainText())

    # The Executive report is built through BaseDocTemplate.multiBuild (a two-pass build is
    # required for real Table-of-Contents page numbers), while other reports still use
    # SimpleDocTemplate.build. BOTH are hooked so this helper captures the story regardless of
    # which build path a report uses -- hooking only one silently returned "" and made every
    # assertion below vacuous.
    orig_build = platypus.BaseDocTemplate.build
    orig_multi = platypus.BaseDocTemplate.multiBuild

    def _capture_build(self, flowables, *a, **k):
        _grab(flowables)
        return orig_build(self, flowables, *a, **k)

    def _capture_multi(self, flowables, *a, **k):
        _grab(flowables)
        return orig_multi(self, flowables, *a, **k)

    platypus.BaseDocTemplate.build = _capture_build
    platypus.BaseDocTemplate.multiBuild = _capture_multi
    try:
        render.render("executive", data)
    finally:
        platypus.BaseDocTemplate.build = orig_build
        platypus.BaseDocTemplate.multiBuild = orig_multi
    return "\n".join(captured)


def _info_only_report(score: int = 100, n_info: int = 19) -> ReportData:
    return ReportData(
        project_name="P", security_score=score,
        severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": n_info},
        total_vulns=n_info, active_vulns=n_info, vulns=[],
    )


# --- Case A: only Info findings ----------------------------------------------------------

def test_summary_for_info_only_explains_the_full_score():
    text = _findings_summary(_info_only_report(100, 19))
    assert "19 active findings" in text
    assert "informational" in text.lower()
    # explains WHY the score stays 100
    assert "do not reduce the security score" in text
    # must NOT call informational detections vulnerabilities
    assert "vulnerabilities found" not in text.lower()
    assert "19 vulnerabilities" not in text.lower()


def test_executive_report_text_reconciles_100_and_19_info_findings():
    text = _exec_summary_text(_info_only_report(100, 19))
    assert "100/100" in text
    assert "19 active finding" in text          # the count is still stated
    assert "informational" in text.lower()      # and clarified as informational
    assert "do not reduce the security score" in text
    # the misreading the P0 targets must not be present
    assert "19 vulnerabilities" not in text.lower()


# --- Case B: findings that actually affect the score -------------------------------------

def test_summary_with_real_penalty_does_not_call_everything_informational():
    data = ReportData(
        project_name="P", security_score=85,
        severity_counts={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 5},
        total_vulns=6, active_vulns=6, vulns=[],
    )
    text = _findings_summary(data)
    assert "all informational" not in text      # NOT all informational -- one high exists
    assert "1 is of low severity or higher" in text   # singular verb for exactly one
    assert "1 are of low severity or higher" not in text
    assert "reduce the security score" in text


def test_summary_non_info_verb_is_plural_for_more_than_one():
    data = ReportData(
        project_name="P", security_score=70,
        severity_counts={"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 5},
        total_vulns=7, active_vulns=7, vulns=[],
    )
    text = _findings_summary(data)
    assert "2 are of low severity or higher" in text   # plural verb for >1
    assert "2 is of low severity or higher" not in text


def test_summary_zero_active_findings():
    text = _findings_summary(_info_only_report(100, 0))
    assert "No active findings" in text


def test_summary_singular_vs_plural_wording():
    one = _findings_summary(ReportData(
        project_name="P", security_score=100,
        severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1},
        total_vulns=1, active_vulns=1, vulns=[],
    ))
    assert "1 active finding detected" in one    # singular
    many = _findings_summary(_info_only_report(100, 3))
    assert "3 active findings detected" in many   # plural


# --- Executive Top Risks: template-level presentation rollup ------------------------------
# Aggregates active/scored findings by template_id for the Executive report ONLY. Vulnerability
# identity / fingerprint / DB dedup are unchanged -- this groups already-persisted rows for
# display so one issue-type across many endpoints is one row (with an endpoint count), not a
# flood of look-alike rows. Tested against the pure render._top_risk_groups helper.
from apps.api.modules.reports.render import _top_risk_groups  # noqa: E402


def _tr_vuln(title, template_id, *, risk=10.0, cvss=9.8, severity="high", status="open",
             matched="https://h/x"):
    return VulnRow(
        id=uuid.uuid4(), title=title, severity=severity, status=status, category=None,
        cvss_score=cvss, cvss_vector=None, final_risk_score=risk, risk_rationale=None,
        compliance=[], evidence_uris=[], template_id=template_id, matcher_name="m",
        matched_at=matched,
    )


def test_top_risks_collapses_same_template_endpoints_into_one_row():
    """(1) Many endpoint-level findings sharing a template become ONE Top-Risk row."""
    vulns = [
        _tr_vuln("Unix Command Injection", "unix-command-injection", matched=f"https://h/{i}")
        for i in range(5)
    ]
    groups = _top_risk_groups(vulns)
    assert len(groups) == 1
    assert groups[0]["title"] == "Unix Command Injection"


def test_top_risks_endpoint_count_is_correct():
    """(2) The endpoint count equals the number of endpoint-level findings in the group."""
    vulns = [_tr_vuln("Unix CI", "unix-command-injection", matched=f"https://h/{i}") for i in range(7)]
    groups = _top_risk_groups(vulns)
    assert groups[0]["endpoint_count"] == 7


def test_top_risks_preserves_highest_risk_and_cvss_in_group():
    """(3) max_risk (and max CVSS) reflect the group's highest members, not the first seen.

    STRENGTHENED (P2-1): the original dataset put the highest risk and the highest CVSS on the
    SAME member, so it passed under either representative rule and could not detect the
    Executive/Technical disagreement. The rows below deliberately DECOUPLE them -- the
    max-risk member (10.0) has a mid CVSS, and the max-CVSS member (9.8) has a low risk --
    so max_risk and max_cvss can only both be right if each is a genuine per-field maximum."""
    vulns = [
        _tr_vuln("Unix CI", "unix-command-injection", risk=6.0, cvss=6.1),
        _tr_vuln("Unix CI", "unix-command-injection", risk=10.0, cvss=7.0),   # max risk
        _tr_vuln("Unix CI", "unix-command-injection", risk=2.0, cvss=9.8),    # max CVSS
    ]
    g = _top_risk_groups(vulns)[0]
    assert g["max_risk"] == 10.0
    assert g["max_cvss"] == 9.8
    assert g["endpoint_count"] == 3
    # ...and the Technical report must report the SAME issue-level risk.
    assert render._finding_groups(vulns)[0]["final_risk_score"] == 10.0


def test_top_risks_keeps_different_templates_separate():
    """(4) Distinct templates remain distinct rows -- never merged."""
    vulns = [
        _tr_vuln("Unix CI", "unix-command-injection"),
        _tr_vuln("Windows CI", "windows-command-injection"),
        _tr_vuln("SQLi", "time-based-sqli", risk=9.0, cvss=9.1),
    ]
    groups = _top_risk_groups(vulns)
    assert len(groups) == 3
    assert {g["title"] for g in groups} == {"Unix CI", "Windows CI", "SQLi"}


def test_top_risks_excludes_inactive_findings():
    """(5) fixed/accepted/false-positive findings never appear.

    UPDATED for P1-1: this test previously also asserted that an UNSCORED (risk=None) active
    finding is excluded. That was the defect -- a critical with no CVSS has no risk score, so
    it vanished from the executive view while still degrading the security score. Unscored
    ACTIVE findings are now expected to appear (as unscored); only non-active ones are
    filtered. The status filter itself is unchanged and still asserted here."""
    vulns = [
        _tr_vuln("Active", "t-active", status="open", risk=10.0),
        _tr_vuln("Fixed", "t-fixed", status="fixed", risk=10.0),
        _tr_vuln("Accepted", "t-accepted", status="accepted_risk", risk=10.0),
        _tr_vuln("FalsePos", "t-fp", status="false_positive", risk=10.0),
        _tr_vuln("Unscored", "t-unscored", status="open", risk=None),
    ]
    titles = {g["title"] for g in _top_risk_groups(vulns)}
    assert titles == {"Active", "Unscored"}
    # The unscored one is present but carries no fabricated risk value.
    unscored = next(g for g in _top_risk_groups(vulns) if g["title"] == "Unscored")
    assert unscored["max_risk"] is None


def test_top_risks_deterministic_ordering_by_risk_then_cvss_then_severity_then_title():
    """(6) Ordering is deterministic: max_risk DESC -> max_cvss DESC -> severity DESC -> title ASC."""
    vulns = [
        _tr_vuln("B-issue", "t-b", risk=10.0, cvss=9.8, severity="high"),
        _tr_vuln("A-issue", "t-a", risk=10.0, cvss=9.8, severity="high"),   # tie w/ B -> title ASC
        _tr_vuln("Mid", "t-mid", risk=10.0, cvss=7.0, severity="high"),      # same risk, lower cvss
        _tr_vuln("Low", "t-low", risk=5.0, cvss=9.9, severity="critical"),   # lower risk -> last
    ]
    order = [g["title"] for g in _top_risk_groups(vulns)]
    assert order == ["A-issue", "B-issue", "Mid", "Low"]
    # Stable across input permutations.
    assert [g["title"] for g in _top_risk_groups(list(reversed(vulns)))] == order


def test_top_risks_rollup_does_not_mutate_underlying_vuln_rows():
    """(7) Grouping is read-only: the input VulnRow objects/identity are untouched."""
    vulns = [_tr_vuln("Unix CI", "unix-command-injection", matched=f"https://h/{i}") for i in range(3)]
    before = [(v.id, v.template_id, v.matched_at, v.final_risk_score, v.status) for v in vulns]
    _top_risk_groups(vulns)
    after = [(v.id, v.template_id, v.matched_at, v.final_risk_score, v.status) for v in vulns]
    assert before == after
    assert len(vulns) == 3  # no collapse of the underlying rows -- only the display groups


def test_top_risks_null_template_falls_back_to_title_not_one_bucket():
    """A finding with no template_id keys on its own title, so unrelated null-template findings
    are NOT collapsed into a single bucket."""
    vulns = [
        _tr_vuln("Legacy A", None),
        _tr_vuln("Legacy B", None),
    ]
    groups = _top_risk_groups(vulns)
    assert len(groups) == 2
    assert {g["title"] for g in groups} == {"Legacy A", "Legacy B"}


# --- Technical Report finding grouping ----------------------------------------------------
# One block per VULNERABILITY (scoring.issue_key identity), not per (template|matcher|url) row.
# A row is one LOCATION, so the old per-row loop turned 21 issue types into 201 near-identical
# blocks on the real dataset. Grouping is presentation only: identity, fingerprints, DB dedup,
# matched_at parsing, the Security Score and the Executive Report are all unchanged.


def _g_row(template_id, matched_at, severity="high", cvss=9.8, **over):
    base = dict(
        id=uuid.uuid4(), title=f"{template_id} title", severity=severity, status="open",
        category="cwe-77", cvss_score=cvss, cvss_vector=None, final_risk_score=10.0,
        risk_rationale=None, compliance=[], evidence_uris=[],
        template_id=template_id, matcher_name="time-based", matched_at=matched_at,
    )
    base.update(over)
    return VulnRow(**base)


def test_same_template_many_locations_renders_one_finding():
    """1. Multiple rows sharing a template_id collapse into ONE technical finding."""
    rows = [_g_row("unix-command-injection", f"https://h/p{i}") for i in range(20)]
    groups = render._finding_groups(rows)
    assert len(groups) == 1
    assert groups[0]["occurrence_count"] == 20


def test_all_unique_locations_are_retained_under_the_finding():
    """2. No location is lost, and duplicates of the same URL collapse to one entry."""
    urls = [f"https://h/p{i}" for i in range(20)]
    rows = [_g_row("unix-command-injection", u) for u in urls]
    rows.append(_g_row("unix-command-injection", urls[0]))  # duplicate location
    (group,) = render._finding_groups(rows)
    assert group["matched_ats"] == sorted(set(urls))
    assert len(group["matched_ats"]) == 20
    assert group["occurrence_count"] == 21  # every row still counted
    text = _group_block_text(group)
    assert "Affected Location(s)" in text and "20 location(s)" in text
    for u in urls:
        assert u in text


def test_different_templates_remain_separate_findings():
    """3. Genuinely different vulnerabilities must NOT be merged."""
    rows = [
        _g_row("unix-command-injection", "https://h/a"),
        _g_row("windows-command-injection", "https://h/a"),
        _g_row("time-based-sqli", "https://h/a", severity="critical", cvss=9.5),
    ]
    groups = render._finding_groups(rows)
    assert len(groups) == 3
    assert {g["template_id"] for g in groups} == {
        "unix-command-injection", "windows-command-injection", "time-based-sqli"
    }


def test_severity_cvss_and_risk_are_not_incorrectly_merged():
    """4. The group header reports the WORST case, never a blend or an arbitrary member."""
    rows = [
        _g_row("t", "https://h/a", severity="low", cvss=2.0, final_risk_score=3.0),
        _g_row("t", "https://h/b", severity="critical", cvss=9.5, final_risk_score=10.0),
        _g_row("t", "https://h/c", severity="medium", cvss=5.0, final_risk_score=6.0),
    ]
    (group,) = render._finding_groups(rows)
    assert group["severity"] == "critical"
    assert group["cvss_score"] == 9.5
    assert group["final_risk_score"] == 10.0
    text = _group_block_text(group)
    assert "CRITICAL" in text and "CVSS: 9.5" in text


def test_single_location_finding_still_renders_normally():
    """5. The common one-location case is unaffected."""
    (group,) = render._finding_groups([_g_row("CVE-2022-0591", "https://h/only")])
    assert group["occurrence_count"] == 1
    text = _group_block_text(group)
    assert "Affected Location(s)" in text and "1 location(s):" in text
    assert "https://h/only" in text
    assert "Template: CVE-2022-0591" in text


def test_grouping_uses_the_same_identity_as_the_security_score():
    """The Technical Report, the Executive Report and the Security Score must agree on
    what one vulnerability is -- otherwise the counts contradict each other."""
    from apps.api.modules.reports.scoring import group_issues, issue_key

    rows = [_g_row("unix-command-injection", f"https://h/p{i}") for i in range(12)]
    rows += [_g_row("time-based-sqli", "https://h/x", severity="critical", cvss=9.5)]
    tech = render._finding_groups(rows)
    assert len(tech) == len(group_issues(rows)) == 2
    assert {g["key"] for g in tech} == {issue_key(r) for r in rows}


def test_legacy_rows_without_template_id_group_by_title():
    """Non-nuclei/legacy rows fall back to title, so they stay distinct findings."""
    rows = [
        _g_row(None, "https://h/a", title="Legacy A"),
        _g_row(None, "https://h/b", title="Legacy B"),
        _g_row(None, "https://h/c", title="Legacy A"),
    ]
    groups = render._finding_groups(rows)
    assert len(groups) == 2
    by_title = {g["title"]: g for g in groups}
    assert len(by_title["Legacy A"]["matched_ats"]) == 2
    assert len(by_title["Legacy B"]["matched_ats"]) == 1


def test_unlocated_occurrences_are_reported_not_dropped():
    """A member with no matched_at must still be accounted for."""
    rows = [
        _g_row("t", "https://h/a"),
        _g_row("t", None),
        _g_row("t", None),
    ]
    (group,) = render._finding_groups(rows)
    assert group["unlocated_count"] == 2
    assert group["occurrence_count"] == 3
    assert "(+2 occurrence(s) with no recorded location)" in _group_block_text(group)


def test_grouping_is_deterministic_and_severity_ordered():
    rows = [
        _g_row("low-issue", "https://h/a", severity="low", cvss=2.0),
        _g_row("crit-issue", "https://h/b", severity="critical", cvss=9.5),
        _g_row("high-issue", "https://h/c", severity="high", cvss=8.0),
    ]
    keys = [g["key"] for g in render._finding_groups(rows)]
    assert keys == [g["key"] for g in render._finding_groups(list(reversed(rows)))]
    assert keys[0] == "template:crit-issue"  # worst first


def test_technical_report_no_longer_repeats_one_issue_per_location():
    """6/end-to-end: the real shape -- many locations of a few issues -- renders a small
    number of blocks and still produces a valid PDF."""
    rows = [_g_row("unix-command-injection", f"https://h/u{i}") for i in range(24)]
    rows += [_g_row("windows-command-injection", f"https://h/w{i}") for i in range(19)]
    rows += [_g_row("time-based-sqli", "https://h/s", severity="critical", cvss=9.5)]
    assert len(rows) == 44
    assert len(render._finding_groups(rows)) == 3  # not 44

    data = ReportData(
        project_name="P", security_score=3,
        severity_counts={"critical": 1, "high": 43, "medium": 0, "low": 0, "info": 0},
        total_vulns=len(rows), active_vulns=len(rows), vulns=rows,
    )
    assert render.render("technical", data)[:5] == b"%PDF-"


def test_executive_top_risk_grouping_is_unchanged_by_technical_grouping():
    """7. The Executive Report keeps its own (active+scored) grouping semantics."""
    rows = [_g_row("unix-command-injection", f"https://h/p{i}") for i in range(5)]
    rows.append(_g_row("fixed-issue", "https://h/z", status="fixed"))
    exec_groups = render._top_risk_groups(rows)
    # Executive filters to ACTIVE+scored, so the fixed finding is excluded there...
    assert [g["title"] for g in exec_groups] == ["unix-command-injection title"]
    assert exec_groups[0]["endpoint_count"] == 5
    # ...while the Technical Report keeps it, being the full record.
    assert len(render._finding_groups(rows)) == 2


# --- matched_at integrity (regression) ----------------------------------------------------
# An audit initially reported matched_at as "corrupted" -- values like `sleep+5` and `dir`
# appearing instead of URLs. That was an ARTIFACT OF THE AUDIT QUERY, not of the code: the
# query used SQL SUBSTRING_INDEX(fingerprint,'|',-1), which takes the text after the LAST
# pipe, while a real matched_at can itself contain pipes (an injection payload such as
# `?lang=|sleep+5` is part of the URL nuclei probed). _parse_fingerprint splits at most TWICE
# from the left, so the trailing field keeps every pipe. These tests pin that, using the exact
# production fingerprints, so the same false alarm cannot be raised again.


def test_matched_at_keeps_injection_payload_pipe_whole():
    """Production fingerprints whose URL contains `|<payload>`. The payload is part of the
    URL, not a delimiter: taking the text after the last pipe would yield `sleep+5`/`dir`."""
    for payload in ("sleep+5", "dir"):
        url = f"https://universities.brightvision-og.com/university/nilai-university/?lang=|{payload}"
        tid, matcher, matched = _parse_fingerprint(f"unix-command-injection|time-based|{url}")
        assert tid == "unix-command-injection"
        assert matcher == "time-based"
        assert matched == url                      # full URL, pipe intact
        assert matched != payload                  # never the bare payload
        assert matched.startswith("https://")


def test_matched_at_is_never_reduced_to_the_last_pipe_segment():
    """The exact mistake to guard against: rsplit('|', 1)[-1] is NOT how matched_at is read."""
    url = "https://h/?a=|b|c"
    _, _, matched = _parse_fingerprint(f"t|m|{url}")
    assert matched == url
    assert matched != url.rsplit("|", 1)[-1]       # would be "c"


def test_normal_url_round_trips_unchanged():
    for url in (
        "https://example.com/",
        "https://example.com/path?x=1&y=2",
        "https://example.com/p?q=1#frag",
        "http://example.com:8080/a",
    ):
        assert _parse_fingerprint(f"tpl|matcher|{url}")[2] == url


def test_matcher_name_survives_a_piped_url():
    """Matcher must not be polluted by pipes further right in the URL."""
    tid, matcher, matched = _parse_fingerprint("windows-command-injection|time-based|https://h/?x=|dir")
    assert (tid, matcher) == ("windows-command-injection", "time-based")
    assert matched == "https://h/?x=|dir"


def test_host_port_matched_at_is_preserved_and_is_not_a_url():
    """Nuclei falls back to `host` when matched-at is absent (e.g. SSH findings), so a
    matched_at is not always an http(s) URL. It must be preserved verbatim -- and anything
    that later fetches a location must treat these as NOT fetchable."""
    for value in ("brightvision-og.com:22", "system.brightvision-og.com"):
        _, _, matched = _parse_fingerprint(f"ssh-sha1-hmac-algo||{value}")
        assert matched == value
        assert not matched.startswith(("http://", "https://"))


def test_piped_urls_stay_distinct_findings_and_group_correctly():
    """5/6: two payload-bearing URLs of one template are distinct LOCATIONS of ONE
    vulnerability -- fingerprints differ (no wrong dedup), grouping yields one finding."""
    base = "https://universities.brightvision-og.com/university"
    fp_a = f"unix-command-injection|time-based|{base}/nilai-university/?lang=|sleep+5"
    fp_b = f"unix-command-injection|time-based|{base}/segi-university/?lang=|sleep+5"
    assert fp_a != fp_b                                   # dedup keeps them separate
    a = _vuln_row_with_fingerprint(fp_a)
    b = _vuln_row_with_fingerprint(fp_b)
    assert a.matched_at != b.matched_at
    groups = render._finding_groups([a, b])
    assert len(groups) == 1                               # one vulnerability
    assert len(groups[0]["matched_ats"]) == 2             # two real locations
    assert all(u.startswith("https://") for u in groups[0]["matched_ats"])



# --- P1-1: unscored findings must not vanish from Executive Top Risks ---------------------
# A finding with no CVSS gets final_risk_score=None from risk/service.py. Top Risks used to
# filter those out, so a CRITICAL active finding with no CVSS disappeared from the executive
# view while still degrading the security score -- a reduced score above "No scored findings."
# It must now appear, presented as UNSCORED, with no fabricated risk value.

def _unscored_critical(**kw):
    return _row("critical", template_id="rce-no-cvss", matched_at="https://h/a",
                title="Critical RCE (no CVSS)", cvss_score=None, final_risk_score=None, **kw)


def test_top_risks_includes_scored_critical():
    """Baseline: a critical WITH CVSS/risk is listed and shows its real risk."""
    v = _row("critical", template_id="rce-scored", matched_at="https://h/a",
             title="Critical RCE", cvss_score=9.8, final_risk_score=10.0)
    groups = render._top_risk_groups([v])
    assert len(groups) == 1
    assert groups[0]["max_risk"] == 10.0
    assert groups[0]["severity"] == "critical"


def test_top_risks_includes_unscored_critical():
    """The regression: no CVSS -> no risk score, but the finding must STILL be listed."""
    groups = render._top_risk_groups([_unscored_critical()])
    assert len(groups) == 1, "an unscored active critical must not disappear from Top Risks"
    assert groups[0]["severity"] == "critical"
    assert groups[0]["title"] == "Critical RCE (no CVSS)"


def test_top_risks_does_not_fabricate_a_risk_score():
    """Unscored stays None -- never coerced to 0.0, which would read as 'zero risk'."""
    groups = render._top_risk_groups([_unscored_critical()])
    assert groups[0]["max_risk"] is None
    assert groups[0]["max_risk"] != 0.0
    assert groups[0]["max_cvss"] is None


def test_unscored_finding_degrades_score_and_is_still_listed():
    """The two views must agree: if it costs score, the executive must be able to see it."""
    v = _unscored_critical()
    assert compute_security_score([v]) < 100          # it really does degrade posture
    assert len(render._top_risk_groups([v])) == 1     # ...and it really is shown


def test_unscored_group_renders_risk_as_na_not_zero():
    """The rendered executive text shows N/A for an unscored group, never 0.0."""
    data = ReportData(
        project_name="P", security_score=60,
        severity_counts={"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
        total_vulns=1, active_vulns=1,
        active_severity_counts={"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
        vulns=[_unscored_critical()],
    )
    # _exec_summary_text captures Paragraph flowables only; the Top Risks rows are Table
    # cells. Assert the rendered cell value directly, and use the captured text for the
    # paragraph-level guarantee that no "nothing to show" message accompanies the score.
    group = render._top_risk_groups(data.vulns)[0]
    rendered_risk = f"{group['max_risk']:.1f}" if group["max_risk"] is not None else "N/A"
    assert rendered_risk == "N/A"
    assert rendered_risk != "0.0"

    text = _exec_summary_text(data)
    assert "No active findings." not in text
    assert "No scored findings." not in text
    # The explanatory note must tell the reader that N/A means unassessed, not low risk.
    assert "unassessed, not low risk" in text


def test_scored_groups_rank_above_unscored():
    """Ordering: real risk first, unscored in the tail -- but present."""
    scored = _row("high", template_id="sqli", matched_at="https://h/b",
                  title="Scored SQLi", cvss_score=9.0, final_risk_score=9.0)
    titles = [g["title"] for g in render._top_risk_groups([_unscored_critical(), scored])]
    assert titles == ["Scored SQLi", "Critical RCE (no CVSS)"]


def test_top_risks_still_excludes_non_active_findings():
    """Dropping the scored-only filter must NOT start showing fixed findings."""
    fixed = _row("critical", status="fixed", template_id="old", matched_at="https://h/c",
                 title="Fixed", cvss_score=9.0, final_risk_score=9.0)
    assert render._top_risk_groups([fixed]) == []


# --- P1-2: the executive summary must describe ACTIVE findings only -----------------------
# _findings_summary used the all-status severity_counts to say what reduces the score, so a
# FIXED high was reported as reducing a score of 100. It now uses active_severity_counts.

def test_summary_ignores_a_fixed_high():
    """1 fixed high + 2 active info, score 100: the fixed high must not be blamed."""
    data = ReportData(
        project_name="P", security_score=100,
        severity_counts={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 2},
        total_vulns=3, active_vulns=2,
        active_severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 2},
        vulns=[],
    )
    text = _findings_summary(data)
    assert "all informational" in text
    assert "1 is of low severity or higher" not in text
    assert "do not reduce the security score" in text


def test_summary_reports_an_active_high():
    """1 active high + 2 active info: the high IS named."""
    data = ReportData(
        project_name="P", security_score=75,
        severity_counts={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 2},
        total_vulns=3, active_vulns=3,
        active_severity_counts={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 2},
        vulns=[],
    )
    text = _findings_summary(data)
    assert "1 is of low severity or higher" in text
    assert "all informational" not in text


def test_summary_all_active_are_informational():
    """All active findings informational -> the 100/100 explanation."""
    data = ReportData(
        project_name="P", security_score=100,
        severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 4},
        total_vulns=4, active_vulns=4,
        active_severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 4},
        vulns=[],
    )
    text = _findings_summary(data)
    assert "all informational" in text
    assert "100/100 can coexist with informational findings" in text


def test_summary_mixed_active_and_fixed_counts_active_only():
    """2 active high + 3 fixed high: only the 2 active ones are described."""
    data = ReportData(
        project_name="P", security_score=50,
        severity_counts={"critical": 0, "high": 5, "medium": 0, "low": 0, "info": 0},
        total_vulns=5, active_vulns=2,
        active_severity_counts={"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0},
        vulns=[],
    )
    text = _findings_summary(data)
    assert "2 are of low severity or higher" in text
    assert "5 are of low severity or higher" not in text


def test_summary_falls_back_to_all_status_counts_when_active_absent():
    """A ReportData built by older code (no active_severity_counts) keeps its old behaviour."""
    data = ReportData(
        project_name="P", security_score=85,
        severity_counts={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 5},
        total_vulns=6, active_vulns=6, vulns=[],
    )
    assert data.active_severity_counts == {}
    assert "1 is of low severity or higher" in _findings_summary(data)


# =========================================================================================
# P2-5 -- affected assets/endpoints must describe the CURRENT state
# =========================================================================================
# The Executive report says assets/endpoints "are affected" (present tense). Previously every
# row counted regardless of status, so a fully remediated project still claimed N affected
# assets beside a 100/100 score -- and false positives, which never affected anything, counted.

_P25_ACTIVE = {"open", "confirmed", "reopened"}


def _aa_vuln(*, status="open", severity="high", asset=None, matched=None, template_id="t"):
    return VulnRow(
        id=uuid.uuid4(), title="F", severity=severity, status=status, category=None,
        cvss_score=7.0, cvss_vector=None, final_risk_score=7.0, risk_rationale=None,
        compliance=[], evidence_uris=[], template_id=template_id, matched_at=matched,
        asset_value=asset,
    )


def _aa_report(vulns):
    return ReportData(
        project_name="P", security_score=compute_security_score(vulns),
        severity_counts={"critical": 0, "high": len(vulns), "medium": 0, "low": 0, "info": 0},
        total_vulns=len(vulns),
        active_vulns=sum(1 for v in vulns if v.status in _P25_ACTIVE),
        vulns=vulns,
    )


def test_fully_remediated_project_has_no_affected_assets_or_endpoints():
    """(1) Every finding fixed/false-positive/accepted -> nothing is currently affected."""
    data = _aa_report([
        _aa_vuln(status="fixed", asset="host-a", matched="https://host-a/1", template_id="t1"),
        _aa_vuln(status="false_positive", asset="host-b", matched="https://host-b/2", template_id="t2"),
        _aa_vuln(status="accepted_risk", asset="host-c", matched="https://host-c/3", template_id="t3"),
    ])
    assert data.affected_assets() == []
    assert data.affected_endpoint_count() == 0
    # ...and this agrees with the rest of the report.
    assert data.security_score == 100
    assert data.active_vulns == 0


def test_affected_assets_mixed_statuses_counts_active_only():
    """(2) Mixed active / fixed / false-positive / info -> only the active weakness counts."""
    data = _aa_report([
        _aa_vuln(status="open", asset="live-host", matched="https://live/1", template_id="t1"),
        _aa_vuln(status="fixed", asset="fixed-host", matched="https://fixed/2", template_id="t2"),
        _aa_vuln(status="false_positive", asset="fp-host", matched="https://fp/3", template_id="t3"),
        _aa_vuln(status="open", severity="info", asset="info-host", matched="https://info/4", template_id="t4"),
    ])
    assert data.affected_assets() == ["live-host"]
    assert data.affected_endpoint_count() == 1


def test_multiple_active_findings_on_one_asset_count_the_asset_once():
    """(3) An asset is affected once, however many active findings it carries."""
    data = _aa_report([
        _aa_vuln(asset="same-host", matched="https://same/1", template_id="t1"),
        _aa_vuln(asset="same-host", matched="https://same/2", template_id="t2"),
        _aa_vuln(asset="same-host", matched="https://same/3", template_id="t3"),
    ])
    assert data.affected_assets() == ["same-host"]


def test_many_endpoints_on_one_asset_are_counted_separately():
    """(4) One host can expose several affected endpoints -- endpoints > assets."""
    data = _aa_report([
        _aa_vuln(asset="one-host", matched="https://one/a", template_id="t1"),
        _aa_vuln(asset="one-host", matched="https://one/b", template_id="t1"),
        _aa_vuln(asset="one-host", matched="https://one/c", template_id="t1"),
    ])
    assert data.affected_assets() == ["one-host"]
    assert data.affected_endpoint_count() == 3


def test_detection_does_not_make_an_asset_affected():
    """A detection-only observation is not a weakness, so it affects nothing (matches scoring).

    cvss_score is cleared: a real technology detection carries no CVSS. With one, the
    classifier correctly rules it a VULNERABILITY (a positive CVSS outranks every detection
    marker), which is the P1 guarantee and must not be weakened here."""
    detection = _aa_vuln(asset="tech-host", matched="https://tech/1", template_id="tech-detect")
    detection.cvss_score = None
    detection.final_risk_score = None
    data = _aa_report([detection])
    assert data.affected_assets() == []
    assert data.affected_endpoint_count() == 0


# =========================================================================================
# P2-1 -- Executive and Technical must agree on one issue's business risk
# =========================================================================================
# final_risk_score is CVSS re-weighted by asset criticality, so the highest-CVSS member of a
# group is NOT necessarily the highest-risk one. Executive prints the group max; Technical
# used to print a representative chosen by (severity, CVSS) -- a different member.

def _p21_pair():
    """One template, two locations, where max-risk member != max-CVSS member."""
    high_cvss_low_risk = _tr_vuln("SQLi", "sqli-x", risk=4.5, cvss=9.0, matched="https://h/a")
    high_cvss_low_risk.risk_rationale = "CVSS 9.0 x asset criticality low (weight 0.5) = 4.5"
    low_cvss_high_risk = _tr_vuln("SQLi", "sqli-x", risk=10.0, cvss=5.0, matched="https://h/b")
    low_cvss_high_risk.risk_rationale = "CVSS 5.0 x asset criticality critical (weight 2.0) = 10.0"
    return [high_cvss_low_risk, low_cvss_high_risk]


def test_executive_and_technical_agree_on_issue_risk():
    """THE regression: fails under the old (severity, CVSS) representative selection."""
    vulns = _p21_pair()
    exec_group = render._top_risk_groups(vulns)[0]
    tech_group = render._finding_groups(vulns)[0]
    assert exec_group["max_risk"] == 10.0
    assert tech_group["final_risk_score"] == exec_group["max_risk"]


def test_technical_risk_and_rationale_describe_the_same_member():
    """Option A: the block is internally coherent -- risk, CVSS and rationale agree."""
    tech_group = render._finding_groups(_p21_pair())[0]
    assert tech_group["final_risk_score"] == 10.0
    assert "10.0" in tech_group["risk_rationale"]
    assert tech_group["cvss_score"] == 5.0            # the risk-bearing member's own CVSS
    assert "weight 0.5" not in tech_group["risk_rationale"]  # not the other member's rationale


def test_issue_risk_prefers_an_active_member():
    """A fixed member must not supply the risk the Executive table never considered."""
    active = _tr_vuln("Iss", "tpl-a", risk=3.0, cvss=4.0, status="open", matched="https://h/a")
    fixed = _tr_vuln("Iss", "tpl-a", risk=10.0, cvss=9.9, status="fixed", matched="https://h/b")
    exec_group = render._top_risk_groups([active, fixed])[0]
    tech_group = render._finding_groups([active, fixed])[0]
    assert exec_group["max_risk"] == 3.0            # exec only sees the active member
    assert tech_group["final_risk_score"] == 3.0    # technical agrees


def test_fully_remediated_issue_still_rendered_in_technical_report():
    """No active member -> the technical report still lists it (it is the full record)."""
    fixed = _tr_vuln("Old", "tpl-old", risk=9.0, cvss=9.0, status="fixed")
    groups = render._finding_groups([fixed])
    assert len(groups) == 1
    assert groups[0]["final_risk_score"] == 9.0
    assert render._top_risk_groups([fixed]) == []   # but the executive excludes it


def test_issue_risk_na_semantics_preserved():
    """Unscored stays None in BOTH reports -- never fabricated as 0.0."""
    unscored = _tr_vuln("NoCVSS", "tpl-n", risk=None, cvss=None, severity="critical")
    exec_group = render._top_risk_groups([unscored])[0]
    tech_group = render._finding_groups([unscored])[0]
    assert exec_group["max_risk"] is None
    assert tech_group["final_risk_score"] is None
    assert tech_group["cvss_score"] is None
    assert tech_group["final_risk_score"] != 0.0


def test_cvss_zero_is_not_treated_as_missing_in_grouping():
    """CVSS 0.0 is a real score and must beat a None member for representative selection."""
    zero = _tr_vuln("Z", "tpl-z", risk=None, cvss=0.0, matched="https://h/a")
    none_ = _tr_vuln("Z", "tpl-z", risk=None, cvss=None, matched="https://h/b")
    assert render._finding_groups([zero, none_])[0]["cvss_score"] == 0.0


# =========================================================================================
# P2-4 -- one canonical grouping identity
# =========================================================================================

def test_top_risk_and_finding_groups_partition_identically():
    """Both groupers must use scoring.issue_key, for every finding shape."""
    from apps.api.modules.reports.scoring import issue_key

    vulns = [
        _tr_vuln("A", "tpl-1", matched="https://h/1"),          # nuclei, same template...
        _tr_vuln("A", "tpl-1", matched="https://h/2"),          # ...two locations
        _tr_vuln("B", None, matched="https://h/3"),             # non-nuclei, title identity
        _tr_vuln("B", None, matched="https://h/4"),             # same title -> same issue
        _tr_vuln("C", None, matched="https://h/5"),             # distinct title
    ]
    exec_keys = {issue_key(v) for v in vulns}
    assert len(render._top_risk_groups(vulns)) == len(exec_keys)
    assert len(render._finding_groups(vulns)) == len(exec_keys)
    assert len(exec_keys) == 3


def test_template_and_title_identities_never_collide():
    """A template_id "X" and a title "X" must stay separate issues in both groupers."""
    by_template = _tr_vuln("other", "X", matched="https://h/1")
    by_title = _tr_vuln("X", None, matched="https://h/2")
    assert len(render._top_risk_groups([by_template, by_title])) == 2
    assert len(render._finding_groups([by_template, by_title])) == 2


def test_grouping_handles_pipe_containing_payload_locations():
    """An injection payload with a pipe stays one location, not a broken key."""
    fp = "windows-command-injection|time-based|https://h/?lang=|dir"
    template_id, matcher, matched_at = _parse_fingerprint(fp)
    assert template_id == "windows-command-injection"
    assert matched_at == "https://h/?lang=|dir"
    v = _tr_vuln("CI", template_id, matched=matched_at)
    assert render._finding_groups([v])[0]["matched_ats"] == ["https://h/?lang=|dir"]


def test_inactive_filtering_differs_by_design():
    """Executive = active only; Technical = full record. Both use the same identity."""
    fixed = _tr_vuln("F", "tpl-f", status="fixed")
    assert render._top_risk_groups([fixed]) == []
    assert len(render._finding_groups([fixed])) == 1


# =========================================================================================
# P2-2 -- MITRE ATT&CK counts DISTINCT ACTIVE ISSUES, not raw mapping rows
# =========================================================================================
# gather_report_data previously incremented one count per AttackMapping row over EVERY
# project finding. A vulnerability row is one (template|matcher|matched_at) LOCATION, so one
# issue at 20 URLs counted 20 times, and fixed / false-positive / accepted-risk / info
# findings all contributed. The tally now mirrors the roll-up implemented in data.py:
# group by scoring.issue_key over scoring.is_scorable findings.
#
# These exercise that exact roll-up as a pure function of VulnRows, so they need no database.

def _attack_tally(rows_and_techniques):
    """Replicate gather_report_data's ATT&CK roll-up: {technique: distinct active issue keys}.

    Mirrors apps/api/modules/reports/data.py -- same two canonical helpers, so a divergence
    between this and production shows up as a failure here."""
    from apps.api.modules.reports.scoring import is_scorable, issue_key

    by_technique: dict[str, set[str]] = {}
    for row, techniques in rows_and_techniques:
        if not is_scorable(row):
            continue
        for technique in techniques:
            by_technique.setdefault(technique, set()).add(issue_key(row))
    return {t: len(keys) for t, keys in by_technique.items()}


def _at_row(*, status="open", severity="high", template_id="tpl", matched="https://h/a", cvss=9.0):
    return VulnRow(
        id=uuid.uuid4(), title="F", severity=severity, status=status, category=None,
        cvss_score=cvss, cvss_vector=None, final_risk_score=9.0, risk_rationale=None,
        compliance=[], evidence_uris=[], template_id=template_id, matched_at=matched,
    )


def test_attack_same_issue_at_many_locations_counts_once():
    """20 endpoints of ONE template is ONE issue, not 20 findings."""
    rows = [(_at_row(template_id="sqli-x", matched=f"https://h/{i}"), ["T1190"]) for i in range(20)]
    assert _attack_tally(rows) == {"T1190": 1}


def test_attack_excludes_fixed_findings():
    rows = [(_at_row(status="fixed", template_id="rce-y"), ["T1190"])]
    assert _attack_tally(rows) == {}


def test_attack_excludes_false_positive_and_accepted_risk():
    rows = [
        (_at_row(status="false_positive", template_id="fp-a"), ["T1190"]),
        (_at_row(status="accepted_risk", template_id="ar-b"), ["T1190"]),
    ]
    assert _attack_tally(rows) == {}


def test_attack_excludes_informational_findings():
    """Info is excluded from the score, so it must not inflate ATT&CK either."""
    rows = [(_at_row(severity="info", template_id="info-z", cvss=None), ["T1190"])]
    assert _attack_tally(rows) == {}


def test_attack_excludes_detection_only_findings():
    """A technology detection is an observation, not an adversary technique in use."""
    rows = [(_at_row(template_id="tech-detect", cvss=None), ["T1190"])]
    assert _attack_tally(rows) == {}


def test_attack_counts_an_active_issue():
    rows = [(_at_row(template_id="unix-command-injection"), ["T1190"])]
    assert _attack_tally(rows) == {"T1190": 1}


def test_attack_one_issue_with_several_techniques_counts_once_per_technique():
    """A technique is its own row, so one issue may legitimately appear under each."""
    rows = [(_at_row(template_id="multi"), ["T1190", "T1059"])]
    assert _attack_tally(rows) == {"T1190": 1, "T1059": 1}


def test_attack_distinct_issues_sharing_a_technique_count_separately():
    rows = [
        (_at_row(template_id="issue-a"), ["T1190"]),
        (_at_row(template_id="issue-b"), ["T1190"]),
    ]
    assert _attack_tally(rows) == {"T1190": 2}


def test_attack_mixed_dataset_matches_the_security_score_population():
    """The realistic dataset from the investigation: 29 raw rows -> 1 distinct active issue."""
    rows = [(_at_row(template_id="sqli-x", matched=f"https://h/{i}"), ["T1190"]) for i in range(20)]
    rows += [(_at_row(status="fixed", template_id="rce-y"), ["T1190"]) for _ in range(3)]
    rows += [(_at_row(status="false_positive", template_id="rce-y"), ["T1190"]) for _ in range(2)]
    rows += [(_at_row(severity="info", template_id="info-z", cvss=None), ["T1190"]) for _ in range(4)]

    from apps.api.modules.reports.scoring import group_issues

    assert _attack_tally(rows) == {"T1190": 1}
    # The score sees exactly the same one issue.
    scorable = [r for r, _ in rows]
    assert len(group_issues(scorable)) == 1


# ==========================================================================================
# ATT&CK API / PDF PARITY (P1 closure)
#
# The PDF tally (data.gather_report_data) already counted DISTINCT LOGICAL ISSUES over the
# scorable population. The API surfaces did not: attack_matrix_for_scan counted raw
# `attack_mappings` ROWS with no status/classification filter, and kill_chain_steps
# de-duplicated by TITLE. So one vulnerability observed at five URLs -- five
# `vulnerabilities` rows, because the dedup identity is (project_id, fingerprint) and a
# fingerprint is `template_id|matcher|matched_at` -- read as 5 in the API and 1 in the PDF,
# and a remediated finding still counted as live coverage in the API.
#
# attack.aggregation is now the single source of truth. These tests pin BOTH the canonical
# semantics and the API==PDF equality, so the two surfaces cannot drift apart again.
# ==========================================================================================

import uuid as _uuid  # noqa: E402

from apps.api.modules.attack.aggregation import (  # noqa: E402
    count_issues_by_technique,
    scorable_issue_key,
    scorable_vuln_ids,
)


class _AtkVuln:
    """Minimal stand-in for a `Vulnerability` ORM row (id + the columns the canonical
    predicates read). The fingerprint is built exactly as nuclei_runner does --
    `template_id|matcher|matched_at` -- so identity is recovered the same way in production."""

    def __init__(self, template_id="unix-command-injection", matched_at="https://h/1",
                 severity="high", status="open", cvss_score=8.0, category="cwe-78",
                 title="Command Injection"):
        self.id = _uuid.uuid4()
        self.fingerprint = f"{template_id}|matcher|{matched_at}"
        self.title = title
        self.severity = severity
        self.status = status
        self.cvss_score = cvss_score
        self.category = category


class _AtkMapping:
    def __init__(self, vuln, technique_id="T1190", technique_name="Exploit Public-Facing Application"):
        self.vulnerability_id = vuln.id
        self.tactic_id = "TA0001"
        self.tactic_name = "Initial Access"
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.kill_chain_phase = "exploitation"


def _counts(vulns, mappings):
    """technique_id -> issue count, via the canonical aggregator."""
    by_id = {v.id: v for v in vulns}
    return {k[2]: n for k, n in count_issues_by_technique(mappings, by_id).items()}


def _pdf_counts(vulns, mappings):
    """The PDF's own rule, computed independently here from report VulnRows rather than by
    calling the aggregator -- so the parity assertions below compare two separate
    implementations of "one issue", not one implementation against itself."""
    from apps.api.modules.reports.data import VulnRow, _parse_fingerprint
    from apps.api.modules.reports.scoring import is_scorable, issue_key

    rows = {}
    for v in vulns:
        template_id, matcher, matched_at = _parse_fingerprint(v.fingerprint)
        rows[v.id] = VulnRow(
            id=v.id, title=v.title, severity=v.severity, status=v.status, category=v.category,
            cvss_score=v.cvss_score, cvss_vector=None, final_risk_score=None, risk_rationale=None,
            compliance=[], evidence_uris=[], template_id=template_id,
            matcher_name=matcher, matched_at=matched_at,
        )
    keys_by_tech = {}
    for m in mappings:
        row = rows.get(m.vulnerability_id)
        if row is None or not is_scorable(row):
            continue
        keys_by_tech.setdefault(m.technique_id, set()).add(issue_key(row))
    return {t: len(k) for t, k in keys_by_tech.items()}


def test_attack_one_issue_at_many_locations_counts_once():
    """The headline over-count: five locations of ONE template are one issue, not five."""
    vulns = [_AtkVuln(matched_at=f"https://h/{i}") for i in range(5)]
    assert _counts(vulns, [_AtkMapping(v) for v in vulns]) == {"T1190": 1}


def test_attack_duplicate_mappings_for_one_finding_count_once():
    v = _AtkVuln()
    assert _counts([v], [_AtkMapping(v), _AtkMapping(v)]) == {"T1190": 1}


def test_attack_excludes_fixed_false_positive_and_accepted_risk():
    """A remediated or dismissed finding is not current ATT&CK coverage."""
    for status in ("fixed", "false_positive", "accepted_risk"):
        v = _AtkVuln(status=status)
        assert _counts([v], [_AtkMapping(v)]) == {}, f"status={status} still counted"


def test_attack_api_excludes_informational_findings():
    v = _AtkVuln(severity="info", cvss_score=None)
    assert _counts([v], [_AtkMapping(v)]) == {}


def test_attack_excludes_detections_including_stale_mappings():
    """A technology/WAF DETECTION contributes nothing -- and because the filter is applied at
    READ time, a stale mapping row written before the detection guard existed is excluded
    without needing a backfill migration."""
    v = _AtkVuln(template_id="tech-detect", cvss_score=None, category="cwe-200", severity="low")
    assert _counts([v], [_AtkMapping(v)]) == {}


def test_attack_api_distinct_issues_sharing_a_technique_count_separately():
    a = _AtkVuln(template_id="tmpl-a")
    b = _AtkVuln(template_id="tmpl-b")
    assert _counts([a, b], [_AtkMapping(a), _AtkMapping(b)]) == {"T1190": 2}


def test_attack_api_one_issue_with_several_techniques_counts_once_per_technique():
    v = _AtkVuln()
    counts = _counts([v], [_AtkMapping(v, "T1190"), _AtkMapping(v, "T1059", "Command Interpreter")])
    assert counts == {"T1190": 1, "T1059": 1}


def test_attack_legacy_row_without_template_id_falls_back_to_title():
    """A non-nuclei / legacy finding has no parseable template_id; it must still be ONE issue
    keyed by its title rather than collapsing into a shared bucket with everything else."""
    a = _AtkVuln()
    a.fingerprint = "bare-hash-no-pipes"
    a.title = "Legacy Finding A"
    b = _AtkVuln()
    b.fingerprint = "another-bare-hash"
    b.title = "Legacy Finding B"
    assert _counts([a, b], [_AtkMapping(a), _AtkMapping(b)]) == {"T1190": 2}


def test_attack_api_matches_pdf_on_a_mixed_dataset():
    """THE PARITY GUARANTEE. One dataset exercising every rule at once; the API aggregator and
    an independent re-implementation of the PDF's rule must agree exactly."""
    active = [_AtkVuln(matched_at=f"https://h/{i}") for i in range(4)]          # 1 issue
    other = [_AtkVuln(template_id="ssrf-basic", matched_at="https://h/x")]      # 1 issue
    fixed = [_AtkVuln(matched_at="https://h/f", status="fixed")]
    info = [_AtkVuln(matched_at="https://h/i", severity="info", cvss_score=None)]
    detection = [_AtkVuln(template_id="waf-detect", cvss_score=None, category="cwe-200")]
    vulns = active + other + fixed + info + detection
    mappings = [_AtkMapping(v) for v in vulns]

    api = _counts(vulns, mappings)
    pdf = _pdf_counts(vulns, mappings)
    assert api == pdf, f"API {api} != PDF {pdf}"
    assert api == {"T1190": 2}


def test_attack_api_matches_pdf_when_nothing_is_scorable():
    """A fully remediated project reports no ATT&CK coverage on either surface."""
    vulns = [_AtkVuln(status="fixed"), _AtkVuln(template_id="tech-detect", cvss_score=None,
                                                category="cwe-200", severity="low")]
    mappings = [_AtkMapping(v) for v in vulns]
    assert _counts(vulns, mappings) == _pdf_counts(vulns, mappings) == {}


def test_scorable_issue_key_is_none_for_excluded_findings():
    assert scorable_issue_key(_AtkVuln(status="fixed")) is None
    assert scorable_issue_key(_AtkVuln(severity="info", cvss_score=None)) is None
    assert scorable_issue_key(_AtkVuln()) == "template:unix-command-injection"


def test_kill_chain_population_excludes_non_scorable_findings():
    """The kill chain must describe the same population as the matrix -- it previously
    de-duplicated by title and included every finding regardless of status."""
    live = _AtkVuln()
    dead = _AtkVuln(matched_at="https://h/2", status="fixed")
    by_id = {v.id: v for v in (live, dead)}
    countable = scorable_vuln_ids([_AtkMapping(live), _AtkMapping(dead)], by_id)
    assert countable == {live.id}


# ==========================================================================================
# EXECUTIVE / TECHNICAL SEVERITY ALIGNMENT (P1 closure)
#
# P2-1 aligned the two reports on business RISK but left SEVERITY divergent: _top_risk_groups
# (Executive) and scoring.group_issues (the Security Score) both take the MAX severity across
# a group's members, while _finding_groups (Technical) took the REPRESENTATIVE member's
# severity -- and the representative is chosen by business risk first, so it is not
# necessarily the most severe member.
#
# The divergence is reachable with an ordinary dataset: an active finding with no CVSS has
# final_risk_score=None by construction, so a group holding an UNSCORED CRITICAL and a SCORED
# MEDIUM picked the medium as representative. The Executive table then printed "critical" and
# the Technical block printed "[MEDIUM]" for the same issue_key.
# ==========================================================================================


def _sev_row(**kw):
    """A VulnRow sharing one template_id (so every row lands in ONE group), with the fields
    the two groupers read."""
    import uuid as _u

    from apps.api.modules.reports.data import VulnRow

    base = dict(
        id=_u.uuid4(), title="Shared Issue", severity="high", status="open", category=None,
        cvss_score=None, cvss_vector=None, final_risk_score=None, risk_rationale=None,
        compliance=[], evidence_uris=[], template_id="shared-template", matched_at="https://h/1",
    )
    base.update(kw)
    return VulnRow(**base)


def test_executive_and_technical_agree_on_group_severity():
    """THE REGRESSION. Unscored critical + scored medium in one group: both surfaces must say
    critical. Before the fix Technical said medium."""
    from apps.api.modules.reports.render import _finding_groups, _top_risk_groups

    members = [
        _sev_row(severity="critical", cvss_score=None, final_risk_score=None,
                 matched_at="https://h/1", title="Unscored Critical"),
        _sev_row(severity="medium", cvss_score=5.0, final_risk_score=5.0,
                 matched_at="https://h/2", title="Scored Medium"),
    ]
    exec_group = _top_risk_groups(members)[0]
    tech_group = _finding_groups(members)[0]
    assert exec_group["severity"] == tech_group["severity"] == "critical"


def test_group_severity_matches_the_security_score_band():
    """All THREE surfaces -- Executive, Technical, and the scoring model that actually sets
    the penalty -- must agree on a group's severity."""
    from apps.api.modules.reports.render import _finding_groups, _top_risk_groups
    from apps.api.modules.reports.scoring import group_issues

    members = [
        _sev_row(severity="critical", cvss_score=None, final_risk_score=None, matched_at="https://h/1"),
        _sev_row(severity="low", cvss_score=9.9, final_risk_score=9.9, matched_at="https://h/2"),
    ]
    assert (
        _top_risk_groups(members)[0]["severity"]
        == _finding_groups(members)[0]["severity"]
        == group_issues(members)[0].severity
        == "critical"
    )


def test_group_severity_is_independent_of_member_order():
    """Severity must be a property of the group, not of whichever row happened to sort first."""
    from apps.api.modules.reports.render import _finding_groups

    a = _sev_row(severity="critical", matched_at="https://h/1", title="A")
    b = _sev_row(severity="medium", cvss_score=9.0, final_risk_score=9.0,
                 matched_at="https://h/2", title="B")
    assert _finding_groups([a, b])[0]["severity"] == _finding_groups([b, a])[0]["severity"] == "critical"


def test_representative_still_anchors_risk_cvss_and_rationale():
    """The severity change must NOT disturb the P2-1 risk contract: risk/CVSS/rationale still
    come from ONE real member (the highest-risk one), so the block stays internally coherent
    rather than mixing per-field maxima from different observations."""
    from apps.api.modules.reports.render import _finding_groups, _top_risk_groups

    members = [
        _sev_row(severity="critical", cvss_score=None, final_risk_score=None, matched_at="https://h/1"),
        _sev_row(severity="medium", cvss_score=5.0, final_risk_score=9.5,
                 risk_rationale="high-criticality asset", matched_at="https://h/2"),
    ]
    tech = _finding_groups(members)[0]
    assert tech["severity"] == "critical"                       # issue-level
    assert tech["final_risk_score"] == 9.5                      # representative member
    assert tech["cvss_score"] == 5.0                            # same member
    assert tech["risk_rationale"] == "high-criticality asset"   # same member
    # and the Executive table reports the same issue-level risk
    assert _top_risk_groups(members)[0]["max_risk"] == 9.5


def test_single_member_group_severity_is_unchanged():
    """Backward compatibility: with one member, max == that member."""
    from apps.api.modules.reports.render import _finding_groups

    assert _finding_groups([_sev_row(severity="medium")])[0]["severity"] == "medium"


def test_group_severity_prefers_max_even_when_highest_is_inactive():
    """_finding_groups is the FULL record and keeps inactive members, so a group whose only
    critical is fixed still reports critical -- the Technical report must not understate what
    the issue is, and the Executive table simply omits the group (no active member)."""
    from apps.api.modules.reports.render import _finding_groups

    members = [
        _sev_row(severity="critical", status="fixed", matched_at="https://h/1"),
        _sev_row(severity="low", matched_at="https://h/2"),
    ]
    assert _finding_groups(members)[0]["severity"] == "critical"
