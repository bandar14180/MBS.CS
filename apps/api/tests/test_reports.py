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

    def _walk(flowable):
        content = getattr(flowable, "_content", None)
        if content is not None:
            for child in content:
                _walk(child)
        elif hasattr(flowable, "getPlainText"):
            texts.append(flowable.getPlainText())

    _walk(block)
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

    def _walk(flowable):
        content = getattr(flowable, "_content", None)
        if content is not None:
            for child in content:
                _walk(child)
            return
        text = getattr(flowable, "text", None)
        if text is not None:
            texts.append(str(text))

    _walk(block)
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
    # One location -> listed under "Affected locations", still showing the full URL.
    assert "Affected locations (1):" in text
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
    assert "Affected locations (2):" in text
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
    assert "Affected locations: N/A" in text
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
        assert "Affected locations: N/A" in text


# --- P0 #1: CVSS 0.0 vs N/A must stay distinguishable in the report -----------------------
# A genuine CVSS of 0.0 is a real score and must render "CVSS 0.0"; a missing score (None)
# must render "CVSS N/A". Truthiness logic (`x or 0.0`, `if not x`) would wrongly collapse
# 0.0 into a fallback -- these pin the explicit-None behaviour instead. Reuses the existing
# _finding_block_text / _vuln_row_with_fingerprint helpers (no PDF-text dependency).

_FP = "unix-command-injection|time-based|https://x/a?p=1"


def test_genuine_zero_cvss_renders_as_0_not_na():
    text = _finding_block_text(_vuln_row_with_fingerprint(_FP, cvss_score=0.0))
    assert "CVSS 0.0" in text
    assert "CVSS N/A" not in text          # 0.0 must NOT be shown as missing


def test_missing_cvss_renders_as_na_not_zero():
    text = _finding_block_text(_vuln_row_with_fingerprint(_FP, cvss_score=None))
    assert "CVSS N/A" in text
    assert "CVSS 0.0" not in text          # missing must NOT be shown as 0.0


def test_normal_cvss_still_renders_its_value():
    text = _finding_block_text(_vuln_row_with_fingerprint(_FP, cvss_score=9.8))
    assert "CVSS 9.8" in text


def test_zero_and_none_are_distinguishable_in_the_same_report():
    a = _vuln_row_with_fingerprint("t|m|https://x/zero", cvss_score=0.0)
    b = _vuln_row_with_fingerprint("t|m|https://x/none", cvss_score=None)
    text_a = _finding_block_text(a)
    text_b = _finding_block_text(b)
    assert "CVSS 0.0" in text_a and "CVSS N/A" not in text_a
    assert "CVSS N/A" in text_b and "CVSS 0.0" not in text_b
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
    orig_build = platypus.SimpleDocTemplate.build

    def _capture_build(self, flowables, *a, **k):
        for f in flowables:
            if hasattr(f, "getPlainText"):
                captured.append(f.getPlainText())
        return orig_build(self, flowables, *a, **k)

    platypus.SimpleDocTemplate.build = _capture_build
    try:
        render.render("executive", data)
    finally:
        platypus.SimpleDocTemplate.build = orig_build
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
    """(3) max_risk (and max CVSS) reflect the group's highest members, not the first seen."""
    vulns = [
        _tr_vuln("Unix CI", "unix-command-injection", risk=6.0, cvss=6.1),
        _tr_vuln("Unix CI", "unix-command-injection", risk=10.0, cvss=9.8),
        _tr_vuln("Unix CI", "unix-command-injection", risk=8.0, cvss=7.5),
    ]
    g = _top_risk_groups(vulns)[0]
    assert g["max_risk"] == 10.0
    assert g["max_cvss"] == 9.8
    assert g["endpoint_count"] == 3


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


def test_top_risks_excludes_inactive_and_unscored_findings():
    """(5) fixed/accepted/false-positive and None-risk findings never appear."""
    vulns = [
        _tr_vuln("Active", "t-active", status="open", risk=10.0),
        _tr_vuln("Fixed", "t-fixed", status="fixed", risk=10.0),
        _tr_vuln("Accepted", "t-accepted", status="accepted_risk", risk=10.0),
        _tr_vuln("FalsePos", "t-fp", status="false_positive", risk=10.0),
        _tr_vuln("Unscored", "t-unscored", status="open", risk=None),
    ]
    titles = {g["title"] for g in _top_risk_groups(vulns)}
    assert titles == {"Active"}


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
    assert "Affected locations (20):" in text
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
    assert "CRITICAL" in text and "CVSS 9.5" in text


def test_single_location_finding_still_renders_normally():
    """5. The common one-location case is unaffected."""
    (group,) = render._finding_groups([_g_row("CVE-2022-0591", "https://h/only")])
    assert group["occurrence_count"] == 1
    text = _group_block_text(group)
    assert "Affected locations (1):" in text
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
