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

def test_score_perfect_when_no_active() -> None:
    assert compute_security_score({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}) == 100


def test_score_penalizes_by_severity() -> None:
    assert compute_security_score({"critical": 1}) == 75  # 100 - 25
    assert compute_security_score({"high": 1, "medium": 2}) == 100 - 15 - 14
    assert compute_security_score({"info": 5}) == 100  # info costs nothing


def test_score_floors_at_zero() -> None:
    assert compute_security_score({"critical": 10}) == 0


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
    block = render._finding_block(1, v, styles, colors, Paragraph, Table, TableStyle, mm)

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
    assert "Matched at: https://x/a?p=1" in text
    assert "Status: open" in text
    # And the whole report still renders to a valid PDF.
    data = ReportData(
        project_name="P", security_score=0,
        severity_counts={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        total_vulns=1, active_vulns=1, vulns=[row],
    )
    assert render.render("technical", data)[:5] == b"%PDF-"


def test_two_findings_same_everything_but_matched_at_show_their_own_url():
    """The whole point: two findings sharing title/severity/template/matcher but DIFFERENT
    URLs each render their own matched_at -- not duplicates."""
    a = _vuln_row_with_fingerprint("unix-command-injection|time-based|https://x/a?p=1")
    b = _vuln_row_with_fingerprint("unix-command-injection|time-based|https://x/b?p=2")
    # Same on every axis except the URL.
    assert (a.title, a.severity, a.template_id, a.matcher_name) == \
           (b.title, b.severity, b.template_id, b.matcher_name)
    assert a.matched_at != b.matched_at

    text_a = _finding_block_text(a)
    text_b = _finding_block_text(b)
    # Each block shows ITS OWN url and not the other's.
    assert "Matched at: https://x/a?p=1" in text_a and "https://x/b?p=2" not in text_a
    assert "Matched at: https://x/b?p=2" in text_b and "https://x/a?p=1" not in text_b

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
    assert ("Matched at: https://universities.brightvision-og.com/university/"
            "nilai-university/?lang=|dir") in text
    assert "Matched at: dir" not in text          # never the mangled tail
    assert "Template: windows-command-injection" in text
    assert "Matcher: time-based" in text


def test_report_renders_na_when_location_is_unavailable():
    """A finding with no parseable fingerprint (older/non-nuclei) must render N/A, not crash."""
    row = _vuln_row_with_fingerprint("legacy-hash-only")   # -> matcher/matched None
    assert row.matcher_name is None and row.matched_at is None
    text = _finding_block_text(row)
    assert "Template: legacy-hash-only" in text    # the one part it could recover
    assert "Matcher: N/A" in text
    assert "Matched at: N/A" in text
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
        assert "Matched at: N/A" in text


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
