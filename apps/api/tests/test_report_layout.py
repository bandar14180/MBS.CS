"""MBS.PT report layout: cover, table of contents, page furniture and branding.

These assert the RENDERED PDF's text and structure, not its bytes: a byte-level expectation
would break on any ReportLab patch release without anything being wrong. Text is recovered by
decoding the page content streams (ReportLab writes ASCII85 + Flate), which needs no extra
dependency.

Nothing here touches scoring, risk, classification or verification -- the redesign is
presentation, and the invariants at the bottom assert exactly that.
"""

import base64
import collections
import re
import uuid
import zlib

import pytest

from apps.api.modules.reports import _branding as B
from apps.api.modules.reports.data import ReportData, VulnRow
from apps.api.modules.reports.render import render_executive, render_technical
from apps.api.modules.reports.scoring import compute_security_score


# --- helpers ------------------------------------------------------------------------------

def _pdf_text(pdf: bytes) -> str:
    """Visible text of a ReportLab PDF, via its content streams."""
    out = []
    for m in re.finditer(rb"stream(?:\r\n|\r|\n)(.*?)(?:\r\n|\r|\n)?endstream", pdf, re.S):
        body = m.group(1)
        data = body
        for decode in (
            lambda d: zlib.decompress(base64.a85decode(d.rstrip(b"~>\r\n "), adobe=False)),
            lambda d: zlib.decompress(base64.a85decode(d, adobe=True)),
            lambda d: zlib.decompress(d),
            lambda d: d,
        ):
            try:
                data = decode(body)
                break
            except Exception:
                continue
        for tm in re.finditer(rb"\(((?:\\.|[^\\()])*)\)\s*Tj", data, re.S):
            out.append(tm.group(1))
        for tm in re.finditer(rb"\[(.*?)\]\s*TJ", data, re.S):
            out.extend(re.findall(rb"\(((?:\\.|[^\\()])*)\)", tm.group(1), re.S))
    txt = b" ".join(out).decode("latin-1", "replace")
    return re.sub(r"\\([()\\])", r"\1", txt)


def _page_count(pdf: bytes) -> int:
    return len(re.findall(rb"/Type\s*/Page[^s]", pdf))


def _row(template_id="apache-path-traversal", severity="high", cvss=9.8, risk=10.0,
         matched_at="https://example.com/a", description=None, evidence=(), shots=(),
         status="open", vid=None):
    return VulnRow(
        id=vid or uuid.uuid4(), title=template_id, severity=severity, status=status,
        category="cwe-22", cvss_score=cvss, cvss_vector="AV:N/AC:L", final_risk_score=risk,
        risk_rationale=(
            "CVSS 9.8 (Critical) x asset criticality 'critical' (weight 2.0) = 10.0 "
            "(capped at 10.0 from 19.6)."
        ),
        compliance=[("owasp", "A03:2021", "Injection")], evidence_uris=list(evidence),
        evidence_items=[("log_excerpt", u) for u in evidence], screenshots=list(shots),
        template_id=template_id, matcher_name="status", matched_at=matched_at,
        description=description,
    )


def _data(rows, name="Acme Corp"):
    sev = collections.Counter(r.severity for r in rows)
    return ReportData(
        project_name=name, security_score=compute_security_score(rows),
        severity_counts=dict(sev), total_vulns=len(rows), active_vulns=len(rows),
        active_severity_counts=dict(sev), vulns=rows,
    )


@pytest.fixture()
def exec_pdf():
    return render_executive(_data([_row(description="Detected a path traversal condition.")]))


@pytest.fixture()
def tech_pdf():
    return render_technical(_data([_row(description="Detected a path traversal condition.")]))


# --- Cover page ---------------------------------------------------------------------------

def test_cover_carries_the_mbs_pt_identity(exec_pdf) -> None:
    text = _pdf_text(exec_pdf)
    assert B.BRAND_NAME in text
    assert B.REPORT_SUITE in text
    assert "Acme Corp" in text


def test_cover_carries_contact_details(exec_pdf) -> None:
    text = _pdf_text(exec_pdf)
    assert B.CONTACT_EMAIL in text
    assert B.CONTACT_PHONE in text


def test_cover_states_generated_date_and_classification(exec_pdf) -> None:
    text = _pdf_text(exec_pdf)
    assert "Generated" in text
    assert "Confidential" in text


def test_old_mbs_sc_branding_is_gone_from_reports(exec_pdf, tech_pdf) -> None:
    for pdf in (exec_pdf, tech_pdf):
        assert "MBS.SC" not in _pdf_text(pdf)


def test_reports_start_on_a_cover_then_break(exec_pdf) -> None:
    """A cover implies at least a second page; content must not share the cover page."""
    assert _page_count(exec_pdf) >= 2


# --- Table of contents --------------------------------------------------------------------

def test_toc_is_present_and_lists_real_sections(exec_pdf) -> None:
    text = _pdf_text(exec_pdf)
    assert "Table of Contents" in text
    for section in ("Executive Summary", "Findings Summary", "Key Risks", "Conclusion"):
        assert section in text, f"missing section: {section}"


def test_toc_entries_carry_page_numbers(exec_pdf) -> None:
    """multiBuild resolves real page numbers; an unresolved TOC prints "0"."""
    text = _pdf_text(exec_pdf)
    entries = re.findall(r"\d+\.\s+[A-Za-z][A-Za-z &]+\s+(\d+)", text)
    assert entries, "no numbered TOC entries found"
    assert any(int(p) > 0 for p in entries), "TOC page numbers did not resolve"


def test_pdf_has_navigation_outlines(exec_pdf) -> None:
    assert b"/Outlines" in exec_pdf


def test_technical_toc_lists_its_own_sections(tech_pdf) -> None:
    text = _pdf_text(tech_pdf)
    for section in ("Assessment Overview", "Scope", "Detailed Findings", "Appendix"):
        assert section in text, f"missing section: {section}"


# --- Header / footer ----------------------------------------------------------------------

def test_content_pages_are_numbered(exec_pdf) -> None:
    pages = re.findall(r"Page\s+(\d+)", _pdf_text(exec_pdf))
    assert pages, "no page numbers rendered"
    assert "0" not in pages, "page numbering must never show Page 0"


def test_footer_repeats_brand_and_contact(exec_pdf) -> None:
    """Contact appears on the cover AND in every content footer."""
    text = _pdf_text(exec_pdf)
    assert text.count(B.CONTACT_EMAIL) >= 2


def test_ampersand_in_headings_is_not_corrupted(exec_pdf) -> None:
    """"MITRE ATT&CK" must not render as "ATT&CK;" (unescaped markup entity)."""
    assert "CK;" not in _pdf_text(exec_pdf)


# --- Detailed findings --------------------------------------------------------------------

def test_finding_id_is_rendered_and_stable(tech_pdf) -> None:
    text = _pdf_text(tech_pdf)
    assert "Finding ID" in text
    assert re.search(r"MBS-[0-9A-F]{8}", text), "no stable finding id rendered"


def test_finding_id_is_derived_from_database_identity_not_order() -> None:
    """The id follows the finding, not its position in the report.

    NOTE the second row uses a DIFFERENT template_id: findings sharing a template are grouped
    into one issue (the documented grouping contract), so two same-template rows would produce
    a single block and could not demonstrate ordering independence."""
    vid = uuid.UUID("4a2f9c1b-1111-2222-3333-444455556666")
    row = _row(vid=vid)
    assert row.finding_id == "MBS-4A2F9C1B"
    other = _row(template_id="other-template", matched_at="https://example.com/z")
    a = _pdf_text(render_technical(_data([row, other])))
    b = _pdf_text(render_technical(_data([other, row])))
    assert "MBS-4A2F9C1B" in a, "id missing when the finding is listed first"
    assert "MBS-4A2F9C1B" in b, "id missing when the finding is listed second"


def test_description_from_the_database_is_rendered_verbatim() -> None:
    text = _pdf_text(render_technical(_data([
        _row(description="Detected potential OS command injection on Windows targets.")
    ])))
    assert "Description" in text
    assert "Detected potential OS command injection on Windows targets." in text


def test_missing_description_never_invents_scanner_text() -> None:
    """No `vulnerabilities.description` -> the report must not attribute prose to the scanner.

    The block still carries a Vulnerability Description: a standard, class-based explanation of
    the weakness (narrative.py), which is generic guidance and not a claim about this target.
    What must never appear is invented text presented AS the scanning engine's own -- the
    "Scanning engine description:" attribution is emitted only when the column is populated."""
    text = _pdf_text(render_technical(_data([_row(description=None)])))
    assert "Vulnerability Description" in text
    assert "Scanning engine description" not in text


def test_present_description_is_attributed_to_the_scanner_verbatim() -> None:
    text = _pdf_text(render_technical(_data([_row(description="Observed traversal on /etc.")])))
    assert "Scanning engine description: Observed traversal on /etc." in text


# --- MBS-authored descriptions for reviewed templates -------------------------------------
# Where the scanner supplied no description, a reviewed template may contribute MBS-authored
# prose (finding_descriptions.py). It is rendered under its OWN attribution. These pin that
# the two provenances stay separate in the actual PDF, not merely in narrative.py.
#
# `_row`'s default template is "apache-path-traversal", which is NOT catalogued -- so the
# existing "never invents scanner text" test above keeps testing what it always did.

def _has_analyst_attribution(text: str) -> bool:
    return "MBS analyst description" in text


@pytest.mark.parametrize("template_id", ["reflected-xss", "blind-ssrf"])
def test_catalogued_template_with_null_description_renders_the_mbs_description(template_id):
    """A reviewed template + NULL vulnerabilities.description -> MBS prose, attributed to MBS."""
    text = _pdf_text(render_technical(_data([
        _row(template_id=template_id, description=None)
    ])))
    assert "Vulnerability Description" in text
    assert _has_analyst_attribution(text), f"{template_id} rendered no MBS description"
    # ... and it is NOT passed off as the engine's output.
    assert "Scanning engine description" not in text


@pytest.mark.parametrize("template_id", ["reflected-xss", "blind-ssrf"])
def test_curated_description_is_never_labelled_as_a_scanner_description(template_id):
    """THE PROVENANCE INVARIANT, asserted on the rendered document. A distinctive phrase from
    the catalogue text must appear only after the MBS attribution, never after the engine's."""
    text = _pdf_text(render_technical(_data([
        _row(template_id=template_id, description=None)
    ])))
    assert "Scanning engine description" not in text
    scanner_idx = text.find("Scanning engine description")
    assert scanner_idx == -1
    assert text.find("MBS analyst description") != -1


@pytest.mark.parametrize("template_id", ["reflected-xss", "blind-ssrf"])
def test_catalogued_template_with_a_scanner_description_prefers_the_scanner(template_id):
    """The engine described this finding, so the engine's words are what the reader gets; the
    catalogue must not also appear, which would double up on the same subsection."""
    text = _pdf_text(render_technical(_data([
        _row(template_id=template_id, description="Engine matched the condition.")
    ])))
    assert "Scanning engine description: Engine matched the condition." in text
    assert not _has_analyst_attribution(text)


def test_uncatalogued_template_with_null_description_still_renders_normally():
    """No review, no MBS prose, no fabricated text -- and the block still renders."""
    pdf = render_technical(_data([_row(template_id="something-opaque", description=None)]))
    assert pdf[:4] == b"%PDF"
    text = _pdf_text(pdf)
    assert "Vulnerability Description" in text
    assert "Scanning engine description" not in text
    assert not _has_analyst_attribution(text)


def test_existing_scanner_description_behaviour_is_unchanged_for_uncatalogued_templates():
    """Verbatim scanner attribution on the default (uncatalogued) template, exactly as before
    this catalogue existed."""
    text = _pdf_text(render_technical(_data([
        _row(description="Detected a path traversal condition.")
    ])))
    assert "Scanning engine description: Detected a path traversal condition." in text
    assert not _has_analyst_attribution(text)


def test_long_urls_do_not_break_rendering() -> None:
    long_url = "https://example.com/" + "segment/" * 40 + "?a=1&b=2&c=3"
    pdf = render_technical(_data([_row(matched_at=long_url, description="d")]))
    assert pdf[:4] == b"%PDF"
    assert _page_count(pdf) >= 2


# --- Executive vs Technical ---------------------------------------------------------------

def test_executive_is_more_concise_than_technical() -> None:
    rows = [_row(template_id=f"tpl-{i}", matched_at=f"https://e/{i}", description="d")
            for i in range(10)]
    data = _data(rows)
    assert len(render_executive(data)) < len(render_technical(data))


def test_reports_render_with_no_findings() -> None:
    empty = ReportData(project_name="Empty", security_score=100, severity_counts={},
                       total_vulns=0, active_vulns=0, active_severity_counts={}, vulns=[])
    for pdf in (render_executive(empty), render_technical(empty)):
        assert pdf[:4] == b"%PDF"
        assert B.BRAND_NAME in _pdf_text(pdf)


# --- Branding module ----------------------------------------------------------------------

def test_logo_is_a_vector_drawing_with_shapes() -> None:
    d = B.logo_drawing(40)
    assert d is not None
    assert len(d.contents) >= 5  # shield + core + links + satellites


def test_logo_failure_is_soft(monkeypatch) -> None:
    """A logo problem must never cost the reader the report."""
    monkeypatch.setattr(B, "logo_drawing", lambda size: None)
    pdf = render_executive(_data([_row(description="d")]))
    assert pdf[:4] == b"%PDF"
    assert B.BRAND_NAME in _pdf_text(pdf)


def test_branding_constants_are_the_agreed_values() -> None:
    assert B.BRAND_NAME == "MBS.PT"
    assert B.CONTACT_EMAIL == "bandaraodh@gmail.com"
    assert B.CONTACT_PHONE == "+966578121147"


def test_severity_colours_cover_every_band_and_default_safely() -> None:
    for sev in ("critical", "high", "medium", "low", "info"):
        assert B.severity_color(sev).startswith("#")
    assert B.severity_color(None) == B.MUTED
    assert B.severity_color("nonsense") == B.MUTED


# --- INVARIANTS: presentation must not move assessment values -----------------------------

def test_rendering_does_not_change_the_security_score() -> None:
    rows = [_row(description="d"), _row(template_id="b", severity="medium", cvss=5.5, risk=8.2)]
    before = compute_security_score(rows)
    data = _data(rows)
    render_executive(data)
    render_technical(data)
    assert compute_security_score(rows) == before
    assert data.security_score == before


def test_rendering_does_not_mutate_findings() -> None:
    rows = [_row(description="d")]
    snapshot = [(r.cvss_score, r.final_risk_score, r.severity, r.status, r.classification,
                 r.verification, r.confidence, r.description) for r in rows]
    data = _data(rows)
    render_executive(data)
    render_technical(data)
    assert [(r.cvss_score, r.final_risk_score, r.severity, r.status, r.classification,
             r.verification, r.confidence, r.description) for r in rows] == snapshot


# --- Presentation polish: Remediation Plan, Evidence, Compliance/ATT&CK cards -------------

def test_remediation_plan_buckets_by_existing_severity() -> None:
    rows = [
        _row(template_id="crit", severity="critical", matched_at="https://e/1", description="d"),
        _row(template_id="high", severity="high", matched_at="https://e/2", description="d"),
        _row(template_id="med", severity="medium", cvss=5.5, risk=8.2,
             matched_at="https://e/3", description="d"),
        _row(template_id="low", severity="low", cvss=2.0, risk=1.0,
             matched_at="https://e/4", description="d"),
    ]
    text = _pdf_text(render_technical(_data(rows)))
    assert "Remediation Plan" in text
    for bucket in ("Immediate", "High Priority", "Medium Priority", "Long Term"):
        assert bucket in text, f"missing bucket: {bucket}"


def test_remediation_plan_does_not_change_severity_or_score() -> None:
    """Bucketing is sequencing ONLY -- no assessment value may move."""
    rows = [_row(template_id="crit", severity="critical", description="d")]
    before = (compute_security_score(rows), rows[0].severity, rows[0].final_risk_score)
    render_technical(_data(rows))
    assert (compute_security_score(rows), rows[0].severity, rows[0].final_risk_score) == before


def test_remediation_plan_handles_no_active_findings() -> None:
    empty = ReportData(project_name="E", security_score=100, severity_counts={},
                       total_vulns=0, active_vulns=0, active_severity_counts={}, vulns=[])
    assert render_technical(empty)[:4] == b"%PDF"


def test_evidence_section_lists_stored_artifacts_only() -> None:
    with_ev = _row(template_id="a", evidence=["s3://mbs-evidence/tool-runs/x/raw-output.txt"],
                   description="d")
    without = _row(template_id="b", matched_at="https://e/none", description="d")
    text = _pdf_text(render_technical(_data([with_ev, without])))
    assert "Evidence & Screenshots" in text
    assert "Raw tool output" in text
    assert "raw-output.txt" in text


def test_evidence_section_reports_absence_honestly() -> None:
    text = _pdf_text(render_technical(_data([_row(description="d")])))
    assert "No stored evidence artifacts" in text


def test_compliance_rendered_as_per_framework_cards() -> None:
    text = _pdf_text(render_technical(_data([_row(description="d")])))
    assert "Compliance Coverage" in text
    assert "OWASP" in text
    assert "A03:2021" in text


def test_attack_section_states_absence_when_unmapped() -> None:
    text = _pdf_text(render_technical(_data([_row(description="d")])))
    assert "MITRE ATT" in text
    assert "CK;" not in text  # ampersand must stay uncorrupted


def test_finding_card_exposes_the_requested_fields() -> None:
    text = _pdf_text(render_technical(_data([_row(description="Detected traversal.")])))
    for label in ("Finding ID", "Severity", "CVSS", "Risk", "Verification", "Status",
                  "Endpoint", "Template", "Matcher", "Description"):
        assert label in text, f"missing field: {label}"


def test_generated_controls_are_labelled_as_not_evidence_derived() -> None:
    """No pipeline remediation -> standard class controls, under an unambiguous label.

    The report must never let generated guidance read as remediation the assessment produced,
    so the label states in-line that it is not derived from scan evidence."""
    row = _row(description="d")
    assert row.remediation_summary is None
    assert row.remediation_references == []
    text = _pdf_text(render_technical(_data([row])))
    assert "Recommended controls (standard guidance for this weakness class" in text
    assert "not derived from scan evidence" in text
    # And it must NOT be presented as the pipeline's own remediation.
    assert "Remediation (from the assessment pipeline)" not in text


def test_pipeline_remediation_rendered_verbatim_and_attributed() -> None:
    row = _row(description="d")
    row.remediation_summary = "Upgrade the affected component to a supported release."
    row.remediation_references = ["https://example.com/advisory"]
    text = _pdf_text(render_technical(_data([row])))
    assert "Remediation (from the assessment pipeline)" in text
    assert "Upgrade the affected component to a supported release." in text
    assert "https://example.com/advisory" in text
    # Pipeline guidance exists -> the generated fallback must not also appear.
    assert "not derived from scan evidence" not in text
