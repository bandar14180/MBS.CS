"""Detection vs Vulnerability classification (P1.5) and its ATT&CK boundary (P1.6)."""

import uuid

from apps.api.modules.attack.catalog import techniques_for
from apps.api.modules.reports import render
from apps.api.modules.reports.classification import (
    DETECTION,
    VULNERABILITY,
    classify,
    classify_row,
)
from apps.api.modules.reports.data import VulnRow


def _row(template_id, severity, cvss, category=None, tool_name="nuclei", **kw):
    return VulnRow(
        id=uuid.uuid4(), title=kw.pop("title", f"{template_id} finding"), severity=severity,
        status="open", category=category, cvss_score=cvss, cvss_vector=None,
        final_risk_score=kw.pop("final_risk_score", None), risk_rationale=None,
        compliance=[], evidence_uris=[], template_id=template_id, matched_at="https://h/a",
        tool_name=tool_name, **kw,
    )


# --- A. Detection is classified as detection ---------------------------------------------

def test_detection_templates_are_detections():
    for tid, cat in [
        ("tech-detect", "cwe-200"),
        ("waf-detect", "cwe-200"),
        ("nginx-version", None),
        ("apollo-server-detect", "cwe-200"),
        ("fingerprinthub-web-fingerprints", "cwe-200"),
        ("nginx-eol", None),
    ]:
        assert classify(template_id=tid, cvss_score=0.0, category=cat) == DETECTION, tid


# --- B. Real vulnerability is classified as vulnerability --------------------------------

def test_real_vulnerabilities_are_vulnerabilities():
    assert classify(template_id="unix-command-injection", cvss_score=9.8, category="cwe-78") == VULNERABILITY
    assert classify(template_id="time-based-sqli", cvss_score=9.5) == VULNERABILITY
    assert classify(template_id="CVE-2022-0591", cvss_score=9.1, cve="CVE-2022-0591") == VULNERABILITY


def test_never_classifies_on_severity_alone():
    """An info finding with a real weakness CWE is NOT a bare detection."""
    # missing security headers: info severity, cwe-693, but a genuine weakness.
    assert classify(template_id="http-missing-security-headers", cvss_score=0.0, category="cwe-693") == VULNERABILITY
    # a high finding is never forced to detection just by its template text.
    assert classify(template_id="unix-command-injection", cvss_score=9.8) == VULNERABILITY


def test_cvss_or_cve_or_exploit_tag_outranks_detection_markers():
    # even a 'detect'-named template with a real CVSS is a vulnerability (fail toward vuln).
    assert classify(template_id="some-detect", cvss_score=8.0) == VULNERABILITY
    assert classify(template_id="x", cvss_score=None, cve="CVE-2021-1") == VULNERABILITY
    assert classify(template_id="x", cvss_score=None, tags=["sqli"]) == VULNERABILITY


def test_classify_row_reads_a_vulnrow():
    assert classify_row(_row("waf-detect", "info", 0.0, "cwe-200")) == DETECTION
    assert classify_row(_row("unix-command-injection", "high", 9.8, "cwe-78")) == VULNERABILITY


# --- C. Detection does NOT get CWE-derived ATT&CK mappings -------------------------------

def test_detection_gets_no_attack_techniques():
    assert techniques_for("cwe-200", ["waf"], template_id="waf-detect", cve=None) == []
    assert techniques_for("cwe-200", ["tech"], template_id="tech-detect", cve=None) == []


# --- D. Real vulnerability RETAINS valid ATT&CK mappings ---------------------------------

def test_vulnerability_retains_attack_techniques():
    ids = [t[1] for t in techniques_for("cwe-78", ["rce"], template_id="unix-command-injection", cve=None)]
    assert "T1190" in ids and "T1059" in ids  # command injection techniques preserved


def test_techniques_for_backward_compatible_without_metadata():
    """Old callers (category/tags only) keep the historical mapping -- classifier not consulted."""
    assert [t[1] for t in techniques_for("cwe-200")] == ["T1592"]
    assert set(t[1] for t in techniques_for("cwe-78")) == {"T1190", "T1059"}


# --- E. Technical report shows the tool + type ------------------------------------------

def _tech_block_text(row):
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Table, TableStyle

    styles = render._styles(getSampleStyleSheet, ParagraphStyle, colors)
    (g,) = render._finding_groups([row])
    block = render._finding_block(1, g, styles, colors, Paragraph, Table, TableStyle, mm)
    texts = []

    def _walk(f):
        c = getattr(f, "_content", None)
        if c is not None:
            for ch in c:
                _walk(ch)
            return
        t = getattr(f, "text", None)
        if t is not None:
            texts.append(str(t))

    _walk(block)
    return "\n".join(texts)


def test_technical_report_shows_tool_and_vulnerability_type():
    row = _row("unix-command-injection", "high", 9.8, "cwe-78", tool_name="nuclei-dast",
               final_risk_score=10.0)
    text = _tech_block_text(row)
    assert "Tool: nuclei-dast" in text
    assert "Type: VULNERABILITY" in text


def test_technical_report_labels_a_detection():
    row = _row("waf-detect", "info", 0.0, "cwe-200", tool_name="nuclei")
    text = _tech_block_text(row)
    assert "Type: DETECTION" in text
    assert "Tool: nuclei" in text


def test_tool_name_falls_back_to_na():
    row = _row("x", "high", 9.8, tool_name="N/A")
    assert "Tool: N/A" in _tech_block_text(row)


def test_group_is_vulnerability_if_any_member_is():
    """A template that is a real weakness anywhere is never downgraded to a bare detection."""
    a = _row("t", "info", 0.0, "cwe-200")            # -> detection on its own
    b = _row("t", "high", 9.8, "cwe-78")             # -> vulnerability
    (g,) = render._finding_groups([a, b])
    assert g["classification"] == "vulnerability"


# --- F/G/H. Guardrails: the fixes must not disturb scoring/CVSS/risk ---------------------

def test_cvss_none_vs_zero_unchanged():
    from apps.api.modules.reports.scoring import _cvss_factor
    assert _cvss_factor(None) == 1.0      # None neutral
    assert _cvss_factor(0.0) == 0.75      # 0.0 real


def test_info_still_excluded_from_scoring():
    from apps.api.modules.reports.scoring import compute_security_score, is_scorable
    assert is_scorable(_row("waf-detect", "info", 0.0)) is False
    assert compute_security_score([_row("tech-detect", "info", 0.0) for _ in range(19)]) == 100


def test_final_risk_independent_from_cvss():
    from apps.api.modules.risk.service import compute_risk
    r = compute_risk(9.8, "critical")
    assert r.business_impact_score == 9.8         # CVSS preserved
    assert r.final_risk_score == 10.0             # min(10, 9.8*2.0), a distinct value
    assert r.final_risk_score != r.business_impact_score
