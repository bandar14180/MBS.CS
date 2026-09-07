"""Detection vs Vulnerability classification (P1.5) and its ATT&CK boundary (P1.6)."""

import datetime
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

    def _plain(node) -> str:
        """Text of one flowable, recursing into nested cards."""
        c = getattr(node, "_content", None)
        if c is not None:
            return " ".join(x for x in (_plain(ch) for ch in c) if x)
        cells = getattr(node, "_cellvalues", None)
        if cells is not None:
            return " ".join(
                x for x in (_plain(cell) for row in cells for cell in row) if x
            )
        t = getattr(node, "text", None)
        if t is not None:
            return str(t)
        return str(node) if isinstance(node, str) else ""

    def _walk(f):
        c = getattr(f, "_content", None)
        if c is not None:
            for ch in c:
                _walk(ch)
            return
        # Finding metadata now lives in label/value CARDS (Tables). Re-joined as
        # "Label: value" so this helper reports what the block actually renders; without
        # this it silently loses the whole metadata card.
        cells = getattr(f, "_cellvalues", None)
        if cells is not None:
            for row in cells:
                parts = [p for p in (_plain(cell) for cell in row) if p]
                if len(parts) == 2:
                    texts.append(f"{parts[0]}: {parts[1]}")
                elif parts:
                    texts.append(" ".join(parts))
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


# --- P1-4: cve / tags must reach the classifier -------------------------------------------
# classify_row used to pass only (template_id, cvss_score, category), dropping the two
# STRONGEST vulnerability signals. That broke the module's own guarantee ("positive
# vulnerability signals outrank the detection markers"): a CVE-backed finding whose CVSS was
# absent and whose template name contained "detect" was classified DETECTION -- hiding a real
# weakness. `cve` is not a column on `vulnerabilities` (the runner's metadata is consumed by
# sync_attack_mappings and discarded), so classify_row also RECOVERS it from the persisted
# template_id/title. Recovery is additive: it can only turn DETECTION into VULNERABILITY.

def test_cve_with_no_cvss_is_a_vulnerability():
    """Explicit cve, no CVSS -- the CVE alone must decide."""
    assert classify(template_id="x", cvss_score=None, cve="CVE-2021-41773") == VULNERABILITY


def test_cve_in_a_detection_named_template_is_a_vulnerability():
    """THE regression: a 'detect'-marked template that is really a CVE finding."""
    row = _row("apache-detect-cve-2021-41773", "high", None,
               title="CVE-2021-41773 Path Traversal")
    assert classify_row(row) == VULNERABILITY


def test_cve_recovered_from_title_when_template_has_none():
    row = _row("some-detect", "high", None, title="Apache CVE-2021-41773 Path Traversal")
    assert classify_row(row) == VULNERABILITY


def test_explicit_cve_on_the_row_is_honoured():
    row = _row("some-detect", "high", None, title="No id here")
    row.cve = "CVE-2021-41773"
    assert classify_row(row) == VULNERABILITY


def test_detection_template_without_a_cve_stays_a_detection():
    """The guard must not be weakened: no CVE anywhere -> still a detection."""
    assert classify_row(_row("tech-detect", "low", None, title="Apache Detection")) == DETECTION
    assert classify_row(_row("nginx-version", "info", None, title="nginx version")) == DETECTION


def test_waf_detection_with_generic_cwe_stays_a_detection():
    """A generic CWE is NOT vulnerability evidence -- category alone must not flip it."""
    row = _row("waf-detect", "low", None, category="cwe-200", title="WAF Detection")
    assert classify_row(row) == DETECTION


def test_tags_reach_the_classifier_through_the_row():
    """An exploit tag on the row is vulnerability evidence; detection-only tags are not."""
    exploit = _row("some-detect", "high", None, title="t")
    exploit.tags = ["sqli"]
    assert classify_row(exploit) == VULNERABILITY

    detect_only = _row("some-detect", "high", None, title="t")
    detect_only.tags = ["tech", "detect"]
    assert classify_row(detect_only) == DETECTION


def test_cve_recovery_does_not_match_arbitrary_hyphenated_text():
    """`_recover_cve` must not fire on look-alike strings."""
    from apps.api.modules.reports.classification import _recover_cve

    assert _recover_cve("not-a-cve-12") is None
    assert _recover_cve("tech-detect") is None
    assert _recover_cve("apache-detect-cve-2021-41773") is not None


def test_classify_row_tolerates_rows_without_cve_or_tags():
    """A row-like stub lacking the new attributes must classify exactly as before."""
    class Bare:
        template_id = "tech-detect"
        cvss_score = None
        category = None
        title = "Apache Detection"

    assert classify_row(Bare()) == DETECTION


# =========================================================================================
# P2-3 -- classification is exposed on the API, derived from the canonical classifier
# =========================================================================================
# P1 made DETECTION findings non-scorable. Without this field a client sees an open
# medium-severity finding that contributes nothing to the security score and has no way to
# tell why -- the PDF said DETECTION, the API did not. The field is DERIVED on read (not a
# column): it is a pure function of data already stored, so persisting it would go stale
# whenever the classifier changes and would need a migration plus a backfill.


def _orm_vuln(fingerprint, title, cvss, category=None, severity="medium", status="open"):
    """A stand-in for the ORM Vulnerability row that VulnerabilityRead validates from."""

    class _V:
        pass

    v = _V()
    v.id = uuid.uuid4()
    v.project_id = uuid.uuid4()
    v.asset_id = None
    v.first_detected_scan_id = None
    v.last_seen_scan_id = None
    v.fingerprint = fingerprint
    v.title = title
    v.category = category
    v.description = None
    v.severity = severity
    v.cvss_vector = None
    v.cvss_score = cvss
    v.status = status
    v.status_justification = None
    v.ai_validated = False
    v.ai_confidence = None
    v.created_at = datetime.datetime.now(datetime.timezone.utc)
    v.updated_at = datetime.datetime.now(datetime.timezone.utc)
    return v


def _classification_of(fingerprint, title, cvss, category=None):
    from apps.api.modules.vulnerabilities.schemas import VulnerabilityRead

    return VulnerabilityRead.model_validate(
        _orm_vuln(fingerprint, title, cvss, category)
    ).classification


def test_api_exposes_classification_field():
    from apps.api.modules.vulnerabilities.schemas import VulnerabilityRead

    dumped = VulnerabilityRead.model_validate(
        _orm_vuln("tech-detect|m|https://h/", "Apache Detection", None, "cwe-200")
    ).model_dump()
    assert "classification" in dumped


def test_api_marks_a_technology_detection_as_detection():
    assert _classification_of("tech-detect|m|https://h/", "Apache Tomcat", None, "cwe-200") == "detection"


def test_api_marks_a_waf_detection_as_detection():
    assert _classification_of("waf-detect|m|https://h/", "WAF Detection", None, "cwe-200") == "detection"


def test_api_marks_a_real_vulnerability_as_vulnerability():
    assert _classification_of("unix-command-injection|m|https://h/", "Command Injection", 9.8, "cwe-78") == "vulnerability"


def test_api_cve_recovery_regression():
    """P1's _recover_cve must still apply through the API path: a CVE in a detection-named
    template is a VULNERABILITY, never hidden as a bare detection."""
    assert _classification_of(
        "apache-detect-cve-2021-41773|m|https://h/", "CVE-2021-41773 Path Traversal", None
    ) == "vulnerability"


def test_api_cve_recovered_from_title():
    assert _classification_of("some-detect|m|https://h/", "Apache CVE-2021-41773 Traversal", None) == "vulnerability"


def test_api_detection_guard_not_weakened_by_a_generic_cwe():
    """A generic CWE is not vulnerability evidence -- it must not flip a detection."""
    assert _classification_of("tech-detect|m|https://h/", "nginx", None, "cwe-200") == "detection"


def test_api_classification_matches_the_report_classifier_exactly():
    """No duplicated rules: the API must agree with the canonical classifier on every case."""
    from apps.api.modules.reports.classification import classify_row
    from apps.api.modules.reports.data import _parse_fingerprint

    cases = [
        ("tech-detect|m|https://h/", "Apache", None, "cwe-200"),
        ("waf-detect|m|https://h/", "WAF", None, "cwe-200"),
        ("unix-command-injection|m|https://h/", "CI", 9.8, "cwe-78"),
        ("apache-detect-cve-2021-41773|m|https://h/", "CVE-2021-41773", None, None),
        ("nginx-version|m|https://h/", "nginx version", None, None),
    ]
    for fingerprint, title, cvss, category in cases:
        template_id, _matcher, _matched = _parse_fingerprint(fingerprint)

        class _Row:
            pass

        row = _Row()
        row.template_id = template_id
        row.title = title
        row.cvss_score = cvss
        row.category = category

        assert _classification_of(fingerprint, title, cvss, category) == classify_row(row), fingerprint


def test_api_classification_is_backward_compatible():
    """Every pre-existing field is still present -- the change is purely additive."""
    from apps.api.modules.vulnerabilities.schemas import VulnerabilityRead

    dumped = VulnerabilityRead.model_validate(
        _orm_vuln("unix-command-injection|m|https://h/", "CI", 9.8, "cwe-78")
    ).model_dump()
    for field in ("id", "project_id", "fingerprint", "title", "severity", "cvss_score",
                  "cvss_vector", "status", "category", "created_at", "updated_at"):
        assert field in dumped


def test_api_classification_handles_a_legacy_fingerprint():
    """A non-nuclei row (bare hash, no pipes) has no template_id and must not raise."""
    assert _classification_of("bare-legacy-hash", "Legacy finding", None) in {"vulnerability", "detection"}


def test_api_detection_is_excluded_from_the_security_score():
    """The field explains real behaviour: what the API calls a detection is what the score drops."""
    from apps.api.modules.reports.scoring import is_scorable

    class _Row:
        template_id = "tech-detect"
        title = "Apache Tomcat"
        cvss_score = None
        category = "cwe-200"
        severity = "medium"
        status = "open"

    assert _classification_of("tech-detect|m|https://h/", "Apache Tomcat", None, "cwe-200") == "detection"
    assert is_scorable(_Row()) is False
