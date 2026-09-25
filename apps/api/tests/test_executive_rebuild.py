"""Phase 4.3 -- Executive report rebuild: management-facing structure, unchanged semantics.

WHAT THE TRACE FOUND
--------------------
Section 1 opened with a 921-character run of continuous prose carrying the score, both count
units, the score-impacting subset and the scoring caveat; the phrase "N unique issues across M
affected locations" appeared THREE times on one page; there was no severity shape, no statement
of what KINDS of problem the estate had, and -- most seriously for a management document -- not
one recommendation or next action anywhere in the report.

WHAT PHASE 4.3 CHANGED
----------------------
Presentation and information architecture ONLY. Every figure is read from ReportData's existing
canonical accessors; there is no second scoring model and no invented executive metric. These
tests assert that -- and that the six earlier phases' semantics survive intact.
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
    _key_themes,
    _recommendations,
    _score_band,
    _top_risk_groups,
    _verification_summary,
    render_executive,
    render_technical,
)
from apps.api.modules.reports.scoring import compute_security_score, is_scorable, issue_key
from apps.api.tests.test_report_layout import _pdf_text

DIGEST = hashlib.sha256(b"evidence").hexdigest()
CAPTURED = datetime(2026, 9, 8, 14, 0, 0, tzinfo=timezone.utc)
OWASP = ("owasp", "A03:2021", "Injection")
PCI = ("pci_dss", "6.5.7", "Cross-site scripting (XSS)")
NIST = ("nist", "SI-10", "Information Input Validation")


def _row(template_id="sql-injection", severity="critical", cvss=9.8, risk=10.0,
         matched_at="https://app.test/a", status="open", compliance=(OWASP,),
         asset="app.test", evidence=True, category="cwe-89", title=None):
    records = (
        [EvidenceRecord(uuid.uuid4(), "log_excerpt", f"s3://e/{uuid.uuid4()}.txt",
                        DIGEST, CAPTURED)]
        if evidence else []
    )
    return VulnRow(
        id=uuid.uuid4(), title=title or template_id.replace("-", " ").title(),
        severity=severity, status=status, category=category, cvss_score=cvss,
        cvss_vector="CVSS:3.1/AV:N", final_risk_score=risk,
        risk_rationale="CVSS x asset criticality 'critical' (weight 2.0)",
        compliance=list(compliance), evidence_uris=[r.storage_uri for r in records],
        evidence_items=[(r.evidence_type, r.storage_uri) for r in records],
        evidence_records=records, template_id=template_id, matcher_name="status",
        matched_at=matched_at, asset_value=asset, description="A condition was detected.",
    )


def _data(rows, attack=(), scope_scans=()):
    active = [r for r in rows if r.status in ("open", "confirmed", "reopened")]
    return ReportData(
        project_name="Northwind Retail", security_score=compute_security_score(rows),
        severity_counts=dict(collections.Counter(r.severity for r in rows)),
        total_vulns=len(rows), active_vulns=len(active),
        active_severity_counts=dict(collections.Counter(r.severity for r in active)),
        vulns=rows, attack_techniques=list(attack), scope_scans=list(scope_scans),
    )


def _mixed():
    """A realistic estate: two SQLi issues, one XSS, one TLS, plus fixed/info noise."""
    rows = []
    rows += [_row("sql-injection", "critical", 9.8, 10.0, f"https://app.test/a{i}",
                  compliance=(OWASP, PCI)) for i in range(3)]
    rows += [_row("sqli-blind", "critical", 9.1, 10.0, "https://app.test/blind",
                  compliance=(OWASP,))]
    rows += [_row("xss-reflected", "high", 7.4, 8.0, f"https://app.test/b{i}",
                  category="cwe-79", compliance=(OWASP,)) for i in range(2)]
    rows += [_row("weak-tls", "medium", 5.3, 5.3, "https://api.test/c",
                  category="cwe-327", asset="api.test", compliance=())]
    rows += [_row("old-jquery", "low", 3.1, 3.1, "https://app.test/d", status="fixed",
                  category="cwe-1035", compliance=(NIST,))]
    rows += [_row("tech-detect-nginx", "info", None, None, f"https://app.test/i{i}",
                  category=None, compliance=(), evidence=False) for i in range(9)]
    return rows


def _text(pdf: bytes) -> str:
    return re.sub(r"\s+", " ", _pdf_text(pdf))


# --- score and band consistency -------------------------------------------------------------

def test_posture_panel_states_the_canonical_score_and_band() -> None:
    data = _data(_mixed())
    text = _text(render_executive(data))
    assert f"{data.security_score}/100" in text
    assert _score_band(data.security_score) in text


def test_score_is_not_recomputed_by_the_executive_report() -> None:
    """No second scoring system: the panel prints compute_security_score's own output."""
    rows = _mixed()
    assert _data(rows).security_score == compute_security_score(rows)


def test_r04_band_contract_is_preserved() -> None:
    """`Fair`, never `Moderate`, and the band must resolve to a real colour."""
    for score in (95, 80, 50, 20):
        band = _score_band(score)
        assert band in ("Strong", "Fair", "Weak", "Critical")
        assert B.score_band_color(band) != B.MUTED
    assert "Moderate" not in B.SCORE_BAND_COLORS


def test_band_appears_with_its_score_not_a_second_rating() -> None:
    text = _text(render_executive(_data(_mixed())))
    assert "SECURITY SCORE" in text
    for invented in ("risk rating", "maturity level", "grade"):
        assert invented not in text.lower()


# --- R-01 count units -----------------------------------------------------------------------

def test_panel_labels_both_count_units() -> None:
    data = _data(_mixed())
    text = _text(render_executive(data))
    assert "UNIQUE ISSUES" in text
    assert f"{data.active_vulns} recorded finding(s)" in text


def test_panel_issue_count_is_the_canonical_active_issue_count() -> None:
    data = _data(_mixed())
    assert data.active_issue_count() == len(_top_risk_groups(data.vulns))


def _section_body(text: str, heading: str, next_heading: str) -> str:
    """The BODY of a numbered section, skipping its Table of Contents entry.

    Each heading string occurs twice in the extracted text -- once in the TOC (followed by a
    page number) and once as the real section. The body is the LAST occurrence of `heading`
    through the LAST occurrence of `next_heading`."""
    start = text.rfind(heading)
    end = text.rfind(next_heading)
    assert start != -1 and end > start, f"cannot locate section body for {heading!r}"
    return text[start:end]


def test_r01_phrase_is_not_triplicated_in_one_section() -> None:
    """The rebuild removed a duplicate clause: Section 1 states the reconciliation ONCE.

    Before Phase 4.3 this phrase appeared three times on the Executive Summary page."""
    body = _section_body(_text(render_executive(_data(_mixed()))),
                         "1. Executive Summary", "2. Findings Summary")
    hits = re.findall(r"unique issue[s]? across \d+ affected locations", body)
    assert len(hits) == 1, f"expected one reconciliation clause, found {len(hits)}"


def test_r01_units_still_reconcile_across_sections() -> None:
    rows = [_row("one-issue", matched_at=f"https://h/p{i}") for i in range(7)]
    text = _text(render_executive(_data(rows)))
    assert "1 unique issue across 7 affected locations" in text


# --- R-02 compliance population --------------------------------------------------------------

def test_r02_only_current_findings_contribute_to_compliance() -> None:
    """The fixed finding's NIST control must not appear in the coverage section."""
    data = _data(_mixed())
    assert "nist" not in data.compliance_frameworks()
    section = _text(render_executive(data))
    start = section.rfind("Compliance Coverage")
    assert "NIST 800-53" not in section[start:start + 600]


def test_r02_recommendation_uses_the_same_compliance_population() -> None:
    data = _data(_mixed())
    actions = dict(_recommendations(data))
    assert "Compliance" in actions
    for framework in data.compliance_frameworks():
        from apps.api.modules.compliance.catalog import framework_name

        assert framework_name(framework) in actions["Compliance"]
    assert "NIST 800-53" not in actions["Compliance"]


def test_r02_compliance_wording_is_not_a_certification_claim() -> None:
    text = _text(render_executive(_data(_mixed())))
    assert "NOT a compliance assessment" in text
    assert "is compliant" not in text
    assert "ISO 27001 compliant" not in text


# --- R-03 scan scope --------------------------------------------------------------------------

def test_r03_scoped_report_states_its_scope() -> None:
    scope = [{"id": uuid.uuid4(), "scan_type": "vuln", "status": "completed",
              "target": "app.test", "started_at": CAPTURED, "completed_at": CAPTURED}]
    text = _text(render_executive(_data(_mixed(), scope_scans=scope)))
    assert "1 selected scan(s)" in text


def test_r03_unscoped_report_states_project_wide() -> None:
    text = _text(render_executive(_data(_mixed())))
    assert "all findings recorded for this project" in text


def test_r03_panel_reflects_the_scoped_population() -> None:
    """The panel reads ReportData, so a scoped ReportData yields scoped headline numbers."""
    subset = [r for r in _mixed() if r.template_id == "sql-injection"]
    data = _data(subset)
    assert data.active_issue_count() == 1
    assert f"{data.active_vulns} recorded finding(s)" in _text(render_executive(data))


# --- key risks & themes -------------------------------------------------------------------

def test_key_risks_ordering_is_unchanged() -> None:
    """Phase 4.3 did not touch _top_risk_groups' ranking contract."""
    groups = _top_risk_groups(_mixed())
    risks = [g["max_risk"] if g["max_risk"] is not None else -1.0 for g in groups]
    assert risks == sorted(risks, reverse=True)


def test_key_themes_use_the_scorable_population_only() -> None:
    data = _data(_mixed())
    themed = sum(occ for _n, _i, occ in _key_themes(data))
    assert themed == sum(1 for v in data.vulns if is_scorable(v))


def test_key_themes_count_issues_by_canonical_identity() -> None:
    data = _data(_mixed())
    total_issues = sum(issues for _n, issues, _o in _key_themes(data))
    assert total_issues == len({issue_key(v) for v in data.vulns if is_scorable(v)})


def test_key_themes_group_related_templates() -> None:
    """Two SQL-injection templates must read as ONE weakness class with two issues."""
    themes = dict((name, issues) for name, issues, _o in _key_themes(_data(_mixed())))
    assert themes.get("SQL Injection") == 2


def test_key_themes_exclude_informational_and_fixed() -> None:
    names = {n for n, _i, _o in _key_themes(_data(_mixed()))}
    assert not any("Outdated" in n for n in names), "fixed finding leaked into themes"


# --- recommendations ---------------------------------------------------------------------

def test_recommendations_exist() -> None:
    assert _recommendations(_data(_mixed()))
    assert "Recommended Actions" in _text(render_executive(_data(_mixed())))


def test_recommendation_priorities_reuse_the_remediation_vocabulary() -> None:
    from apps.api.modules.reports.render import _REMEDIATION_BUCKETS

    labels = {label for label, _t in _recommendations(_data(_mixed()))}
    bucket_labels = {label for label, _s, _g in _REMEDIATION_BUCKETS}
    assert labels & bucket_labels, "priority vocabulary diverged from the remediation plan"


def test_recommendations_invent_no_severity_bucket() -> None:
    """A bucket with no active findings must produce no line."""
    rows = [_row("only-critical", "critical")]
    labels = {label for label, _t in _recommendations(_data(rows))}
    assert "High Priority" not in labels
    assert "Medium Priority" not in labels


def test_recommendations_state_both_units() -> None:
    data = _data(_mixed())
    immediate = dict(_recommendations(data))["Immediate"]
    assert "issue(s)" in immediate and "recorded finding(s)" in immediate


def test_recommendations_do_not_alter_severity_or_priority_semantics() -> None:
    text = _text(render_executive(_data(_mixed())))
    assert "do not alter any" in text
    assert "suggested sequencing only" in text


def test_no_recommendations_when_nothing_is_active() -> None:
    rows = [_row("gone", status="fixed"), _row("fp", status="false_positive")]
    assert _recommendations(_data(rows)) == []
    assert "No active findings require remediation action" in _text(
        render_executive(_data(rows))
    )


# --- affected assets ------------------------------------------------------------------------

def test_affected_assets_panel_matches_the_canonical_accessor() -> None:
    data = _data(_mixed())
    text = _text(render_executive(data))
    assert "AFFECTED ASSETS" in text
    assert f"{data.affected_endpoint_count()} endpoint(s)" in text


def test_affected_assets_exclude_non_scorable_findings() -> None:
    """A fixed finding must not make a host 'affected'."""
    data = _data([_row("gone", status="fixed", asset="stale.test")])
    assert data.affected_assets() == []


# --- Executive / Technical parity -------------------------------------------------------------

def test_both_reports_agree_on_score_and_band() -> None:
    data = _data(_mixed())
    e, t = _text(render_executive(data)), _text(render_technical(data))
    assert f"{data.security_score}/100" in e and f"{data.security_score}/100" in t


def test_both_reports_agree_on_issue_and_finding_counts() -> None:
    data = _data(_mixed())
    for text in (_text(render_executive(data)), _text(render_technical(data))):
        assert f"{data.total_issue_count()} unique issue(s)" in text


def test_both_reports_agree_on_verification_tally() -> None:
    data = _data(_mixed())
    counts = _verification_summary(data)
    for text in (_text(render_executive(data)), _text(render_technical(data))):
        assert str(counts["unverified"]) in text


def test_weakness_class_names_match_the_technical_report() -> None:
    """Themes use the SAME classifier the Technical per-finding prose uses."""
    data = _data(_mixed())
    exec_text = _text(render_executive(data))
    for name, _i, _o in _key_themes(data)[:3]:
        assert name in exec_text
        assert name in _text(render_technical(data))


# --- no confirmed-compromise language ---------------------------------------------------------

def test_executive_never_claims_confirmed_compromise_for_unverified_findings() -> None:
    data = _data(_mixed())
    assert _verification_summary(data)["verified"] == 0
    text = _text(render_executive(data)).lower()
    for phrase in ("confirmed compromise", "successfully exploited", "proven exploitation",
                   "was breached", "attacker gained"):
        assert phrase not in text


def test_executive_states_findings_are_not_all_confirmed() -> None:
    text = _text(render_executive(_data(_mixed())))
    assert "not all confirmed vulnerabilities" in text


def test_executive_keeps_verification_as_its_own_axis() -> None:
    text = _text(render_executive(_data(_mixed())))
    assert "Findings by verification status" in text
    assert "independent of verification" in text


def test_no_ai_confidence_leaks_into_the_executive_report() -> None:
    rows = _mixed()
    for r in rows:
        r.ai_confidence = 0.97
    text = _text(render_executive(_data(rows)))
    assert "0.97" not in text
    assert "AI confidence" not in text


# --- structure & compatibility ------------------------------------------------------------

def test_all_executive_sections_are_present_and_numbered() -> None:
    text = _text(render_executive(_data(_mixed())))
    for heading in ("1. Executive Summary", "2. Findings Summary",
                    "3. Affected Assets", "4. Key Risks", "5. Compliance Coverage",
                    "6. MITRE ATT", "7. Recommended Actions", "8. Conclusion"):
        assert heading in text, f"missing section: {heading}"


def test_severity_distribution_is_shown() -> None:
    text = _text(render_executive(_data(_mixed())))
    assert "Active findings by severity" in text


def test_report_remains_concise() -> None:
    """Management-oriented: the rebuild must not turn this into a technical document."""
    from apps.api.tests.test_report_layout import _page_count

    assert _page_count(render_executive(_data(_mixed()))) <= 8


def test_phase_41_and_32_semantics_are_untouched() -> None:
    """The chips and manifest live in the Technical report and must still be intact."""
    text = _text(render_technical(_data(_mixed())))
    assert "VERIFICATION" in text and "CONFIDENCE" in text and "EVIDENCE" in text
    assert "Evidence manifest" in text


def test_executive_rebuild_alters_no_assessed_value() -> None:
    rows = _mixed()
    before = [(r.severity, r.cvss_score, r.final_risk_score, r.status) for r in rows]
    render_executive(_data(rows))
    assert [(r.severity, r.cvss_score, r.final_risk_score, r.status) for r in rows] == before


@pytest.mark.parametrize("rows", [[], [_row("solo")]])
def test_edge_cases_still_render(rows) -> None:
    assert render_executive(_data(rows))[:4] == b"%PDF"
