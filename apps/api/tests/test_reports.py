import uuid

import pytest

from apps.api.modules.reports import render
from apps.api.modules.reports.data import ReportData, VulnRow, compute_security_score


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
