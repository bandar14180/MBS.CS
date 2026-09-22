"""Client Risk Assessment: parity with the Executive report, freezing, immutability, trend.

The load-bearing test here is `test_assessment_numbers_equal_the_executive_report`: an
assessment must not be a second calculator. Everything else follows from that -- if the numbers
are read out of the existing pipeline rather than recomputed, parity is structural.
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from apps.api.tests.test_remediation import (
    _auth,
    _register,
    _rem_base,
    _seed_findings,
    _workspace_project,
)


def _base(wid: str, pid: str) -> str:
    return f"/api/v1/workspaces/{wid}/projects/{pid}/risk-assessments"


def _period() -> dict:
    now = datetime.now(timezone.utc)
    return {
        "period_start": (now - timedelta(days=30)).isoformat(),
        "period_end": now.isoformat(),
    }


def _create_and_issue(client, headers, wid, pid, title="Q3 Assessment") -> dict:
    draft = client.post(_base(wid, pid), headers=headers, json={"title": title, **_period()})
    assert draft.status_code == 201, draft.text
    issued = client.post(f"{_base(wid, pid)}/{draft.json()['id']}/issue", headers=headers)
    assert issued.status_code == 200, issued.text
    return issued.json()


# =============================================================================================
# PARITY (requirement 35)
# =============================================================================================

def test_assessment_numbers_equal_the_executive_report(client: TestClient) -> None:
    """For IDENTICAL underlying data, the assessment's figures must equal the report pipeline's
    exactly -- because they are read from it, not recomputed."""
    import asyncio

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.modules.reports.data import gather_report_data
    from apps.api.modules.reports.render import _score_band

    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    _seed_findings(wid, pid, [
        {"fingerprint": "sqli|m|https://h/a", "title": "SQLi", "severity": "critical",
         "cvss_score": 9.8, "final_risk_score": 9.8},
        {"fingerprint": "sqli|m|https://h/b", "title": "SQLi", "severity": "critical",
         "cvss_score": 9.8, "final_risk_score": 9.8},
        {"fingerprint": "xss|m|https://h/c", "title": "XSS", "severity": "high",
         "cvss_score": 7.2, "final_risk_score": 7.2},
        {"fingerprint": "info|m|https://h/d", "title": "Server banner", "severity": "info",
         "cvss_score": 0.0},
        {"fingerprint": "fixedone|m|https://h/e", "title": "Old", "severity": "high",
         "status": "fixed", "cvss_score": 7.0},
    ])

    assessment = _create_and_issue(client, headers, wid, pid)
    summary = assessment["summary"]

    async def _report_numbers() -> dict:
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                with tenancy.workspace_scope(uuid.UUID(wid)):
                    data = await gather_report_data(session, uuid.UUID(pid))
                    return {
                        "security_score": data.security_score,
                        "score_band": _score_band(data.security_score),
                        "severity_counts": dict(data.severity_counts),
                        "active_severity_counts": dict(data.active_severity_counts),
                        "total_findings": data.total_vulns,
                        "active_findings": data.active_vulns,
                        "affected_endpoint_count": data.affected_endpoint_count(),
                    }
        finally:
            await engine.dispose()

    report = asyncio.run(_report_numbers())

    assert assessment["security_score"] == report["security_score"]
    assert assessment["score_band"] == report["score_band"]
    for key, expected in report.items():
        assert summary[key] == expected, f"{key}: assessment {summary[key]!r} != report {expected!r}"

    # And the score is a REAL number derived from real findings, not a default.
    assert 0 <= assessment["security_score"] <= 100
    # 4 = the 2 criticals + the high + the INFO row. `active_findings` is a status tally
    # (ReportData.active_vulns), so an informational finding is active even though it is not
    # SCORABLE -- the two populations are deliberately different and the assessment copies
    # both as-is rather than reconciling them into one number.
    assert summary["active_findings"] == 4
    assert summary["active_severity_counts"]["critical"] == 2
    assert summary["active_severity_counts"]["high"] == 1
    assert summary["active_severity_counts"]["info"] == 1
    # The fixed row is counted in the all-status tally but not the active one.
    assert summary["severity_counts"]["high"] == 2
    # Scorable ISSUES: sqli + xss. The info row and the fixed row contribute nothing.
    assert summary["unresolved_issue_count"] == 2


def test_assessment_uses_the_canonical_issue_identity(client: TestClient) -> None:
    """Frozen findings carry scoring.issue_key, so an assessment, the score, the report
    groupings and the remediation items all agree on what "one issue" means."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    _seed_findings(wid, pid, [
        {"fingerprint": f"onetemplate|m|https://h/{i}", "title": "One Issue", "severity": "high"}
        for i in range(4)
    ])

    assessment = _create_and_issue(client, headers, wid, pid)
    findings = client.get(
        f"{_base(wid, pid)}/{assessment['id']}/findings", headers=headers
    ).json()

    # FOUR frozen rows (a client report lists findings) but ONE issue identity.
    assert len(findings) == 4
    assert {f["issue_key"] for f in findings} == {"template:onetemplate"}
    # And the summary counts ISSUES, not rows -- which is what the score is computed over.
    assert assessment["summary"]["unresolved_issue_count"] == 1
    assert all(f["location_count"] == 4 for f in findings)


# =============================================================================================
# FREEZING + IMMUTABILITY (requirements 14, 36)
# =============================================================================================

def test_issued_assessment_does_not_change_when_live_findings_change(client: TestClient) -> None:
    """THE freeze guarantee: a document a client received in March must still say in June what
    it said in March."""
    import asyncio

    from sqlalchemy import update
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.modules.vulnerabilities.models import Vulnerability

    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": f"freeze{uuid.uuid4().hex[:6]}|m|https://h/1", "title": "Frozen Issue",
         "severity": "critical", "cvss_score": 9.5, "final_risk_score": 9.5},
    ])

    assessment = _create_and_issue(client, headers, wid, pid)
    score_at_issue = assessment["security_score"]
    findings_at_issue = client.get(
        f"{_base(wid, pid)}/{assessment['id']}/findings", headers=headers
    ).json()
    assert findings_at_issue[0]["frozen_severity"] == "critical"
    assert findings_at_issue[0]["frozen_cvss_score"] == 9.5

    # Now the world moves on: the finding is downgraded and fixed.
    async def _mutate() -> None:
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                with tenancy.workspace_scope(uuid.UUID(wid)):
                    await session.execute(
                        update(Vulnerability)
                        .where(Vulnerability.id == vuln_ids[0])
                        .values(severity="low", cvss_score=2.0, status="fixed")
                    )
                    await session.commit()
        finally:
            await engine.dispose()

    asyncio.run(_mutate())

    after = client.get(f"{_base(wid, pid)}/{assessment['id']}", headers=headers).json()
    assert after["security_score"] == score_at_issue
    assert after["summary"] == assessment["summary"]

    frozen_after = client.get(
        f"{_base(wid, pid)}/{assessment['id']}/findings", headers=headers
    ).json()
    assert frozen_after[0]["frozen_severity"] == "critical", "frozen severity must not follow the live row"
    assert frozen_after[0]["frozen_cvss_score"] == 9.5
    assert frozen_after[0]["frozen_vulnerability_status"] == "open"


def test_reissuing_an_issued_assessment_is_refused(client: TestClient) -> None:
    """A client-facing document that can be silently restated is worthless."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    _seed_findings(wid, pid, [
        {"fingerprint": f"reissue{uuid.uuid4().hex[:6]}|m|https://h/1", "title": "R", "severity": "high"},
    ])
    assessment = _create_and_issue(client, headers, wid, pid)

    again = client.post(f"{_base(wid, pid)}/{assessment['id']}/issue", headers=headers)
    assert again.status_code == 409, again.text
    assert "already been issued" in again.json()["detail"]


def test_no_assessment_update_or_delete_endpoint_exists() -> None:
    """Immutability enforced by the ABSENCE of a write route -- asserted against the real
    OpenAPI surface so a future PATCH/DELETE fails here."""
    from apps.api.main import create_app

    spec = create_app().openapi()
    for path, methods in spec["paths"].items():
        if "/risk-assessments" not in path:
            continue
        assert "delete" not in methods, f"{path} exposes DELETE"
        assert "patch" not in methods, f"{path} exposes PATCH"
        assert "put" not in methods, f"{path} exposes PUT"
    # And no route addresses an individual frozen finding for writing.
    assert not any("/findings/{" in p for p in spec["paths"])


def test_draft_holds_no_frozen_numbers_until_issued(client: TestClient) -> None:
    """A NULL score on a draft is distinct from a score of 0 (a real, terrible posture)."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    draft = client.post(
        _base(wid, pid), headers=headers, json={"title": "Draft", **_period()}
    ).json()

    assert draft["status"] == "draft"
    assert draft["security_score"] is None
    assert draft["score_band"] is None
    assert draft["summary"] == {}
    assert client.get(f"{_base(wid, pid)}/{draft['id']}/findings", headers=headers).json() == []


def test_preview_writes_nothing(client: TestClient) -> None:
    """The draft screen can poll the live snapshot without creating or freezing anything."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    _seed_findings(wid, pid, [
        {"fingerprint": f"prev{uuid.uuid4().hex[:6]}|m|https://h/1", "title": "P", "severity": "high"},
    ])

    preview = client.get(f"{_base(wid, pid)}/preview", headers=headers)
    assert preview.status_code == 200, preview.text
    assert "security_score" in preview.json()
    # Nothing was persisted.
    assert client.get(_base(wid, pid), headers=headers).json() == []


# =============================================================================================
# HISTORICAL COMPARISON (requirement 16)
# =============================================================================================

def test_comparison_uses_the_previous_issued_snapshot(client: TestClient) -> None:
    """Trends compare snapshot to snapshot. The second assessment records the first as its
    predecessor at ISSUE time, so the comparison cannot drift afterwards."""
    import asyncio

    from sqlalchemy import update
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.modules.vulnerabilities.models import Vulnerability

    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": f"trend{uuid.uuid4().hex[:6]}|m|https://h/1", "title": "T",
         "severity": "critical", "cvss_score": 9.8, "final_risk_score": 9.8},
    ])

    first = _create_and_issue(client, headers, wid, pid, "Period 1")
    assert first["previous_assessment_id"] is None
    assert client.get(
        f"{_base(wid, pid)}/{first['id']}/comparison", headers=headers
    ).json()["has_previous"] is False

    # The team fixes it, so posture IMPROVES.
    async def _fix() -> None:
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                with tenancy.workspace_scope(uuid.UUID(wid)):
                    await session.execute(
                        update(Vulnerability)
                        .where(Vulnerability.id == vuln_ids[0]).values(status="fixed")
                    )
                    await session.commit()
        finally:
            await engine.dispose()

    asyncio.run(_fix())

    second = _create_and_issue(client, headers, wid, pid, "Period 2")
    assert second["previous_assessment_id"] == first["id"]

    comparison = client.get(
        f"{_base(wid, pid)}/{second['id']}/comparison", headers=headers
    ).json()
    assert comparison["has_previous"] is True
    assert comparison["previous_security_score"] == first["security_score"]
    assert comparison["security_score_delta"] == second["security_score"] - first["security_score"]
    assert comparison["direction"] == "improved"
    assert comparison["security_score_delta"] > 0


def test_compare_distinguishes_no_basis_from_no_change() -> None:
    """None ("no basis for comparison") and 0 ("measured, unchanged") are different answers and
    must not collapse into each other."""
    from apps.api.modules.assessment.service import compare

    assert compare({"security_score": 80}, None) == {"has_previous": False}

    unchanged = compare({"security_score": 80}, {"security_score": 80})
    assert unchanged["security_score_delta"] == 0
    assert unchanged["direction"] == "unchanged"

    # A metric absent from the OLDER snapshot yields None, not a fabricated 0.
    partial = compare({"security_score": 80, "active_findings": 3}, {"security_score": 70})
    assert partial["security_score_delta"] == 10
    assert partial["active_findings_delta"] is None


# =============================================================================================
# RECOMMENDATIONS (requirement 17)
# =============================================================================================

def test_recommendations_are_derived_from_actual_data() -> None:
    """Deterministic and grounded: each recommendation appears only when the data supports it."""
    from apps.api.modules.assessment.narrative import build_narrative

    summary = {
        "security_score": 42, "score_band": "Weak",
        "active_severity_counts": {"critical": 2, "high": 3, "medium": 1},
        "unresolved_issue_count": 6,
        "affected_assets": ["host-a"], "affected_endpoint_count": 9,
        "remediation_progress": {"overdue": 4, "open": 6, "completion_percent": 10},
        "risk_accepted_count": 1,
    }
    text = build_narrative(summary)

    assert "42/100" in text and "Weak" in text
    assert "2 active critical-severity" in text
    assert "3 active high-severity" in text
    assert "4 remediation items are past the agreed due date" in text
    assert "risk acceptance" in text
    # Deterministic: same input, byte-identical output.
    assert build_narrative(summary) == text


def test_recommendations_do_not_invent_work_that_does_not_exist() -> None:
    """A clean project gets an honest short narrative, not padded filler about criticals it
    does not have."""
    from apps.api.modules.assessment.narrative import build_narrative

    text = build_narrative({
        "security_score": 100, "score_band": "Strong",
        "active_severity_counts": {}, "unresolved_issue_count": 0,
        "affected_assets": [], "affected_endpoint_count": 0,
        "remediation_progress": {"overdue": 0, "open": 0, "completion_percent": 0},
        "risk_accepted_count": 0,
    })
    assert "critical-severity" not in text
    assert "past the agreed due date" not in text
    assert "No outstanding critical or high-severity findings" in text


def test_narrative_is_labelled_system_not_ai(client: TestClient) -> None:
    """Provenance must be truthful in BOTH directions: deterministic template output is not
    AI-authored any more than AI text is human-authored."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    _seed_findings(wid, pid, [
        {"fingerprint": f"narr{uuid.uuid4().hex[:6]}|m|https://h/1", "title": "N", "severity": "high"},
    ])
    assessment = _create_and_issue(client, headers, wid, pid)
    assert assessment["narrative_source"] == "system"
    assert assessment["narrative"]


# =============================================================================================
# REMEDIATION PROGRESS IN THE SNAPSHOT (requirement 15)
# =============================================================================================

def test_assessment_freezes_remediation_progress_and_status(client: TestClient) -> None:
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    key = f"prog{uuid.uuid4().hex[:6]}"
    _seed_findings(wid, pid, [
        {"fingerprint": f"{key}|m|https://h/1", "title": "Progress Issue", "severity": "high"},
    ])
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/transition",
        headers=headers, json={"version": item["version"], "to_status": "accepted"},
    )

    assessment = _create_and_issue(client, headers, wid, pid)
    progress = assessment["summary"]["remediation_progress"]
    assert progress["total"] == 1
    assert progress["accepted"] == 1

    findings = client.get(
        f"{_base(wid, pid)}/{assessment['id']}/findings", headers=headers
    ).json()
    assert findings[0]["frozen_remediation_status"] == "accepted"


# =============================================================================================
# AUTHORIZATION (requirements 4, 25)
# =============================================================================================

@pytest.mark.parametrize("role,expected", [("admin", 200), ("member", 200), ("client_viewer", 200)])
def test_every_role_including_client_viewer_can_read_assessments(
    client: TestClient, role, expected
) -> None:
    """The assessment IS the client-facing deliverable -- client_viewer must be able to read it."""
    from apps.api.tests.test_remediation import _invite

    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)

    user = _register(client, role)
    _invite(client, headers, wid, user["email"], role)
    resp = client.get(_base(wid, pid), headers=_auth(user))
    assert resp.status_code == expected, resp.text


@pytest.mark.parametrize("role,expected", [("admin", 201), ("member", 403), ("client_viewer", 403)])
def test_only_owner_and_admin_may_create_assessments(client: TestClient, role, expected) -> None:
    """Issuing publishes and permanently freezes a client document -- a publishing decision,
    not day-to-day work."""
    from apps.api.tests.test_remediation import _invite

    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)

    user = _register(client, role)
    _invite(client, headers, wid, user["email"], role)
    resp = client.post(
        _base(wid, pid), headers=_auth(user), json={"title": "T", **_period()}
    )
    assert resp.status_code == expected, resp.text


def test_assessment_from_another_workspace_is_not_found(client: TestClient) -> None:
    owner_a = _register(client, "OwnerA")
    headers_a = _auth(owner_a)
    wid_a, pid_a = _workspace_project(client, headers_a)
    _seed_findings(wid_a, pid_a, [
        {"fingerprint": f"xa{uuid.uuid4().hex[:6]}|m|https://h/1", "title": "A", "severity": "high"},
    ])
    assessment = _create_and_issue(client, headers_a, wid_a, pid_a)

    owner_b = _register(client, "OwnerB")
    headers_b = _auth(owner_b)
    wid_b, pid_b = _workspace_project(client, headers_b)

    resp = client.get(f"{_base(wid_b, pid_b)}/{assessment['id']}", headers=headers_b)
    assert resp.status_code == 404, resp.text


def test_period_end_must_follow_period_start(client: TestClient) -> None:
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    now = datetime.now(timezone.utc)
    resp = client.post(_base(wid, pid), headers=headers, json={
        "title": "Backwards",
        "period_start": now.isoformat(),
        "period_end": (now - timedelta(days=1)).isoformat(),
    })
    assert resp.status_code == 400, resp.text


# =============================================================================================
# REPORT PIPELINE REUSE (requirement 13 / section 13)
# =============================================================================================

def test_risk_assessment_reuses_the_single_render_entry_point() -> None:
    """No second PDF pipeline: `render.render` dispatches on type, and the assessment branch
    REFUSES to fall back to live data when the frozen snapshot is missing."""
    import pytest as _pytest

    from apps.api.modules.reports import render
    from apps.api.modules.reports.data import ReportData

    data = ReportData(project_name="P", security_score=80, severity_counts={}, total_vulns=0,
                      active_vulns=0)
    with _pytest.raises(ValueError, match="require the issued assessment"):
        render.render("risk_assessment", data)


def test_only_one_pdf_renderer_module_exists() -> None:
    """Structural check against a duplicate report pipeline: reportlab document construction
    must appear in exactly one module."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    # Application code only. Tests legitimately NAME the renderer (this file included), and
    # counting them would make the check assert something it does not mean.
    hits = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*.py")
        if "__pycache__" not in path.parts
        and "tests" not in path.parts
        and "SimpleDocTemplate" in path.read_text(encoding="utf-8")
    )
    assert hits == ["modules/reports/render.py"], f"more than one PDF renderer: {hits}"
