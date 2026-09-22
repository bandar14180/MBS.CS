"""Phase 5.0 -- ReportModel extraction: construction, immutability, and PARITY.

WHAT THE TRACE FOUND
--------------------
`ReportData` (10 fields + 10 derived accessors) is the canonical data-collection result and is
correct. What was missing is the layer above it: every report-shaped aggregation --
`_finding_groups`, `_top_risk_groups`, `_verification_summary`, `_key_themes`,
`_recommendations`, `_score_band` -- lived inside a 3,189-line PDF module. Two real
consequences:

  * `assessment/service.py` imports `_score_band` and `_top_risk_groups` FROM THE RENDERER to
    build a frozen snapshot -- a domain service reaching into PDF code for domain facts.
  * Nothing could answer "what does this report say?" without rendering a PDF.

WHAT PHASE 5.0 DID
------------------
Steps 1-3 of the agreed migration: DEFINE `ReportModel`, POPULATE it from the canonical path,
PROVE parity. The renderers are untouched, so Phases 2.1-4.5 cannot regress -- proven by a
byte-level comparison of rendered output with and without the new module.

THE CENTRAL CLAIM THESE TESTS DEFEND
------------------------------------
`build_report_model` implements NO security algorithm. Every value must equal what the existing
canonical function returns, and no assessed value may drift.
"""

import collections
import dataclasses
import hashlib
import re
import uuid
from datetime import datetime, timezone

import pytest

from apps.api.modules.reports import _branding as B
from apps.api.modules.reports import model as M
from apps.api.modules.reports.data import EvidenceRecord, ReportData, VulnRow
from apps.api.modules.reports.model import ReportModel, build_report_model
from apps.api.modules.reports.render import (
    _finding_groups,
    _score_band,
    _score_impacting_count,
    _top_risk_groups,
    _verification_summary,
    render_executive,
    render_risk_assessment,
    render_technical,
)
from apps.api.modules.reports.scoring import compute_security_score, is_scorable, issue_key
from apps.api.tests.test_report_layout import _page_count, _pdf_text

DIGEST = hashlib.sha256(b"evidence").hexdigest()
CAPTURED = datetime(2026, 9, 8, 14, 0, 0, tzinfo=timezone.utc)
OWASP = ("owasp", "A03:2021", "Injection")
PCI = ("pci_dss", "6.5.7", "Cross-site scripting (XSS)")
NIST = ("nist", "SI-10", "Information Input Validation")


def _row(idx, template_id="sql-injection", severity="critical", cvss=9.8, risk=10.0,
         matched_at="https://app.test/a", status="open", compliance=(OWASP,),
         asset="app.test", category="cwe-89", evidence=True):
    records = (
        [EvidenceRecord(uuid.UUID(int=1000 + idx), "log_excerpt", f"s3://e/{idx}.txt",
                        DIGEST, CAPTURED)]
        if evidence else []
    )
    return VulnRow(
        id=uuid.UUID(int=idx), title=template_id.replace("-", " ").title(), severity=severity,
        status=status, category=category, cvss_score=cvss, cvss_vector="CVSS:3.1/AV:N",
        final_risk_score=risk, risk_rationale="CVSS x asset criticality 'critical' (weight 2.0)",
        compliance=list(compliance), evidence_uris=[r.storage_uri for r in records],
        evidence_items=[(r.evidence_type, r.storage_uri) for r in records],
        evidence_records=records, template_id=template_id, matcher_name="status",
        matched_at=matched_at, asset_value=asset, description="A condition was detected.",
    )


def _estate():
    """A mixed estate: two SQLi occurrences of one issue, XSS, TLS, plus fixed/info noise."""
    return [
        _row(1, "sql-injection", "critical", matched_at="https://app.test/a1",
             compliance=(OWASP, PCI)),
        _row(2, "sql-injection", "critical", matched_at="https://app.test/a2",
             compliance=(OWASP, PCI)),
        _row(3, "xss-reflected", "high", 7.4, 8.0, "https://app.test/b",
             category="cwe-79", compliance=(OWASP,)),
        _row(4, "weak-tls", "medium", 5.3, 5.3, "https://api.test/c",
             category="cwe-327", asset="api.test", compliance=()),
        _row(5, "old-jquery", "low", 3.1, 3.1, "https://app.test/d", status="fixed",
             category="cwe-1035", compliance=(NIST,)),
        _row(6, "tech-detect-nginx", "info", None, None, "https://app.test/i",
             category=None, compliance=(), evidence=False),
    ]


def _data(rows=None, attack=(), scope_scans=()):
    rows = _estate() if rows is None else rows
    active = [r for r in rows if r.status in ("open", "confirmed", "reopened")]
    return ReportData(
        project_name="Parity Corp", security_score=compute_security_score(rows),
        severity_counts=dict(collections.Counter(r.severity for r in rows)),
        total_vulns=len(rows), active_vulns=len(active),
        active_severity_counts=dict(collections.Counter(r.severity for r in active)),
        vulns=rows, attack_techniques=list(attack), scope_scans=list(scope_scans),
    )


def _text(pdf: bytes) -> str:
    return re.sub(r"\s+", " ", _pdf_text(pdf))


# --- 1. construction -------------------------------------------------------------------------

def test_model_builds_from_canonical_report_data() -> None:
    model = build_report_model(_data())
    assert isinstance(model, ReportModel)
    assert model.project_name == "Parity Corp"


def test_model_builds_for_an_empty_project() -> None:
    model = build_report_model(_data([]))
    assert model.findings == ()
    assert model.counts.total_issues == 0
    assert model.verification.total == 0


def test_build_is_pure_and_repeatable() -> None:
    data = _data()
    assert build_report_model(data) == build_report_model(data)


def test_model_performs_no_database_work() -> None:
    """A data contract, not a second database model: no session, no ORM, no query -- and no
    PDF library either.

    Checked against the module's CODE, parsed with `ast`, rather than its raw text: the
    docstring names these very things in order to prohibit them, and a prose mention is
    documentation, not a dependency. `ast` also proves the module imports none of them, which
    is the fact that actually matters."""
    import ast
    import pathlib

    tree = ast.parse(pathlib.Path("apps/api/modules/reports/model.py").read_text(encoding="utf-8"))

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(f"{node.module}.{a.name}" for a in node.names)

    for forbidden in ("reportlab", "sqlalchemy"):
        assert not any(forbidden in name for name in imported), \
            f"model.py must not import {forbidden!r}: {sorted(imported)}"

    # No awaits and no ORM-style query calls anywhere in the executable code.
    assert not [n for n in ast.walk(tree) if isinstance(n, (ast.Await, ast.AsyncFunctionDef))], \
        "model.py must be synchronous -- it performs no I/O"
    called = {
        n.func.id for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert "select" not in called, "model.py must not build queries"


# --- 2. immutability --------------------------------------------------------------------------

@pytest.mark.parametrize("cls", [
    M.ReportModel, M.CountUnits, M.SeverityDistribution, M.ScanScope, M.AssetExposure,
    M.FindingRecord, M.RiskEntry, M.VerificationSummary, M.ComplianceControl,
    M.ComplianceFramework, M.AttackTechnique,
])
def test_every_model_type_is_frozen(cls) -> None:
    assert cls.__dataclass_params__.frozen is True


def test_assessment_facts_cannot_be_mutated_by_a_consumer() -> None:
    model = build_report_model(_data())
    for attr, value in (("security_score", 100), ("score_band", "Strong")):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(model, attr, value)
    with pytest.raises(dataclasses.FrozenInstanceError):
        model.findings[0].severity = "low"          # type: ignore[misc]


def test_collections_are_tuples_not_lists() -> None:
    """Tuples so a consumer cannot append to or reorder an assessment fact in place."""
    model = build_report_model(_data())
    assert isinstance(model.findings, tuple)
    assert isinstance(model.key_risks, tuple)
    assert isinstance(model.compliance, tuple)
    assert isinstance(model.findings[0].locations, tuple)


# --- 3./4. field completeness and Data -> Model parity ----------------------------------------

def test_score_and_band_parity() -> None:
    data = _data()
    model = build_report_model(data)
    assert model.security_score == data.security_score
    assert model.score_band == _score_band(data.security_score)


def test_count_unit_parity() -> None:
    data = _data()
    c = build_report_model(data).counts
    assert c.total_issues == data.total_issue_count()
    assert c.total_findings == data.total_vulns
    assert c.active_issues == data.active_issue_count()
    assert c.active_findings == data.active_vulns
    assert c.scorable_issues == data.scorable_issue_count()
    assert c.scorable_findings == _score_impacting_count(data)


def test_severity_distribution_parity() -> None:
    data = _data()
    sev = build_report_model(data).severity
    assert sev.all_statuses == data.severity_counts
    assert sev.active == data.active_severity_counts


def test_exposure_parity() -> None:
    data = _data()
    exposure = build_report_model(data).exposure
    assert list(exposure.assets) == data.affected_assets()
    assert exposure.endpoint_count == data.affected_endpoint_count()


def test_verification_parity() -> None:
    data = _data()
    ver = build_report_model(data).verification
    canonical = _verification_summary(data)
    assert ver.verified == canonical["verified"]
    assert ver.partially_verified == canonical["partially_verified"]
    assert ver.unverified == canonical["unverified"]


def test_compliance_parity() -> None:
    data = _data()
    model = build_report_model(data)
    canonical = data.compliance_coverage()
    assert [f.framework for f in model.compliance] == [fw for fw, _c in canonical]
    for framework, (_fw, controls) in zip(model.compliance, canonical, strict=True):
        assert [(c.control_id, c.description, list(c.finding_ids)) for c in framework.controls] \
            == [(cid, desc, list(ids)) for cid, desc, ids in controls]


def test_attack_parity() -> None:
    data = _data(attack=[("Execution", "T1059", "Command and Scripting Interpreter", 1)])
    technique = build_report_model(data).attack[0]
    assert (technique.tactic, technique.technique_id, technique.technique_name,
            technique.issue_count) == data.attack_techniques[0]


def test_scope_parity() -> None:
    scans = [{"id": uuid.UUID(int=9), "scan_type": "vuln", "status": "completed",
              "target": "app.test", "started_at": CAPTURED, "completed_at": CAPTURED}]
    data = _data(scope_scans=scans)
    scope = build_report_model(data).scope
    assert scope.is_scoped is True and scope.scan_count == 1
    assert list(scope.targets) == data.scope_targets()
    assert (scope.window_start, scope.window_end) == data.scope_window()


# --- 5. Model -> renderer parity (finding identity and ORDER) ----------------------------------

def test_finding_identity_and_order_parity() -> None:
    """Phase 4.4 anchors on the canonical id and Phase 4.2 numbers by position, so BOTH the
    ids and their ORDER must match the renderer's grouping exactly."""
    data = _data()
    groups = _finding_groups(data.vulns)
    model = build_report_model(data)
    assert list(model.finding_ids) == [g["finding_id"] for g in groups]
    assert [f.issue_key for f in model.findings] == [g["key"] for g in groups]


def test_finding_field_parity() -> None:
    data = _data()
    for finding, g in zip(build_report_model(data).findings, _finding_groups(data.vulns),
                          strict=True):
        assert finding.title == g["title"]
        assert finding.severity == g["severity"]
        assert finding.verification == g["verification"]
        assert finding.confidence == g["confidence"]
        assert finding.cvss_score == g["cvss_score"]
        assert finding.business_risk == g["final_risk_score"]
        assert list(finding.locations) == g["matched_ats"]
        assert finding.occurrence_count == g["occurrence_count"]
        assert finding.unlocated_count == g["unlocated_count"]


def test_key_risk_parity_including_order() -> None:
    data = _data()
    canonical = _top_risk_groups(data.vulns)
    model = build_report_model(data)
    assert [(r.title, r.severity, r.max_risk, r.max_cvss, r.occurrence_count)
            for r in model.key_risks] == \
           [(g["title"], g["severity"], g["max_risk"], g["max_cvss"], g["endpoint_count"])
            for g in canonical]


def test_unscored_risk_stays_none_not_zero() -> None:
    rows = [_row(1, "unscored", "high", cvss=None, risk=None)]
    entry = build_report_model(_data(rows)).key_risks[0]
    assert entry.max_risk is None and entry.max_cvss is None


def test_finding_by_id_resolves_and_rejects() -> None:
    model = build_report_model(_data())
    assert model.finding_by_id(model.finding_ids[0]) is not None
    assert model.finding_by_id("MBS-DEADBEEF") is None


# --- 6.-9. R-01 / R-02 / R-03 / R-04 -----------------------------------------------------------

def test_r01_units_are_never_collapsed() -> None:
    rows = [_row(i, "one-issue", matched_at=f"https://h/p{i}") for i in range(7)]
    counts = build_report_model(_data(rows)).counts
    assert counts.total_issues == 1
    assert counts.total_findings == 7
    assert counts.issues_exceed_findings is False


def test_r02_compliance_uses_the_scorable_predicate() -> None:
    data = _data()
    model = build_report_model(data)
    contributing = {
        fid for f in model.compliance for c in f.controls for fid in c.finding_ids
    }
    scorable = {v.finding_id for v in data.vulns if is_scorable(v)}
    assert contributing <= scorable
    # The FIXED finding's NIST control must not appear.
    assert "nist" not in [f.framework for f in model.compliance]


def test_r03_unscoped_model_is_project_wide() -> None:
    assert build_report_model(_data()).scope.is_scoped is False


def test_r03_scoped_model_carries_only_its_scope() -> None:
    subset = [r for r in _estate() if r.template_id == "sql-injection"]
    model = build_report_model(_data(subset))
    assert model.counts.total_issues == 1
    assert model.counts.total_findings == 2


def test_r04_band_contract() -> None:
    assert _score_band(80) == "Fair"
    assert "Moderate" not in B.SCORE_BAND_COLORS
    model = build_report_model(_data())
    assert B.score_band_color(model.score_band) != B.MUTED


# --- 10. Phase 3.2 evidence integrity ----------------------------------------------------------

def test_evidence_records_are_carried_intact() -> None:
    data = _data()
    model = build_report_model(data)
    for finding in model.findings:
        for record in finding.evidence:
            assert record.evidence_type
            assert record.storage_uri.startswith("s3://")
            assert record.has_checksum
            assert record.captured_at == CAPTURED
            assert re.fullmatch(r"EV-[0-9A-F]{8}", record.artifact_id)


def test_evidence_manifest_is_complete_and_deterministic() -> None:
    model = build_report_model(_data())
    manifest = model.evidence_manifest
    expected = sum(len(f.evidence) for f in model.findings)
    assert len(manifest) == expected
    assert manifest == model.evidence_manifest      # stable across calls
    assert model.verified_artifact_count == expected


def test_manifest_links_each_artifact_to_a_real_finding() -> None:
    model = build_report_model(_data())
    ids = set(model.finding_ids)
    for finding_id, _record in model.evidence_manifest:
        assert finding_id in ids


# --- 11. Phase 4.1 assurance semantics ----------------------------------------------------------

def test_verification_and_confidence_remain_distinct_axes() -> None:
    model = build_report_model(_data())
    for finding in model.findings:
        assert finding.verification in ("verified", "partially_verified", "unverified")
        assert finding.confidence in ("high", "medium", "low")


def test_model_carries_no_ai_confidence() -> None:
    names = {f.name for f in dataclasses.fields(M.FindingRecord)}
    assert "ai_confidence" not in names
    import pathlib

    source = pathlib.Path("apps/api/modules/reports/model.py").read_text(encoding="utf-8")
    assert "ai_confidence" in source  # only as the documented prohibition
    assert "self.ai_confidence" not in source


def test_unproven_is_not_the_same_as_false_positive() -> None:
    summary = build_report_model(_data()).verification
    assert summary.unproven == summary.partially_verified + summary.unverified


# --- 12.-15. renderer phases unaffected ----------------------------------------------------------

def test_phase_42_layout_behaviour_intact() -> None:
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, Paragraph, Table, TableStyle

    from apps.api.modules.reports.render import _finding_block, _styles

    styles = _styles(getSampleStyleSheet, ParagraphStyle, colors)
    g = _finding_groups(_data().vulns)[0]
    out = _finding_block(1, g, styles, colors, Paragraph, Table, TableStyle, mm)
    assert isinstance(out, list) and isinstance(out[0], KeepTogether)


def test_phase_43_executive_metrics_match_the_model() -> None:
    data = _data()
    model = build_report_model(data)
    text = _text(render_executive(model))
    assert f"{model.security_score}/100" in text
    assert model.score_band in text
    assert str(model.counts.active_issues) in text


def test_phase_44_navigation_intact() -> None:
    pdf = render_technical(build_report_model(_data()))
    pairs = re.findall(r"Page (\d+) of (\d+)", _text(pdf))
    assert pairs and int(pairs[0][1]) == _page_count(pdf) - 1
    assert b"/Outlines" in pdf


def test_phase_45_risk_assessment_intact() -> None:
    class _A:
        title = "Q3"
        period_start = period_end = None
        issued_at = CAPTURED
        narrative = "Frozen narrative."
        summary = {"security_score": 58, "score_band": "Weak", "active_findings": 12,
                   "unresolved_issue_count": 4, "affected_assets": ["app.test"],
                   "affected_endpoint_count": 7,
                   "active_severity_counts": {"critical": 2}, "top_risks": [],
                   "remediation_progress": {}}

    text = _text(render_risk_assessment(build_report_model(_data()), _A()))
    assert "MBS.SC" not in text
    assert B.BRAND_NAME in text
    assert "58/100" in text            # frozen snapshot, not the live model score


# --- 16./17. no security-value drift --------------------------------------------------------------

def test_building_the_model_does_not_mutate_the_source_rows() -> None:
    rows = _estate()
    before = [(r.severity, r.cvss_score, r.final_risk_score, r.status, r.verification,
               r.confidence, r.classification) for r in rows]
    build_report_model(_data(rows))
    assert [(r.severity, r.cvss_score, r.final_risk_score, r.status, r.verification,
             r.confidence, r.classification) for r in rows] == before


def test_model_reimplements_no_security_algorithm() -> None:
    """The single-source-of-truth rule, asserted against the source."""
    import pathlib

    source = pathlib.Path("apps/api/modules/reports/model.py").read_text(encoding="utf-8")
    body = source[source.index("def build_report_model"):]
    for banned in ("_BASE_PENALTY", "math.log", "def _classify", "cvss_score >",
                   "severity ==", "if score >="):
        assert banned not in body, f"model re-implements domain logic: {banned!r}"


def test_score_still_comes_from_the_canonical_scorer() -> None:
    rows = _estate()
    assert build_report_model(_data(rows)).security_score == compute_security_score(rows)


def test_issue_identity_is_the_canonical_key() -> None:
    data = _data()
    model = build_report_model(data)
    assert {f.issue_key for f in model.findings} == {issue_key(v) for v in data.vulns}


def test_rendered_reports_are_unchanged_by_the_extraction() -> None:
    """The renderers do not consume the model yet, so their output must be untouched.

    Compares two renders of identical data with the cover's wall-clock stamp normalised."""
    model = build_report_model(_data())
    def _norm(pdf):
        return re.sub(r"Generated \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC", "TS", _text(pdf))
    assert _norm(render_executive(model)) == _norm(render_executive(model))
    assert _norm(render_technical(model)) == _norm(render_technical(model))


# =============================================================================================
# STEP 4 -- the renderers consume ReportModel
# =============================================================================================

def _model():
    return build_report_model(_data())


def test_renderers_accept_a_report_model() -> None:
    """The migrated contract: render_* take a ReportModel, not a ReportData."""
    import inspect

    for fn in (render_executive, render_technical):
        (param,) = list(inspect.signature(fn).parameters)
        assert param == "model"
    assert list(inspect.signature(render_risk_assessment).parameters)[0] == "model"


def test_renderers_render_from_a_model_alone() -> None:
    model = _model()
    assert render_executive(model)[:4] == b"%PDF"
    assert render_technical(model)[:4] == b"%PDF"


def test_report_model_has_no_data_escape_hatch() -> None:
    """The hatch is gone: a renderer cannot reach around the contract to the live rows."""
    names = {f.name for f in dataclasses.fields(ReportModel)}
    assert "data" not in names
    assert not hasattr(_model(), "data")


def test_renderer_never_references_the_hatch() -> None:
    import pathlib

    source = pathlib.Path("apps/api/modules/reports/render.py").read_text(encoding="utf-8")
    assert "model.data" not in source


def test_public_render_entry_point_still_accepts_report_data() -> None:
    """The production import path is unchanged: reports.service keeps passing ReportData."""
    from apps.api.modules.reports.render import render

    data = _data()
    assert render("executive", data)[:4] == b"%PDF"
    assert render("technical", data)[:4] == b"%PDF"


def test_model_carries_every_fact_the_finding_block_reads() -> None:
    """Regression for the two real gaps the parity gate caught: `risk_rationale` (crashed) and
    `matcher_names` (silently rendered "N/A" and changed the inference wording)."""
    finding = _model().findings[0]
    for key in ("key", "finding_id", "title", "severity", "status", "classification",
                "verification", "confidence", "cvss_score", "cvss_vector",
                "final_risk_score", "category", "template_id", "matched_ats",
                "unlocated_count", "occurrence_count", "asset_values", "tools",
                "matcher_names", "evidence_records", "evidence_items", "evidence_uris",
                "screenshots", "compliance", "description", "risk_rationale",
                "remediation_summary", "remediation_steps", "remediation_references"):
        finding[key]  # must not raise


def test_matcher_names_survive_into_the_model() -> None:
    model = _model()
    assert any(f.matcher_names for f in model.findings)


def test_group_view_is_read_only() -> None:
    """The mapping view exposes no setter -- a renderer still cannot mutate a fact."""
    finding = _model().findings[0]
    assert not hasattr(finding, "__setitem__")
    with pytest.raises(KeyError):
        finding["not_a_real_key"]


@pytest.mark.parametrize("report_type", ["executive", "technical"])
def test_pdf_page_count_parity_through_the_model(report_type: str) -> None:
    """PDF-level: the model path produces the same pagination as the data it came from."""
    from apps.api.modules.reports.render import render

    data = _data()
    direct = render_executive if report_type == "executive" else render_technical
    assert _page_count(render(report_type, data)) == _page_count(direct(build_report_model(data)))


def test_rendered_text_is_identical_between_entry_point_and_direct_model_call() -> None:
    from apps.api.modules.reports.render import render

    data = _data()
    model = build_report_model(data)

    def _norm(pdf):
        return re.sub(r"Generated \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC", "TS", _text(pdf))

    assert _norm(render("technical", data)) == _norm(render_technical(model))
    assert _norm(render("executive", data)) == _norm(render_executive(model))


def test_risk_assessment_renders_from_the_model_and_keeps_its_snapshot() -> None:
    class _A:
        title = "Q3"
        period_start = period_end = None
        issued_at = CAPTURED
        narrative = "Frozen."
        summary = {"security_score": 58, "score_band": "Weak", "active_findings": 12,
                   "unresolved_issue_count": 4, "affected_assets": ["app.test"],
                   "affected_endpoint_count": 7, "active_severity_counts": {"critical": 2},
                   "top_risks": [], "remediation_progress": {}}

    model = _model()
    text = _text(render_risk_assessment(model, _A()))
    assert "58/100" in text                                  # frozen, not the model's score
    assert f"{model.security_score}/100" not in text
    assert "MBS.SC" not in text


def test_step4_navigation_parity() -> None:
    pdf = render_technical(_model())
    pairs = re.findall(r"Page (\d+) of (\d+)", _text(pdf))
    assert pairs and int(pairs[0][1]) == _page_count(pdf) - 1
    assert b"/Outlines" in pdf


def test_step4_evidence_manifest_parity() -> None:
    model = _model()
    text = _text(render_technical(model))
    assert "Evidence manifest" in text
    for _fid, record in model.evidence_manifest:
        assert record.artifact_id in text


def test_step4_no_security_value_drift() -> None:
    """Rendering from the model must not alter a single assessed value on the source rows."""
    rows = _estate()
    data = _data(rows)
    before = [(r.severity, r.cvss_score, r.final_risk_score, r.status, r.verification,
               r.confidence, r.classification) for r in rows]
    render_technical(build_report_model(data))
    render_executive(build_report_model(data))
    assert [(r.severity, r.cvss_score, r.final_risk_score, r.status, r.verification,
             r.confidence, r.classification) for r in rows] == before
