"""Phase 2.2 (R-02) -- compliance coverage must describe CURRENT findings only.

THE DEFECT THIS PINS
--------------------
Both compliance surfaces (`render._compliance_cards` and the Executive framework line) walked
`data.vulns` UNFILTERED, while every neighbouring aggregate -- the security score, the MITRE
tally (attack.aggregation) and `_currently_affecting` -- filters on `scoring.is_scorable`.

So a project whose findings were ALL fixed or dismissed as false positives, scoring 100/100
with an empty ATT&CK section, still rendered PCI DSS and ISO 27001 control cards. A false
positive is a finding that never existed; mapping it to a PCI control is an affirmative
misstatement, not a display quirk.

THE CONTRACT (traced from the code, not assumed)
------------------------------------------------
`is_scorable` is NOT interchangeable with "status is active". It composes THREE independent
exclusions -- non-active status, `info` severity, and a DETECTION classification -- so an
ACTIVE info finding and an ACTIVE technology detection are both is_active=True but
is_scorable=False. The tests below pin that distinction explicitly, because choosing the
weaker predicate would leave two of the three exclusions unenforced.

WHAT IS DELIBERATELY UNCHANGED
------------------------------
The catalogue (compliance/catalog.py), the CWE -> control mapping semantics, the stored
`compliance_mappings` rows and all five frameworks. Phase 2.2 filters WHICH FINDINGS are read
at render time and carries the contributing finding IDs; it writes nothing.
"""

import collections
import re
import uuid

from apps.api.modules.compliance.catalog import controls_for_category, framework_name
from apps.api.modules.reports.data import ReportData, VulnRow
from apps.api.modules.reports.render import render_executive, render_technical
from apps.api.modules.reports.scoring import compute_security_score, is_active, is_scorable

from apps.api.tests.test_report_layout import _pdf_text

OWASP = ("owasp", "A03:2021", "Injection")
NIST = ("nist", "SI-10", "Information Input Validation")
ISO = ("iso27001", "A.8.28", "Secure coding")
PCI = ("pci_dss", "6.5.7", "Cross-site scripting (XSS)")
CIS = ("cis", "16.11", "Leverage Vetted Modules")


def _row(template_id="xss-reflected", severity="high", status="open", cvss=6.1,
         compliance=(OWASP,), matched_at="https://h/a", category="cwe-79"):
    return VulnRow(
        id=uuid.uuid4(), title=f"{template_id} finding", severity=severity, status=status,
        category=category, cvss_score=cvss, cvss_vector=None, final_risk_score=cvss,
        risk_rationale=None, compliance=list(compliance), evidence_uris=[],
        template_id=template_id, matcher_name="status", matched_at=matched_at,
    )


def _data(rows, name="Proj", attack=()):
    active = [r for r in rows if r.status in ("open", "confirmed", "reopened")]
    return ReportData(
        project_name=name,
        security_score=compute_security_score(rows),
        severity_counts=dict(collections.Counter(r.severity for r in rows)),
        total_vulns=len(rows),
        active_vulns=len(active),
        active_severity_counts=dict(collections.Counter(r.severity for r in active)),
        vulns=rows,
        attack_techniques=list(attack),
    )


def _text(pdf: bytes) -> str:
    return re.sub(r"\s+", " ", _pdf_text(pdf))


def _compliance_section(pdf: bytes) -> str:
    """Just the Compliance Coverage SECTION of a rendered report.

    Scoped deliberately. A finding's OWN block still prints the controls that finding was
    mapped to, under References -- that is per-finding provenance and Phase 2.2 leaves it
    alone (see test_per_finding_control_line_in_the_finding_block_is_unchanged). Asserting
    over the whole document would therefore conflate the coverage AGGREGATE, which R-02 fixes,
    with that provenance line, which is correct as it stands.

    `rfind` skips the Table of Contents entry, which carries the same heading text."""
    text = _text(pdf)
    start = text.rfind("Compliance Coverage")
    assert start != -1, "no Compliance Coverage section in the rendered report"
    end = text.find("MITRE ATT", start)
    return text[start:end if end != -1 else len(text)]


# --- the contract itself: is_scorable is NOT "status is active" ---------------------------

def test_scorable_and_active_are_not_interchangeable() -> None:
    """Pins WHY the fix uses is_scorable. If these ever converge, the choice of predicate
    stops mattering and this test should be revisited deliberately -- not silently."""
    info_active = _row(template_id="missing-header", severity="info", status="open")
    detection_active = _row(template_id="tech-detect-nginx", severity="low", status="open",
                            cvss=None, category=None)
    assert is_active(info_active) is True and is_scorable(info_active) is False
    assert is_active(detection_active) is True and is_scorable(detection_active) is False


def test_info_severity_active_finding_does_not_create_coverage() -> None:
    data = _data([_row(template_id="missing-header", severity="info", status="open",
                       compliance=(OWASP,))])
    assert data.compliance_coverage() == []
    assert data.compliance_frameworks() == []


def test_detection_only_active_finding_does_not_create_coverage() -> None:
    data = _data([_row(template_id="tech-detect-nginx", severity="low", status="open",
                       cvss=None, category=None, compliance=(OWASP,))])
    assert data.compliance_coverage() == []


# --- CASE A: dismissed findings -----------------------------------------------------------

def test_case_a_only_the_scorable_finding_contributes() -> None:
    """One active/scorable + one fixed + one false_positive, each on a DIFFERENT control."""
    live = _row(template_id="xss-live", status="open", compliance=(OWASP,))
    fixed = _row(template_id="sqli-gone", status="fixed", compliance=(NIST,))
    fp = _row(template_id="not-real", status="false_positive", compliance=(ISO,))
    data = _data([live, fixed, fp])

    coverage = data.compliance_coverage()
    assert [fw for fw, _ in coverage] == ["owasp"]
    control_id, _desc, finding_ids = coverage[0][1][0]
    assert control_id == "A03:2021"
    assert finding_ids == [live.finding_id]


def test_case_a_accepted_risk_also_excluded() -> None:
    """accepted_risk is a sticky analyst decision and is non-active like the other two."""
    data = _data([
        _row(template_id="xss-live", status="open", compliance=(OWASP,)),
        _row(template_id="accepted", status="accepted_risk", compliance=(PCI,)),
    ])
    assert data.compliance_frameworks() == ["owasp"]


def test_case_a_reopened_is_active_and_does_contribute() -> None:
    """A regression is a live problem again -- the exclusion must not over-reach."""
    data = _data([_row(template_id="xss-back", status="reopened", compliance=(PCI,))])
    assert data.compliance_frameworks() == ["pci_dss"]


def test_case_a_fixed_finding_does_not_leak_into_the_coverage_sections() -> None:
    data = _data([
        _row(template_id="xss-live", status="open", compliance=(OWASP,)),
        _row(template_id="pci-gone", status="fixed", compliance=(PCI,)),
    ])
    for section in (_compliance_section(render_executive(data)),
                    _compliance_section(render_technical(data))):
        assert "OWASP" in section
        assert "PCI DSS" not in section  # the fixed finding's framework must not appear


# --- CASE B: nothing active ---------------------------------------------------------------

def test_case_b_no_active_findings_claims_no_coverage() -> None:
    data = _data([
        _row(template_id="a", status="fixed", compliance=(PCI,)),
        _row(template_id="b", status="false_positive", compliance=(ISO,)),
    ])
    assert data.compliance_coverage() == []
    assert data.compliance_frameworks() == []


def test_case_b_compliance_agrees_with_mitre_and_assets() -> None:
    """The three aggregates must describe ONE population -- this is the R-02 regression."""
    data = _data([
        _row(template_id="a", status="fixed", compliance=(PCI,)),
        _row(template_id="b", status="false_positive", compliance=(ISO,)),
    ], attack=[])
    assert data.compliance_frameworks() == []
    assert data.attack_techniques == []
    assert data.affected_assets() == []
    assert data.scorable_issue_count() == 0


def test_case_b_rendered_reports_state_the_absence_honestly() -> None:
    data = _data([
        _row(template_id="a", status="fixed", compliance=(PCI,)),
        _row(template_id="b", status="false_positive", compliance=(ISO,)),
    ])
    exec_section = _compliance_section(render_executive(data))
    tech_section = _compliance_section(render_technical(data))
    assert "No current findings map to compliance controls" in exec_section
    assert "No current findings map to compliance controls" in tech_section
    for section in (exec_section, tech_section):
        assert "PCI DSS" not in section
        assert "ISO/IEC" not in section


# --- CASE C: contributing finding IDs -----------------------------------------------------

def test_case_c_shared_control_appears_once_with_every_contributing_id() -> None:
    a = _row(template_id="xss-1", compliance=(OWASP,))
    b = _row(template_id="xss-2", compliance=(OWASP,))
    data = _data([a, b])

    coverage = data.compliance_coverage()
    assert len(coverage) == 1
    controls = coverage[0][1]
    assert len(controls) == 1                      # the control appears ONCE
    control_id, _desc, finding_ids = controls[0]
    assert control_id == "A03:2021"
    assert finding_ids == sorted([a.finding_id, b.finding_id])


def test_case_c_finding_ids_are_deduplicated() -> None:
    """One issue at many locations is many rows; a control must not list the same id twice,
    and two rows of the same issue are two DB identities -- both legitimately listed."""
    rows = [_row(template_id="xss-1", matched_at=f"https://h/p{i}", compliance=(OWASP, OWASP))
            for i in range(3)]
    data = _data(rows)
    _cid, _desc, finding_ids = data.compliance_coverage()[0][1][0]
    assert len(finding_ids) == len(set(finding_ids)) == 3


def test_case_c_ids_use_the_existing_canonical_identifier() -> None:
    """No new identity system: the IDs are VulnRow.finding_id, i.e. MBS-XXXXXXXX."""
    row = _row()
    data = _data([row])
    _cid, _desc, finding_ids = data.compliance_coverage()[0][1][0]
    assert finding_ids == [row.finding_id]
    assert re.fullmatch(r"MBS-[0-9A-F]{8}", finding_ids[0])


def test_case_c_association_reaches_the_technical_pdf() -> None:
    a = _row(template_id="xss-1", compliance=(OWASP,))
    b = _row(template_id="xss-2", compliance=(OWASP,))
    text = _text(render_technical(_data([a, b])))
    assert "Mapped from 2 finding(s)" in text
    assert a.finding_id in text
    assert b.finding_id in text


def test_case_c_executive_and_technical_share_one_population() -> None:
    """Requirement 6: both sections must use the same underlying population/contract."""
    data = _data([
        _row(template_id="xss-live", status="open", compliance=(OWASP, PCI)),
        _row(template_id="gone", status="fixed", compliance=(ISO, NIST, CIS)),
    ])
    exec_section = _compliance_section(render_executive(data))
    tech_section = _compliance_section(render_technical(data))
    for fw in data.compliance_frameworks():
        assert framework_name(fw) in exec_section
        assert framework_name(fw) in tech_section
    # The fixed finding's three frameworks must appear in NEITHER coverage section.
    for absent in ("ISO/IEC 27001", "NIST 800-53", "CIS Controls"):
        assert absent not in exec_section
        assert absent not in tech_section


# --- CASE D: the PDF population must not contradict the stored/API mappings ----------------

def test_case_d_catalogue_mappings_are_preserved_unchanged() -> None:
    """The per-vulnerability API serves controls_for_category(). Phase 2.2 must not alter what
    that returns for any category -- it only narrows WHICH FINDINGS the report reads."""
    for cwe in ("cwe-79", "cwe-89", "cwe-22", "cwe-693", "cwe-327"):
        assert controls_for_category(cwe) == controls_for_category(cwe.upper())
        assert controls_for_category(cwe), f"catalogue lost mappings for {cwe}"


def test_case_d_all_five_frameworks_still_reachable() -> None:
    """Requirement 2: every advertised framework must still be able to appear."""
    rows = [
        _row(template_id="xss", compliance=(OWASP,)),
        _row(template_id="inj", compliance=(NIST,)),
        _row(template_id="code", compliance=(ISO,)),
        _row(template_id="pci", compliance=(PCI,)),
        _row(template_id="cis", compliance=(CIS,)),
    ]
    assert set(_data(rows).compliance_frameworks()) == {
        "owasp", "nist", "iso27001", "pci_dss", "cis"
    }


def test_case_d_pdf_population_is_a_subset_of_the_stored_mappings() -> None:
    """The report can only ever narrow the stored mappings, never invent one: every
    (framework, control) it prints must exist on a finding that carries it."""
    rows = [
        _row(template_id="xss-live", status="open", compliance=(OWASP, PCI)),
        _row(template_id="gone", status="fixed", compliance=(ISO,)),
    ]
    data = _data(rows)
    stored = {(fw, cid) for r in rows for (fw, cid, _d) in r.compliance}
    rendered = {(fw, cid) for fw, ctrls in data.compliance_coverage() for cid, _d, _i in ctrls}
    assert rendered <= stored
    assert rendered == {("owasp", "A03:2021"), ("pci_dss", "6.5.7")}


def test_case_d_compliance_population_matches_the_mitre_population() -> None:
    """Both now filter on is_scorable, so the set of findings behind each must be identical."""
    rows = [
        _row(template_id="live", status="open", compliance=(OWASP,)),
        _row(template_id="fixed", status="fixed", compliance=(NIST,)),
        _row(template_id="info", severity="info", status="open", compliance=(ISO,)),
        _row(template_id="tech-detect-x", status="open", cvss=None, category=None,
             compliance=(PCI,)),
    ]
    data = _data(rows)
    contributing = {fid for _fw, ctrls in data.compliance_coverage()
                    for _cid, _d, ids in ctrls for fid in ids}
    scorable = {r.finding_id for r in rows if is_scorable(r)}
    assert contributing == scorable


# --- wording: finding-based coverage, never a compliance claim -----------------------------

def test_reports_do_not_claim_certification_or_compliance() -> None:
    data = _data([_row(compliance=(OWASP, ISO))])
    for section in (_compliance_section(render_executive(data)),
                    _compliance_section(render_technical(data))):
        assert "NOT a compliance assessment" in section
        assert "certification" in section
    # The specific overstatements the brief names must never appear ANYWHERE in either report.
    for text in (_text(render_executive(data)), _text(render_technical(data))):
        assert "ISO 27001 compliant" not in text
        assert "is compliant" not in text


def test_reports_say_coverage_is_finding_based() -> None:
    data = _data([_row(compliance=(OWASP,))])
    for section in (_compliance_section(render_executive(data)),
                    _compliance_section(render_technical(data))):
        assert "finding-based coverage" in section


# --- invariants: Phase 2.2 changed nothing else --------------------------------------------

def test_r01_issue_counts_remain_intact() -> None:
    """Phase 2.1 must still hold: 1 issue x 7 locations reads as both units."""
    rows = [_row(template_id="xss-1", matched_at=f"https://h/p{i}") for i in range(7)]
    data = _data(rows)
    assert data.total_issue_count() == 1
    assert data.active_issue_count() == 1
    assert data.total_vulns == 7
    assert "1 unique issue across 7 affected locations" in _text(render_executive(data))


def test_security_score_and_mitre_are_untouched_by_the_compliance_fix() -> None:
    rows = [
        _row(template_id="live", status="open", compliance=(OWASP,)),
        _row(template_id="fixed", status="fixed", compliance=(NIST,)),
    ]
    data = _data(rows, attack=[("Execution", "T1059", "Command and Scripting Interpreter", 1)])
    assert data.security_score == compute_security_score(rows)
    assert data.attack_techniques == [("Execution", "T1059",
                                       "Command and Scripting Interpreter", 1)]


def test_compliance_aggregation_does_not_mutate_rows() -> None:
    rows = [_row(template_id="a", compliance=(OWASP, PCI)),
            _row(template_id="b", status="fixed", compliance=(ISO,))]
    before = [(r.status, r.severity, tuple(r.compliance)) for r in rows]
    data = _data(rows)
    data.compliance_coverage()
    data.compliance_frameworks()
    render_executive(data)
    render_technical(data)
    assert [(r.status, r.severity, tuple(r.compliance)) for r in rows] == before


def test_per_finding_control_line_in_the_finding_block_is_unchanged() -> None:
    """_finding_groups' own `compliance` union is per-finding provenance, NOT the coverage
    aggregate, and Phase 2.2 deliberately leaves it alone -- a fixed finding's own block
    should still state the controls it was mapped to."""
    from apps.api.modules.reports.render import _finding_groups

    fixed = _row(template_id="gone", status="fixed", compliance=(ISO,))
    groups = _finding_groups([fixed])
    assert groups[0]["compliance"] == [ISO]


def test_determinism() -> None:
    rows = [_row(template_id=f"t{i}", compliance=(OWASP, PCI, ISO)) for i in range(4)]
    data = _data(rows)
    assert data.compliance_coverage() == data.compliance_coverage()
    assert data.compliance_frameworks() == sorted(data.compliance_frameworks())
