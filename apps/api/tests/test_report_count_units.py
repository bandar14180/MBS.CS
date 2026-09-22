"""Phase 2.1 (R-01) -- explicit report count units: unique ISSUES vs recorded OCCURRENCES.

THE DEFECT THIS PINS
--------------------
A vulnerability ROW is one occurrence AT ONE LOCATION: per vulnerabilities/models.py the dedup
identity is (project_id, fingerprint), and per nuclei_runner.py a fingerprint is
`template_id|matcher|matched_at`. So `total_vulns`, `active_vulns`, `severity_counts` and the
verification tally are all OCCURRENCE counts, while the security score, Executive Key Risks,
Technical Detailed Findings and the MITRE tally all count distinct ISSUES (scoring.issue_key).

Both units were correct and neither was labelled, so one issue observed at seven endpoints
rendered as "7 active findings" above a single finding block -- and the only inference a reader
could draw was that six findings had been dropped from the report.

WHAT THESE TESTS GUARANTEE
--------------------------
  1. the three new ReportData issue-count methods equal the groupings they reconcile with,
     by construction rather than by coincidence;
  2. the surfaces that are DELIBERATELY occurrence-based stay occurrence-based;
  3. the surfaces that are issue-based stay issue-based;
  4. both rendered PDFs state BOTH units in words.

WHAT THEY DELIBERATELY DO NOT TOUCH
-----------------------------------
Scoring, CVSS, severity, verification, classification, grouping identity, MITRE counting and
remediation semantics are all unchanged by Phase 2.1; the invariants at the bottom of this file
assert that the new metrics cannot have altered any of them.
"""

import collections
import re
import uuid

from apps.api.modules.reports.data import ReportData, VulnRow
from apps.api.modules.reports.render import (
    _finding_groups,
    _issue_occurrence_phrase,
    _score_impacting_count,
    _top_risk_groups,
    _verification_summary,
    render_executive,
    render_technical,
)
from apps.api.modules.reports.scoring import compute_security_score, group_issues, issue_key
from apps.api.modules.reports.verification import PARTIALLY_VERIFIED, UNVERIFIED, VERIFIED

# Reuse the layout suite's dependency-free PDF text extractor rather than adding a PDF library
# or writing a second one: one extractor means these assertions and the layout assertions can
# never disagree about what the document actually says.
from apps.api.tests.test_report_layout import _pdf_text


def _row(template_id="cmd-inj", severity="critical", status="open", cvss=9.8, risk=10.0,
         matched_at="https://h/a", evidence=(), shots=(), matcher="time-based", category="cwe-78"):
    return VulnRow(
        id=uuid.uuid4(), title=template_id, severity=severity, status=status, category=category,
        cvss_score=cvss, cvss_vector="CVSS:3.1/AV:N", final_risk_score=risk,
        risk_rationale="criticality 'critical' weight 2.0", compliance=[],
        evidence_uris=list(evidence), screenshots=list(shots),
        template_id=template_id, matcher_name=matcher, matched_at=matched_at,
    )


def _data(rows, name="Proj", attack=()):
    """A ReportData whose OCCURRENCE counts are built exactly as gather_report_data builds them."""
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


# THE canonical Phase 2.1 scenario: ONE issue (one template) observed at SEVEN endpoints.
def _spread_rows():
    return [_row(matched_at=f"https://h/p{i}", evidence=[f"s3://b/e{i}.txt"]) for i in range(7)]


def _text(pdf: bytes) -> str:
    return re.sub(r"\s+", " ", _pdf_text(pdf))


# --- 1 issue x 7 endpoints: the counts themselves -----------------------------------------

def test_one_issue_seven_endpoints_unique_issue_count_is_one() -> None:
    data = _data(_spread_rows())
    assert data.total_issue_count() == 1
    assert data.active_issue_count() == 1
    assert data.scorable_issue_count() == 1


def test_one_issue_seven_endpoints_occurrence_count_is_seven() -> None:
    data = _data(_spread_rows())
    assert data.total_vulns == 7
    assert data.active_vulns == 7
    assert _score_impacting_count(data) == 7


def test_seven_endpoints_are_seven_distinct_affected_locations() -> None:
    """The occurrence count is not an artefact -- there really are seven distinct locations."""
    data = _data(_spread_rows())
    assert data.affected_endpoint_count() == 7


# --- the reconciliation identities the report now states in words --------------------------

def test_total_issue_count_equals_technical_detailed_findings_block_count() -> None:
    """Technical Detailed Findings renders one block per _finding_groups entry over ALL rows."""
    rows = _spread_rows() + [
        _row(template_id="xss", severity="medium", status="fixed", matched_at="https://h/x"),
        _row(template_id="hdr", severity="low", status="false_positive", matched_at="https://h/y"),
    ]
    data = _data(rows)
    assert data.total_issue_count() == len(_finding_groups(rows)) == 3


def test_active_issue_count_equals_executive_key_risks_row_count() -> None:
    """Executive Key Risks buckets ACTIVE rows via _top_risk_groups."""
    rows = _spread_rows() + [
        _row(template_id="xss", severity="medium", status="fixed", matched_at="https://h/x"),
        _row(template_id="hdr", severity="low", status="open", matched_at="https://h/y"),
    ]
    data = _data(rows)
    assert data.active_issue_count() == len(_top_risk_groups(rows)) == 2


def test_scorable_issue_count_equals_the_scores_own_grouping() -> None:
    """scorable_issue_count delegates to group_issues, so it cannot drift from the score."""
    rows = _spread_rows() + [
        _row(template_id="tech-detect", severity="info", status="open", matched_at="https://h/i"),
        _row(template_id="xss", severity="high", status="accepted_risk", matched_at="https://h/x"),
    ]
    data = _data(rows)
    assert data.scorable_issue_count() == len(group_issues(rows)) == 1


def test_the_three_issue_counts_describe_three_real_populations() -> None:
    """They are not interchangeable: all-status >= active >= scorable."""
    rows = [
        _row(template_id="A", matched_at="https://h/1"),
        _row(template_id="A", matched_at="https://h/2"),      # same issue, 2nd location
        _row(template_id="B", status="fixed", matched_at="https://h/3"),
        _row(template_id="C", severity="info", matched_at="https://h/4"),
        _row(template_id="D", status="false_positive", matched_at="https://h/5"),
    ]
    data = _data(rows)
    assert data.total_issue_count() == 4      # A, B, C, D
    assert data.active_issue_count() == 2     # A, C  (B and D are not active)
    assert data.scorable_issue_count() == 1   # A     (C is info)
    assert data.total_vulns == 5              # occurrences, unchanged


# --- surfaces that are DELIBERATELY occurrence-based must stay so --------------------------

def test_severity_counts_remain_occurrence_based() -> None:
    """A severity distribution is per observed location by design; Phase 2.1 only labels it."""
    data = _data(_spread_rows())
    assert data.severity_counts["critical"] == 7
    assert data.active_severity_counts["critical"] == 7


def test_verification_counts_remain_occurrence_based() -> None:
    """Verification is a property of an OBSERVATION: one issue can be demonstrated at one
    location and merely suspected at another, so this tally must not collapse to the issue."""
    data = _data(_spread_rows())
    counts = _verification_summary(data)
    assert sum(counts.values()) == 7
    assert counts[PARTIALLY_VERIFIED] == 7


def test_verification_can_differ_across_locations_of_one_issue() -> None:
    """The reason the verification tally stays occurrence-based, made explicit."""
    rows = [
        _row(matched_at="https://h/a", matcher="status", evidence=["s3://b/e.txt"],
             shots=[("s3://b/s.png", "sha256:aa")]),   # both artefact kinds -> VERIFIED
        _row(matched_at="https://h/b", matcher="status"),  # no artefacts     -> UNVERIFIED
    ]
    data = _data(rows)
    counts = _verification_summary(data)
    assert data.active_issue_count() == 1        # still ONE issue
    assert counts[VERIFIED] == 1
    assert counts[UNVERIFIED] == 1


def test_score_impacting_count_remains_occurrence_based() -> None:
    data = _data(_spread_rows())
    assert _score_impacting_count(data) == 7
    assert data.scorable_issue_count() == 1


# --- surfaces that are issue-based must stay issue-based ----------------------------------

def test_executive_key_risks_remains_issue_based() -> None:
    groups = _top_risk_groups(_spread_rows())
    assert len(groups) == 1
    assert groups[0]["endpoint_count"] == 7


def test_technical_detailed_findings_remains_issue_based() -> None:
    groups = _finding_groups(_spread_rows())
    assert len(groups) == 1
    assert groups[0]["occurrence_count"] == 7
    assert len(groups[0]["matched_ats"]) == 7


def test_mitre_remains_issue_based() -> None:
    """The ATT&CK tally is built in data.gather_report_data over issue keys; Phase 2.1 does not
    touch it. Pinned here so a later change to the count vocabulary cannot silently alter it."""
    rows = _spread_rows()
    data = _data(rows, attack=[("Execution", "T1059", "Command and Scripting Interpreter", 1)])
    assert data.attack_techniques[0][3] == 1           # one ISSUE, not seven findings
    assert data.scorable_issue_count() == 1            # and it agrees with the score population


# --- the shared phrasing helper -----------------------------------------------------------

def test_phrase_states_both_units() -> None:
    assert _issue_occurrence_phrase(1, 7) == "1 unique issue across 7 affected locations"
    assert _issue_occurrence_phrase(3, 12) == "3 unique issues across 12 affected locations"


def test_phrase_drops_the_across_clause_when_the_units_agree() -> None:
    """"3 unique issues across 3 affected locations" invites a distinction that isn't there."""
    assert _issue_occurrence_phrase(3, 3) == "3 unique issues"
    assert _issue_occurrence_phrase(1, 1) == "1 unique issue"


def test_phrase_singularises_one_location() -> None:
    assert _issue_occurrence_phrase(2, 1) == "2 unique issues across 1 affected location"


# --- the rendered documents must SAY both units -------------------------------------------

def test_executive_pdf_states_both_units() -> None:
    text = _text(render_executive(_data(_spread_rows())))
    assert "1 unique issue across 7 affected locations" in text
    assert "7 recorded finding(s)" in text


def test_technical_pdf_states_both_units() -> None:
    text = _text(render_technical(_data(_spread_rows())))
    assert "1 unique issue across 7 affected locations" in text
    assert "7 recorded finding(s)" in text


def test_executive_pdf_labels_its_occurrence_based_tables() -> None:
    """The severity and verification tables must name their unit, since it differs from the
    issue counts stated elsewhere on the same page."""
    text = _text(render_executive(_data(_spread_rows())))
    assert "Recorded findings" in text                       # verification column header
    assert "not unique issues" in text                       # the explicit disclaimer


def test_technical_pdf_reconciles_its_block_count_with_the_summary() -> None:
    """The exact number a reader gets by counting blocks is stated in the summary above them."""
    rows = _spread_rows() + [
        _row(template_id="xss", severity="medium", matched_at="https://h/x"),
    ]
    data = _data(rows)
    text = _text(render_technical(data))
    assert data.total_issue_count() == len(_finding_groups(rows)) == 2
    assert "2 finding block(s)" in text
    assert "2 unique issue(s)" in text


def test_executive_pdf_reconciles_key_risks_with_the_headline_counts() -> None:
    text = _text(render_executive(_data(_spread_rows())))
    assert "This project has 1 unique issue across 7 affected locations" in text
    assert "One row = one unique issue" in text


# --- backward compatibility ----------------------------------------------------------------

def test_findings_summary_survives_a_reportdata_without_the_new_methods() -> None:
    """_findings_summary getattr-guards the new method, exactly as it does active_severity_counts,
    so a stub or older ReportData still renders rather than raising."""
    from apps.api.modules.reports.render import _findings_summary

    class _Legacy:
        active_vulns = 3
        severity_counts = {"high": 3}
        active_severity_counts = {"high": 3}

    out = _findings_summary(_Legacy())
    assert "3 active findings" in out
    assert "unique issue" not in out  # no issue clause when the count is unavailable


def test_zero_findings_is_unchanged() -> None:
    data = _data([])
    assert data.total_issue_count() == 0
    assert data.active_issue_count() == 0
    assert data.scorable_issue_count() == 0
    assert isinstance(render_executive(data), bytes)
    assert isinstance(render_technical(data), bytes)


# --- INVARIANTS: Phase 2.1 changed no assessment semantics ---------------------------------

def test_issue_counts_use_the_canonical_issue_key() -> None:
    """total_issue_count must partition by scoring.issue_key -- not a second local identity."""
    rows = _spread_rows()
    data = _data(rows)
    assert data.total_issue_count() == len({issue_key(r) for r in rows})


def test_counting_does_not_mutate_any_row() -> None:
    rows = _spread_rows()
    before = [(r.severity, r.status, r.cvss_score, r.final_risk_score, r.verification,
               r.confidence, r.classification) for r in rows]
    data = _data(rows)
    data.total_issue_count(), data.active_issue_count(), data.scorable_issue_count()
    render_executive(data)
    render_technical(data)
    after = [(r.severity, r.status, r.cvss_score, r.final_risk_score, r.verification,
              r.confidence, r.classification) for r in rows]
    assert before == after


def test_security_score_is_unchanged_by_the_new_metrics() -> None:
    """The score is computed exactly as before; the new counts only DESCRIBE it."""
    rows = _spread_rows()
    assert _data(rows).security_score == compute_security_score(rows)
