"""STEP 4 -- Executive Report clarity, plus a pinned audit of the security-score arithmetic.

The Executive Report showed severity but not VERIFICATION, and gave no indication that most
findings carry no score penalty. A reader saw "157 findings, score 25" and could reasonably
conclude 157 confirmed vulnerabilities. Both facts are now stated.

Nothing here changes an assessment value: the two new helpers COUNT findings using the same
classifier and the same `is_scorable` predicate the rest of the pipeline already uses.
"""

import collections
import uuid

from apps.api.modules.reports.data import ReportData, VulnRow
from apps.api.modules.reports.render import (
    _findings_summary,
    _score_impacting_count,
    _verification_summary,
    render_executive,
    render_technical,
)
from apps.api.modules.reports.scoring import compute_security_score
from apps.api.modules.reports.verification import PARTIALLY_VERIFIED, UNVERIFIED, VERIFIED

LOG = ["s3://mbs-evidence/tool-runs/a/raw-output.txt"]
SHOT = [("s3://mbs-evidence/shots/a.png", "sha256:aa")]


def _row(template_id="apache-path-traversal-2021", severity="high", status="open", cvss=9.8,
         risk=10.0, matched_at="https://e.com/a", evidence=(), shots=(), matcher="status"):
    return VulnRow(
        id=uuid.uuid4(), title=template_id, severity=severity, status=status, category=None,
        cvss_score=cvss, cvss_vector=None, final_risk_score=risk, risk_rationale=None,
        compliance=[], evidence_uris=list(evidence), screenshots=list(shots),
        template_id=template_id, matcher_name=matcher, matched_at=matched_at,
    )


def _data(rows, name="Proj"):
    sev = collections.Counter(r.severity for r in rows)
    active = [r for r in rows if r.status in ("open", "confirmed", "reopened")]
    return ReportData(
        project_name=name, security_score=compute_security_score(rows), severity_counts=dict(sev),
        total_vulns=len(rows), active_vulns=len(active),
        active_severity_counts=dict(collections.Counter(r.severity for r in active)), vulns=rows,
    )


# ============ Security-score arithmetic, pinned against the REAL dataset shape =============

def test_security_score_matches_hand_calculation_for_the_157_finding_shape() -> None:
    """AUDIT: reproduces the real 157-finding project (152 info + 4 high + 1 medium).

    The four scorable issues, from the live database:
        unix-command-injection      high  cvss 9.8 risk 10.0  1 location
        windows-command-injection   high  cvss 9.8 risk 10.0  1 location (2 rows, same location)
        CVE-2025-55184              high  cvss 7.5 risk 10.0  1 location
        django-debug-config-enabled med   cvss 5.5 risk 10.0  1 location

    Hand calculation from scoring.py's own constants:
        penalties 35.650, 35.650, 32.344, 11.787
        score = 100 * PROD(1 - p/100) = 100 * 0.247136 -> 25

    This is a REGRESSION PIN, not a claim the number should be any particular value: it fails
    if the model ever silently changes. The 152 informational findings contribute nothing,
    which is the property that makes "157 findings, score 25" internally consistent."""
    rows = [
        _row("unix-command-injection", "high", cvss=9.8, risk=10.0, matched_at="https://u/1"),
        _row("windows-command-injection", "high", cvss=9.8, risk=10.0, matched_at="dir"),
        _row("windows-command-injection", "high", cvss=9.8, risk=10.0, matched_at="dir"),
        _row("CVE-2025-55184", "high", cvss=7.5, risk=10.0, matched_at="https://c/1"),
        _row("django-debug-config-enabled", "medium", cvss=5.5, risk=10.0, matched_at="https://d/1"),
    ]
    rows += [_row(f"info-{i}", "info", cvss=None, risk=None, matched_at=f"https://h/{i}")
             for i in range(152)]
    assert len(rows) == 157
    assert compute_security_score(rows) == 25


def test_informational_findings_never_reduce_the_score() -> None:
    scorable = [_row("x", "high", cvss=9.8, risk=10.0)]
    with_info = scorable + [_row(f"i-{i}", "info", cvss=None, risk=None) for i in range(200)]
    assert compute_security_score(scorable) == compute_security_score(with_info)


def test_score_impacting_count_matches_the_scores_own_predicate() -> None:
    """Excludes exactly what scoring.is_scorable excludes: inactive, info, and detections.

    NOTE the detection row carries NO CVSS. classification.py fails toward VULNERABILITY, so a
    positive CVSS deliberately OUTRANKS a detection template marker (never hide a real
    weakness). A `waf-detect` row WITH cvss 9.8 is therefore scorable by design -- asserted
    separately below rather than mistaken for a bug here."""
    rows = [
        _row("a", "high"),
        _row("b", "info", cvss=None, risk=None),
        _row("c", "high", status="fixed"),                       # inactive -> not counted
        _row("waf-detect", "medium", cvss=None, risk=None),      # detection -> not counted
    ]
    assert _score_impacting_count(_data(rows)) == 1


def test_detection_template_with_real_cvss_still_counts() -> None:
    """Pins the documented precedence: a positive CVSS outranks a detection marker, so such a
    finding DOES affect the score. Counting it is the safe direction."""
    rows = [_row("waf-detect", "high", cvss=9.8, risk=10.0)]
    assert _score_impacting_count(_data(rows)) == 1


# ============================ Verification summary ========================================

def test_verification_summary_counts_each_state() -> None:
    rows = [
        _row("spec-1", evidence=LOG, shots=SHOT),                 # verified
        _row("spec-2", evidence=LOG),                             # partially
        _row("spec-3"),                                           # unverified
        _row("spec-4"),                                           # unverified
    ]
    assert _verification_summary(_data(rows)) == {
        VERIFIED: 1, PARTIALLY_VERIFIED: 1, UNVERIFIED: 2
    }


def test_verification_summary_counts_active_findings_only() -> None:
    rows = [_row("spec-1", evidence=LOG, shots=SHOT), _row("spec-2", status="fixed",
                                                           evidence=LOG, shots=SHOT)]
    assert _verification_summary(_data(rows))[VERIFIED] == 1


def test_verification_summary_totals_match_active_count() -> None:
    rows = [_row(f"spec-{i}") for i in range(7)]
    data = _data(rows)
    assert sum(_verification_summary(data).values()) == data.active_vulns


def test_verification_summary_is_empty_safe() -> None:
    assert _verification_summary(_data([])) == {
        VERIFIED: 0, PARTIALLY_VERIFIED: 0, UNVERIFIED: 0
    }


def test_verification_summary_agrees_with_the_shared_classifier() -> None:
    """The Executive tally must be derived from the SAME classifier the Technical Report uses,
    so the two documents can never disagree about how many findings are evidence-backed."""
    from apps.api.modules.reports.verification import classify_verification_row

    rows = [_row("spec-1", evidence=LOG, shots=SHOT), _row("spec-2", evidence=LOG), _row("spec-3")]
    expected = collections.Counter(classify_verification_row(r)[0] for r in rows)
    summary = _verification_summary(_data(rows))
    for state, count in expected.items():
        assert summary[state] == count


# ============================ Executive vs Technical ======================================

def _pdf(rows, which):
    return which(_data(rows))


def test_executive_and_technical_both_render() -> None:
    rows = [_row("spec-1", evidence=LOG, shots=SHOT), _row("i", "info", cvss=None, risk=None)]
    assert _pdf(rows, render_executive)[:4] == b"%PDF"
    assert _pdf(rows, render_technical)[:4] == b"%PDF"


def test_executive_stays_more_concise_than_technical() -> None:
    """Executive must summarise, not duplicate the Technical Report."""
    rows = [_row(f"spec-{i}", evidence=LOG, shots=SHOT, matched_at=f"https://e/{i}")
            for i in range(12)]
    assert len(_pdf(rows, render_executive)) < len(_pdf(rows, render_technical))


def test_executive_renders_safely_with_no_findings() -> None:
    assert _pdf([], render_executive)[:4] == b"%PDF"


def test_executive_renders_safely_with_only_informational_findings() -> None:
    rows = [_row(f"i-{i}", "info", cvss=None, risk=None) for i in range(20)]
    data = _data(rows)
    assert data.security_score == 100          # info costs nothing
    assert _score_impacting_count(data) == 0
    assert render_executive(data)[:4] == b"%PDF"


def test_findings_summary_does_not_assert_findings_are_vulnerabilities() -> None:
    """A detection is not a confirmed vulnerability, and the wording must not imply otherwise.

    The word "vulnerabilities" IS allowed to appear -- the sentence uses it to DENY the claim
    ("These are detections, not confirmed vulnerabilities"). So this asserts the meaning: the
    findings are called detections/findings, and any use of the word is negated."""
    rows = [_row(f"i-{i}", "info", cvss=None, risk=None) for i in range(5)]
    text = _findings_summary(_data(rows))
    lowered = text.lower()
    assert "finding" in lowered or "detection" in lowered
    if "vulnerabilit" in lowered:
        assert "not confirmed vulnerabilities" in lowered, (
            f"'vulnerabilities' used without negation: {text!r}"
        )


def test_reports_do_not_mutate_findings() -> None:
    """Rendering is read-only: no assessment value may move as a side effect."""
    rows = [_row("spec-1", evidence=LOG, shots=SHOT), _row("i", "info", cvss=None, risk=None)]
    data = _data(rows)
    before = [(r.cvss_score, r.final_risk_score, r.severity, r.status, r.classification)
              for r in rows]
    score_before = data.security_score
    render_executive(data)
    render_technical(data)
    after = [(r.cvss_score, r.final_risk_score, r.severity, r.status, r.classification)
             for r in rows]
    assert before == after
    assert compute_security_score(rows) == score_before


def test_summaries_do_not_change_the_security_score() -> None:
    rows = [_row("spec-1", evidence=LOG, shots=SHOT), _row("spec-2")]
    before = compute_security_score(rows)
    _verification_summary(_data(rows))
    _score_impacting_count(_data(rows))
    assert compute_security_score(rows) == before
