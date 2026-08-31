"""Regression tests for the security posture score (modules/reports/scoring.py).

These pin the SEMANTICS, not the arithmetic: assertions are written as orderings and
invariants ("a high scores below a medium", "20 locations is not 20 issues") so the
constants can be retuned without rewriting the suite, while any change that breaks the
meaning fails loudly.

Background: the previous model was `100 - sum(per_row_penalty[severity])`, which counted
one penalty per vulnerability ROW. A row is one (template, matcher, matched_at)
fingerprint -- a LOCATION -- so one issue across many endpoints saturated the score at 0.
Several tests below exist specifically to prevent that regression.
"""

import math

import pytest

from apps.api.modules.reports.scoring import (
    ACTIVE_STATUSES,
    ScoredIssue,
    compute_security_score,
    group_issues,
    issue_key,
    score_from_issues,
)


class F:
    """Minimal finding stub with the same attribute surface the scorer reads from a
    report VulnRow. Defaults are the common case: an active, located, CVSS-less finding."""

    def __init__(
        self,
        severity="high",
        status="open",
        template_id="tpl",
        title="Finding",
        matched_at="https://h/a",
        cvss_score=None,
        final_risk_score=None,
    ):
        self.severity = severity
        self.status = status
        self.template_id = template_id
        self.title = title
        self.matched_at = matched_at
        self.cvss_score = cvss_score
        self.final_risk_score = final_risk_score


def _one(severity, **kw):
    """A single distinct issue of the given severity."""
    return [F(severity=severity, template_id=f"tpl-{severity}", **kw)]


# --- 1. Info / detection-only findings never reduce the score -----------------------------

def test_nineteen_info_findings_score_100():
    """The real 'ss' project: 19 open info findings and nothing else. Info is
    detection-only, so posture is untouched."""
    findings = [F(severity="info", template_id=f"tech-{i}", matched_at=f"https://h/{i}") for i in range(19)]
    assert compute_security_score(findings) == 100


def test_no_findings_scores_100():
    assert compute_security_score([]) == 100


def test_info_does_not_dilute_a_real_finding():
    """Adding info findings alongside a real one must not change the score at all."""
    high = _one("high")
    with_info = high + [F(severity="info", template_id=f"i{i}", matched_at=f"u{i}") for i in range(50)]
    assert compute_security_score(with_info) == compute_security_score(high)


# --- 2-5. Severity ordering: each step down in severity costs strictly more ---------------

def test_single_low_is_below_100():
    assert compute_security_score(_one("low")) < 100


def test_severity_ordering_is_strict():
    """critical < high < medium < low < clean, as SCORES (higher severity = lower score)."""
    clean = 100
    low = compute_security_score(_one("low"))
    medium = compute_security_score(_one("medium"))
    high = compute_security_score(_one("high"))
    critical = compute_security_score(_one("critical"))
    assert critical < high < medium < low < clean


def test_single_critical_has_meaningful_impact():
    """A lone critical must move the score decisively -- not a rounding nudge -- while
    still leaving headroom for additional issues to lower it further."""
    critical = compute_security_score(_one("critical"))
    assert 30 <= critical <= 75


def test_single_low_is_a_nudge_not_a_collapse():
    assert compute_security_score(_one("low")) >= 90


# --- 6 & 16. Locations of ONE issue must not multiply linearly ---------------------------

def test_same_issue_at_many_locations_is_not_many_issues():
    """THE core regression. One template at 20 URLs vs 20 distinct templates at 1 URL each.
    Under the old per-row model both were 20 x 15 = 300 penalty -> both 0/100."""
    one_issue_20_locations = [
        F(severity="high", template_id="unix-command-injection", matched_at=f"https://h/p{i}")
        for i in range(20)
    ]
    twenty_issues = [
        F(severity="high", template_id=f"tpl-{i}", matched_at="https://h/p") for i in range(20)
    ]
    spread = compute_security_score(one_issue_20_locations)
    distinct = compute_security_score(twenty_issues)
    assert spread > distinct
    # And the difference must be large, not incidental.
    assert spread - distinct > 20


def test_many_locations_of_one_issue_cannot_force_zero():
    """Requirement: breadth alone must never reach 0. Checked at absurd scale."""
    for n in (20, 100, 1000):
        findings = [
            F(severity="critical", template_id="one-issue", matched_at=f"https://h/{i}")
            for i in range(n)
        ]
        score = compute_security_score(findings)
        assert score > 0, f"{n} locations of a single issue collapsed the score to 0"


def test_more_locations_still_lowers_the_score():
    """Sub-linear must not mean 'ignored' -- breadth is still real evidence of exposure."""
    few = [F(severity="high", template_id="t", matched_at=f"u{i}") for i in range(2)]
    many = [F(severity="high", template_id="t", matched_at=f"u{i}") for i in range(30)]
    assert compute_security_score(many) < compute_security_score(few)


def test_location_growth_is_sublinear():
    """Doubling locations must cost far less than doubling issues."""
    base = compute_security_score([F(severity="high", template_id="t", matched_at="u0")])
    doubled_locations = compute_security_score(
        [F(severity="high", template_id="t", matched_at=f"u{i}") for i in range(2)]
    )
    doubled_issues = compute_security_score(
        [F(severity="high", template_id=f"t{i}", matched_at="u") for i in range(2)]
    )
    assert doubled_issues < doubled_locations < base


def test_duplicate_occurrences_at_same_location_count_once():
    """Two matchers of one template on one URL is ONE affected location, so matcher
    granularity cannot inflate breadth."""
    single = [F(severity="high", template_id="t", matched_at="https://h/a")]
    duplicated = [
        F(severity="high", template_id="t", matched_at="https://h/a"),
        F(severity="high", template_id="t", matched_at="https://h/a"),
    ]
    assert compute_security_score(duplicated) == compute_security_score(single)
    (issue,) = group_issues(duplicated)
    assert issue.location_count == 1
    assert issue.occurrence_count == 2


# --- 7. Distinct vulnerabilities contribute separately -----------------------------------

def test_two_different_highs_score_below_one_high():
    one = [F(severity="high", template_id="a", matched_at="u")]
    two = one + [F(severity="high", template_id="b", matched_at="u")]
    assert compute_security_score(two) < compute_security_score(one)


def test_each_additional_distinct_issue_lowers_the_score():
    """Monotonicity across a long run -- the property the old model lost once it hit 0.

    Two levels, because they are different claims:

      * The UNDERLYING score is strictly decreasing for every added issue. This is the
        model property, and it holds for all 25 steps.
      * The DISPLAYED (integer) score is non-increasing, and strictly decreasing while it
        is still informative. Deep in the tail the continuous value falls 1.34 -> 1.00 ->
        0.75, which rounds to 1, 1, 1: consecutive integers tie. That is integer
        resolution, not a flat model -- a project with 15 vs 25 distinct active highs is
        catastrophic either way, and 0-100 has no room to rank the ruins. The old model
        genuinely went flat at 0 from the FOURTH critical, while still in the range where
        the difference mattered."""
    raw_scores, scores, findings = [], [], []
    for i in range(25):
        findings.append(F(severity="high", template_id=f"tpl-{i}", matched_at="u"))
        issues = group_issues(list(findings))
        raw = 100.0
        for issue in issues:
            raw *= 1 - issue.penalty / 100.0
        raw_scores.append(raw)
        scores.append(compute_security_score(list(findings)))

    assert all(b < a for a, b in zip(raw_scores, raw_scores[1:])), raw_scores
    assert all(b <= a for a, b in zip(scores, scores[1:])), scores
    # Strict while the displayed score still carries information (>= 10).
    informative = [s for s in scores if s >= 10]
    assert all(b < a for a, b in zip(informative, informative[1:])), informative
    assert len(informative) >= 8


# --- 8-10. Status lifecycle --------------------------------------------------------------

def test_resolved_finding_carries_no_penalty():
    assert compute_security_score([F(severity="critical", status="fixed")]) == 100


def test_false_positive_carries_no_penalty():
    assert compute_security_score([F(severity="critical", status="false_positive")]) == 100


def test_accepted_risk_carries_no_penalty():
    """accepted_risk is a sticky analyst decision and is NOT in ACTIVE_STATUSES, so the
    domain treats it as non-active."""
    assert "accepted_risk" not in ACTIVE_STATUSES
    assert compute_security_score([F(severity="critical", status="accepted_risk")]) == 100


def test_reopened_finding_is_penalised():
    """A regression is live again and must count."""
    reopened = compute_security_score([F(severity="high", status="reopened")])
    assert reopened < 100
    assert reopened == compute_security_score([F(severity="high", status="open")])


def test_confirmed_is_penalised():
    assert compute_security_score([F(severity="high", status="confirmed")]) < 100


def test_inactive_findings_do_not_dilute_active_ones():
    active = [F(severity="high", template_id="a")]
    mixed = active + [
        F(severity="critical", template_id="b", status="fixed"),
        F(severity="critical", template_id="c", status="false_positive"),
        F(severity="critical", template_id="d", status="accepted_risk"),
    ]
    assert compute_security_score(mixed) == compute_security_score(active)


# --- 11-12. CVSS: None is N/A, 0.0 is a number -------------------------------------------

def test_missing_cvss_is_not_treated_as_zero():
    """None must be neutral, NOT the 0.0 floor -- otherwise every unscored finding would
    be silently treated as the least technically severe."""
    none_cvss = compute_security_score([F(severity="high", cvss_score=None)])
    zero_cvss = compute_security_score([F(severity="high", cvss_score=0.0)])
    assert none_cvss != zero_cvss


def test_missing_cvss_stays_none_in_the_grouped_issue():
    (issue,) = group_issues([F(severity="high", cvss_score=None)])
    assert issue.max_cvss is None


def test_zero_cvss_stays_numeric_zero():
    (issue,) = group_issues([F(severity="high", cvss_score=0.0)])
    assert issue.max_cvss == 0.0
    assert isinstance(issue.max_cvss, float)


def test_zero_cvss_scores_better_than_high_cvss():
    """CVSS 0.0 is a legitimate, meaningful value: least technical severity."""
    low_cvss = compute_security_score([F(severity="high", cvss_score=0.0)])
    high_cvss = compute_security_score([F(severity="high", cvss_score=9.8)])
    assert high_cvss < low_cvss


def test_higher_cvss_lowers_the_score_monotonically():
    scores = [compute_security_score([F(severity="high", cvss_score=c)]) for c in (0.0, 2.5, 5.0, 7.5, 10.0)]
    assert all(b <= a for a, b in zip(scores, scores[1:])), scores
    assert scores[-1] < scores[0]


def test_partial_cvss_within_a_group_uses_the_scored_members():
    """A group where only some members have a CVSS must use those, not fall back to None."""
    (issue,) = group_issues(
        [
            F(severity="high", template_id="t", matched_at="u1", cvss_score=None),
            F(severity="high", template_id="t", matched_at="u2", cvss_score=9.8),
        ]
    )
    assert issue.max_cvss == 9.8


# --- 13-14. final_risk_score: business risk, correct direction ---------------------------

def test_missing_final_risk_score_is_deterministic_and_neutral():
    """No risk row must not crash, and must not be read as 0.0 business risk."""
    missing = compute_security_score([F(severity="high", final_risk_score=None)])
    zero = compute_security_score([F(severity="high", final_risk_score=0.0)])
    assert missing == compute_security_score([F(severity="high", final_risk_score=None)])  # deterministic
    assert missing != zero
    (issue,) = group_issues([F(severity="high", final_risk_score=None)])
    assert issue.max_risk is None


def test_higher_final_risk_gives_a_lower_security_score():
    """DIRECTION CHECK. final_risk_score is min(10, cvss * asset_criticality_weight):
    higher = worse business risk = lower security score. Getting this backwards would make
    the most business-critical assets look safest."""
    low_risk = compute_security_score([F(severity="high", final_risk_score=1.0)])
    high_risk = compute_security_score([F(severity="high", final_risk_score=10.0)])
    assert high_risk < low_risk


def test_final_risk_is_a_secondary_modifier_not_a_severity_override():
    """Business risk refines within a severity band; it must not let a low outrank a high.
    Worst-case low (max risk) must still score above best-case high (min risk)."""
    worst_low = compute_security_score(
        [F(severity="low", template_id="l", cvss_score=10.0, final_risk_score=10.0)]
    )
    best_high = compute_security_score(
        [F(severity="high", template_id="h", cvss_score=0.0, final_risk_score=0.0)]
    )
    assert worst_low > best_high


def test_cvss_and_risk_are_distinct_inputs():
    """They must not be conflated: holding CVSS fixed, varying business risk still moves
    the score (and vice versa)."""
    a = compute_security_score([F(severity="high", cvss_score=9.8, final_risk_score=2.0)])
    b = compute_security_score([F(severity="high", cvss_score=9.8, final_risk_score=10.0)])
    assert b < a
    c = compute_security_score([F(severity="high", cvss_score=2.0, final_risk_score=10.0)])
    d = compute_security_score([F(severity="high", cvss_score=9.8, final_risk_score=10.0)])
    assert d < c


# --- 15. Bounds and determinism ----------------------------------------------------------

@pytest.mark.parametrize("n_issues", [0, 1, 5, 50, 500])
@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info"])
def test_score_always_within_bounds(n_issues, severity):
    findings = [
        F(severity=severity, template_id=f"t{i}", matched_at=f"u{i}", cvss_score=10.0, final_risk_score=10.0)
        for i in range(n_issues)
    ]
    score = compute_security_score(findings)
    assert 0 <= score <= 100
    assert isinstance(score, int)


def test_score_is_order_independent():
    findings = [
        F(severity="critical", template_id="a", matched_at="u1", cvss_score=9.5),
        F(severity="high", template_id="b", matched_at="u2", cvss_score=7.5),
        F(severity="low", template_id="c", matched_at="u3"),
        F(severity="info", template_id="d", matched_at="u4"),
    ]
    assert compute_security_score(findings) == compute_security_score(list(reversed(findings)))


def test_score_is_repeatable():
    findings = [F(severity="high", template_id=f"t{i}", matched_at=f"u{i}") for i in range(7)]
    assert len({compute_security_score(findings) for _ in range(10)}) == 1


def test_worst_case_approaches_but_never_goes_below_zero():
    findings = [
        F(severity="critical", template_id=f"t{i}", matched_at=f"u{i}", cvss_score=10.0, final_risk_score=10.0)
        for i in range(200)
    ]
    assert compute_security_score(findings) == 0


# --- Grouping identity -------------------------------------------------------------------

def test_issue_key_uses_template_id_not_fingerprint_or_location():
    a = F(template_id="unix-command-injection", matched_at="https://h/a", title="A")
    b = F(template_id="unix-command-injection", matched_at="https://h/b", title="B")
    assert issue_key(a) == issue_key(b)


def test_findings_without_template_id_fall_back_to_title():
    """Legacy / non-nuclei rows must stay DISTINCT issues, not collapse into one bucket."""
    findings = [
        F(severity="high", template_id=None, title="Legacy A", matched_at="u1"),
        F(severity="high", template_id=None, title="Legacy B", matched_at="u2"),
    ]
    assert len(group_issues(findings)) == 2


def test_same_legacy_title_groups_together():
    findings = [
        F(severity="high", template_id=None, title="Same Issue", matched_at="u1"),
        F(severity="high", template_id=None, title="Same Issue", matched_at="u2"),
    ]
    assert len(group_issues(findings)) == 1


def test_template_id_never_collides_with_a_title():
    findings = [
        F(severity="high", template_id="X", matched_at="u1"),
        F(severity="high", template_id=None, title="X", matched_at="u2"),
    ]
    assert len(group_issues(findings)) == 2


def test_group_takes_the_highest_severity_of_its_members():
    (issue,) = group_issues(
        [
            F(severity="low", template_id="t", matched_at="u1"),
            F(severity="critical", template_id="t", matched_at="u2"),
        ]
    )
    assert issue.severity == "critical"


def test_unlocated_findings_still_count_as_locations():
    findings = [
        F(severity="high", template_id="t", matched_at=None),
        F(severity="high", template_id="t", matched_at=None),
    ]
    (issue,) = group_issues(findings)
    assert issue.location_count == 2


def test_unknown_severity_is_not_silently_ignored():
    """An unrecognised severity is an unknown risk, so it must still cost something."""
    assert compute_security_score([F(severity="weird")]) < 100


def test_grouping_is_deterministically_ordered():
    findings = [
        F(severity="low", template_id="a", matched_at="u"),
        F(severity="critical", template_id="b", matched_at="u"),
        F(severity="medium", template_id="c", matched_at="u"),
    ]
    keys = [i.key for i in group_issues(findings)]
    assert keys == [i.key for i in group_issues(list(reversed(findings)))]
    assert keys[0] == "template:b"  # highest penalty first


def test_group_issues_excludes_inactive_and_info():
    findings = [
        F(severity="high", template_id="a", status="open"),
        F(severity="info", template_id="b", status="open"),
        F(severity="critical", template_id="c", status="fixed"),
    ]
    issues = group_issues(findings)
    assert [i.key for i in issues] == ["template:a"]


# --- Explainability ----------------------------------------------------------------------

def test_score_from_issues_matches_the_documented_formula():
    """score = 100 * PRODUCT(1 - penalty_i/100), rounded once at the end."""
    issues = [
        ScoredIssue("a", "A", "high", 1, 1, None, None, penalty=30.0),
        ScoredIssue("b", "B", "medium", 1, 1, None, None, penalty=10.0),
    ]
    expected = round(100 * (1 - 0.30) * (1 - 0.10))
    assert score_from_issues(issues) == expected == 63


def test_grouped_issues_explain_the_score():
    """The issue list must be sufficient to reproduce the score by hand."""
    findings = [
        F(severity="critical", template_id="sqli", matched_at=f"u{i}", cvss_score=9.5, final_risk_score=10.0)
        for i in range(2)
    ] + [F(severity="medium", template_id="debug", matched_at="d", cvss_score=5.5, final_risk_score=10.0)]
    issues = group_issues(findings)
    assert score_from_issues(issues) == compute_security_score(findings)
    manual = 100.0
    for issue in issues:
        manual *= 1 - issue.penalty / 100.0
    assert round(manual) == compute_security_score(findings)


def test_penalty_components_are_reproducible_by_hand():
    """Recompute one issue's penalty from the documented factors."""
    findings = [
        F(severity="high", template_id="t", matched_at=f"u{i}", cvss_score=9.8, final_risk_score=10.0)
        for i in range(4)
    ]
    (issue,) = group_issues(findings)
    expected = (
        25.0  # base(high)
        * (0.75 + 0.05 * 9.8)  # cvss factor
        * (0.85 + 0.03 * 10.0)  # business-risk factor
        * (1 + 0.35 * math.log(4))  # location factor
    )
    assert issue.penalty == pytest.approx(min(65.0, expected))


def test_single_issue_penalty_is_capped():
    """No lone issue may exceed the ceiling, however severe or widespread."""
    findings = [
        F(severity="critical", template_id="t", matched_at=f"u{i}", cvss_score=10.0, final_risk_score=10.0)
        for i in range(500)
    ]
    (issue,) = group_issues(findings)
    assert issue.penalty <= 65.0
    assert compute_security_score(findings) >= 35


# --- Real-dataset shapes -----------------------------------------------------------------

def test_real_info_only_project_shape_stays_100():
    """Mirrors the 'ss' project: 19 open info findings."""
    findings = [
        F(severity="info", template_id=f"tech-detect-{i}", matched_at="https://target/", cvss_score=0.0)
        for i in range(19)
    ]
    assert compute_security_score(findings) == 100


def test_real_saturated_project_gets_a_meaningful_score():
    """Mirrors the project that scored 0/100 under the old model: 62 active non-info rows
    that are only 5 distinct issue types. The score must be informative, not floored."""
    findings = []
    shape = [
        ("unix-command-injection", "high", 9.8, 22),
        ("windows-command-injection", "high", 9.8, 20),
        ("time-based-sqli", "critical", 9.5, 2),
        ("CVE-2025-55184", "high", 7.5, 1),
        ("django-debug-config-enabled", "medium", 5.5, 1),
    ]
    for template_id, severity, cvss, n in shape:
        for i in range(n):
            findings.append(
                F(
                    severity=severity,
                    template_id=template_id,
                    matched_at=f"https://target/{template_id}/{i}",
                    cvss_score=cvss,
                    final_risk_score=10.0,
                )
            )
    assert len(findings) == 46
    assert len(group_issues(findings)) == 5
    score = compute_security_score(findings)
    assert 0 < score < 40, "a badly-broken project should score low but not be floored at 0"
