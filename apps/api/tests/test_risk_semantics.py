"""§3 -- risk semantics: CVSS severity vs asset-criticality-adjusted business risk.

WHY THIS FILE EXISTS
--------------------
`final_risk_score` is `min(10, cvss * criticality_weight)`. With weight 2.0 (a critical asset)
ANY cvss >= 5.0 saturates at 10.0, so a MEDIUM CVSS 5.5 and a CRITICAL CVSS 9.8 both rendered
as a bare "risk 10.0" and the Medium finding read as a Critical vulnerability.

The fix is deliberately ADDITIVE and presentation-only:
  * `final_risk_score` keeps its exact prior arithmetic -- it is persisted, and
    scoring._risk_factor, the frozen RiskAssessmentFinding snapshots and the remediation read
    paths all depend on its meaning being unchanged. Tests below pin that.
  * `cvss_severity` states the TECHNICAL band of the CVSS base score ALONE.
  * `uncapped_risk_score` exposes the pre-cap product so a capped 10.0 is distinguishable from
    a genuine one.

The load-bearing invariant, asserted several ways below: asset criticality must NEVER change
`cvss_severity`.
"""

import pytest

from apps.api.modules.risk.service import (
    CRITICALITY_WEIGHT,
    ComputedRisk,
    compute_risk,
    cvss_severity_band,
)


# --- The seven required cases -------------------------------------------------------------

def test_case1_cvss_98_critical_asset_caps_at_ten_but_stays_critical_band() -> None:
    r = compute_risk(9.8, "critical")
    assert r.final_risk_score == 10.0            # 9.8 * 2.0 = 19.6 -> capped
    assert r.uncapped_risk_score == 19.6
    assert r.is_capped is True
    assert r.cvss_severity == "Critical"         # from CVSS alone -- genuinely critical here


def test_case2_cvss_55_critical_asset_caps_at_ten_but_band_stays_medium() -> None:
    """THE reported defect: a Medium flaw must not become a Critical one via asset weight."""
    r = compute_risk(5.5, "critical")
    assert r.final_risk_score == 10.0            # 5.5 * 2.0 = 11.0 -> capped
    assert r.uncapped_risk_score == 11.0
    assert r.is_capped is True
    assert r.cvss_severity == "Medium"           # NOT "Critical"


def test_case3_cvss_55_high_asset_is_not_capped() -> None:
    r = compute_risk(5.5, "high")
    # 5.5 * 1.5 = 8.25; the engine's pre-existing round(_, 1) yields 8.2 (banker's rounding on
    # the binary float). Asserted as the ACTUAL preserved arithmetic rather than an idealised
    # 8.25 -- changing the rounding would change persisted values, which is out of scope.
    assert r.final_risk_score == pytest.approx(8.2, abs=0.05)
    assert r.is_capped is False
    assert r.uncapped_risk_score == r.final_risk_score
    assert r.cvss_severity == "Medium"


def test_case4_cvss_30_low_asset_is_dampened() -> None:
    r = compute_risk(3.0, "low")
    assert r.final_risk_score == 1.5             # 3.0 * 0.5
    assert r.is_capped is False
    assert r.cvss_severity == "Low"


def test_case5_cvss_none_yields_no_scores_and_no_band() -> None:
    """None means NOT SCORED -- it must never collapse into 0.0 anywhere."""
    r = compute_risk(None, "critical")
    assert r.final_risk_score is None
    assert r.uncapped_risk_score is None
    assert r.business_impact_score is None
    assert r.cvss_severity is None               # not "None" the string, not 0.0
    assert r.is_capped is False
    assert r.asset_criticality_weight == 2.0     # weight is still known


def test_case6_cap_is_explicit_and_only_claimed_when_it_bit() -> None:
    capped = compute_risk(9.8, "critical")
    assert capped.is_capped is True
    assert "capped" in capped.rationale.lower()
    assert "19.6" in capped.rationale            # the pre-cap value is stated

    uncapped = compute_risk(3.0, "low")
    assert uncapped.is_capped is False
    # The old rationale appended "(capped at 10.0)" unconditionally, so a risk of 1.5 also
    # read as capped. It must not any more.
    assert "capped" not in uncapped.rationale.lower()


def test_case7_cvss_severity_is_independent_of_asset_criticality() -> None:
    """The core invariant, swept over every criticality tier."""
    for cvss, expected_band in [(9.8, "Critical"), (7.5, "High"), (5.5, "Medium"), (2.0, "Low")]:
        bands = {compute_risk(cvss, c).cvss_severity for c in CRITICALITY_WEIGHT}
        assert bands == {expected_band}, f"CVSS {cvss} band varied with criticality: {bands}"


# --- Band function, incl. the 0.0-vs-None distinction -------------------------------------

def test_band_boundaries_follow_cvss_v31() -> None:
    assert cvss_severity_band(10.0) == "Critical"
    assert cvss_severity_band(9.0) == "Critical"
    assert cvss_severity_band(8.9) == "High"
    assert cvss_severity_band(7.0) == "High"
    assert cvss_severity_band(6.9) == "Medium"
    assert cvss_severity_band(4.0) == "Medium"
    assert cvss_severity_band(3.9) == "Low"
    assert cvss_severity_band(0.1) == "Low"


def test_band_zero_is_scored_none_is_not() -> None:
    """0.0 is a REAL score whose band is 'None'; a missing score has no band at all."""
    assert cvss_severity_band(0.0) == "None"
    assert cvss_severity_band(None) is None


# --- Backward compatibility: the persisted contract is untouched --------------------------

def test_final_risk_score_arithmetic_is_unchanged() -> None:
    """Pins the EXACT prior formula: min(10, cvss * weight), rounded to 1dp.

    scoring._risk_factor, RiskAssessmentFinding.frozen_final_risk_score and the remediation
    read paths all consume this value; changing it would silently move every security score
    and desynchronise already-issued client assessments from live findings."""
    for cvss in (0.0, 1.0, 3.3, 5.0, 5.5, 7.5, 9.8, 10.0):
        for crit, weight in CRITICALITY_WEIGHT.items():
            expected = round(min(10.0, cvss * weight), 1)
            assert compute_risk(cvss, crit).final_risk_score == expected


def test_unknown_criticality_still_defaults_to_weight_one() -> None:
    r = compute_risk(6.0, "not-a-tier")
    assert r.asset_criticality_weight == 1.0
    assert r.final_risk_score == 6.0
    assert r.cvss_severity == "Medium"


def test_new_fields_are_optional_so_existing_constructions_keep_working() -> None:
    """ComputedRisk gained fields with defaults; any caller building one positionally (or
    without them) must still work, since this dataclass is returned across module lines."""
    r = ComputedRisk(
        business_impact_score=5.0,
        asset_criticality_weight=1.0,
        final_risk_score=5.0,
        rationale="x",
    )
    assert r.cvss_severity is None
    assert r.uncapped_risk_score is None
    assert r.is_capped is False


def test_rationale_states_band_and_that_criticality_does_not_change_it() -> None:
    r = compute_risk(5.5, "critical")
    assert "Medium" in r.rationale
    assert "business risk only" in r.rationale.lower()
