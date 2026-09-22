"""Report display: a STORED risk rationale must not claim a cap that never happened.

`risk_scores.rationale` is written once at scan time and read back verbatim by the Technical
Report. An earlier risk/service.py appended "(capped at 10.0)" UNCONDITIONALLY, so historical
rows assert a cap even at risk 0.0:

    CVSS 0.0 x asset criticality 'critical' (weight 2.0) = 0.0 (capped at 10.0).

The engine is already correct for every NEW computation (asserted below, so this file also
guards that). These tests pin the DISPLAY fix for the rows already in the database.
"""

import pytest

from apps.api.modules.reports.render import _sanitise_risk_rationale
from apps.api.modules.risk.service import compute_risk

# The exact historical shape, as found in the live dataset (604 of 692 rows).
LEGACY = "CVSS {c} x asset criticality '{k}' (weight {w}) = {r} (capped at 10.0)."


def _legacy(c, k, w, r):
    return LEGACY.format(c=c, k=k, w=w, r=r)


# ============ The five required cases, asserted on BOTH the engine and the display =========

@pytest.mark.parametrize(
    "cvss,criticality,expected_risk,expected_capped",
    [
        (0.0, "critical", 0.0, False),
        (3.0, "low", 1.5, False),
        (5.5, "high", 8.2, False),
        (5.5, "critical", 10.0, True),
        (9.8, "critical", 10.0, True),
    ],
)
def test_engine_is_capped_flag_and_rationale_agree(
    cvss, criticality, expected_risk, expected_capped
) -> None:
    """The risk ENGINE: is_capped, the score, and the cap wording must all agree."""
    r = compute_risk(cvss, criticality)
    assert r.final_risk_score == pytest.approx(expected_risk, abs=0.05)
    assert r.is_capped is expected_capped
    assert ("capped" in r.rationale.lower()) is expected_capped


@pytest.mark.parametrize(
    "cvss,criticality,weight,risk,expected_capped",
    [
        (0.0, "critical", 2.0, 0.0, False),
        (3.0, "low", 0.5, 1.5, False),
        (5.5, "high", 1.5, 8.2, False),
        (5.5, "critical", 2.0, 10.0, True),
        (9.8, "critical", 2.0, 10.0, True),
    ],
)
def test_stored_legacy_rationale_only_shows_cap_when_actually_capped(
    cvss, criticality, weight, risk, expected_capped
) -> None:
    """The DISPLAY fix, applied to the legacy unconditional-cap text."""
    shown = _sanitise_risk_rationale(_legacy(cvss, criticality, weight, risk), risk)
    assert ("capped" in shown.lower()) is expected_capped


def test_the_exact_reported_string_loses_its_false_cap_claim() -> None:
    stored = "CVSS 0.0 x asset criticality 'critical' (weight 2.0) = 0.0 (capped at 10.0)."
    shown = _sanitise_risk_rationale(stored, 0.0)
    assert shown == "CVSS 0.0 x asset criticality 'critical' (weight 2.0) = 0.0."
    assert "capped" not in shown.lower()


# ============================ Values and wording are preserved ============================

def test_numbers_and_wording_are_otherwise_untouched() -> None:
    """Only the cap phrase is removed -- CVSS, criticality, weight and product all survive."""
    stored = "CVSS 3.0 x asset criticality 'low' (weight 0.5) = 1.5 (capped at 10.0)."
    shown = _sanitise_risk_rationale(stored, 1.5)
    for fragment in ("CVSS 3.0", "criticality 'low'", "weight 0.5", "= 1.5"):
        assert fragment in shown
    assert shown.rstrip().endswith(".")


def test_a_genuinely_capped_rationale_is_never_altered() -> None:
    """At 10.0 the claim may be true, so the text is left exactly as stored."""
    for stored in (
        "CVSS 9.8 x asset criticality 'critical' (weight 2.0) = 10.0 (capped at 10.0).",
        "CVSS 5.5 (Medium) x asset criticality 'critical' (weight 2.0) = 10.0 "
        "(capped at 10.0 from 11.0). Asset criticality adjusts BUSINESS risk only.",
    ):
        assert _sanitise_risk_rationale(stored, 10.0) == stored


def test_current_engine_rationale_passes_through_unchanged() -> None:
    """The sanitiser must be a no-op for text the CURRENT engine produces."""
    for cvss, crit in [(0.0, "critical"), (3.0, "low"), (5.5, "high"), (5.5, "critical"), (9.8, "critical")]:
        r = compute_risk(cvss, crit)
        assert _sanitise_risk_rationale(r.rationale, r.final_risk_score) == r.rationale


# ============================ Safety / edge inputs =========================================

def test_none_and_empty_inputs_are_safe() -> None:
    assert _sanitise_risk_rationale(None, 0.0) == ""
    assert _sanitise_risk_rationale("", 0.0) == ""
    # A None risk means "not scored" -- nothing is asserted about a cap, so leave the text be.
    stored = "x (capped at 10.0)."
    assert _sanitise_risk_rationale(stored, None) == stored


def test_rationale_without_a_cap_phrase_is_unchanged() -> None:
    stored = "CVSS 5.5 (Medium) x asset criticality 'high' (weight 1.5) = 8.2."
    assert _sanitise_risk_rationale(stored, 8.2) == stored


def test_sanitiser_is_pure_and_deterministic() -> None:
    stored = "CVSS 0.0 x asset criticality 'critical' (weight 2.0) = 0.0 (capped at 10.0)."
    first = _sanitise_risk_rationale(stored, 0.0)
    assert all(_sanitise_risk_rationale(stored, 0.0) == first for _ in range(10))
    assert stored.endswith("(capped at 10.0).")  # input not mutated


def test_sanitising_is_idempotent() -> None:
    stored = "CVSS 0.0 x asset criticality 'critical' (weight 2.0) = 0.0 (capped at 10.0)."
    once = _sanitise_risk_rationale(stored, 0.0)
    assert _sanitise_risk_rationale(once, 0.0) == once


# ============================ Invariants ===================================================

def test_display_fix_does_not_change_any_risk_value() -> None:
    """The sanitiser takes the score as INPUT and returns text -- it can never move a number."""
    for cvss, crit in [(0.0, "critical"), (5.5, "high"), (9.8, "critical")]:
        r = compute_risk(cvss, crit)
        before = (r.final_risk_score, r.uncapped_risk_score, r.cvss_severity, r.is_capped)
        _sanitise_risk_rationale(r.rationale, r.final_risk_score)
        assert (r.final_risk_score, r.uncapped_risk_score, r.cvss_severity, r.is_capped) == before
