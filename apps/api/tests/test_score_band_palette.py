"""Phase 2.3 (R-04) -- the score-band vocabulary and its colour palette must agree.

THE DEFECT THIS PINS
--------------------
`render._score_band` has returned Strong / Fair / Weak / Critical since the original Reporting
Engine (Step 10, 2026-07-27). `_branding.SCORE_BAND_COLORS` arrived with the branding redesign
(2026-09-07) and keyed the 70-89 band as "Moderate", so `score_band_color("Fair")` fell through
to MUTED grey for every score in 70-89 -- a fifth of the whole range.

It was latent only because `score_band_color()` has never had a call site; it was wrong from the
moment it was written, and would have surfaced the first time a score panel was coloured by band.

WHY THE PALETTE MOVED, NOT THE BAND
-----------------------------------
"Fair" is the established contract: it is what `_score_band` returns, what every rendered PDF
has printed, and what `assessment.service` freezes into `risk_assessments.score_band` -- an
IMMUTABLE client-facing snapshot column. Renaming the band would alter a value an issued
assessment promises never changes. The comment above SCORE_BAND_COLORS already stated the
intended direction ("keyed to render._score_band's existing labels"), so this restores the
intent rather than inventing a new one.

Thresholds, scoring semantics and the band strings themselves are UNCHANGED.
"""

import pytest

from apps.api.modules.reports import _branding as B
from apps.api.modules.reports.render import _score_band

# The canonical vocabulary. Written out literally rather than derived from either side, so a
# change to EITHER _score_band or SCORE_BAND_COLORS has to come past this list deliberately.
CANONICAL_BANDS = ("Strong", "Fair", "Weak", "Critical")


# --- the structural guard: no band may fall through ---------------------------------------

def test_every_score_in_range_has_a_real_colour() -> None:
    """The exhaustive R-04 regression: walk EVERY integer score 0-100 and assert its band
    resolves to a real palette entry rather than the MUTED fallback."""
    unmapped = [s for s in range(0, 101) if B.score_band_color(_score_band(s)) == B.MUTED]
    assert unmapped == [], (
        f"scores {unmapped[0]}-{unmapped[-1]} fall back to MUTED: "
        f"band {_score_band(unmapped[0])!r} is missing from SCORE_BAND_COLORS"
    )


def test_every_band_emitted_by_score_band_has_a_colour_entry() -> None:
    emitted = {_score_band(s) for s in range(0, 101)}
    assert emitted == set(CANONICAL_BANDS)
    for band in emitted:
        assert band in B.SCORE_BAND_COLORS, f"{band!r} has no colour"


def test_palette_defines_no_band_the_calculator_cannot_emit() -> None:
    """The other direction: a stale key like "Moderate" is dead weight that reads as a
    supported band. This is the assertion that actually fails on the R-04 defect."""
    emitted = {_score_band(s) for s in range(0, 101)}
    orphans = set(B.SCORE_BAND_COLORS) - emitted
    assert orphans == set(), f"palette keys no score can produce: {sorted(orphans)}"


def test_the_two_sides_are_exactly_the_same_key_set() -> None:
    assert set(B.SCORE_BAND_COLORS) == set(CANONICAL_BANDS)


# --- the specific band the defect hid ------------------------------------------------------

def test_fair_band_resolves_to_its_intended_amber_not_grey() -> None:
    """The regression itself: 70-89 must be amber, the colour the palette always held for
    this band under the wrong key."""
    assert B.score_band_color("Fair") == "#b45309"
    assert B.score_band_color("Fair") != B.MUTED


def test_moderate_is_no_longer_a_key() -> None:
    """"Moderate" was never emitted by _score_band; it must not linger in the palette."""
    assert "Moderate" not in B.SCORE_BAND_COLORS


@pytest.mark.parametrize("score", [70, 75, 80, 85, 89])
def test_scores_in_the_fair_range_are_coloured(score: int) -> None:
    assert _score_band(score) == "Fair"
    assert B.score_band_color(_score_band(score)) == "#b45309"


# --- score_band_color() directly (it has no production call site yet) ----------------------

@pytest.mark.parametrize(
    ("band", "expected"),
    [("Strong", "#15803d"), ("Fair", "#b45309"), ("Weak", "#c2410c"), ("Critical", "#b91c1c")],
)
def test_score_band_color_returns_the_intended_palette_value(band: str, expected: str) -> None:
    assert B.score_band_color(band) == expected


def test_score_band_color_still_fails_soft_on_genuinely_unknown_input() -> None:
    """The MUTED fallback is correct behaviour for input that is not a band -- R-04 was about
    a VALID band hitting it, not about removing the guard."""
    for bogus in (None, "", "   ", "Nonsense", "moderate"):
        assert B.score_band_color(bogus) == B.MUTED


def test_score_band_color_tolerates_surrounding_whitespace() -> None:
    """Existing .strip() behaviour, pinned so the fix did not quietly alter lookup semantics."""
    assert B.score_band_color("  Fair  ") == "#b45309"


def test_lookup_is_case_sensitive_by_design() -> None:
    """Bands are capitalised labels, not normalised keys; `severity_color` lowercases, this
    one does not. Pinned so the difference stays deliberate."""
    assert B.score_band_color("fair") == B.MUTED


# --- thresholds unchanged (R-04 is naming-only) --------------------------------------------

@pytest.mark.parametrize(
    ("score", "band"),
    [
        (100, "Strong"), (95, "Strong"), (90, "Strong"),   # >= 90
        (89, "Fair"), (80, "Fair"), (70, "Fair"),          # >= 70
        (69, "Weak"), (50, "Weak"), (40, "Weak"),          # >= 40
        (39, "Critical"), (20, "Critical"), (0, "Critical"),
    ],
)
def test_existing_thresholds_are_unchanged(score: int, band: str) -> None:
    assert _score_band(score) == band


def test_band_boundaries_are_exactly_where_they_were() -> None:
    """Each boundary tested from both sides, so an off-by-one cannot slip in."""
    assert (_score_band(90), _score_band(89)) == ("Strong", "Fair")
    assert (_score_band(70), _score_band(69)) == ("Fair", "Weak")
    assert (_score_band(40), _score_band(39)) == ("Weak", "Critical")


def test_band_is_monotonic_across_the_whole_range() -> None:
    """A higher score is never a worse band."""
    rank = {"Critical": 0, "Weak": 1, "Fair": 2, "Strong": 3}
    ranks = [rank[_score_band(s)] for s in range(0, 101)]
    assert ranks == sorted(ranks)


# --- the persisted/immutable consumer ------------------------------------------------------

def test_assessment_snapshot_still_receives_the_established_band_strings() -> None:
    """assessment.service freezes _score_band's output into risk_assessments.score_band, an
    immutable client-facing column. R-04 must not have changed what that column receives."""
    assert _score_band(80) == "Fair"
    # The column is String(16); every band must fit, or an issue would surface only at write.
    for band in CANONICAL_BANDS:
        assert len(band) <= 16


# --- rendering still works -----------------------------------------------------------------

def test_reports_still_render_and_print_the_band() -> None:
    import collections
    import re
    import uuid

    from apps.api.modules.reports.data import ReportData, VulnRow
    from apps.api.modules.reports.render import render_executive, render_technical
    from apps.api.modules.reports.scoring import compute_security_score
    from apps.api.tests.test_report_layout import _pdf_text

    rows = [
        VulnRow(
            id=uuid.uuid4(), title="low finding", severity="low", status="open",
            category="cwe-79", cvss_score=3.1, cvss_vector=None, final_risk_score=3.1,
            risk_rationale=None, compliance=[], evidence_uris=[],
            template_id="minor", matcher_name="status", matched_at="https://h/a",
        )
    ]
    sev = dict(collections.Counter(r.severity for r in rows))
    data = ReportData(
        project_name="Band Probe", security_score=compute_security_score(rows),
        severity_counts=sev, total_vulns=1, active_vulns=1,
        active_severity_counts=sev, vulns=rows,
    )
    band = _score_band(data.security_score)
    assert band in CANONICAL_BANDS
    assert B.score_band_color(band) != B.MUTED

    for pdf in (render_executive(data), render_technical(data)):
        assert pdf[:4] == b"%PDF"
    assert band in re.sub(r"\s+", " ", _pdf_text(render_executive(data)))
