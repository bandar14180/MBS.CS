"""MBS.PT report branding: identity constants, palette, and the logo mark.

WHY THIS MODULE EXISTS
----------------------
Branding was previously a single `_BRAND = "#0f172a"` constant inside render.py, with the
company name hardcoded into each report's H1 and no contact details anywhere. Everything a
reader uses to identify who produced the report -- name, logo, email, phone -- now lives here,
so it is stated once and cannot drift between the cover, the header, the footer and the
appendix.

THE LOGO
--------
The web UI's mark lives in apps/web/components/landing/Logo.tsx as inline JSX SVG, which
ReportLab cannot consume. Rather than invent a different mark or add a dependency, the SAME
geometry is re-expressed below using reportlab.graphics, which ships with ReportLab -- so the
PDF logo is the web logo, drawn as native vector (crisp at any zoom, no raster asset to keep
in sync, and NO new dependency; svglib is not installed and is not needed).

Coordinates are taken verbatim from Logo.tsx's 40x40 viewBox and scaled at draw time.

COLOURS
-------
Cyan -> Violet is the identity gradient from Logo.tsx; the dark brand is the existing
_BRAND value, preserved so the redesign does not silently restyle every existing table.
Accents are used deliberately -- cover, section rules, header/footer, score band -- and NOT
sprayed across body text, which would read as decoration rather than as a security document.
"""

# --- Identity -----------------------------------------------------------------------------
BRAND_NAME = "MBS.PT"
REPORT_SUITE = "Security Assessment Report"
CONTACT_EMAIL = "bandaraodh@gmail.com"
CONTACT_PHONE = "+966578121147"

# --- Palette ------------------------------------------------------------------------------
# From Logo.tsx's linearGradient stops, plus the pre-existing dark brand.
CYAN = "#22d3ee"
VIOLET = "#7c5cff"
DARK = "#0f172a"

INK = "#111827"          # body text
MUTED = "#6b7280"        # metadata / secondary
RULE = "#d1d5db"         # table grid
BAND = "#f3f4f6"         # zebra rows
PAPER_TINT = "#f8fafc"   # card fill

# Severity colours. Presentation only -- severity VALUES come from the scanner and are never
# derived or altered here.
SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#b45309",
    "low": "#0369a1",
    "info": "#4b5563",
}

# --- Verification / confidence chip colours (Phase 4.1) -----------------------------------
# A DELIBERATELY SEPARATE AXIS FROM SEVERITY.
#
# Verification answers "was this demonstrated?"; severity answers "how bad would it be?".
# They are independent (verification.py never reads severity, CVSS or risk, and never alters
# them), so painting verification in the SEVERITY palette would imply a relationship that does
# not exist -- a red "Unverified" chip beside a red CRITICAL severity reads as one escalating
# signal rather than two orthogonal facts.
#
# These are therefore blue-greys and a single confirmatory green: VERIFIED is the only state
# that earns a positive colour, because it is the only one backed by two independent artefact
# kinds. Partially verified and unverified are deliberately NEUTRAL -- an unverified finding is
# not a false positive and must not be painted as "safe", nor as "dangerous".
#
# Keyed by verification.py's own state constants, so a new state cannot silently fall through
# to a default (see render._verification_chip_colors, which fails to MUTED and is tested).
#
# Every value below is DISJOINT from SEVERITY_COLORS and from CONFIDENCE_COLORS, and none is
# MUTED -- MUTED is reserved as the fail-safe for an unrecognised state, so a real state must
# never coincide with it (that is what makes the "unknown never looks confirmatory" guarantee
# observable). Both properties are asserted by test_report_assurance_chips.py.
VERIFICATION_COLORS = {
    "verified": "#15803d",            # green: corroborated from two directions
    "partially_verified": "#1d4ed8",  # indigo: artefacts captured, not proof
    "unverified": "#57534e",          # warm slate: a pattern match awaiting validation
}
VERIFICATION_BG = {
    "verified": "#e6f2ea",
    "partially_verified": "#e7f1f8",
    "unverified": "#f3f4f6",
}

# Confidence is a THIRD axis: how much the signal is worth, independent of whether it was
# proven. Rendered in a muted amber ramp so it is visually distinguishable from BOTH severity
# (reds/oranges at full saturation) and verification (greens/blues) at a glance.
CONFIDENCE_COLORS = {
    "high": "#4d7c0f",    # olive
    "medium": "#a16207",  # ochre
    "low": "#92400e",     # deep amber -- distinct from severity medium (#b45309)
}

# Security-score band colours, keyed to render._score_band's existing labels. The BANDS
# THEMSELVES are not defined here -- scoring semantics stay in scoring.py / _score_band.
#
# R-04. The 70-89 key read "Moderate" while _score_band has emitted "Fair" since the original
# Reporting Engine (Step 10, 2026-07-27); this table arrived with the branding redesign
# (2026-09-07) and mis-keyed that one band, so every score in 70-89 fell through to MUTED grey.
# Latent only because score_band_color() has never had a call site -- it was wrong from birth.
#
# CORRECTED TOWARD "Fair", NOT by renaming the band, because "Fair" is the established
# contract: it is what _score_band returns, what every rendered PDF has printed for over a
# month, and what assessment.service freezes into the IMMUTABLE risk_assessments.score_band
# snapshot column. Renaming the band would change a client-facing value that an issued
# assessment promises never changes. The comment directly above states the intended direction
# ("keyed to render._score_band's existing labels") -- this restores it.
SCORE_BAND_COLORS = {
    "Strong": "#15803d",
    "Fair": "#b45309",
    "Weak": "#c2410c",
    "Critical": "#b91c1c",
}


def severity_color(severity: str | None) -> str:
    return SEVERITY_COLORS.get((severity or "").strip().lower(), MUTED)


def score_band_color(band: str | None) -> str:
    return SCORE_BAND_COLORS.get((band or "").strip(), MUTED)


def verification_color(state: str | None) -> str:
    """Ink colour for a verification chip. Unknown state -> MUTED, never a positive colour.

    Fails toward the neutral grey for the same reason verification.py fails toward UNVERIFIED:
    an unrecognised state must never be painted as if it had been demonstrated."""
    return VERIFICATION_COLORS.get((state or "").strip().lower(), MUTED)


def verification_bg(state: str | None) -> str:
    """Chip fill for a verification state. Unknown -> the neutral band."""
    return VERIFICATION_BG.get((state or "").strip().lower(), BAND)


def confidence_color(level: str | None) -> str:
    """Ink colour for a confidence chip. Unknown level -> MUTED."""
    return CONFIDENCE_COLORS.get((level or "").strip().lower(), MUTED)


def logo_drawing(size: float):
    """The MBS.PT mark as a ReportLab Drawing, `size` points square.

    Re-expresses Logo.tsx's 40x40 geometry: a hexagonal shield outline, a neural core node,
    three links and three satellite nodes. Drawn with reportlab.graphics (bundled), so there
    is no image asset to keep in sync and no new dependency.

    Fail-soft by contract: callers treat a None return as "render without a logo" so a report
    is never lost to a drawing error (see _page_furniture and the cover builder)."""
    try:
        from reportlab.graphics.shapes import Circle, Drawing, Line, Path
        from reportlab.lib import colors
    except Exception:  # pragma: no cover - reportlab is a hard dependency of this package
        return None

    try:
        s = size / 40.0  # Logo.tsx viewBox is 40x40
        cyan = colors.HexColor(CYAN)
        violet = colors.HexColor(VIOLET)
        d = Drawing(size, size)

        # SVG's y axis points DOWN, ReportLab's points UP: y_pdf = (40 - y_svg) * s.
        def pt(x, y):
            return (x * s, (40 - y) * s)

        # Shield outline -- "M20 3l13 5.2v9.3c0 8.3-5.4 15.2-13 19.2-7.6-4-13-10.9-13-19.2V8.2L20 3z".
        # The two curves are approximated by their chord endpoints; at report sizes (14-64pt)
        # the difference is sub-pixel, and this avoids hand-converting cubic control points.
        shield = Path(strokeColor=cyan, strokeWidth=max(0.6, 2 * s), fillColor=None)
        x0, y0 = pt(20, 3)
        shield.moveTo(x0, y0)
        for x, y in ((33, 8.2), (33, 17.5), (20, 36.7), (7, 17.5), (7, 8.2)):
            shield.lineTo(*pt(x, y))
        shield.closePath()
        d.add(shield)

        # Links from the core to the three satellites.
        cx, cy = pt(20, 18)
        for x, y in ((14, 23), (26, 23), (20, 12)):
            lx, ly = pt(x, y)
            d.add(Line(cx, cy, lx, ly, strokeColor=violet, strokeWidth=max(0.5, 1.6 * s)))

        # Core node, then the satellites.
        d.add(Circle(cx, cy, 3.2 * s, fillColor=violet, strokeColor=None))
        for x, y in ((14, 23), (26, 23), (20, 12)):
            nx, ny = pt(x, y)
            d.add(Circle(nx, ny, 1.8 * s, fillColor=cyan, strokeColor=None))
        return d
    except Exception:
        # Never let branding break a report.
        return None


def contact_line(separator: str = "  ·  ") -> str:
    """Single-line contact block used by the cover and the footer."""
    return separator.join((CONTACT_EMAIL, CONTACT_PHONE))
