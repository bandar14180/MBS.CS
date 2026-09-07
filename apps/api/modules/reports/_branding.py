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

# Security-score band colours, keyed to render._score_band's existing labels. The BANDS
# THEMSELVES are not defined here -- scoring semantics stay in scoring.py / _score_band.
SCORE_BAND_COLORS = {
    "Strong": "#15803d",
    "Moderate": "#b45309",
    "Weak": "#c2410c",
    "Critical": "#b91c1c",
}


def severity_color(severity: str | None) -> str:
    return SEVERITY_COLORS.get((severity or "").strip().lower(), MUTED)


def score_band_color(band: str | None) -> str:
    return SCORE_BAND_COLORS.get((band or "").strip(), MUTED)


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
