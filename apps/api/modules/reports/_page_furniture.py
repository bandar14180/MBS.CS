"""Per-page header/footer/page-number painting for MBS.PT reports.

WHY THIS EXISTS
---------------
Every report was previously built with a bare `doc.build(story)` -- no onFirstPage/onLaterPages
callback anywhere in render.py. The consequence: no page numbers, no running header, no footer,
and therefore no way for a reader to cite a page or tell which document a loose sheet came from.

ReportLab paints page furniture through a canvas callback invoked once per page, which is what
this module provides. It draws ONLY chrome -- it never reads findings, scores, severities or
any assessment value, so it cannot influence report content.

The cover gets no chrome (a header over a cover looks like a mistake), which is why
`PageFurniture` distinguishes the first page from later ones.
"""

from apps.api.modules.reports import _branding as B

# Page geometry shared with the document templates, so margins and furniture cannot drift.
MARGIN_L = 18  # mm
MARGIN_R = 18
MARGIN_T = 22
MARGIN_B = 20


class PageFurniture:
    """Callable page decorator. One instance per rendered document.

    Usage:
        furniture = PageFurniture("Technical Security Report", "Acme", "2026-09-07")
        doc.build(story, onFirstPage=furniture.cover, onLaterPages=furniture.content)

    `page_offset` exists because the cover is page 1 of the PDF but should not be numbered:
    content numbering starts at 1 on the first page AFTER the cover.
    """

    def __init__(self, report_title: str, project_name: str, generated: str):
        self.report_title = report_title
        self.project_name = project_name
        self.generated = generated

    # --- Cover: deliberately no chrome ----------------------------------------------------
    def cover(self, canvas, doc):
        return None

    # --- Content pages --------------------------------------------------------------------
    def content(self, canvas, doc):
        try:
            self._draw(canvas, doc)
        except Exception:
            # Chrome must never be the reason a report fails to render.
            return None

    def _draw(self, canvas, doc):
        from reportlab.lib import colors
        from reportlab.lib.units import mm

        w, h = doc.pagesize
        canvas.saveState()

        # ---- Header -----------------------------------------------------------------
        # Small mark + brand on the left, report title on the right, over a hairline rule.
        logo = B.logo_drawing(9 * mm)
        if logo is not None:
            try:
                from reportlab.graphics import renderPDF

                renderPDF.draw(logo, canvas, MARGIN_L * mm, h - (MARGIN_T - 2) * mm)
            except Exception:
                pass  # fail-soft: header still renders without the mark

        canvas.setFillColor(colors.HexColor(B.DARK))
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString((MARGIN_L + 11) * mm, h - (MARGIN_T - 4.5) * mm, B.BRAND_NAME)

        canvas.setFillColor(colors.HexColor(B.MUTED))
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(w - MARGIN_R * mm, h - (MARGIN_T - 4.5) * mm, self.report_title)

        # Cyan->violet rule: two abutting segments, so the identity reads without a gradient.
        rule_y = h - (MARGIN_T - 7) * mm
        mid = (MARGIN_L * mm + (w - MARGIN_R * mm)) / 2
        canvas.setLineWidth(1.1)
        canvas.setStrokeColor(colors.HexColor(B.CYAN))
        canvas.line(MARGIN_L * mm, rule_y, mid, rule_y)
        canvas.setStrokeColor(colors.HexColor(B.VIOLET))
        canvas.line(mid, rule_y, w - MARGIN_R * mm, rule_y)

        # ---- Footer -----------------------------------------------------------------
        foot_y = (MARGIN_B - 8) * mm
        canvas.setStrokeColor(colors.HexColor(B.RULE))
        canvas.setLineWidth(0.4)
        canvas.line(MARGIN_L * mm, foot_y + 5 * mm, w - MARGIN_R * mm, foot_y + 5 * mm)

        canvas.setFillColor(colors.HexColor(B.MUTED))
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(MARGIN_L * mm, foot_y + 1.5 * mm, f"{B.BRAND_NAME}  ·  {B.contact_line()}")

        # Page number. `doc.page` counts PDF pages; the cover is page 1 and is unnumbered, so
        # content numbering is offset by one and never shows "Page 0".
        number = max(1, doc.page - 1)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawRightString(w - MARGIN_R * mm, foot_y + 1.5 * mm, f"Page {number}")

        canvas.restoreState()
