"""PDF rendering for reports. reportlab is imported lazily inside the render
functions so importing this module (e.g. for the service/CRUD path) doesn't
require reportlab to be installed."""

import html
from datetime import datetime, timezone

from apps.api.modules.reports.data import ReportData, VulnRow

_SEVERITY_COLORS = {
    "critical": "#7f1d1d",
    "high": "#b91c1c",
    "medium": "#b45309",
    "low": "#1d4ed8",
    "info": "#374151",
}
_BRAND = "#0f172a"


def _score_band(score: int) -> str:
    if score >= 90:
        return "Strong"
    if score >= 70:
        return "Fair"
    if score >= 40:
        return "Weak"
    return "Critical"


def _esc(text) -> str:
    return html.escape(str(text)) if text is not None else ""


def render_executive(data: ReportData) -> bytes:
    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = _styles(getSampleStyleSheet, ParagraphStyle, colors)
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title=f"Executive Report — {data.project_name}")
    story = []

    story.append(Paragraph("MBS.SC — Executive Security Report", styles["H1"]))
    story.append(Paragraph(f"Project: {_esc(data.project_name)}", styles["Meta"]))
    story.append(
        Paragraph(f"Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}", styles["Meta"])
    )
    story.append(Spacer(1, 8 * mm))

    # Security score panel
    band = _score_band(data.security_score)
    story.append(Paragraph(f"Security Score: <b>{data.security_score}/100</b> ({band})", styles["Score"]))
    story.append(
        Paragraph(
            f"{data.active_vulns} active finding(s) out of {data.total_vulns} total. The score "
            "reflects open, confirmed, and reopened findings weighted by severity; resolved, "
            "accepted-risk, and false-positive findings do not reduce it.",
            styles["Body"],
        )
    )
    story.append(Spacer(1, 6 * mm))

    # Severity summary table
    story.append(Paragraph("Findings by severity", styles["H2"]))
    sev_rows = [["Severity", "Count"]]
    for sev in ("critical", "high", "medium", "low", "info"):
        sev_rows.append([sev.capitalize(), str(data.severity_counts.get(sev, 0))])
    tbl = Table(sev_rows, colWidths=[80 * mm, 40 * mm])
    tbl.setStyle(_table_style(colors))
    story.append(tbl)
    story.append(Spacer(1, 6 * mm))

    # Top risks
    story.append(Paragraph("Top risks (by business risk score)", styles["H2"]))
    ranked = sorted(
        [v for v in data.vulns if v.final_risk_score is not None],
        key=lambda v: v.final_risk_score,
        reverse=True,
    )[:10]
    if ranked:
        risk_rows = [["Finding", "Severity", "Risk"]]
        for v in ranked:
            risk_rows.append([Paragraph(_esc(v.title), styles["Cell"]), v.severity, f"{v.final_risk_score:.1f}"])
        rtbl = Table(risk_rows, colWidths=[110 * mm, 30 * mm, 25 * mm])
        rtbl.setStyle(_table_style(colors))
        story.append(rtbl)
    else:
        story.append(Paragraph("No scored findings.", styles["Body"]))

    story.append(Spacer(1, 6 * mm))
    frameworks = sorted({fw for v in data.vulns for (fw, _, _) in v.compliance})
    story.append(Paragraph("Compliance coverage", styles["H2"]))
    story.append(
        Paragraph(
            "Findings mapped to controls in: " + (", ".join(fw.upper() for fw in frameworks) or "none")
            + ". See the technical report for per-finding control mappings.",
            styles["Body"],
        )
    )

    doc.build(story)
    return buf.getvalue()


def render_technical(data: ReportData) -> bytes:
    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = _styles(getSampleStyleSheet, ParagraphStyle, colors)
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title=f"Technical Report — {data.project_name}")
    story = []

    story.append(Paragraph("MBS.SC — Technical Security Report", styles["H1"]))
    story.append(Paragraph(f"Project: {_esc(data.project_name)}", styles["Meta"]))
    story.append(Paragraph(f"Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}", styles["Meta"]))
    story.append(
        Paragraph(f"Security score {data.security_score}/100 · {data.total_vulns} finding(s).", styles["Meta"])
    )
    story.append(Spacer(1, 6 * mm))

    if not data.vulns:
        story.append(Paragraph("No findings recorded for this project.", styles["Body"]))
        doc.build(story)
        return buf.getvalue()

    for i, v in enumerate(data.vulns, 1):
        story.append(_finding_block(i, v, styles, colors, Paragraph, Table, TableStyle, mm))
        story.append(Spacer(1, 4 * mm))

    doc.build(story)
    return buf.getvalue()


def _finding_block(idx, v: VulnRow, styles, colors, Paragraph, Table, TableStyle, mm):
    from reportlab.platypus import KeepTogether

    color = _SEVERITY_COLORS.get(v.severity, "#374151")
    parts = [
        Paragraph(f"{idx}. {_esc(v.title)}", styles["H2"]),
        Paragraph(
            f'<font color="{color}"><b>{v.severity.upper()}</b></font> · status: {_esc(v.status)}'
            + (f" · CVSS {v.cvss_score}" if v.cvss_score is not None else "")
            + (f" · risk {v.final_risk_score:.1f}" if v.final_risk_score is not None else ""),
            styles["Body"],
        ),
    ]
    if v.category:
        parts.append(Paragraph(f"Category: {_esc(v.category)}", styles["Small"]))
    if v.cvss_vector:
        parts.append(Paragraph(f"CVSS vector: {_esc(v.cvss_vector)}", styles["Small"]))
    if v.risk_rationale:
        parts.append(Paragraph(f"Risk: {_esc(v.risk_rationale)}", styles["Small"]))
    if v.compliance:
        controls = "; ".join(f"{fw.upper()} {cid}" for (fw, cid, _) in v.compliance)
        parts.append(Paragraph(f"Compliance: {_esc(controls)}", styles["Small"]))
    if v.evidence_uris:
        parts.append(Paragraph("Evidence:", styles["Small"]))
        for uri in v.evidence_uris:
            parts.append(Paragraph(f"• {_esc(uri)}", styles["Mono"]))
    else:
        parts.append(Paragraph("Evidence: (none linked)", styles["Small"]))
    return KeepTogether(parts)


def _styles(getSampleStyleSheet, ParagraphStyle, colors):
    base = getSampleStyleSheet()
    return {
        "H1": ParagraphStyle("H1", parent=base["Heading1"], textColor=colors.HexColor(_BRAND), fontSize=20),
        "H2": ParagraphStyle("H2", parent=base["Heading2"], textColor=colors.HexColor(_BRAND), fontSize=13),
        "Score": ParagraphStyle("Score", parent=base["Normal"], fontSize=16, spaceAfter=6),
        "Meta": ParagraphStyle("Meta", parent=base["Normal"], fontSize=9, textColor=colors.HexColor("#6b7280")),
        "Body": ParagraphStyle("Body", parent=base["Normal"], fontSize=10, leading=14),
        "Small": ParagraphStyle("Small", parent=base["Normal"], fontSize=9, leading=12),
        "Mono": ParagraphStyle("Mono", parent=base["Normal"], fontName="Courier", fontSize=8, leading=11),
        "Cell": ParagraphStyle("Cell", parent=base["Normal"], fontSize=9, leading=12),
    }


def _table_style(colors):
    from reportlab.platypus import TableStyle

    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(_BRAND)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
    )


def render(report_type: str, data: ReportData) -> bytes:
    if report_type == "executive":
        return render_executive(data)
    if report_type == "technical":
        return render_technical(data)
    raise ValueError(f"Unknown report type: {report_type}")
