"""PDF rendering for reports. reportlab is imported lazily inside the render
functions so importing this module (e.g. for the service/CRUD path) doesn't
require reportlab to be installed."""

import html
from datetime import datetime, timezone

from apps.api.modules.compliance.catalog import framework_name
from apps.api.modules.reports.data import _ACTIVE_STATUSES, _SEVERITY_ORDER, ReportData, VulnRow

# Rank a severity for deterministic tie-breaking: critical=highest. Mirrors data._SEVERITY_ORDER
# (critical..info) so "higher severity first" is a single source of truth. Unknown severities
# sort last (lowest rank).
_SEVERITY_RANK = {sev: len(_SEVERITY_ORDER) - i for i, sev in enumerate(_SEVERITY_ORDER)}


def _top_risk_groups(vulns) -> list[dict]:
    """Executive Top Risks, aggregated at the TEMPLATE level (presentation only -- vulnerability
    identity, fingerprints, and DB deduplication are unchanged; this only groups already-persisted
    rows for display). One row per issue-type rather than one per endpoint, so a single template
    hitting many URLs no longer floods the list or reads as many distinct vulnerabilities.

    Considers only ACTIVE, SCORED findings (final_risk_score not None and status in
    data._ACTIVE_STATUSES) -- identical to the pre-rollup filter. Findings are grouped by
    `template_id`; a finding with no template_id falls back to its own `title` as the key, so
    non-nuclei/legacy findings each stay a distinct row instead of collapsing into one bucket.

    Each group dict carries:
      * title           -- representative finding: the title of the group's highest-risk member
                           (deterministic: max risk, then max CVSS, then severity, then title asc);
      * endpoint_count  -- how many endpoint-level findings the group aggregates (NOT distinct
                           vulnerabilities -- the renderer labels the column so);
      * max_risk        -- the group's highest final_risk_score (drives ranking + display);
      * max_cvss        -- the group's highest CVSS (None only if every member's CVSS is None);
      * severity        -- the highest severity among the group's members.

    Groups are returned in deterministic order: max_risk DESC, then max_cvss DESC, then severity
    DESC, then representative title ASC -- the same key discipline the per-finding list used."""
    active_scored = [
        v for v in vulns if v.final_risk_score is not None and v.status in _ACTIVE_STATUSES
    ]
    buckets: dict[str, list] = {}
    for v in active_scored:
        # `tid:`/`title:` prefixes keep a template_id and an identical-looking title from ever
        # colliding into one bucket.
        key = f"tid:{v.template_id}" if v.template_id else f"title:{v.title or ''}"
        buckets.setdefault(key, []).append(v)

    def _member_sort_key(v):
        return (
            -v.final_risk_score,
            -(v.cvss_score if v.cvss_score is not None else -1.0),
            -_SEVERITY_RANK.get(v.severity, 0),
            v.title or "",
        )

    groups: list[dict] = []
    for members in buckets.values():
        rep = min(members, key=_member_sort_key)  # highest-risk member (min of negated keys)
        cvss_values = [m.cvss_score for m in members if m.cvss_score is not None]
        groups.append(
            {
                "title": rep.title,
                "endpoint_count": len(members),
                "max_risk": max(m.final_risk_score for m in members),
                "max_cvss": max(cvss_values) if cvss_values else None,
                "severity": max(members, key=lambda m: _SEVERITY_RANK.get(m.severity, 0)).severity,
            }
        )

    groups.sort(
        key=lambda g: (
            -g["max_risk"],
            -(g["max_cvss"] if g["max_cvss"] is not None else -1.0),
            -_SEVERITY_RANK.get(g["severity"], 0),
            g["title"] or "",
        )
    )
    return groups

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


def _findings_summary(data) -> str:
    """One sentence reconciling the security score with the finding count, so a reader never
    reads "100/100" as "zero findings" or "N active findings" as "N vulnerabilities".

    Pure and testable (like _score_band). Uses only ReportData fields that already exist
    (active_vulns / total_vulns / severity_counts / security_score) -- it does NOT recompute
    the score or reweight anything. The wording is derived from the ACTUAL scoring model
    (scoring.py: info findings are filtered out before scoring, so they cost nothing),
    so it states plain fact:

      * findings are called "finding(s)/detection(s)", never "vulnerabilities" -- an
        informational detection is not necessarily a vulnerability;
      * when the active findings are ALL informational, it says so and explains that
        informational findings carry no score penalty (which is why the score can be 100);
      * otherwise it names how many of the active findings are non-informational (the ones
        that actually move the score), without claiming they are all informational."""
    active = data.active_vulns
    if active == 0:
        return "No active findings. The score is not reduced by any active finding."
    # active_vulns counts active findings; severity_counts is over ALL findings, so the
    # "all informational" case is asserted via the non-info active severities below rather
    # than by comparing active to a total info count.
    non_info_active = sum(
        data.severity_counts.get(sev, 0) for sev in ("critical", "high", "medium", "low")
    )
    noun = "active finding" if active == 1 else "active findings"
    non_info_verb = "is" if non_info_active == 1 else "are"
    if non_info_active == 0:
        return (
            f"{active} {noun} detected — all informational. Informational findings are "
            "reported for visibility and do not reduce the security score under the current "
            "scoring model, so a score of 100/100 can coexist with informational findings. "
            "These are detections, not confirmed vulnerabilities."
        )
    return (
        f"{active} {noun} detected, of which {non_info_active} {non_info_verb} of low severity or higher "
        "and reduce the security score; informational findings are reported for visibility "
        "but carry no score penalty. Findings are detections, not all confirmed vulnerabilities."
    )


def _esc(text) -> str:
    return html.escape(str(text)) if text is not None else ""


def render_executive(data: ReportData) -> bytes:
    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table

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
            f"{data.active_vulns} active finding(s) out of {data.total_vulns} total. "
            + _findings_summary(data)
            + " The score reflects open, confirmed, and reopened findings weighted by "
            "severity; resolved, accepted-risk, and false-positive findings do not reduce it.",
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

    # Affected assets / endpoints. Management-level rollup, NOT a per-endpoint dump: the distinct
    # inventoried assets/hosts (assets.value) plus how many distinct endpoints (matched_at) were
    # observed. Asset (host) and endpoint (exact URL) are deliberately named separately. Assets
    # appear ONLY when the finding is linked to an inventoried asset -- an empty list means the
    # findings carry no asset linkage, never that nothing is affected. Full per-finding endpoints
    # remain in the technical report.
    story.append(Paragraph("Affected assets / endpoints", styles["H2"]))
    assets = data.affected_assets()
    endpoints = data.affected_endpoint_count()
    endpoint_phrase = (
        f"{endpoints} distinct endpoint(s) (URLs/locations) were affected"
        if endpoints
        else "No specific endpoint locations were recorded for these findings"
    )
    if assets:
        shown = ", ".join(_esc(a) for a in assets[:15])
        more = f" (+{len(assets) - 15} more)" if len(assets) > 15 else ""
        story.append(
            Paragraph(
                f"{len(assets)} inventoried asset/host(s) are affected: {shown}{more}. "
                f"{endpoint_phrase}. An asset/host is the scanned system; an endpoint is the "
                "specific URL/location on it -- one host can expose many affected endpoints.",
                styles["Body"],
            )
        )
    else:
        story.append(
            Paragraph(
                f"{endpoint_phrase}. Findings are not linked to inventoried assets for this "
                "project, so affected hosts are identified by endpoint (see the technical report "
                "for each finding's exact location).",
                styles["Body"],
            )
        )
    story.append(Spacer(1, 6 * mm))

    # Scope / limitations -- keep management honest about what the score and findings mean.
    story.append(
        Paragraph(
            "Scope & limitations: results are automated, detection-based findings from the "
            "configured scan. They indicate where issues were observed and are not manually "
            "validated confirmed vulnerabilities unless supporting evidence states otherwise. "
            "Coverage is limited to the assets and endpoints reached by this scan.",
            styles["Body"],
        )
    )
    story.append(Spacer(1, 6 * mm))

    # Top risks. ACTIVE, scored findings only -- same active-status set the Security Score uses
    # (data._ACTIVE_STATUSES: open/confirmed/reopened) -- aggregated at the TEMPLATE level so one
    # issue-type that hit many endpoints is ONE row (with an endpoint count), not a flood of
    # look-alike rows that reads as many distinct vulnerabilities. This is presentation grouping
    # only: vulnerability identity, fingerprints, and DB deduplication are unchanged (see
    # _top_risk_groups). Deterministic ordering: max business risk DESC -> max CVSS DESC ->
    # severity DESC -> representative title ASC.
    story.append(Paragraph("Top risks (by business risk score)", styles["H2"]))
    groups = _top_risk_groups(data.vulns)[:10]
    if groups:
        story.append(
            Paragraph(
                "Grouped by issue type. “Endpoints” is how many affected "
                "endpoints/findings each issue was observed at — not a count of distinct "
                "vulnerabilities. Risk is the highest business risk score within the group.",
                styles["Body"],
            )
        )
        risk_rows = [["Issue", "Severity", "Endpoints", "Risk"]]
        for g in groups:
            risk_rows.append(
                [
                    Paragraph(_esc(g["title"]), styles["Cell"]),
                    g["severity"],
                    str(g["endpoint_count"]),
                    f"{g['max_risk']:.1f}",
                ]
            )
        rtbl = Table(risk_rows, colWidths=[95 * mm, 28 * mm, 22 * mm, 20 * mm])
        rtbl.setStyle(_table_style(colors))
        story.append(rtbl)
    else:
        story.append(Paragraph("No scored findings.", styles["Body"]))

    story.append(Spacer(1, 6 * mm))
    frameworks = sorted({fw for v in data.vulns for (fw, _, _) in v.compliance})
    story.append(Paragraph("Compliance coverage", styles["H2"]))
    story.append(
        Paragraph(
            "Findings mapped to controls in: " + (", ".join(framework_name(fw) for fw in frameworks) or "none")
            + ". See the technical report for per-finding control mappings.",
            styles["Body"],
        )
    )

    # MITRE ATT&CK coverage: which adversary techniques the findings map to, most
    # frequently observed first. The per-scan kill-chain view sequences these.
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("MITRE ATT&CK coverage", styles["H2"]))
    if data.attack_techniques:
        att_rows = [["Tactic", "Technique", "ID", "Findings"]]
        for tactic, tid, tname, count in data.attack_techniques[:15]:
            att_rows.append([_esc(tactic), Paragraph(_esc(tname), styles["Cell"]), tid, str(count)])
        atbl = Table(att_rows, colWidths=[45 * mm, 70 * mm, 25 * mm, 20 * mm])
        atbl.setStyle(_table_style(colors))
        story.append(atbl)
        story.append(
            Paragraph(
                "Techniques are mapped to the Cyber Kill Chain; see the scan kill-chain view for the "
                "sequenced attack path.",
                styles["Body"],
            )
        )
    else:
        story.append(Paragraph("No findings mapped to ATT&CK techniques.", styles["Body"]))

    # Autonomous-engagement attack graph (M4.4.6): evidence-backed asset -> service ->
    # finding -> technique -> access relationships, plus any confirmed access. Present
    # only for agent-driven scans; fail-soft otherwise. Never reports unsupported
    # privilege escalation / lateral movement.
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Autonomous engagement: attack graph", styles["H2"]))
    ag = data.attack_graph or {}
    if ag.get("has_data"):
        counts = ag.get("node_counts", {})
        story.append(
            Paragraph(
                "Evidence-backed graph: "
                + ", ".join(f"{counts[t]} {t}" for t in sorted(counts))
                + f" (across {ag.get('engagement_count', 0)} autonomous engagement(s)).",
                styles["Body"],
            )
        )
        confirmed = ag.get("confirmed_access") or []
        if confirmed:
            story.append(Paragraph("Confirmed access (evidence-backed):", styles["Body"]))
            for a in confirmed[:10]:
                story.append(
                    Paragraph(
                        f"&bull; {_esc(a.get('target'))} — {_esc(a.get('access_state'))} "
                        f"(module {_esc(a.get('module'))})",
                        styles["Body"],
                    )
                )
        else:
            story.append(Paragraph("No access was confirmed.", styles["Body"]))
        story.append(
            Paragraph(
                "All graph relationships and access states are derived from collected evidence. "
                "Host nodes are inferred from observed services; privilege escalation and lateral "
                "movement are reported only when supported by evidence.",
                styles["Body"],
            )
        )
    else:
        story.append(
            Paragraph("No autonomous engagement graph for this project (non-agent scans).", styles["Body"])
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
    story.append(Paragraph(_findings_summary(data), styles["Small"]))
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
            # `is not None`, never truthiness: a real CVSS of 0.0 must show as "CVSS 0.0",
            # only a genuinely absent score (None) shows "CVSS N/A". `x or 0.0`-style logic
            # would wrongly collapse 0.0 into a fallback, and `if not x` would wrongly treat
            # 0.0 as missing. This is representation only -- the stored score is untouched.
            + (f" · CVSS {v.cvss_score}" if v.cvss_score is not None else " · CVSS N/A")
            + (f" · risk {v.final_risk_score:.1f}" if v.final_risk_score is not None else ""),
            styles["Body"],
        ),
    ]
    # WHERE the finding was observed (Phase 1). Always shown -- N/A when unavailable -- so two
    # findings that share a title/severity but hit different URLs/params are distinguishable in
    # the report rather than looking like duplicates. matched_at can be a long URL, so it is
    # rendered in the monospace style and word-wraps like the evidence URIs below.
    parts.append(Paragraph(f"Template: {_esc(v.template_id or 'N/A')}", styles["Small"]))
    parts.append(Paragraph(f"Matcher: {_esc(v.matcher_name or 'N/A')}", styles["Small"]))
    parts.append(Paragraph(f"Matched at: {_esc(v.matched_at or 'N/A')}", styles["Mono"]))
    parts.append(Paragraph(f"Status: {_esc(v.status or 'N/A')}", styles["Small"]))
    if v.category:
        parts.append(Paragraph(f"Category: {_esc(v.category)}", styles["Small"]))
    if v.cvss_vector:
        parts.append(Paragraph(f"CVSS vector: {_esc(v.cvss_vector)}", styles["Small"]))
    if v.risk_rationale:
        parts.append(Paragraph(f"Risk: {_esc(v.risk_rationale)}", styles["Small"]))
    if v.compliance:
        controls = "; ".join(f"{framework_name(fw)} {cid}" for (fw, cid, _) in v.compliance)
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
