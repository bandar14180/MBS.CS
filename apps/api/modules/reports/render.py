"""PDF rendering for reports. reportlab is imported lazily inside the render
functions so importing this module (e.g. for the service/CRUD path) doesn't
require reportlab to be installed."""

import html
from datetime import datetime, timezone

from apps.api.modules.compliance.catalog import framework_name
from apps.api.modules.reports.data import _ACTIVE_STATUSES, _SEVERITY_ORDER, ReportData, VulnRow
from apps.api.modules.reports.classification import classify_row
from apps.api.modules.reports.scoring import issue_key

# Rank a severity for deterministic tie-breaking: critical=highest. Mirrors data._SEVERITY_ORDER
# (critical..info) so "higher severity first" is a single source of truth. Unknown severities
# sort last (lowest rank).
_SEVERITY_RANK = {sev: len(_SEVERITY_ORDER) - i for i, sev in enumerate(_SEVERITY_ORDER)}


def _top_risk_groups(vulns) -> list[dict]:
    """Executive Top Risks, aggregated at the TEMPLATE level (presentation only -- vulnerability
    identity, fingerprints, and DB deduplication are unchanged; this only groups already-persisted
    rows for display). One row per issue-type rather than one per endpoint, so a single template
    hitting many URLs no longer floods the list or reads as many distinct vulnerabilities.

    Considers all ACTIVE findings (status in data._ACTIVE_STATUSES), whether or not they
    carry a business-risk score: a finding with no CVSS has final_risk_score=None and must
    still be shown, as unscored, rather than disappearing from the executive view while it
    continues to reduce the security score. Findings are grouped by
    `template_id`; a finding with no template_id falls back to its own `title` as the key, so
    non-nuclei/legacy findings each stay a distinct row instead of collapsing into one bucket.

    Each group dict carries:
      * title           -- representative finding: the title of the group's highest-risk member
                           (deterministic: max risk, then max CVSS, then severity, then title asc);
      * endpoint_count  -- how many endpoint-level findings the group aggregates (NOT distinct
                           vulnerabilities -- the renderer labels the column so);
      * max_risk        -- the group's highest final_risk_score, or None when no member is
      scored (drives ranking + display; rendered as N/A, never 0.0);
      * max_cvss        -- the group's highest CVSS (None only if every member's CVSS is None);
      * severity        -- the highest severity among the group's members.

    Groups are returned in deterministic order: max_risk DESC, then max_cvss DESC, then severity
    DESC, then representative title ASC -- the same key discipline the per-finding list used."""
    # ACTIVE findings, scored or not. The `final_risk_score is not None` filter used to live
    # here and silently dropped every finding with no CVSS -- no CVSS means risk/service.py
    # returns final_risk_score=None -- so a CRITICAL active finding with no CVSS vanished from
    # Top Risks while STILL degrading the security score. An executive then read a reduced
    # score above an empty table saying "No scored findings." The finding is now kept and
    # presented as unscored (max_risk None -> the renderer prints "N/A"); no business-risk
    # value is fabricated for it.
    active = [v for v in vulns if v.status in _ACTIVE_STATUSES]
    buckets: dict[str, list] = {}
    for v in active:
        # `tid:`/`title:` prefixes keep a template_id and an identical-looking title from ever
        # colliding into one bucket.
        key = f"tid:{v.template_id}" if v.template_id else f"title:{v.title or ''}"
        buckets.setdefault(key, []).append(v)

    def _member_sort_key(v):
        # A None risk/CVSS sorts BELOW any real value (including 0.0) rather than raising --
        # unscored members are legitimate now, and a scored member is preferred as the
        # group's representative when both exist.
        return (
            -(v.final_risk_score if v.final_risk_score is not None else -1.0),
            -(v.cvss_score if v.cvss_score is not None else -1.0),
            -_SEVERITY_RANK.get(v.severity, 0),
            v.title or "",
        )

    groups: list[dict] = []
    for members in buckets.values():
        rep = min(members, key=_member_sort_key)  # highest-risk member (min of negated keys)
        cvss_values = [m.cvss_score for m in members if m.cvss_score is not None]
        # None only when EVERY member is unscored; a single scored member still yields a real
        # max. Never coerced to 0.0 -- "not scored" and "scored zero" stay distinct, exactly as
        # they do for CVSS everywhere else in the report.
        risk_values = [m.final_risk_score for m in members if m.final_risk_score is not None]
        groups.append(
            {
                "title": rep.title,
                "endpoint_count": len(members),
                "max_risk": max(risk_values) if risk_values else None,
                "max_cvss": max(cvss_values) if cvss_values else None,
                "severity": max(members, key=lambda m: _SEVERITY_RANK.get(m.severity, 0)).severity,
            }
        )

    # Unscored groups (max_risk None) rank below every scored one but ABOVE nothing -- they
    # still appear, ordered among themselves by CVSS then severity then title. Severity is
    # already in the key, so a critical unscored finding sorts to the top of that tail rather
    # than being buried.
    groups.sort(
        key=lambda g: (
            -(g["max_risk"] if g["max_risk"] is not None else -1.0),
            -(g["max_cvss"] if g["max_cvss"] is not None else -1.0),
            -_SEVERITY_RANK.get(g["severity"], 0),
            g["title"] or "",
        )
    )
    return groups

def _finding_groups(vulns) -> list[dict]:
    """Technical Report findings, aggregated per underlying vulnerability (presentation only).

    The Technical Report used to render one block per VulnRow. A row is one
    (template_id|matcher|matched_at) fingerprint -- one LOCATION, not one issue -- so a single
    template observed at 24 URLs produced 24 near-identical blocks, repeating the same severity,
    CVSS, risk, category and compliance text each time. On the real dataset that turned 21
    distinct issue types into 201 blocks. This collapses them into one block per vulnerability
    with the affected locations listed underneath.

    Grouping key is `issue_key` from scoring.py -- the SAME identity the Security Score and the
    Executive Report's _top_risk_groups already use (template_id, falling back to title for
    legacy/non-nuclei rows). Reusing it is the point: all three surfaces now agree on what "one
    vulnerability" means, and the identity was validated against the database in the scoring work
    (no template_id spans more than one title/severity/CVSS/category).

    Unlike _top_risk_groups this keeps EVERY finding -- no active-status or scored-only filter --
    because the Technical Report is the full record: fixed, false-positive and unscored findings
    must still appear.

    Each group dict carries:
      * title/severity/status/category/cvss_score/cvss_vector/final_risk_score/risk_rationale --
        taken from the group's representative row (highest severity, then highest CVSS), so the
        header states the worst case rather than an arbitrary member;
      * matched_ats     -- every DISTINCT location, sorted, None dropped;
      * unlocated_count -- members with no matched_at, so they are not silently lost;
      * occurrence_count-- how many rows the group aggregates;
      * template_id/matcher_names -- provenance; matcher_names is sorted+deduped because one
        template can match via several matchers;
      * compliance/evidence_uris  -- union across members, deduped, order-stable.

    Vulnerability identity, fingerprints, DB deduplication, matched_at parsing, the Security
    Score and the Executive Report are all untouched: this only regroups already-persisted rows
    for display."""
    buckets: dict[str, list] = {}
    for v in vulns:
        buckets.setdefault(issue_key(v), []).append(v)

    def _rep_key(v):
        # Worst-case representative: highest severity, then highest CVSS. A None CVSS sorts
        # below a real 0.0 so a scored member is preferred as the representative.
        return (
            _SEVERITY_RANK.get(v.severity, 0),
            v.cvss_score if v.cvss_score is not None else -1.0,
        )

    groups: list[dict] = []
    for key, members in buckets.items():
        rep = max(members, key=_rep_key)

        matched_ats = sorted({m.matched_at for m in members if m.matched_at})
        unlocated = sum(1 for m in members if not m.matched_at)

        compliance: list[tuple[str, str, str]] = []
        for m in members:
            for c in m.compliance or []:
                if c not in compliance:
                    compliance.append(c)

        evidence_uris: list[str] = []
        for m in members:
            for uri in m.evidence_uris or []:
                if uri not in evidence_uris:
                    evidence_uris.append(uri)

        # Screenshots for this vulnerability, deduplicated BY CHECKSUM: two locations that
        # rendered byte-identical pages contribute one image, while genuinely different pages
        # each keep their own. Dedup is on content, never on "same finding" -- distinct
        # locations with distinct screenshots stay distinct.
        screenshots: list[tuple[str, str]] = []
        seen_checksums: set[str] = set()
        for m in members:
            for uri, checksum in getattr(m, "screenshots", None) or []:
                if checksum in seen_checksums:
                    continue
                seen_checksums.add(checksum)
                screenshots.append((uri, checksum))

        groups.append(
            {
                "key": key,
                "title": rep.title,
                "severity": rep.severity,
                "status": rep.status,
                "category": rep.category,
                "cvss_score": rep.cvss_score,
                "cvss_vector": rep.cvss_vector,
                "final_risk_score": rep.final_risk_score,
                "risk_rationale": rep.risk_rationale,
                "template_id": rep.template_id,
                # Producing tool(s) across the grouped rows (e.g. nuclei-dast). Sorted+deduped;
                # a group is usually one tool but this is robust if several produced it.
                "tools": sorted({m.tool_name for m in members if getattr(m, "tool_name", None) and m.tool_name != "N/A"}),
                # Detection vs vulnerability for the whole group. A group is a VULNERABILITY if
                # ANY member is -- so a template that is a real weakness anywhere is never
                # downgraded to a bare detection by a stray member. Classified from each row's
                # own fields (classify_row) so grouping is correct even for rows built outside
                # gather_report_data; see classification.py.
                "classification": (
                    "vulnerability"
                    if any(classify_row(m) == "vulnerability" for m in members)
                    else "detection"
                ),
                "matcher_names": sorted({m.matcher_name for m in members if m.matcher_name}),
                "matched_ats": matched_ats,
                "unlocated_count": unlocated,
                "occurrence_count": len(members),
                "compliance": sorted(compliance),
                "evidence_uris": evidence_uris,
                "screenshots": screenshots,
            }
        )

    # Deterministic: severity DESC, then CVSS DESC, then title ASC, then key ASC.
    groups.sort(
        key=lambda g: (
            -_SEVERITY_RANK.get(g["severity"], 0),
            -(g["cvss_score"] if g["cvss_score"] is not None else -1.0),
            g["title"] or "",
            g["key"],
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
    (active_vulns / active_severity_counts / severity_counts / security_score) -- it does NOT recompute
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
    # ACTIVE severities only. severity_counts is over ALL findings regardless of status, so
    # using it here described two different populations in one sentence: a FIXED high was
    # reported as "of low severity or higher and reduce the security score" even though it is
    # excluded from scoring and the score was 100 -- the report contradicting itself. It also
    # suppressed the honest "all informational" branch below whenever a stale fixed finding
    # existed. active_severity_counts is the matching population (data.gather_report_data).
    #
    # Fall back to severity_counts ONLY when active_severity_counts is absent (a ReportData
    # built by older code that predates the field); when it is present it is authoritative,
    # including when it is legitimately all-zero.
    severities = ("critical", "high", "medium", "low")
    active_by_severity = data.active_severity_counts or None
    if active_by_severity is None:
        non_info_active = sum(data.severity_counts.get(sev, 0) for sev in severities)
    else:
        non_info_active = sum(active_by_severity.get(sev, 0) for sev in severities)
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
                "vulnerabilities. Risk is the highest business risk score within the group; "
                "“N/A” means the finding carries no CVSS, so no business-risk score could "
                "be derived — it is unassessed, not low risk.",
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
                    # "N/A" -- NOT 0.0 -- when the group has no business-risk score at all
                    # (no CVSS anywhere in it). Fabricating a number here would misreport an
                    # unassessed finding as a zero-risk one.
                    (f"{g['max_risk']:.1f}" if g["max_risk"] is not None else "N/A"),
                ]
            )
        rtbl = Table(risk_rows, colWidths=[95 * mm, 28 * mm, 22 * mm, 20 * mm])
        rtbl.setStyle(_table_style(colors))
        story.append(rtbl)
    else:
        # Reached only when there are NO ACTIVE findings at all. It can no longer be shown
        # while an active finding exists, which is what previously let a degraded score sit
        # above an empty table.
        story.append(Paragraph("No active findings.", styles["Body"]))

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

    # One block per VULNERABILITY, not per row: a template observed at many URLs is a single
    # finding with its affected locations listed, instead of the same severity/CVSS/risk text
    # repeated once per location. Presentation only -- see _finding_groups.
    for i, g in enumerate(_finding_groups(data.vulns), 1):
        story.append(_finding_block(i, g, styles, colors, Paragraph, Table, TableStyle, mm))
        story.append(Spacer(1, 4 * mm))

    doc.build(story)
    return buf.getvalue()


def _finding_block(idx, g: dict, styles, colors, Paragraph, Table, TableStyle, mm):
    """Render ONE vulnerability (a group from _finding_groups), with its affected locations
    listed once at the end instead of the whole block repeating per location."""
    from reportlab.platypus import KeepTogether

    color = _SEVERITY_COLORS.get(g["severity"], "#374151")
    # Detection vs vulnerability, stated in the heading so a technology/WAF/version DETECTION
    # is never read as a confirmed vulnerability. Presentation only -- identity, grouping and
    # scoring are unchanged (see classification.py).
    kind_label = "DETECTION" if g.get("classification") == "detection" else "VULNERABILITY"
    parts = [
        Paragraph(f"{idx}. {_esc(g['title'])}", styles["H2"]),
        Paragraph(f"Type: {kind_label}", styles["Small"]),
        Paragraph(
            f'<font color="{color}"><b>{g["severity"].upper()}</b></font> · status: {_esc(g["status"])}'
            # `is not None`, never truthiness: a real CVSS of 0.0 must show as "CVSS 0.0",
            # only a genuinely absent score (None) shows "CVSS N/A". `x or 0.0`-style logic
            # would wrongly collapse 0.0 into a fallback, and `if not x` would wrongly treat
            # 0.0 as missing. This is representation only -- the stored score is untouched.
            + (f" · CVSS {g['cvss_score']}" if g["cvss_score"] is not None else " · CVSS N/A")
            + (f" · risk {g['final_risk_score']:.1f}" if g["final_risk_score"] is not None else ""),
            styles["Body"],
        ),
    ]
    # Producing scanner tool(s), e.g. nuclei-dast. "N/A" when no tool linkage exists.
    parts.append(Paragraph(f"Tool: {_esc(', '.join(g.get('tools') or []) or 'N/A')}", styles["Small"]))
    parts.append(Paragraph(f"Template: {_esc(g['template_id'] or 'N/A')}", styles["Small"]))
    parts.append(
        Paragraph(f"Matcher: {_esc(', '.join(g['matcher_names']) or 'N/A')}", styles["Small"])
    )
    parts.append(Paragraph(f"Status: {_esc(g['status'] or 'N/A')}", styles["Small"]))
    if g["category"]:
        parts.append(Paragraph(f"Category: {_esc(g['category'])}", styles["Small"]))
    if g["cvss_vector"]:
        parts.append(Paragraph(f"CVSS vector: {_esc(g['cvss_vector'])}", styles["Small"]))
    if g["risk_rationale"]:
        parts.append(Paragraph(f"Risk: {_esc(g['risk_rationale'])}", styles["Small"]))
    if g["compliance"]:
        controls = "; ".join(f"{framework_name(fw)} {cid}" for (fw, cid, _) in g["compliance"])
        parts.append(Paragraph(f"Compliance: {_esc(controls)}", styles["Small"]))

    # WHERE the finding was observed. Listed once per DISTINCT location under the single
    # finding, so one issue across many endpoints reads as one vulnerability with a breadth
    # count -- not as many separate vulnerabilities. Long URLs word-wrap in the mono style.
    locations = g["matched_ats"]
    if locations:
        parts.append(Paragraph(f"Affected locations ({len(locations)}):", styles["Small"]))
        for loc in locations:
            parts.append(Paragraph(f"• {_esc(loc)}", styles["Mono"]))
        # Occurrences with no matched_at are still real findings; say so rather than drop them.
        if g["unlocated_count"]:
            parts.append(
                Paragraph(
                    f"• (+{g['unlocated_count']} occurrence(s) with no recorded location)",
                    styles["Small"],
                )
            )
    else:
        parts.append(Paragraph("Affected locations: N/A", styles["Small"]))

    if g["evidence_uris"]:
        parts.append(Paragraph("Evidence:", styles["Small"]))
        for uri in g["evidence_uris"]:
            parts.append(Paragraph(f"• {_esc(uri)}", styles["Mono"]))
    else:
        parts.append(Paragraph("Evidence: (none linked)", styles["Small"]))

    # Visual evidence, embedded under the finding it belongs to. Fail-soft at every step:
    # a screenshot that cannot be fetched or decoded is simply omitted (the finding and the
    # rest of the report still render), and nothing is drawn when there are none.
    for uri, checksum in g.get("screenshots") or []:
        image = _screenshot_flowable(uri, mm)
        if image is None:
            continue
        parts.append(Paragraph(f"Screenshot ({_esc(checksum[:12])}):", styles["Small"]))
        parts.append(image)
    return KeepTogether(parts)


def _screenshot_flowable(storage_uri: str, mm):
    """Fetch a stored screenshot and return a reportlab Image scaled to the page width.

    Returns None on ANY problem -- missing object, storage outage, unreadable bytes -- so a
    broken image can never break report generation. Reading happens here, at render time;
    the capture itself ran during the scan (see scanner_engine/screenshot.py)."""
    from io import BytesIO

    try:
        from reportlab.platypus import Image as RLImage

        from apps.api.scanner_engine.storage_provider import get_storage_provider

        # s3://bucket/key -> key. Anything else is not a fetchable evidence object.
        if not storage_uri.startswith("s3://"):
            return None
        _, _, rest = storage_uri.partition("s3://")
        bucket, _, key = rest.partition("/")
        if not key:
            return None

        data = get_storage_provider(bucket).get(key)
        if not data:
            return None

        img = RLImage(BytesIO(data))
        # Scale to fit the printable width while preserving aspect ratio.
        max_width = 160 * mm
        if img.imageWidth and img.imageWidth > max_width:
            ratio = max_width / float(img.imageWidth)
            img.drawWidth = max_width
            img.drawHeight = img.imageHeight * ratio
        return img
    except Exception:  # noqa: BLE001 -- evidence is decorative; the report must still build
        return None


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
