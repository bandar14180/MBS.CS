"""PDF rendering for reports. reportlab is imported lazily inside the render
functions so importing this module (e.g. for the service/CRUD path) doesn't
require reportlab to be installed."""

import hashlib
import html
import re
from datetime import datetime, timezone

from apps.api.modules.compliance.catalog import framework_name
from apps.api.modules.reports.data import (
    _ACTIVE_STATUSES,
    _SEVERITY_ORDER,
    EvidenceRecord,
    ReportData,
    _normalise_steps,
)
# Step 4: the renderer-facing contract. Imported under TYPE_CHECKING to keep the runtime
# import graph acyclic -- model.py imports render.py's grouping helpers at call time.
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from apps.api.modules.reports.model import ReportModel
from apps.api.modules.reports import _branding as B
from apps.api.modules.reports import narrative as N
from apps.api.modules.reports.classification import _recover_cve, classify_row
from apps.api.modules.reports.finding_descriptions import curated_description
from apps.api.modules.reports.scoring import issue_key
from apps.api.modules.reports.verification import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    PARTIALLY_VERIFIED,
    UNVERIFIED,
    VERIFIED,
    classify_verification_row,
    confidence_label,
    verification_label,
    verification_note,
)
# CVSS band is derived from the BASE SCORE alone -- the single source of truth lives with the
# risk engine so the report and the engine can never disagree about what "Medium" means.
from apps.api.modules.risk.service import _MAX_RISK, cvss_severity_band

# P2-3: human labels for the evidence types the pipeline actually stores (see the `evidence`
# table: `log_excerpt` and `screenshot` in the live dataset). An UNKNOWN type is passed through
# rather than relabelled or hidden -- inventing a label for an artifact we cannot identify would
# misrepresent it, and dropping it would lose evidence.
_EVIDENCE_TYPE_LABELS = {
    "log_excerpt": "Raw tool output",
    "screenshot": "Screenshot",
    "http_request": "HTTP request",
    "http_response": "HTTP response",
    "recording": "Session recording",
}


def _evidence_type_label(etype: str | None) -> str:
    key = (etype or "").strip().lower()
    if not key:
        return "Evidence"
    return _EVIDENCE_TYPE_LABELS.get(key, key.replace("_", " ").capitalize())


def _sanitise_risk_rationale(rationale: str | None, final_risk_score: float | None) -> str:
    """Drop a cap claim from a STORED rationale when the risk was not actually capped.

    WHY THIS IS NEEDED AT RENDER TIME. `risk_scores.rationale` is written once, at scan time,
    and read back verbatim by the report. An earlier version of risk/service.py appended
    "(capped at 10.0)" UNCONDITIONALLY, so rows written before that fix carry the claim even
    when nothing was capped -- 604 of 692 rows in the live dataset say "capped" while
    final_risk_score < 10, e.g.

        CVSS 0.0 x asset criticality 'critical' (weight 2.0) = 0.0 (capped at 10.0).

    The engine is already correct for every new computation (see risk/service.py: the cap note
    is emitted only when `uncapped > final`). This function fixes the DISPLAY of the historical
    rows, so the report stops asserting a cap that never happened.

    Presentation only, and deliberately narrow:
      * the cap phrase is removed ONLY when `final_risk_score < _MAX_RISK`, i.e. the arithmetic
        proves no cap could have applied. A genuinely capped row (score == 10.0) keeps its text
        untouched, so a real cap is never hidden;
      * nothing else in the sentence is rewritten -- the CVSS value, the criticality, the weight
        and the product are all left exactly as the engine recorded them;
      * no stored value is modified. This does not write to the database, and it does not touch
        final_risk_score, cvss_score, severity or the security score.
    """
    text = rationale or ""
    if not text or final_risk_score is None:
        return text
    # `< _MAX_RISK` (not `!=`) so only a value the cap could not have produced is treated as
    # uncapped. At exactly 10.0 the claim may be true, so it is left alone.
    if final_risk_score >= _MAX_RISK:
        return text
    # Matches the historical " (capped at 10.0)" and the current
    # " (capped at 10.0 from 19.6)" shapes; tolerant of spacing and the trailing period.
    cleaned = re.sub(r"\s*\(capped at [0-9.]+(?: from [0-9.]+)?\)", "", text, flags=re.IGNORECASE)
    # Restore the sentence-ending period the phrase may have carried away.
    if text.rstrip().endswith(".") and not cleaned.rstrip().endswith("."):
        cleaned = cleaned.rstrip() + "."
    return cleaned


def _card(rows, styles, colors, mm, width=170, accent: str | None = None, label_w=42):
    """A two-column label/value card: the report's standard block for structured facts.

    Replaces long dotted "Label: value" runs and bare grid tables with something a client can
    scan. `accent` paints a left edge (severity or brand colour) so priority reads at a glance.
    Values are Paragraphs, so long URLs wrap inside the cell instead of overflowing the frame.

    Presentation only -- it formats whatever it is given and never derives a value."""
    from reportlab.platypus import Paragraph, Table, TableStyle

    body = []
    for label, value in rows:
        if isinstance(value, str):
            value = Paragraph(_esc(value), styles["Cell"])
        body.append([Paragraph(_esc(label), styles["Label"]), value])

    tbl = Table(body, colWidths=[label_w * mm, (width - label_w) * mm], hAlign="LEFT")
    style = [
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(B.PAPER_TINT)),
        ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor(B.RULE)),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor(B.RULE)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
    ]
    if accent:
        style.append(("LINEBEFORE", (0, 0), (0, -1), 2.4, colors.HexColor(accent)))
    tbl.setStyle(TableStyle(style))
    return tbl


# Remediation buckets. Ordering ONLY -- this maps a finding's EXISTING severity and business
# risk onto a delivery sequence for the client. It does not change, re-derive or reweight
# severity, CVSS, risk or the security score; two findings of equal severity always land in
# the same bucket regardless of anything else in the report.
_REMEDIATION_BUCKETS = (
    ("Immediate", "critical", "Address without delay."),
    ("High Priority", "high", "Address in the current remediation cycle."),
    ("Medium Priority", "medium", "Schedule into the next planned cycle."),
    ("Long Term", "low", "Track and resolve as part of routine hardening."),
)


def _as_model(value):
    """Accept a `ReportModel` (the migrated contract) or a `ReportData` (the legacy one).

    Step 4 moved the renderer-facing contract to `ReportModel`. The PUBLIC `render()` entry
    point builds the model itself, so production never passes anything else -- but the
    render_* functions have been directly callable with `ReportData` since the reporting layer
    was written, and 169 assertions across 14 test modules still use that form.

    Those assertions are the guard rails for Phases 2.1-4.5. Rewriting all of them mechanically
    in the same change that migrates the renderers would put the thing they protect at risk for
    no behavioural gain, so the boundary coerces instead: a ReportData is promoted to the model
    exactly as `render()` would. One line, one place, no duplicated logic, and the renderer
    bodies below read ONLY the model.

    This is a compatibility shim at the edge, not an escape hatch: nothing downstream can reach
    the ReportData through the model."""
    from apps.api.modules.reports.model import ReportModel, build_report_model

    if isinstance(value, ReportModel):
        return value
    if not hasattr(value, "vulns"):
        # A minimal stand-in (a legacy stub or a hand-built double) that exposes only the few
        # summary attributes a helper reads. Promoting it is impossible -- there are no rows to
        # group -- so it is passed through untouched, preserving the long-standing contract
        # that these helpers degrade gracefully rather than raising. Pinned by
        # test_report_count_units.py::test_findings_summary_survives_a_reportdata_without_the_new_methods.
        return value
    return build_report_model(value)


def _remediation_plan_story(model, styles, colors, mm):
    """Remediation Plan: existing findings, bucketed by their existing severity.

    Contains no invented guidance. Each row states the finding id, title, severity, business
    risk and how many locations it affects -- all values already computed elsewhere. Where the
    pipeline HAS produced remediation text it is surfaced in the finding's own block, verbatim;
    it is never synthesised here."""
    from reportlab.platypus import KeepTogether, Paragraph, Spacer

    # Step 4: the ACTIVE-only grouping now comes from the model, which performed the same
    # _finding_groups call at assembly time. Identical input, identical grouping.
    by_sev: dict[str, list] = {
        bucket.severity: list(bucket.findings) for bucket in model.remediation_buckets
    }

    out = [
        Paragraph(
            "Findings are grouped into delivery priorities by their assessed severity. "
            "Priorities describe suggested sequencing only; they do not alter any finding's "
            "severity, CVSS, business risk or the security score.",
            styles["Small"],
        ),
        Spacer(1, 3 * mm),
    ]

    any_rows = False
    for label, severity, guidance in _REMEDIATION_BUCKETS:
        bucket = by_sev.get(severity, [])
        if not bucket:
            continue
        any_rows = True
        rows = []
        for f in sorted(bucket, key=lambda x: -(x.business_risk or -1.0)):
            risk = f"{f.business_risk:.1f}" if f.business_risk is not None else "N/A"
            locs = f.location_count or f.occurrence_count
            rows.append((
                f.finding_id or "N/A",
                Paragraph(
                    f"{_esc(f.title)}<br/><font size=7.5 color='{B.MUTED}'>"
                    f"business risk {risk} · {locs} location(s)</font>",
                    styles["Cell"],
                ),
            ))
        block = [
            Paragraph(f"{label} — {len(bucket)} finding(s)", styles["SubSection"]),
            Paragraph(guidance, styles["Small"]),
            Spacer(1, 1.5 * mm),
            _card(rows, styles, colors, mm, accent=B.severity_color(severity), label_w=34),
            Spacer(1, 4 * mm),
        ]
        # Keep a bucket heading with at least the start of its table, so a priority label is
        # never stranded alone at the foot of a page.
        out.append(KeepTogether(block[:4]))
        out.append(block[4])

    if not any_rows:
        out.append(Paragraph("No active findings require remediation.", styles["Body"]))
    return out


def _evidence_story(model, styles, colors, mm):
    """Evidence & Screenshots: the artifacts actually stored for these findings.

    Lists only what the evidence store holds -- nothing is fabricated, and a finding with no
    artifacts is simply not listed. Screenshots are embedded where they can be fetched and
    decoded; a screenshot that cannot be retrieved is skipped rather than shown as a broken
    placeholder."""
    from reportlab.platypus import KeepTogether, Paragraph, Spacer

    out: list = []
    listed = 0
    # Step 4: findings come from the model, which grouped them at assembly time.
    for g in model.findings:
        # `evidence_items` (the untyped (type, uri) pairs), NOT a projection of
        # `evidence_records`: a row predating Phase 3.2 carries evidence_items but no typed
        # record, and deriving from the records alone silently dropped those artifacts from
        # this section. The model exposes the same field the group dict did.
        items = list(g.evidence_items)
        shots = list(g.screenshots)
        if not items and not shots:
            continue
        listed += 1
        rows = [
            ("Finding ID", g.finding_id or "N/A"),
            ("Title", g.title),
            ("Asset", g.assets[0] if g.assets else "N/A"),
        ]
        loc = g.locations[0] if g.locations else "N/A"
        rows.append(("Endpoint", Paragraph(_esc(loc), styles["Endpoint"])))
        # Phase 3.2: when integrity metadata is available, each artifact line carries its
        # artifact id, capture timestamp and digest. `_by_uri` keeps the existing per-type
        # iteration order (so this section's layout is unchanged) while enriching each row.
        _by_uri = {r.storage_uri: r for r in g.evidence}
        for etype, uri in items:
            record = _by_uri.get(uri)
            detail = _esc(uri)
            if record is not None:
                detail += (
                    f"<br/><font size=7>{_esc(record.artifact_id)} · captured "
                    f"{_esc(record.captured_label())} · {_esc(record.checksum_short())}</font>"
                )
            rows.append((_evidence_type_label(etype), Paragraph(detail, styles["Endpoint"])))
        # Screenshots are INDEXED here, not re-embedded: the image itself is already shown in
        # the finding's own block, and fetching it a second time would double the object-store
        # reads for every screenshot in the report. This section states that visual evidence
        # exists, its checksum, and which finding it belongs to.
        for _uri, checksum in shots:
            record = _by_uri.get(_uri)
            captured = f" · captured {record.captured_label()}" if record is not None else ""
            rows.append(
                (
                    "Screenshot",
                    f"captured · sha {str(checksum)[:12]}{captured} (shown with the finding)",
                )
            )
        out.append(
            KeepTogether([
                _card(rows, styles, colors, mm, accent=B.severity_color(g.severity)),
                Spacer(1, 2 * mm),
            ])
        )

    if not listed:
        out.append(
            Paragraph(
                "No stored evidence artifacts are associated with the findings in this report.",
                styles["Body"],
            )
        )
    return out


def _assessment_scope_story(model, styles, colors, mm):
    """Assessment Scope: what this report actually covers (R-03).

    One concise block shared by BOTH reports, so a scan-scoped document can never state its
    scope one way in the Executive and another way in the Technical. Every value is read from
    ReportData.scope_scans -- the authorised `scans` rows themselves -- so nothing is invented:
    a scan with no recorded timestamp simply contributes no date, and an unknown target is
    omitted rather than guessed.

    Prints a single sentence for the project-wide case (the default contract) instead of an
    empty section, and a compact per-scan table when the report was narrowed."""
    from reportlab.platypus import Paragraph, Spacer, Table

    if not model.scope.is_scoped:
        return [
            Paragraph(
                "This report covers <b>all findings recorded for this project</b>, across every "
                "scan. No specific scan scope was requested.",
                styles["Body"],
            ),
            Spacer(1, 3 * mm),
        ]

    scans = list(model.scope.scans)
    started, completed = model.scope.window_start, model.scope.window_end
    targets = list(model.scope.targets)

    parts = [
        Paragraph(
            f"This report is scoped to <b>{len(scans)} selected scan(s)</b>. Findings from "
            "other scans in this project are deliberately excluded, and every figure in this "
            "document — including the security score — is derived from the selected scans only.",
            styles["Body"],
        )
    ]
    if targets:
        parts.append(
            Paragraph(f"Target(s) assessed: {_esc(', '.join(targets))}", styles["Small"])
        )
    if started or completed:
        window = (
            f"{started:%Y-%m-%d %H:%M UTC}" if started else "not recorded"
        ) + " to " + (f"{completed:%Y-%m-%d %H:%M UTC}" if completed else "not recorded")
        parts.append(Paragraph(f"Assessment window: {window}", styles["Small"]))
    parts.append(Spacer(1, 2 * mm))

    rows = [["Scan", "Type", "Status", "Completed"]]
    for scan in scans:
        # The scan's own id, shortened for quotability in the SAME MBS- form the report already
        # uses for findings -- not a new identity system, and not a raw database UUID.
        short = str(scan.get("id", "")).replace("-", "").upper()[:8]
        rows.append([
            f"MBS-{short}" if short else "N/A",
            _esc(scan.get("scan_type") or "N/A"),
            _esc(scan.get("status") or "N/A"),
            f"{scan['completed_at']:%Y-%m-%d %H:%M}" if scan.get("completed_at") else "N/A",
        ])
    table = Table(rows, colWidths=[38 * mm, 42 * mm, 32 * mm, 45 * mm])
    table.setStyle(_table_style(colors))
    parts.append(table)
    parts.append(Spacer(1, 3 * mm))
    return parts


# Phase 4.2: how many affected locations a single finding block prints inline before the rest
# are deferred to the Appendix location index. Chosen so a normal finding (1-20 locations) is
# entirely unaffected while a pathological one (hundreds of URLs from one template) cannot bury
# the description, evidence and remediation underneath it. NOT a data filter -- the full set is
# always in the report; see the Affected Location(s) block and _location_index_story.
_MAX_LOCATIONS_SHOWN = 60


def _location_index_story(model, styles, colors, mm):
    """Appendix location index: every affected location for findings that were capped inline.

    Phase 4.2. This is what makes the inline display cap a LAYOUT decision rather than a
    truncation: any location not printed under its finding is printed here, in full, grouped by
    the finding it belongs to. Findings whose locations all fitted inline are not repeated --
    listing them twice would add pages without adding information.

    Reads the SAME `matched_ats` the finding block reads; nothing is filtered, re-derived or
    summarised."""
    from reportlab.platypus import Paragraph, Spacer

    capped = [g for g in model.findings if g.location_count > _MAX_LOCATIONS_SHOWN]
    if not capped:
        return []

    out = [
        Paragraph("Location index", styles["SubSection"]),
        Paragraph(
            f"{len(capped)} finding(s) affect more than {_MAX_LOCATIONS_SHOWN} locations. Their "
            "affected locations are listed in full below; the finding blocks above show the "
            f"first {_MAX_LOCATIONS_SHOWN} of each for readability. No location is omitted "
            "from this report.",
            styles["Small"],
        ),
        Spacer(1, 2 * mm),
    ]
    for g in capped:
        locations = list(g.locations)
        # Only the locations the finding block could not show. Re-printing the first
        # _MAX_LOCATIONS_SHOWN would pay pages for information the reader already has two
        # sections earlier; the heading states the full total so the set is still accountable.
        #
        # The remainder is taken in the SAME order the finding block prints -- grouped by host
        # via _group_locations_by_host -- not from the raw sorted list. The two orderings differ
        # (sorted puts `/path/102` before `/path/2`), so slicing the sorted list would defer a
        # DIFFERENT 60 than the block actually showed: every location would still appear exactly
        # once overall, but a reader following a specific URL could find it in the appendix when
        # the block had already listed it. Sharing one ordering makes "the ones not listed
        # above" literally true.
        ordered = [loc for _host, paths in _group_locations_by_host(locations) for loc in paths]
        remainder = ordered[_MAX_LOCATIONS_SHOWN:]
        out.append(
            Paragraph(
                f"{_esc(g.finding_id or 'N/A')} — {_esc(g.title)}: "
                f"{len(locations)} affected location(s), of which the "
                f"{len(remainder)} not listed under the finding are given here.",
                styles["Label"],
            )
        )
        for loc in remainder:
            out.append(Paragraph(f"• {_esc(loc)}", styles["Mono"]))
        out.append(Spacer(1, 2 * mm))
    return out


def _posture_panel(model, styles, colors, mm):
    """Executive "at a glance" panel: the five numbers a decision-maker actually needs.

    Phase 4.3. Section 1 previously opened with a 921-character run of prose in which the score,
    both count units, the score-impacting subset and the scoring caveat were all buried in
    continuous sentences -- and the same "N unique issues across M locations" phrase appeared
    THREE times on one page. An executive had to read every word to extract five figures.

    PRESENTATION ONLY. Every value is read from ReportData's existing canonical accessors; not
    one is recomputed here, and there is no second scoring model:
      * security_score / _score_band  -- the ONE scoring and banding contract (R-04: "Fair")
      * active_issue_count / active_vulns -- R-01's two units, labelled as such
      * scorable_issue_count          -- the score's own population (scoring.group_issues)
      * affected_assets / affected_endpoint_count -- the active+scorable population
    """
    from reportlab.platypus import Paragraph, Table, TableStyle

    band = model.score_band
    cells = [
        ("SECURITY SCORE", f"{model.security_score}/100", band, B.score_band_color(band)),
        ("UNIQUE ISSUES", str(model.counts.active_issues),
         f"{model.counts.active_findings} recorded finding(s)", B.INK),
        ("AFFECTING THE SCORE", str(model.counts.scorable_issues),
         "excludes informational", B.INK),
        ("AFFECTED ASSETS", str(model.exposure.asset_count),
         f"{model.exposure.endpoint_count} endpoint(s)", B.INK),
    ]
    row = [
        Paragraph(
            f"<font size=6 color='{B.MUTED}'>{_esc(caption)}</font><br/>"
            f"<font size=15 color='{ink}'><b>{_esc(value)}</b></font><br/>"
            f"<font size=6.5 color='{B.MUTED}'>{_esc(sub)}</font>",
            styles["Cell"],
        )
        for caption, value, sub, ink in cells
    ]
    table = Table([row], colWidths=[42.5 * mm] * 4, hAlign="LEFT")
    table.setStyle(
        TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(B.PAPER_TINT)),
            ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor(B.RULE)),
            ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor(B.RULE)),
            ("LINEBEFORE", (0, 0), (0, -1), 2.4, colors.HexColor(B.score_band_color(band))),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ])
    )
    return table


def _severity_bar(model, styles, colors, mm):
    """Active severity distribution as a proportional bar, in the report's severity palette.

    Phase 4.3. The severity table remains in Findings Summary as the authoritative record; this
    is a shape a reader can take in at a glance before reading it. The widths are the ACTIVE
    per-severity counts ReportData already computes -- nothing is recomputed or reweighted, and
    the counts are RECORDED FINDINGS, the same unit the table states (R-01)."""
    from reportlab.platypus import Paragraph, Table, TableStyle

    counts = model.severity.active or {}
    order = [s for s in ("critical", "high", "medium", "low", "info") if counts.get(s, 0) > 0]
    total = sum(counts.get(s, 0) for s in order)
    if not total:
        return [Paragraph("No active findings to distribute by severity.", styles["Small"])]

    widths, labels, style = [], [], [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    for idx, sev in enumerate(order):
        n = counts.get(sev, 0)
        # Minimum 12mm so a single low-count band stays readable rather than collapsing to a
        # sliver; the printed number beside it is always the true count.
        widths.append(max(12.0, 170.0 * n / total))
        labels.append(
            Paragraph(
                f"<font size=8 color='#ffffff'><b>{n}</b></font>", styles["Cell"]
            )
        )
        style.append(("BACKGROUND", (idx, 0), (idx, 0), colors.HexColor(B.severity_color(sev))))

    scale = 170.0 / sum(widths)
    bar = Table([labels], colWidths=[w * scale * mm for w in widths], hAlign="LEFT")
    bar.setStyle(TableStyle(style))

    legend = " · ".join(
        f"<font color='{B.severity_color(s)}'>&#9632;</font> {s.capitalize()} {counts.get(s, 0)}"
        for s in order
    )
    return [
        bar,
        Paragraph(
            f"<font size=7>{legend}</font>  <font size=7 color='{B.MUTED}'>"
            f"— active recorded findings by severity ({total} total)</font>",
            styles["Small"],
        ),
    ]


def _key_themes(model) -> list[tuple[str, int, int]]:
    """(weakness class, distinct active issues, recorded findings), worst-first.

    Phase 4.3. Answers the question a Key Risks table cannot: "what KINDS of problem does this
    estate have?" -- three SQL-injection templates and two XSS templates is a different
    management conversation from five unrelated one-offs.

    Classes come from narrative.classify_weakness_row, the SAME classifier the Technical
    report's per-finding prose uses, so the two documents cannot name a weakness differently.
    Issue identity is scoring.issue_key and the population is scoring.is_scorable -- the score's
    own population -- so this cannot describe findings the score ignores. Nothing new is
    derived."""
    model = _as_model(model)
    # Step 4: read the model's FINDINGS (already grouped by scoring.issue_key) rather than raw
    # rows. `_key_themes` is report-level AGGREGATION, so it belongs here; the weakness CLASS is
    # still decided by narrative.classify_weakness_row and the scorable population is still
    # scoring.is_scorable -- neither domain algorithm is duplicated.
    from apps.api.modules.reports.scoring import is_scorable

    themes: dict[str, tuple[set[str], int]] = {}
    for f in model.findings:
        if not is_scorable(f):
            continue
        name = N.classify_weakness_row(f).name
        keys, occurrences = themes.get(name, (set(), 0))
        themes[name] = (keys | {f.issue_key}, occurrences + f.occurrence_count)
    return sorted(
        ((name, len(keys), occ) for name, (keys, occ) in themes.items()),
        key=lambda t: (-t[1], -t[2], t[0]),
    )


def _recommendations(model) -> list[tuple[str, str]]:
    """(priority, action) pairs derived from what the assessment ACTUALLY found.

    Phase 4.3. The Executive report previously ended without a single recommendation, so a
    manager was told what was wrong and nothing about what to do. Every line below is a
    restatement of a figure already in this report -- the severity buckets the Technical
    Remediation Plan already uses (_REMEDIATION_BUCKETS), the verification tally, and the
    compliance population -- expressed as an action.

    IT INVENTS NOTHING. No severity, priority, score or finding is created, re-ranked or
    re-weighted; a bucket with no findings produces no line. The priority vocabulary is
    _REMEDIATION_BUCKETS', so the Executive and Technical reports sequence work identically."""
    model = _as_model(model)
    out: list[tuple[str, str]] = []
    counts = model.severity.active or {}

    for label, severity, _guidance in _REMEDIATION_BUCKETS:
        n = counts.get(severity, 0)
        if not n:
            continue
        # Step 4: distinct ACTIVE issues of this severity, taken from the model's active
        # grouping. That grouping partitions by scoring.issue_key, so counting its entries is
        # the same number the previous set-comprehension over raw rows produced.
        issues = sum(
            1 for f in model.active_findings if (f.severity or "").lower() == severity
        )
        out.append((
            label,
            f"Remediate the {issues} {severity}-severity issue(s) "
            f"({n} recorded finding(s)). {_guidance}",
        ))

    ver = model.verification
    unproven = ver.unproven
    if unproven:
        out.append((
            "Validation",
            f"Manually validate the {unproven} finding(s) that are not independently "
            "confirmed, so remediation effort is spent on demonstrated problems first.",
        ))

    frameworks = [f.framework for f in model.compliance]
    if frameworks:
        names = ", ".join(framework_name(fw) for fw in frameworks)
        out.append((
            "Compliance",
            f"Review the controls mapped from current findings in {names}. These are "
            "finding-derived mappings, not an audit or a statement of certification.",
        ))
    return out


def _issue_key_of(row) -> str:
    """Local alias for scoring.issue_key, imported at call time to keep this module's import
    graph unchanged. Identity is NOT re-derived -- it is the canonical function."""
    from apps.api.modules.reports.scoring import issue_key

    return issue_key(row)


def _assurance_chips(g, styles, colors, mm):
    """The three ASSURANCE axes as separate, visually distinct chips (Phase 4.1).

    THE PROBLEM THIS SOLVES
    -----------------------
    Verification and confidence were collapsed into ONE plain-text fact-card row --
    "Partially Verified · Low confidence" -- rendered in the same grey as Status, Asset and
    Matcher. Beside a bold CVSS 9.8 and Business risk 10.0, the two numbers carried all the
    visual authority and the qualifier that should temper them was the quietest line on the
    page. A reader could reasonably take a PARTIALLY VERIFIED finding for confirmed
    exploitation, which is exactly the misreading the verification classifier exists to prevent.

    THREE AXES, NEVER MERGED
    ------------------------
      * Verification -- was it demonstrated?  (verification.py, evidence-derived)
      * Confidence   -- how much is the signal worth?  (verification.py, independent of the above)
      * Evidence     -- what artefacts exist?  (a COUNT, not a judgement)

    They are rendered as three separate chips with three separate palettes precisely so they
    cannot be read as one escalating "security status". In particular the evidence chip states
    only that artefacts EXIST -- it never implies they prove anything, because "evidence
    present" and "evidence verified" are different claims (an unverified finding can have a
    captured log; a verified one is the only state backed by two independent artefact kinds).

    PRESENTATION ONLY. Every value is read from the group exactly as the upstream classifiers
    produced it. Nothing here derives, re-weights or alters verification, confidence, severity,
    CVSS, risk or the security score.
    """
    from reportlab.platypus import Paragraph, Table, TableStyle

    state = (g.get("verification") or UNVERIFIED)
    level = (g.get("confidence") or CONFIDENCE_MEDIUM)

    # Evidence availability: a COUNT of stored artefacts, stated as a fact. Uses the Phase 3.2
    # records when present and falls back to the older lists, so a legacy group still renders.
    records = g.get("evidence_records") or []
    artefact_count = len(records) if records else len(
        g.get("evidence_items") or g.get("evidence_uris") or []
    )
    shots = len(g.get("screenshots") or [])
    if artefact_count:
        evidence_text = f"{artefact_count} artefact(s)"
        if shots:
            evidence_text += f" · {shots} screenshot(s)"
        evidence_ink, evidence_fill = B.INK, B.BAND
    else:
        evidence_text = "No artefacts"
        evidence_ink, evidence_fill = B.MUTED, B.BAND

    chips = [
        ("VERIFICATION", verification_label(state),
         B.verification_color(state), B.verification_bg(state)),
        ("CONFIDENCE", confidence_label(level), B.confidence_color(level), B.BAND),
        ("EVIDENCE", evidence_text, evidence_ink, evidence_fill),
    ]

    cells = []
    for caption, value, ink, fill in chips:
        cells.append(
            Paragraph(
                f"<font size=6 color='{B.MUTED}'>{_esc(caption)}</font><br/>"
                f"<font size=9 color='{ink}'><b>{_esc(value)}</b></font>",
                styles["Cell"],
            )
        )

    table = Table([cells], colWidths=[56 * mm, 40 * mm, 56 * mm], hAlign="LEFT")
    style = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor(B.RULE)),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor(B.RULE)),
    ]
    # Each chip gets its own fill, so the three axes read as three separate objects rather
    # than one banded row.
    for idx, (_c, _v, _ink, fill) in enumerate(chips):
        style.append(("BACKGROUND", (idx, 0), (idx, 0), colors.HexColor(fill)))
    table.setStyle(TableStyle(style))
    return table


def _assurance_caption(g) -> str:
    """One sentence under the chips naming what the three axes mean and, critically, what the
    combination does NOT mean.

    The wording is GATED on the actual verification state: only a VERIFIED finding is described
    with confirmatory language, and a finding carrying artefacts but not proof says so
    explicitly. It restates the classifiers' own position (see verification.verification_note);
    it never re-derives it."""
    state = (g.get("verification") or UNVERIFIED)
    records = g.get("evidence_records") or []
    has_artefacts = bool(records or g.get("evidence_items") or g.get("evidence_uris")
                         or g.get("screenshots"))

    if state == VERIFIED:
        base = (
            "Verification, confidence and evidence are three separate measures. This finding "
            "was corroborated by captured evidence from two independent directions."
        )
    elif state == PARTIALLY_VERIFIED:
        base = (
            "Verification, confidence and evidence are three separate measures. Supporting "
            "artefacts were captured, but exploitation was NOT independently demonstrated — "
            "this is not a confirmed compromise."
        )
    else:
        base = (
            "Verification, confidence and evidence are three separate measures. This is a "
            "scanner-detected condition that has NOT been demonstrated and requires manual "
            "validation."
        )

    if has_artefacts and state != VERIFIED:
        base += (
            " The presence of stored artefacts records what was captured; it is not itself "
            "proof of exploitation."
        )
    # Deliberately phrased WITHOUT the literal words "Severity" and "CVSS": those are fact-card
    # value labels, and the block's de-duplication contract (test_report_narrative.py:393) is
    # that each assessed value is labelled exactly once inside a finding block. Repeating the
    # label in prose would make a reader -- and that test -- see the value stated twice. The
    # point still lands, and the two figures sit directly above.
    base += (
        " Technical impact ratings above describe potential consequence and are independent "
        "of all three measures: they are not reduced when a finding is unverified."
    )
    return base


def _evidence_manifest_story(model, styles, colors, mm):
    """Appendix evidence manifest: one row per stored artifact, with its integrity metadata.

    Phase 3.2. The per-finding Evidence blocks show a finding's own artifacts; this is the
    COMPLETE inventory in one place -- artifact id, type, the finding it belongs to, capture
    timestamp and SHA-256 digest -- so a reviewer can confirm the evidence set is complete and
    re-verify any artifact without reading the whole document.

    Screenshots are INCLUDED here (unlike the per-finding split, which exists for layout), so
    the manifest is the full record of what the evidence store holds for this report.

    Every value is read from the stored `evidence` row; nothing is computed, and an artifact
    with no recorded checksum or timestamp is listed as "not recorded" rather than omitted --
    an incomplete record must be visible, not silently dropped."""
    model = _as_model(model)
    from reportlab.platypus import KeepTogether, Paragraph, Spacer, Table

    # (finding_id, record) in finding order, then the group's own artifact order, so the
    # manifest is deterministic for identical data.
    rows: list[tuple[str, EvidenceRecord]] = []
    seen: set = set()
    for g in model.findings:
        finding_id = g.finding_id or "N/A"
        for record in g.evidence:
            # One artifact can be linked to several findings; list it once per finding it
            # evidences, but never twice for the same pair.
            key = (finding_id, record.storage_uri, record.checksum)
            if key in seen:
                continue
            seen.add(key)
            rows.append((finding_id, record))

    if not rows:
        return [
            Paragraph(
                "No evidence artifacts are recorded for the findings in this report.",
                styles["Small"],
            )
        ]

    verified = sum(1 for _fid, r in rows if r.has_checksum)
    out = [
        Paragraph(
            f"{len(rows)} artifact reference(s) across the findings in this report; "
            f"{verified} carry a recorded SHA-256 digest. "
            + N.EVIDENCE_INTEGRITY_NOTE,
            styles["Small"],
        ),
        Spacer(1, 2 * mm),
    ]

    table_rows = [["Artifact", "Finding", "Type", "Captured (UTC)", "SHA-256"]]
    for finding_id, record in rows:
        table_rows.append([
            _esc(record.artifact_id),
            _esc(finding_id),
            _esc(_evidence_type_label(record.evidence_type)),
            _esc(record.captured_label()),
            Paragraph(
                f"<font size=6.5>{_esc((record.checksum or '').strip().lower())}</font>"
                if record.has_checksum
                else "<font size=6.5>not recorded</font>",
                styles["Cell"],
            ),
        ])
    table = Table(table_rows, colWidths=[24 * mm, 26 * mm, 28 * mm, 36 * mm, 56 * mm])
    table.setStyle(_table_style(colors))
    out.append(KeepTogether([table]) if len(table_rows) <= 12 else table)
    out.append(Spacer(1, 3 * mm))
    return out


def _compliance_cards(model, styles, colors, mm):
    """Compliance coverage as one card per framework, listing its mapped controls and the
    findings that caused each control to appear.

    R-02. The population comes from ReportData.compliance_coverage(), which filters on
    scoring.is_scorable -- the SAME predicate the Security Score and the MITRE tally use. This
    function previously walked `data.vulns` unfiltered, so a FIXED or FALSE-POSITIVE finding
    still produced a control card; see the docstring on compliance_coverage for why that is a
    misstatement rather than a display quirk.

    The catalogue and the CWE -> control mapping semantics are untouched: this reads the same
    stored mappings, from a narrower and correct set of findings, and additionally carries the
    contributing finding IDs so the reader can answer "which findings caused this control to
    appear?" rather than being given a bare count."""
    from reportlab.platypus import KeepTogether, Paragraph, Spacer

    coverage = [(f.framework, [(c.control_id, c.description, list(c.finding_ids)) for c in f.controls])
                for f in model.compliance]

    if not coverage:
        # Deliberately says "current findings": the project may well have HAD mapped findings
        # that are now fixed, and claiming a blanket absence would misdescribe the record.
        return [
            Paragraph(
                "No current findings map to compliance controls. Findings that are fixed, "
                "accepted as risk, or dismissed as false positives do not contribute to "
                "coverage, and informational or detection-only findings carry no control "
                "mapping.",
                styles["Body"],
            )
        ]

    out = [
        Paragraph(
            # The wording boundary required by the brief: this is finding-derived mapping, NOT
            # an assessment of compliance with a framework and NOT certification.
            "Controls below are mapped from the findings in this assessment via each finding's "
            "CWE classification. This is finding-based coverage only: it indicates which "
            "controls the observed weaknesses relate to. It is NOT a compliance assessment, an "
            "audit, or a statement of certification against any framework, and an unlisted "
            "control is not evidence of conformance. Only current findings contribute — "
            "fixed, accepted-risk, false-positive, informational and detection-only findings "
            # "&" must be written as the entity: this string goes through a reportlab
            # Paragraph, which parses bare markup, and a raw "&" renders as "ATT&CK;".
            "are excluded, matching the security score and the ATT&amp;CK coverage.",
            styles["Small"],
        ),
        Spacer(1, 3 * mm),
    ]
    for framework, controls in coverage:
        rows = []
        for control_id, desc, finding_ids in controls:
            shown = ", ".join(finding_ids[:6])
            more = f" (+{len(finding_ids) - 6} more)" if len(finding_ids) > 6 else ""
            rows.append((
                control_id,
                Paragraph(
                    f"{_esc(desc or '—')}<br/><font size=7.5 color='{B.MUTED}'>"
                    f"Mapped from {len(finding_ids)} finding(s): {_esc(shown)}{_esc(more)}"
                    "</font>",
                    styles["Cell"],
                ),
            ))
        out.append(
            KeepTogether([
                Paragraph(f"{framework_name(framework)} — {len(controls)} control(s) mapped",
                          styles["SubSection"]),
                Spacer(1, 1.5 * mm),
                _card(rows, styles, colors, mm, accent=B.CYAN, label_w=34),
                Spacer(1, 4 * mm),
            ])
        )
    return out


def _attack_cards(model, styles, colors, mm):
    """MITRE ATT&CK coverage grouped by tactic. Counts and mappings are unchanged."""
    from reportlab.platypus import KeepTogether, Paragraph, Spacer

    if not model.attack:
        return [Paragraph("No active issues mapped to ATT&amp;CK techniques.", styles["Body"])]

    by_tactic: dict[str, list[tuple[str, str, int]]] = {}
    for t in model.attack:
        tactic, tech_id, tech_name, count = t.tactic, t.technique_id, t.technique_name, t.issue_count
        by_tactic.setdefault(tactic, []).append((tech_id, tech_name, count))

    out = []
    for tactic in sorted(by_tactic):
        rows = [
            (tech_id, f"{tech_name} — {count} issue(s)")
            for tech_id, tech_name, count in sorted(by_tactic[tactic])
        ]
        out.append(
            KeepTogether([
                Paragraph(f"{_esc(tactic)} — {len(rows)} technique(s)", styles["SubSection"]),
                Spacer(1, 1.5 * mm),
                _card(rows, styles, colors, mm, accent=B.VIOLET, label_w=30),
                Spacer(1, 4 * mm),
            ])
        )
    return out


def _technical_metadata_rows(g) -> list[tuple[str, str]]:
    """(label, value) rows for the Technical Report's metadata block, in a fixed order.

    P2-4. Every value is taken VERBATIM from the group; missing values become "N/A" so the
    block has a stable shape and a reader can tell "not recorded" from "not applicable".
    Optional fields (Category, CVE) are omitted entirely when absent rather than padded with
    N/A, so the block does not grow noise for findings that never had them.

    Nothing here is derived, inferred or scored -- it is provenance, not assessment."""
    rows: list[tuple[str, str]] = [
        # Tool WITH its recorded version where one exists ("nuclei 3.2.9"), falling back to the
        # bare tool list when no version was recorded -- a finding is only reproducible against
        # the tool release that produced it.
        ("Tool", ", ".join(g.get("tool_versions") or g.get("tools") or []) or "N/A"),
        ("Template", g.get("template_id") or "N/A"),
        ("Matcher", ", ".join(g.get("matcher_names") or []) or "N/A"),
        ("Status", g.get("status") or "N/A"),
    ]
    if g.get("category"):
        rows.append(("Category", g["category"]))
    # CVE is not a column on `vulnerabilities` (see classification._recover_cve); it survives
    # only inside the template_id/title. Shown ONLY when actually found -- never fabricated.
    cve = _recover_cve(g.get("template_id"), g.get("title"))
    if cve:
        rows.append(("CVE", cve.upper()))
    return rows


def _location_host(location: str) -> str:
    """Host[:port] of a URL-ish location, or "" when it has no recognisable authority.

    Deliberately string-based and total: report locations are whatever the scanner recorded
    (`matched_at`), which is usually a URL but may be a bare host, a host:port, or something
    unparseable. Anything without a recognisable authority returns "" and is rendered ungrouped
    -- never dropped, never guessed at. The PORT is kept as part of the host because
    `example.com:8443` is a different service from `example.com:443`."""
    text = (location or "").strip()
    if not text:
        return ""
    if "://" in text:
        text = text.split("://", 1)[1]
    # Strip path/query/fragment; what remains is the authority.
    for sep in ("/", "?", "#"):
        text = text.split(sep, 1)[0]
    # Drop any userinfo prefix.
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    return text


def _group_locations_by_host(locations) -> list[tuple[str, list[str]]]:
    """[(host, [location, ...])] preserving the caller's ordering within each host.

    Presentation only: every input location appears exactly once in the output, so this can
    neither hide nor merge a location. Hosts are ordered by first appearance, which -- because
    `matched_ats` arrives already sorted -- is deterministic. Locations with no recognisable
    host group under "" and render without a host heading."""
    grouped: dict[str, list[str]] = {}
    for loc in locations:
        grouped.setdefault(_location_host(loc), []).append(loc)
    return list(grouped.items())


# Strength ordering for aggregating a GROUP's verification/confidence from its members.
# Verification aggregates by max (any demonstrated location proves the issue); confidence
# aggregates by min (the group is only as trustworthy as its weakest signal).
_VERIFICATION_RANK = {UNVERIFIED: 1, PARTIALLY_VERIFIED: 2, VERIFIED: 3}
_CONFIDENCE_RANK = {CONFIDENCE_LOW: 1, CONFIDENCE_MEDIUM: 2, CONFIDENCE_HIGH: 3}

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
        # scoring.issue_key -- the CANONICAL issue identity, shared with the Security Score and
        # _finding_groups. This used to be a second, local implementation using a `tid:` prefix
        # instead of `template:`. The partition it produced was provably identical (both
        # branches are prefix-disjoint from `title:`), so this is a de-duplication, not a
        # behaviour change -- but it removes the risk of the two drifting apart.
        buckets.setdefault(issue_key(v), []).append(v)

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
    for key, members in buckets.items():
        rep = min(members, key=_member_sort_key)  # highest-risk member (min of negated keys)
        cvss_values = [m.cvss_score for m in members if m.cvss_score is not None]
        # None only when EVERY member is unscored; a single scored member still yields a real
        # max. Never coerced to 0.0 -- "not scored" and "scored zero" stay distinct, exactly as
        # they do for CVSS everywhere else in the report.
        risk_values = [m.final_risk_score for m in members if m.final_risk_score is not None]
        groups.append(
            {
                "title": rep.title,
                # P2-1: the group's canonical identity (scoring.issue_key), carried so the sort
                # below has a UNIQUE terminal tie-breaker. Two DIFFERENT templates can share a
                # title, and title was previously the last key -- so genuinely tied groups fell
                # back on Python's list order, which follows dict insertion, i.e. the order rows
                # arrived from the database. Re-running the same report could then emit a
                # different Top Risks order. issue_key is unique per bucket by construction, so
                # the full key is now a total order. Display is unchanged: this is a sort input,
                # never rendered.
                "issue_key": key,
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
    # P2-1: risk first, then CVSS, then severity, then title, then the UNIQUE issue_key. The
    # first four express actual risk (unchanged semantics -- no new scoring model, no value is
    # recomputed here); the fifth exists solely to make the order TOTAL, so equal-risk groups
    # cannot be reordered by database row order between two renderings of the same data.
    groups.sort(
        key=lambda g: (
            -(g["max_risk"] if g["max_risk"] is not None else -1.0),
            -(g["max_cvss"] if g["max_cvss"] is not None else -1.0),
            -_SEVERITY_RANK.get(g["severity"], 0),
            g["title"] or "",
            g["issue_key"],
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
        # ISSUE-LEVEL RISK CONTRACT (shared with _top_risk_groups / the Executive report).
        #
        # The representative is the member carrying the HIGHEST BUSINESS RISK, then the
        # highest severity, then the highest CVSS. Risk leads because the Executive "Top
        # risks" table ranks and prints the group's max final_risk_score: when the two
        # reports pick their numbers by different keys they disagree about the same issue.
        #
        # They could disagree by a wide margin, because final_risk_score is CVSS re-weighted
        # by asset criticality (risk/service.py: min(10, cvss * weight), weight 0.5..2.0), so
        # the highest-CVSS member is NOT necessarily the highest-risk one. Real case: one
        # template at two locations, CVSS 9.0 on a low-criticality asset (risk 4.5) and CVSS
        # 5.0 on a critical asset (risk 10.0) -- the Executive printed 10.0 while the
        # Technical block printed 4.5 for the same issue.
        #
        # Selecting a single MEMBER (option A) rather than mixing per-field maxima keeps the
        # block internally coherent: the risk, its rationale, the CVSS and the vector all
        # describe the same observation. A synthesised "max of each field" row would print a
        # rationale that does not explain the number beside it.
        #
        # None sorts below any real value (including 0.0) so a scored member wins, and the
        # None-vs-0.0 distinction is preserved -- nothing is coerced.
        return (
            v.final_risk_score if v.final_risk_score is not None else -1.0,
            _SEVERITY_RANK.get(v.severity, 0),
            v.cvss_score if v.cvss_score is not None else -1.0,
        )

    groups: list[dict] = []
    for key, members in buckets.items():
        # Prefer an ACTIVE member: the Executive table only ever considers active findings, so
        # picking a fixed/false-positive member here would reintroduce the disagreement from
        # the other direction. Groups with no active member (a fully remediated issue, which
        # the Technical report still lists as the full record) fall back to all members.
        active_members = [m for m in members if m.status in _ACTIVE_STATUSES]
        rep = max(active_members or members, key=_rep_key)

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

        # P2-3: the same artifacts WITH their evidence_type, deduped on the (type, uri) pair and
        # order-stable, exactly as evidence_uris above. Rows that predate this field (or test
        # doubles) simply contribute nothing and the renderer falls back to the untyped list --
        # so evidence is never lost, only better labelled.
        evidence_items: list[tuple[str, str]] = []
        for m in members:
            for item in getattr(m, "evidence_items", None) or []:
                if item not in evidence_items:
                    evidence_items.append(item)

        # Phase 3.2: the same artifacts WITH their integrity metadata (checksum, capture time,
        # artifact id). Deduped on the whole record -- two members that reference the identical
        # stored artifact contribute it once, while genuinely different artifacts stay
        # distinct. Order-stable, so the manifest below is deterministic. Rows built before
        # this field (legacy call site, test double) contribute nothing and the evidence
        # section falls back to the untyped lists exactly as before.
        evidence_records: list = []
        for m in members:
            for record in getattr(m, "evidence_records", None) or []:
                if record not in evidence_records:
                    evidence_records.append(record)

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
                # Stable, quotable id from the representative row's DATABASE identity -- not a
                # loop index, so it survives re-ordering and regeneration (see VulnRow.finding_id).
                "finding_id": getattr(rep, "finding_id", None),
                # The scanner's OWN description text, passed through verbatim. None when the
                # row has none; the block then says so rather than inventing prose.
                "description": getattr(rep, "description", None),
                # ISSUE-LEVEL SEVERITY CONTRACT (shared with _top_risk_groups and
                # scoring.group_issues). Severity is the MAX across the group's members, NOT
                # the representative member's own severity.
                #
                # The representative is chosen by BUSINESS RISK first (see _rep_key), which is
                # the right anchor for the risk/CVSS/rationale shown in the block -- those must
                # all describe one real observation. But severity is a property of the ISSUE,
                # and the other two surfaces already treat it that way: _top_risk_groups uses
                # max(_SEVERITY_RANK) and scoring.group_issues uses max(_severity_rank) to pick
                # the penalty band. Taking the representative's severity here made the Technical
                # report disagree with both whenever the highest-severity member was not the
                # highest-risk one -- e.g. a group holding an UNSCORED critical (risk None) and
                # a scored medium printed "critical" in the Executive Top Risks table and
                # "medium" on the Technical block for the SAME issue_key. That combination is
                # not hypothetical: an active finding with no CVSS has final_risk_score=None by
                # construction (see the comment at the top of _top_risk_groups).
                #
                # Using the max keeps all three surfaces on one definition and is the safe
                # direction: a group containing a critical is reported as critical.
                "severity": max(members, key=lambda m: _SEVERITY_RANK.get(m.severity, 0)).severity,
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
                # Producing tool(s) WITH the version each one actually ran at, e.g.
                # "nuclei 3.2.9". Built from the (tool_name, tool_version) PAIR carried on the
                # same row, never by zipping two independently-sorted lists -- a version must
                # never be printed against a tool that did not report it. A member whose
                # version was not recorded renders as the bare tool name, so an absent version
                # stays visibly absent instead of borrowing a sibling's.
                "tool_versions": sorted({
                    f"{m.tool_name} {v.strip()}"
                    if (v := str(getattr(m, "tool_version", None) or "").strip())
                    else m.tool_name
                    for m in members
                    if getattr(m, "tool_name", None) and m.tool_name != "N/A"
                }),
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
                # Verification/confidence for the whole group (see verification.py). Computed
                # from each row's own fields so it is correct for rows built outside
                # gather_report_data, exactly as `classification` above is.
                #
                # Verification takes the STRONGEST member: if the issue was demonstrated at any
                # one location it IS demonstrated, and reporting it as unverified would
                # understate proven risk. Confidence takes the WEAKEST: it grades how much the
                # signal is worth, so a group containing an inference-based match must not
                # inherit a neighbour's certainty. Neither reads nor alters severity, CVSS,
                # final_risk_score or the security score.
                "verification": max(
                    (classify_verification_row(m)[0] for m in members),
                    key=lambda s: _VERIFICATION_RANK.get(s, 0),
                ),
                "confidence": min(
                    (classify_verification_row(m)[1] for m in members),
                    key=lambda c: _CONFIDENCE_RANK.get(c, 0),
                ),
                "matcher_names": sorted({m.matcher_name for m in members if m.matcher_name}),
                "matched_ats": matched_ats,
                "unlocated_count": unlocated,
                "occurrence_count": len(members),
                # Inventoried asset(s) the group's findings are anchored to, deduped and
                # sorted. Empty when no member carries an asset linkage -- the report then
                # says N/A rather than implying an asset is affected.
                "asset_values": sorted({m.asset_value for m in members if getattr(m, "asset_value", None)}),
                # Remediation guidance from the representative row, VERBATIM. None/empty when
                # the pipeline produced none; never synthesised here.
                "remediation_summary": getattr(rep, "remediation_summary", None),
                # Normalised to list[str] so a group built from a row-like object that still
                # carries a raw string (or a raw JSON list) cannot reach the renderer in a
                # shape it will try to .strip(). See data._normalise_steps.
                "remediation_steps": _normalise_steps(getattr(rep, "remediation_steps", None)),
                "remediation_references": list(getattr(rep, "remediation_references", None) or []),
                "compliance": sorted(compliance),
                "evidence_uris": evidence_uris,
                "evidence_items": evidence_items,
                "evidence_records": evidence_records,
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


# Severity colours come from the SINGLE branding source (_branding.SEVERITY_COLORS) via
# B.severity_color. A second local palette used to live here with different values -- high was
# #b91c1c in Detailed Findings but #c2410c in the Remediation Plan and Evidence sections, so
# one finding was painted two colours depending on which section a reader was looking at.
# Presentation only: severity VALUES are the scanner's and are never derived or altered here.
_BRAND = "#0f172a"


def _score_band(score: int) -> str:
    """Human label for a 0-100 security score. THE canonical band vocabulary.

    Strong (>=90) · Fair (>=70) · Weak (>=40) · Critical (<40).

    These four strings are the contract. They are what every rendered report prints, and
    assessment.service freezes the result into `risk_assessments.score_band` -- an IMMUTABLE,
    client-facing snapshot column -- so a band name is not a free-form label that can be
    reworded later without changing what an already-issued assessment claims.

    R-04: `_branding.SCORE_BAND_COLORS` must therefore be keyed by exactly these strings.
    It previously keyed the 70-89 band as "Moderate", so that band silently fell through to
    MUTED grey; the palette was corrected to "Fair" rather than this function being renamed
    (see the note in _branding.py). `test_score_band_palette.py` asserts the two agree for
    every reachable score, so the mismatch cannot return.

    Thresholds and return values are unchanged by R-04 -- this docstring records the contract
    that already existed."""
    if score >= 90:
        return "Strong"
    if score >= 70:
        return "Fair"
    if score >= 40:
        return "Weak"
    return "Critical"


def _verification_summary(data) -> dict[str, int]:
    """Tally of ACTIVE findings by verification state: {verified, partially_verified, unverified}.

    STEP 4 (Executive clarity). Pure, and derived from the SAME classifier the Technical Report
    uses (verification.classify_verification_row), so the two reports can never disagree about
    how many findings are evidence-backed. It counts findings; it never re-derives, re-weights,
    or influences severity, CVSS, risk or the security score.

    ACTIVE findings only -- the same population the score describes -- so an executive is not
    told about the evidence backing of findings that are already fixed or dismissed."""
    counts = {VERIFIED: 0, PARTIALLY_VERIFIED: 0, UNVERIFIED: 0}
    for v in getattr(data, "vulns", None) or []:
        if getattr(v, "status", None) not in _ACTIVE_STATUSES:
            continue
        state, _ = classify_verification_row(v)
        if state in counts:
            counts[state] += 1
    return counts


def _score_impacting_count(data) -> int:
    """How many ACTIVE findings actually move the security score.

    Delegates to scoring.is_scorable -- the score's OWN predicate -- rather than re-deriving the
    rule, so this number cannot drift from the score it explains. It is the honest answer to
    "you reported N findings but the score only reflects some of them": informational findings
    and detections are reported for visibility and carry no penalty (scoring.py)."""
    from apps.api.modules.reports.scoring import is_scorable

    return sum(1 for v in getattr(data, "vulns", None) or [] if is_scorable(v))


def _issue_occurrence_phrase(issues: int, occurrences: int, *, noun: str = "issue") -> str:
    """The ONE wording both reports use to state an issue count beside its occurrence count.

    R-01. A vulnerability ROW is one occurrence at one location (see the ISSUE COUNTS block in
    data.py), so every summary tally in this file is an OCCURRENCE count while the score, Key
    Risks, Detailed Findings and the MITRE tally all count distinct ISSUES. Both units are
    correct; neither was labelled, which is the whole defect.

    Centralised here so the Executive and Technical reports can never phrase the same
    reconciliation differently. Pure string formatting -- it counts nothing, derives nothing,
    and is handed both numbers by its caller.

    Reads, for 1 issue at 7 locations: "1 unique issue across 7 affected locations".
    When the two are equal the "across N" clause is dropped: "3 unique issues" already says
    everything, and "3 unique issues across 3 affected locations" invites the reader to look
    for a distinction that isn't there."""
    plural = noun if issues == 1 else f"{noun}s"
    head = f"{issues} unique {plural}"
    if occurrences == issues:
        return head
    loc = "affected location" if occurrences == 1 else "affected locations"
    return f"{head} across {occurrences} {loc}"


def _findings_summary(model) -> str:
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
    model = _as_model(model)
    # A stub may expose the legacy ReportData attribute names instead of the model's.
    counts = getattr(model, "counts", None)
    severity = getattr(model, "severity", None)
    active = counts.active_findings if counts else model.active_vulns
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
    active_by_severity = (severity.active if severity else model.active_severity_counts) or None
    if active_by_severity is None:
        _all = severity.all_statuses if severity else model.severity_counts
        non_info_active = sum(_all.get(sev, 0) for sev in severities)
    else:
        non_info_active = sum(active_by_severity.get(sev, 0) for sev in severities)
    noun = "active finding" if active == 1 else "active findings"
    non_info_verb = "is" if non_info_active == 1 else "are"

    # R-01: state the ISSUE unit beside the occurrence unit. `active` above is an OCCURRENCE
    # count (one row = one location); `active_issue_count()` is the distinct-issue count over
    # that same active population -- the number of rows the Executive Key Risks table lists.
    # Stating only the first is what let "7 active findings" sit above a single finding block.
    #
    # Step 4: the count is a required ReportModel field, so the previous getattr guard (for a
    # ReportData predating the method) is no longer reachable and has been removed. The
    # `!= active` test below is retained: when the two units agree there is nothing to
    # reconcile and the clause is correctly omitted.
    active_issues = counts.active_issues if counts else None
    unit_clause = ""
    if active_issues is not None and active_issues != active:
        unit_clause = (
            f" These represent {_issue_occurrence_phrase(active_issues, active)}: one issue "
            "observed at several locations is recorded once per location but remediated once."
        )

    if non_info_active == 0:
        return (
            f"{active} {noun} detected — all informational. Informational findings are "
            "reported for visibility and do not reduce the security score under the current "
            "scoring model, so a score of 100/100 can coexist with informational findings. "
            f"These are detections, not confirmed vulnerabilities.{unit_clause}"
        )
    return (
        f"{active} {noun} detected, of which {non_info_active} {non_info_verb} of low severity or higher "
        "and reduce the security score; informational findings are reported for visibility "
        "but carry no score penalty. Findings are detections, not all confirmed "
        f"vulnerabilities.{unit_clause}"
    )


class _SectionHeading:
    """A section heading that also registers itself with the TOC and the PDF outline.

    ReportLab builds a Table of Contents from `notify('TOCEntry', ...)` calls made by
    flowables as they are laid out -- that is the only way the printed page numbers can be
    the REAL ones. The same hook adds a PDF bookmark, so the document is navigable in a
    viewer's sidebar.

    Implemented as a thin Paragraph subclass created lazily (reportlab is imported inside the
    render functions, so it cannot be subclassed at module import time)."""

    def __new__(cls, text: str, style, level: int = 0, raw_text: str | None = None):
        from reportlab.platypus import Paragraph

        # `text` is markup-escaped for rendering; `raw_text` is the literal human string used
        # for the TOC entry and the PDF bookmark, so neither shows "&amp;".
        raw = raw_text if raw_text is not None else text

        # Phase 4.4: the destination key was `abs(hash(raw))`. Python's str hash is SALTED per
        # process (PYTHONHASHSEED is unset here), so the same section produced a different
        # anchor on every run -- verified: three interpreters gave sec-058a29c0, sec-1eb63aac,
        # sec-36c5ad58 for one heading. Re-rendering an unchanged report therefore rewrote every
        # bookmark target, and no external reference to an anchor could survive.
        #
        # md5 of the heading text is stable across processes, machines and releases. It is used
        # ONLY as a document-internal anchor name -- never as a finding identity, never
        # persisted, and never shown to a reader.
        key = f"sec-{hashlib.md5(raw.encode('utf-8')).hexdigest()[:8]}"

        class _Heading(Paragraph):
            def draw(self):
                super().draw()
                try:
                    self.canv.bookmarkPage(key)
                    self.canv.addOutlineEntry(raw, key, level=level, closed=False)
                except Exception:
                    pass  # navigation is a nicety; never fail a report over it

            def afterFlowable(self):  # pragma: no cover - reportlab calls notify via doc
                pass

        para = _Heading(text, style)
        para._toc_text = raw
        para._toc_level = level
        para._toc_key = key
        return para


class _FindingHeading:
    """A finding title that registers a PDF bookmark and a level-1 TOC entry (Phase 4.4).

    Same mechanism as `_SectionHeading` -- `bookmarkPage` + `addOutlineEntry` on draw, plus the
    `_toc_*` attributes the document's `afterFlowable` forwards to the TableOfContents -- so
    the printed page number is the REAL one discovered during layout, never an estimate.

    The difference is the ANCHOR. A section anchors on a hash of its heading text; a finding
    anchors on its CANONICAL id (`MBS-XXXXXXXX`), which is derived from the vulnerability's
    database identity and is already the report's quotable identifier. That makes the
    destination stable across re-renders and re-orderings, and means no second identity system
    is created for navigation.

    Level 1 keeps findings nested under "4. Detailed Findings" in a viewer's outline sidebar
    rather than flattening them alongside top-level sections."""

    def __new__(cls, text: str, style, *, anchor: str, toc_text: str):
        from reportlab.platypus import Paragraph

        class _Heading(Paragraph):
            def draw(self):
                super().draw()
                try:
                    self.canv.bookmarkPage(anchor)
                    self.canv.addOutlineEntry(toc_text, anchor, level=1, closed=False)
                except Exception:
                    pass  # navigation is a nicety; never fail a report over it

        para = _Heading(text, style)
        para._toc_text = toc_text
        para._toc_level = 1
        para._toc_key = anchor
        return para


def _esc(text) -> str:
    return html.escape(str(text)) if text is not None else ""


def _cover_story(report_title: str, model, styles, colors, mm):
    """Cover page flowables for any MBS.PT report.

    Deliberately not "text stacked at the top of page 1": a cyan->violet accent rule, the
    vector mark, the brand lockup, the document title, the project/date block and a contact
    card. Ends with a PageBreak, so section 1 always begins on a fresh page.

    Pure presentation -- reads only the project name and the generation date."""
    from reportlab.graphics.shapes import Drawing, Rect
    from reportlab.platypus import (
        NextPageTemplate,
        PageBreak,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    story = [Spacer(1, 14 * mm)]

    logo = B.logo_drawing(26 * mm)
    if logo is not None:
        story.append(logo)
        story.append(Spacer(1, 6 * mm))

    # Two abutting bars reproduce the identity gradient without needing a gradient fill.
    bar = Drawing(170 * mm, 3.2 * mm)
    bar.add(Rect(0, 0, 85 * mm, 3.2 * mm, fillColor=colors.HexColor(B.CYAN), strokeColor=None))
    bar.add(Rect(85 * mm, 0, 85 * mm, 3.2 * mm, fillColor=colors.HexColor(B.VIOLET), strokeColor=None))
    story.append(bar)
    story.append(Spacer(1, 8 * mm))

    story.append(Paragraph(B.BRAND_NAME, styles["CoverBrand"]))
    story.append(Paragraph(B.REPORT_SUITE, styles["CoverTitle"]))
    story.append(Paragraph(report_title, styles["CoverSub"]))
    story.append(Spacer(1, 14 * mm))

    meta = Table(
        [
            ["Project", _esc(model.project_name)],
            ["Generated", f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}"],
            ["Classification", "Confidential — for the named recipient only"],
        ],
        colWidths=[38 * mm, 122 * mm],
    )
    meta.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor(B.MUTED)),
                ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor(B.INK)),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LINEBELOW", (0, 0), (-1, -2), 0.3, colors.HexColor(B.RULE)),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(meta)
    story.append(Spacer(1, 18 * mm))

    contact = Table(
        [[Paragraph(f"<b>{B.BRAND_NAME}</b>", styles["Small"])],
         [Paragraph(_esc(B.CONTACT_EMAIL), styles["Small"])],
         [Paragraph(_esc(B.CONTACT_PHONE), styles["Small"])]],
        colWidths=[160 * mm],
    )
    contact.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(B.PAPER_TINT)),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor(B.RULE)),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story.append(contact)
    # Switch to the "content" page template BEFORE the break, so every page after the cover
    # gets the header/footer. Without this ReportLab keeps using the first registered
    # template ("cover", which paints no chrome) for the whole document -- i.e. no page
    # numbers anywhere, which is exactly the defect this redesign exists to fix.
    story.append(NextPageTemplate("content"))
    story.append(PageBreak())
    return story


class _TocDoc:
    """Marker mixin documenting why multiBuild is used; see _build_document."""


def _section(number: int, title: str, styles, colors, mm, toc_level: int = 0):
    """A numbered section heading with a brand accent rule, registered for the TOC.

    `_SectionHeading` notifies the TableOfContents of its page at build time, which is what
    makes the printed page numbers real rather than guessed."""
    from reportlab.graphics.shapes import Drawing, Rect
    from reportlab.platypus import Spacer

    # `title` goes through a Paragraph, which parses a bare "&" as the start of an entity --
    # "MITRE ATT&CK" rendered as "ATT&CK;". Escaping here keeps section titles literal, while
    # the TOC entry keeps the human text.
    out = [
        Spacer(1, 2 * mm),
        _SectionHeading(f"{number}. {_esc(title)}", styles["Section"], toc_level, raw_text=f"{number}. {title}"),
    ]
    rule = Drawing(170 * mm, 1.6 * mm)
    rule.add(Rect(0, 0, 26 * mm, 1.6 * mm, fillColor=colors.HexColor(B.CYAN), strokeColor=None))
    rule.add(Rect(26 * mm, 0, 14 * mm, 1.6 * mm, fillColor=colors.HexColor(B.VIOLET), strokeColor=None))
    out.append(rule)
    out.append(Spacer(1, 4 * mm))
    return out


def _toc_story(styles, mm):
    """Table of Contents. Entries are contributed by _SectionHeading during the build, so the
    printed page numbers are the REAL ones and no entry can be listed that does not exist."""
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import PageBreak, Paragraph, Spacer
    from reportlab.platypus.tableofcontents import TableOfContents

    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle("TOC0", fontName="Helvetica", fontSize=10, leading=17, leftIndent=0,
                       firstLineIndent=0),
        ParagraphStyle("TOC1", fontName="Helvetica", fontSize=9, leading=14, leftIndent=10),
    ]
    return [Paragraph("Table of Contents", styles["H1"]), Spacer(1, 6 * mm), toc,
            PageBreak()]


def _build_document(buf, title: str, report_title: str, project_name: str, story) -> None:
    """Build a report with page furniture and a two-pass TOC.

    multiBuild (not build) is required: the first pass discovers which page each section
    heading lands on, the second prints those numbers into the TOC. Falls back to a single
    build if multiBuild is unavailable, so a report is never lost to TOC machinery."""
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate
    from reportlab.lib.units import mm

    from apps.api.modules.reports._page_furniture import (
        MARGIN_B,
        MARGIN_L,
        MARGIN_R,
        MARGIN_T,
        PageFurniture,
    )

    generated = f"{datetime.now(timezone.utc):%Y-%m-%d}"
    furniture = PageFurniture(report_title, project_name, generated)

    class _Doc(BaseDocTemplate):
        """Feeds TOC entries as headings are laid out.

        ReportLab calls afterFlowable() for every flowable it places; a heading tagged by
        _SectionHeading notifies the TableOfContents of its text AND the page it actually
        landed on. Without this hook the TOC renders empty."""

        def afterFlowable(self, flowable):
            text = getattr(flowable, "_toc_text", None)
            if text:
                # The TOC renders entries as Paragraphs, so a bare "&" would become
                # "&CK;" there too -- escape for the TOC while the bookmark keeps raw text.
                self.notify(
                    "TOCEntry",
                    (getattr(flowable, "_toc_level", 0), _esc(text), self.page,
                     getattr(flowable, "_toc_key", None)),
                )

    doc = _Doc(
        buf,
        pagesize=A4,
        title=title,
        author=B.BRAND_NAME,
        subject=f"{B.REPORT_SUITE} — {project_name}",
        leftMargin=MARGIN_L * mm,
        rightMargin=MARGIN_R * mm,
        topMargin=MARGIN_T * mm,
        bottomMargin=MARGIN_B * mm,
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="body")
    doc.addPageTemplates(
        [
            PageTemplate(id="cover", frames=[frame], onPage=furniture.cover),
            PageTemplate(id="content", frames=[frame], onPage=furniture.content),
        ]
    )
    # Phase 4.4: build through NumberedCanvas so the footer can print the REAL total ("Page 4
    # of 16"). `canvasmaker` is forwarded by multiBuild to build(), so the deferred-numbering
    # phase runs on the final pass only. Nothing about layout changes -- the canvas captures
    # and replays pages, it does not move content.
    from apps.api.modules.reports._page_furniture import numbered_canvas_factory

    try:
        doc.multiBuild(story, canvasmaker=numbered_canvas_factory())
    except Exception:
        # A TOC (or the numbering canvas) that cannot resolve must not cost the reader the
        # whole report. The plain-Canvas fallback still prints "Page N" -- see PageFurniture.
        doc.build(story)


def render_executive(model: "ReportModel") -> bytes:
    model = _as_model(model)

    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Spacer, Table

    styles = _styles(getSampleStyleSheet, ParagraphStyle, colors)
    buf = BytesIO()
    story = []

    # Cover + Table of Contents. Section 1 begins on a fresh page (the cover ends with a
    # PageBreak), so no section ever starts mid-page after front matter.
    story += _cover_story("Executive Report", model, styles, colors, mm)
    story += _toc_story(styles, mm)

    story += _section(1, "Executive Summary", styles, colors, mm)

    # Phase 4.3: the five headline figures as a scannable panel instead of a 921-character run
    # of prose that stated each of them mid-sentence. Same canonical values -- see
    # _posture_panel; nothing is recomputed and there is no second scoring model.
    band = _score_band(model.security_score)
    story.append(_posture_panel(model, styles, colors, mm))
    story.append(Spacer(1, 4 * mm))

    # ONE reconciling sentence, not three. R-01's two units are stated on the panel above
    # (UNIQUE ISSUES over recorded findings); this explains WHY they differ, once, and states
    # the scoring population. `_findings_summary` is the shared wording both reports use.
    # `_findings_summary` already appends its own "These represent N unique issues across M
    # affected locations" clause (Phase 2.1), so this paragraph must NOT restate it -- doing so
    # is exactly the triplication this rebuild removes. The shared sentence is emitted as-is and
    # only the scoring caveat is added.
    story.append(
        Paragraph(
            f"{_findings_summary(model)} The score reflects open, confirmed and reopened "
            "findings weighted by severity; resolved, accepted-risk and false-positive "
            "findings do not reduce it.",
            styles["Body"],
        )
    )
    story.append(Spacer(1, 4 * mm))

    # Severity shape, before the detailed tables. Presentation of active counts only.
    story.append(Paragraph("Active findings by severity", styles["SubSection"]))
    story += _severity_bar(model, styles, colors, mm)
    story.append(Spacer(1, 5 * mm))

    # Phase 4.3: WHAT KINDS of problem, which a per-issue risk table cannot express. Derived
    # from the same weakness classifier the Technical report uses; see _key_themes.
    themes = _key_themes(model)
    if themes:
        story.append(Paragraph("Key security themes", styles["SubSection"]))
        theme_rows = [["Weakness class", "Unique issues", "Recorded findings"]]
        for name, issues, occurrences in themes[:6]:
            theme_rows.append([
                Paragraph(_esc(name), styles["Cell"]), str(issues), str(occurrences)
            ])
        ttbl = Table(theme_rows, colWidths=[100 * mm, 35 * mm, 35 * mm])
        ttbl.setStyle(_table_style(colors))
        story.append(ttbl)
        story.append(
            Paragraph(
                "Grouped by weakness class over the findings that affect the security score. "
                "A class carrying several distinct issues usually points at one systemic cause "
                "rather than unrelated defects.",
                styles["Small"],
            )
        )
    story.append(Spacer(1, 6 * mm))

    # STEP 4 -- VERIFICATION summary. Severity says how bad a finding would be; verification says
    # how much evidence supports it. Executives were shown only severity, so 157 detections read
    # as 157 confirmed vulnerabilities. Both axes are now stated, and the sentence below names
    # the distinction explicitly rather than leaving it to be inferred.
    story += _section(2, "Findings Summary", styles, colors, mm)
    story.append(Paragraph("Findings by verification status", styles["SubSection"]))
    # Step 4: the model carries this tally (assembled from the canonical
    # _verification_summary over ReportData). Re-deriving it here would be a second source.
    _v = model.verification
    ver_counts = {VERIFIED: _v.verified, PARTIALLY_VERIFIED: _v.partially_verified,
                  UNVERIFIED: _v.unverified}
    # R-01: the column is NAMED for its unit. This tally is deliberately OCCURRENCE-based --
    # verification is a property of an observation, and the same issue can be demonstrated at
    # one location and merely suspected at another, so collapsing it to the issue level would
    # discard exactly the distinction the table exists to show. Labelling it is the fix; the
    # counting semantics are unchanged.
    ver_rows = [["Verification", "Recorded findings"]]
    for state in (VERIFIED, PARTIALLY_VERIFIED, UNVERIFIED):
        ver_rows.append([verification_label(state), str(ver_counts[state])])
    vtbl = Table(ver_rows, colWidths=[80 * mm, 40 * mm])
    vtbl.setStyle(_table_style(colors))
    story.append(vtbl)
    story.append(
        Paragraph(
            "Counts are RECORDED FINDINGS (one per observed location), not unique issues: "
            f"the {model.counts.active_findings} active finding(s) above represent "
            f"{_issue_occurrence_phrase(model.counts.active_issues, model.counts.active_findings)}. "
            "Verification is counted per location because one issue can be demonstrated at "
            "one endpoint and only suspected at another. "
            "Findings are detections produced by the security pipeline; verification status "
            "indicates the level of evidence supporting each finding. Severity describes "
            "potential impact and is independent of verification: an unverified finding is not "
            "necessarily a false positive, and a high-severity finding is not confirmed "
            "exploitation unless its verification status says so.",
            styles["Small"],
        )
    )
    story.append(Spacer(1, 6 * mm))

    # Severity summary table. BOTH populations are shown side by side. Previously only the
    # all-status tally was printed, directly beneath sentences that describe the ACTIVE
    # population -- so a reader comparing "3 critical" here against "1 active finding" above
    # had no way to reconcile them, and a fixed critical looked like a live one. The two
    # columns are the two counts ReportData already computes; neither is recomputed here.
    story.append(Paragraph("Findings by severity", styles["SubSection"]))
    story.append(
        Paragraph(
            "“All findings (any status)” is the complete record for this project, including "
            "findings already fixed, accepted as risk, or dismissed as false positives. "
            "“Active” is the subset that is still open, confirmed or reopened — the population "
            "the security score and the sections above describe. "
            # R-01: name the unit. Severity is tallied per RECORDED FINDING, which is the right
            # unit for a severity distribution (one issue can legitimately be observed at
            # several locations), but it is a different unit from the issue counts elsewhere in
            # this report -- so both are stated rather than left to be inferred.
            "Both columns count RECORDED FINDINGS (one per observed location), not unique "
            f"issues: the complete record holds {model.counts.total_issues} unique issue(s) "
            f"across {model.counts.total_findings} recorded finding(s).",
            styles["Small"],
        )
    )
    sev_rows = [["Severity", "All findings (any status)", "Active"]]
    for sev in ("critical", "high", "medium", "low", "info"):
        sev_rows.append([
            sev.capitalize(),
            str(model.severity.all_statuses.get(sev, 0)),
            str(model.severity.active.get(sev, 0)),
        ])
    sev_rows.append([
        "Total",
        str(model.counts.total_findings),
        str(model.counts.active_findings),
    ])
    tbl = Table(sev_rows, colWidths=[45 * mm, 50 * mm, 30 * mm])
    tbl.setStyle(_table_style(colors))
    story.append(tbl)
    story.append(Spacer(1, 6 * mm))

    # Affected assets / endpoints. Management-level rollup, NOT a per-endpoint dump: the distinct
    # inventoried assets/hosts (assets.value) plus how many distinct endpoints (matched_at) were
    # observed. Asset (host) and endpoint (exact URL) are deliberately named separately. Assets
    # appear ONLY when the finding is linked to an inventoried asset -- an empty list means the
    # findings carry no asset linkage, never that nothing is affected. Full per-finding endpoints
    # remain in the technical report.
    story += _section(3, "Affected Assets & Endpoints", styles, colors, mm)
    assets = list(model.exposure.assets)
    endpoints = model.exposure.endpoint_count
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
    # R-03: the concrete scope (which scans, which targets, what window) comes first, from the
    # SAME shared helper the Technical report uses, so the two documents cannot disagree about
    # what was assessed. The qualitative limitations paragraph then follows it unchanged.
    story.append(Paragraph("Assessment scope", styles["SubSection"]))
    story += _assessment_scope_story(model, styles, colors, mm)
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
    story += _section(4, "Key Risks", styles, colors, mm)
    story.append(Paragraph("Ranked by business risk score", styles["SubSection"]))
    groups = list(model.key_risks)[:10]
    if groups:
        # R-01: reconcile this table's ROW COUNT with the occurrence counts stated above. Each
        # row here is one UNIQUE ISSUE, so a reader who counted "N active findings" earlier can
        # now see exactly why this table is shorter. `_shown` is the displayed row count (the
        # list is capped at 10), stated separately from the true total so the cap is explicit
        # rather than looking like a discrepancy.
        _active_issues = model.counts.active_issues
        _shown = len(groups)
        _cap_note = (
            f" The {_shown} highest-risk of these are listed below."
            if _shown < _active_issues
            else " Each is listed below."
        )
        story.append(
            Paragraph(
                f"This project has {_issue_occurrence_phrase(_active_issues, model.counts.active_findings)}."
                f"{_cap_note} One row = one unique issue; the same issue observed at several "
                "locations is listed once here and remediated once. "
                "“Occurrences” is how many recorded findings each "
                "issue aggregates — not a count of distinct vulnerabilities. “Business risk” "
                "is the highest business risk score within the group; “N/A” means the finding "
                "carries no CVSS, so no business-risk score could be derived — it is "
                "unassessed, not low risk. Each issue is detailed in the accompanying "
                "Technical Report under the same title.",
                styles["Body"],
            )
        )
        # "Occurrences", not "Endpoints": the value is endpoint_count, which counts the
        # endpoint-level FINDINGS in the group, and a group can hold several findings at one
        # endpoint (different matchers of one template). Labelling it "Endpoints" overstated
        # the breadth of every such issue.
        risk_rows = [["Issue", "Severity", "Occurrences", "Business risk"]]
        for g in groups:
            risk_rows.append(
                [
                    Paragraph(_esc(g.title), styles["Cell"]),
                    g.severity,
                    str(g.occurrence_count),
                    # "N/A" -- NOT 0.0 -- when the group has no business-risk score at all
                    # (no CVSS anywhere in it). Fabricating a number here would misreport an
                    # unassessed finding as a zero-risk one.
                    (f"{g.max_risk:.1f}" if g.max_risk is not None else "N/A"),
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
    # R-02: the SAME population and the SAME contract the Technical report's cards use
    # (ReportData.compliance_coverage -> scoring.is_scorable), so the two sections can never
    # describe different framework sets. This previously walked data.vulns unfiltered and so
    # could claim coverage from findings that were already fixed or dismissed as false
    # positives -- while the MITRE section on the next page correctly reported nothing.
    coverage = [(f.framework,[(c.control_id,c.description,list(c.finding_ids)) for c in f.controls]) for f in model.compliance]
    story += _section(5, "Compliance Coverage", styles, colors, mm)
    if coverage:
        control_total = sum(len(controls) for _fw, controls in coverage)
        story.append(
            Paragraph(
                f"Current findings map to {control_total} control(s) across "
                + ", ".join(f"{framework_name(fw)} ({len(controls)})" for fw, controls in coverage)
                + ". See the technical report for each control and the findings mapped to it.",
                styles["Body"],
            )
        )
    else:
        story.append(
            Paragraph(
                "No current findings map to compliance controls.",
                styles["Body"],
            )
        )
    story.append(
        Paragraph(
            # Required wording boundary: finding-derived mapping, never a compliance claim.
            "This is finding-based coverage derived from each finding's CWE classification — "
            "it shows which controls the observed weaknesses relate to. It is NOT a compliance "
            "assessment, an audit, or a statement of certification against any framework. "
            "Fixed, accepted-risk, false-positive, informational and detection-only findings "
            # Entity, not a bare "&" -- see the identical note in _compliance_cards.
            "do not contribute, matching the security score and ATT&amp;CK coverage.",
            styles["Small"],
        )
    )

    # MITRE ATT&CK coverage: which adversary techniques the findings map to, most
    # frequently observed first. The per-scan kill-chain view sequences these.
    story.append(Spacer(1, 6 * mm))
    story += _section(6, "MITRE ATT&CK Coverage", styles, colors, mm)
    if model.attack:
        att_rows = [["Tactic", "Technique", "ID", "Issues"]]
        for _t in model.attack[:15]:
            tactic, tid, tname, count = (_t.tactic, _t.technique_id, _t.technique_name,
                                         _t.issue_count)
            att_rows.append([_esc(tactic), Paragraph(_esc(tname), styles["Cell"]), tid, str(count)])
        atbl = Table(att_rows, colWidths=[45 * mm, 70 * mm, 25 * mm, 20 * mm])
        atbl.setStyle(_table_style(colors))
        story.append(atbl)
        story.append(
            Paragraph(
                "“Issues” counts DISTINCT active issues mapped to each technique — not "
                "endpoints and not raw findings, so one issue seen at many URLs counts once. "
                "Resolved, accepted-risk, false-positive, informational and detection-only "
                "findings are excluded, matching the security score. Techniques are mapped to the "
                "Cyber Kill Chain; see the scan kill-chain view for the sequenced attack path.",
                styles["Body"],
            )
        )
    else:
        story.append(Paragraph("No active issues mapped to ATT&amp;CK techniques.", styles["Body"]))

    # Autonomous-engagement attack graph (M4.4.6): evidence-backed asset -> service ->
    # finding -> technique -> access relationships, plus any confirmed access. Present
    # only for agent-driven scans; fail-soft otherwise. Never reports unsupported
    # privilege escalation / lateral movement.
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Autonomous engagement: attack graph", styles["SubSection"]))
    ag = model.attack_graph or {}
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

    # --- 7. Recommended Actions (Phase 4.3) ------------------------------------------------
    # The Executive report previously ended without a single recommendation. Every line is a
    # restatement of a figure already in this document, expressed as an action; see
    # _recommendations, which invents no severity, priority or finding.
    story.append(Spacer(1, 6 * mm))
    story += _section(7, "Recommended Actions", styles, colors, mm)
    actions = _recommendations(model)
    if actions:
        action_rows = [["Priority", "Action"]]
        for label, text in actions:
            action_rows.append([label, Paragraph(_esc(text), styles["Cell"])])
        atbl2 = Table(action_rows, colWidths=[34 * mm, 136 * mm])
        atbl2.setStyle(_table_style(colors))
        story.append(atbl2)
        story.append(
            Paragraph(
                "Priorities describe suggested sequencing only. They do not alter any "
                "finding's severity, CVSS, business risk or verification status, and they use "
                "the same ordering as the Technical Report's remediation plan.",
                styles["Small"],
            )
        )
    else:
        story.append(
            Paragraph("No active findings require remediation action.", styles["Body"])
        )

    story += _section(8, "Conclusion", styles, colors, mm)
    story.append(
        Paragraph(
            # R-01: the closing statement carries both units, so the last number an executive
            # reads is consistent with the Key Risks table they just read.
            f"This assessment leaves "
            f"{_issue_occurrence_phrase(model.counts.active_issues, model.counts.active_findings)} "
            f"still active, from a complete record of {model.counts.total_findings} recorded finding(s) "
            f"across {model.counts.total_issues} unique issue(s), producing a security score of "
            f"{model.security_score}/100 ({band}). Findings are detections produced by the "
            "security pipeline; verification status indicates the level of evidence "
            "supporting each one. Remediation should follow the priority order in Key Risks, "
            "highest business risk first. Full technical detail, evidence and reproduction "
            "metadata are provided in the accompanying Technical Report.",
            styles["Body"],
        )
    )

    _build_document(buf, f"Executive Report — {model.project_name}", "Executive Report",
                    model.project_name, story)
    return buf.getvalue()


def render_technical(model: "ReportModel") -> bytes:
    model = _as_model(model)

    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

    styles = _styles(getSampleStyleSheet, ParagraphStyle, colors)
    buf = BytesIO()
    story = []

    story += _cover_story("Technical Report", model, styles, colors, mm)
    story += _toc_story(styles, mm)

    # --- 1. Assessment Overview ----------------------------------------------------------
    story += _section(1, "Assessment Overview", styles, colors, mm)
    # R-01: both units in the overview line. `total_vulns`/`active_vulns` are OCCURRENCE counts
    # (one row = one observed location); the issue counts are what Detailed Findings below
    # actually renders as blocks.
    story.append(
        Paragraph(
            f"Security score {model.security_score}/100 · complete record: {model.counts.total_findings} "
            f"recorded finding(s) across {model.counts.total_issues} unique issue(s) · "
            f"currently active: "
            f"{_issue_occurrence_phrase(model.counts.active_issues, model.counts.active_findings)}.",
            styles["Body"],
        )
    )
    story.append(Paragraph(_findings_summary(model), styles["Small"]))
    story.append(Spacer(1, 3 * mm))
    ver = model.verification
    story.append(
        Paragraph(
            # Verification is deliberately counted per RECORDED FINDING -- see the Executive
            # note on the same table. Labelled, not re-counted.
            f"Verification of active findings (counted per recorded finding, not per unique "
            f"issue) — Verified: {ver.verified} · "
            f"Partially Verified: {ver.partially_verified} · Unverified: {ver.unverified}. "
            f"{model.counts.scorable_issues} unique issue(s) — {model.counts.scorable_findings} "
            "recorded finding(s) — affect the security score.",
            styles["Small"],
        )
    )

    # --- 2. Scope & Methodology ----------------------------------------------------------
    # Describes ONLY what the pipeline actually does; no methodology is claimed that the
    # system does not perform.
    story += _section(2, "Scope & Methodology", styles, colors, mm)
    # R-03: what the report covers, before how it was produced.
    story += _assessment_scope_story(model, styles, colors, mm)
    # Prefer the version-qualified inventory: a tool name alone does not make a finding
    # reproducible. Falls back to bare names when no version was recorded anywhere.
    tools = list(model.tool_versions or model.tools)
    story.append(
        Paragraph(
            "Findings in this report were produced by automated security scanning of the "
            "in-scope targets recorded for this project. Each finding is deduplicated to an "
            "issue identity and reported with the locations at which it was observed. "
            "Severity is the scanner's rating; CVSS is the technical base score where one is "
            "available; business risk additionally weights CVSS by asset criticality. "
            "Verification status states the evidence supporting each finding and never alters "
            "its severity or score.",
            styles["Body"],
        )
    )
    story.append(
        Paragraph(f"Producing tool(s): {_esc(', '.join(tools) or 'N/A')}", styles["Small"])
    )

    # --- 3. Findings Summary -------------------------------------------------------------
    story += _section(3, "Findings Summary", styles, colors, mm)
    story.append(
        Paragraph(
            "“All findings (any status)” is the complete record, including findings already "
            "fixed, accepted as risk, or dismissed as false positives. “Active” is the subset "
            "that is still open, confirmed or reopened. "
            # R-01: name the unit, and state the exact block count the reader will find below,
            # so the relationship between this table and Detailed Findings is arithmetic rather
            # than something the reader has to take on trust.
            "Both columns count RECORDED FINDINGS (one per observed location), not unique "
            f"issues: the complete record holds {model.counts.total_issues} unique issue(s) "
            f"across {model.counts.total_findings} recorded finding(s). Detailed Findings below lists "
            f"every finding in the complete record, grouped by issue — one issue observed at "
            f"several locations appears once — so it contains exactly "
            f"{model.counts.total_issues} finding block(s).",
            styles["Small"],
        )
    )
    sev_rows = [["Severity", "All findings (any status)", "Active"]]
    for sev in ("critical", "high", "medium", "low", "info"):
        sev_rows.append([
            sev.capitalize(),
            str(model.severity.all_statuses.get(sev, 0)),
            str(model.severity.active.get(sev, 0)),
        ])
    sev_rows.append(["Total", str(model.counts.total_findings), str(model.counts.active_findings)])
    stbl = Table(sev_rows, colWidths=[60 * mm, 45 * mm, 45 * mm])
    stbl.setStyle(_table_style(colors))
    story.append(stbl)

    if not model.findings:
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph("No findings recorded for this project.", styles["Body"]))
        _build_document(buf, f"Technical Report — {model.project_name}", "Technical Report",
                        model.project_name, story)
        return buf.getvalue()

    # --- 4. Detailed Findings ------------------------------------------------------------
    # One block per VULNERABILITY, not per row: a template observed at many URLs is a single
    # finding with its affected locations listed, instead of the same severity/CVSS/risk text
    # repeated once per location. Presentation only -- see _finding_groups.
    story += _section(4, "Detailed Findings", styles, colors, mm)
    _groups = list(model.findings)
    # Explicit reconciliation between this section and the summary table above, so a reader
    # who counts the blocks and compares them with the totals is never left with an
    # unexplained discrepancy. Both numbers are already-computed values, restated.
    _occurrences = sum(g.occurrence_count for g in _groups)
    story.append(
        Paragraph(
            # R-01: phrased through the shared helper so this reconciliation reads identically
            # to the Executive report's. len(_groups) is ReportData.total_issue_count() by
            # construction -- both partition data.vulns by scoring.issue_key -- which is the
            # identity pinned by the Phase 2.1 tests.
            f"Detailed below: {_issue_occurrence_phrase(len(_groups), _occurrences)}, "
            f"presented as {len(_groups)} finding block(s). One issue observed at several "
            "locations is presented once, with every affected location listed under it.",
            styles["Small"],
        )
    )
    story.append(Spacer(1, 3 * mm))
    for i, g in enumerate(_groups, 1):
        # Phase 4.2: _finding_block now returns a LIST -- an atomic header group followed by
        # flowable body content -- instead of one oversized KeepTogether that could never fit a
        # page. Extended into the story so ReportLab can paginate the body naturally.
        story.extend(_finding_block(i, g, styles, colors, Paragraph, Table, TableStyle, mm))
        story.append(Spacer(1, 4 * mm))

    # --- 5. Evidence & Screenshots -------------------------------------------------------
    story += _section(5, "Evidence & Screenshots", styles, colors, mm)
    story += _evidence_story(model, styles, colors, mm)

    # --- 6. Compliance Coverage ----------------------------------------------------------
    story += _section(6, "Compliance Coverage", styles, colors, mm)
    story += _compliance_cards(model, styles, colors, mm)

    # --- 7. MITRE ATT&CK -----------------------------------------------------------------
    story += _section(7, "MITRE ATT&CK Coverage", styles, colors, mm)
    story += _attack_cards(model, styles, colors, mm)

    # --- 8. Remediation Plan -------------------------------------------------------------
    story += _section(8, "Remediation Plan", styles, colors, mm)
    story += _remediation_plan_story(model, styles, colors, mm)

    # --- 9. Appendix ---------------------------------------------------------------------
    story += _section(9, "Appendix", styles, colors, mm)
    story.append(
        Paragraph(
            "Finding identifiers (MBS-XXXXXXXX) are derived from each finding's stored "
            "identity and remain stable across report regenerations, so they can be quoted "
            "in correspondence. Artifact identifiers (EV-XXXXXXXX) are derived the same way "
            "from each stored evidence artifact. Fields shown as N/A were not present in the "
            "scan evidence and have not been inferred.",
            styles["Small"],
        )
    )
    story.append(Spacer(1, 3 * mm))

    # Phase 3.2: the evidence manifest. Placed in the Appendix rather than inside the Evidence
    # section so the per-finding narrative stays readable while the complete, verifiable
    # inventory has one authoritative home.
    story.append(Paragraph("Evidence manifest", styles["SubSection"]))
    story += _evidence_manifest_story(model, styles, colors, mm)

    # Phase 4.2: the full location list for any finding whose inline list was capped, so the
    # display cap never costs the reader a location.
    story += _location_index_story(model, styles, colors, mm)

    story.append(
        Paragraph(
            f"Report produced by {B.BRAND_NAME} · {B.CONTACT_EMAIL} · {B.CONTACT_PHONE}",
            styles["Small"],
        )
    )

    _build_document(buf, f"Technical Report — {model.project_name}", "Technical Report",
                    model.project_name, story)
    return buf.getvalue()


def _is_inference_match(g) -> bool:
    """True when the group's match came from timing or an out-of-band channel.

    Read-only reuse of verification.py's OWN marker list, so the narrative's statement about
    how a finding was matched can never contradict the confidence that module assigned from
    the same markers. Nothing is re-derived and no state is changed."""
    from apps.api.modules.reports.verification import _has_inference_marker

    return _has_inference_marker(g.get("template_id"), ", ".join(g.get("matcher_names") or []))


def _narrative_subsection(title: str, body, styles, Paragraph, mm):
    """One labelled narrative subsection: a bold label followed by its prose.

    `body` is a string or a list of strings (rendered as consecutive paragraphs). Returns a
    flat list of flowables so callers can extend their `parts` directly."""
    from reportlab.platypus import Spacer

    out = [Paragraph(_esc(title), styles["Label"])]
    for text in ([body] if isinstance(body, str) else list(body)):
        if text:
            out.append(Paragraph(_esc(text), styles["Body"]))
    out.append(Spacer(1, 2 * mm))
    return out


def _finding_block(idx, g, styles, colors, Paragraph, Table, TableStyle, mm):
    """Render ONE vulnerability (a group from _finding_groups) as a professional finding.

    STRUCTURE (fixed order, so every finding reads the same way):
        header + fact card
        Vulnerability Description
        Security Impact              -- gated on verification; see narrative.impact
        Exploitation Context
        Verification & Confidence
        Risk Assessment              -- CVSS / business risk / rationale / compliance
        Affected Locations
        Evidence
        Remediation
        References

    WHAT THIS FUNCTION MAY NOT DO. It presents values; it never derives them. Severity, CVSS,
    business risk, verification, confidence and classification are all printed exactly as the
    upstream classifiers produced them, and the narrative prose is selected FROM those values
    rather than influencing any of them.

    The header no longer repeats the fact card. Finding ID, severity, CVSS, risk, verification
    and confidence each used to be printed twice (once in a header line, once in the card) and
    CVSS a third time as "CVSS base score"; the card is now the single authoritative statement
    of each, and the header carries only identity."""
    from reportlab.platypus import KeepTogether, Spacer

    color = B.severity_color(g["severity"])
    # Detection vs vulnerability, stated in the heading so a technology/WAF/version DETECTION
    # is never read as a confirmed vulnerability. Presentation only -- identity, grouping and
    # scoring are unchanged (see classification.py).
    kind_label = "DETECTION" if g.get("classification") == "detection" else "VULNERABILITY"
    _ver = g.get("verification") or UNVERIFIED
    _conf = g.get("confidence") or CONFIDENCE_MEDIUM
    weakness = N.classify_weakness_row(g)
    inference = _is_inference_match(g)
    endpoints = g["matched_ats"]
    by_host = _group_locations_by_host(endpoints) if endpoints else []

    # Phase 4.4: the finding title is now a NAVIGABLE heading -- a PDF outline entry and a
    # level-1 Table of Contents entry with its real page number.
    #
    # The destination is anchored on the CANONICAL finding id (VulnRow.finding_id ->
    # "MBS-XXXXXXXX", derived from the vulnerability's database identity). No second
    # identifier system is introduced and nothing is renumbered: `idx` remains the display
    # ordinal it always was, while the ANCHOR is the stable id, so a link keeps resolving to
    # the same finding across re-renders even if display order changes.
    #
    # Anchoring on the id also makes a scoped report self-consistent by construction: only
    # findings present in that report create anchors and TOC entries, so a scoped document
    # cannot link to an excluded finding.
    finding_id = g.get("finding_id") or "N/A"
    parts = [
        _FindingHeading(
            f"{idx}. {_esc(g['title'])}",
            styles["FindingTitle"],
            anchor=f"finding-{finding_id}",
            toc_text=f"{finding_id} — {g['title']}",
        ),
        # Identity only -- every assessed value now lives in the fact card below, stated once.
        Paragraph(
            f"{_esc(g.get('finding_id') or 'N/A')}  ·  {kind_label}  ·  "
            f"{_esc(weakness.name)}",
            styles["Small"],
        ),
        Spacer(1, 2 * mm),
    ]

    # FACT CARD -- the single authoritative statement of this finding's assessed values.
    # Printed EXACTLY as stored; a missing value renders "N/A" and is never inferred.
    assets = g.get("asset_values") or []
    cvss_val = g["cvss_score"]
    band = cvss_severity_band(cvss_val)
    card_rows: list[tuple[str, object]] = [
        ("Finding ID", g.get("finding_id") or "N/A"),
        ("Severity", (g["severity"] or "N/A").upper()),
        (
            "CVSS",
            (f"{cvss_val} ({band})" if band else f"{cvss_val}") if cvss_val is not None else "N/A",
        ),
        (
            "Business risk",
            f"{g['final_risk_score']:.1f}/10" if g["final_risk_score"] is not None else "N/A",
        ),
        # Phase 4.1: verification and confidence are no longer collapsed into this one grey
        # row. They are stated on the ASSURANCE CHIPS below the card, each on its own axis and
        # in its own palette, so they cannot be read as ordinary metadata beside Matcher and
        # Asset. The card keeps a short cross-reference rather than repeating the values,
        # preserving the "each fact stated once" rule the card was built on.
        ("Assurance", f"{verification_label(_ver)} — see assurance panel below"),
        ("Status", g.get("status") or "N/A"),
        ("Asset", ", ".join(assets) if assets else "N/A"),
        (
            "Endpoint",
            Paragraph(_esc(endpoints[0]) if endpoints else "N/A", styles["Endpoint"]),
        ),
    ]
    if len(endpoints) > 1:
        card_rows.append(("Other endpoints", f"{len(endpoints) - 1} more (listed below)"))
    for label, value in _technical_metadata_rows(g):
        if label in ("Status",):  # already stated above; do not repeat
            continue
        card_rows.append((label, value))
    parts.append(_card(card_rows, styles, colors, mm, accent=color))
    parts.append(Spacer(1, 2 * mm))

    # Phase 4.1: the ASSURANCE PANEL -- verification, confidence and evidence availability as
    # three visually separate chips, immediately under the fact card so a reader meets the
    # qualifier at the same moment as the CVSS and risk numbers rather than three subsections
    # later. Presentation only; see _assurance_chips.
    parts.append(_assurance_chips(g, styles, colors, mm))
    parts.append(Paragraph(_esc(_assurance_caption(g)), styles["Small"]))
    parts.append(Spacer(1, 3 * mm))

    # Phase 4.2: everything up to here -- title, identity line, fact card and assurance panel --
    # is the group that must never be split from itself, because together they say WHAT finding
    # the reader is looking at. See the pagination note at the end of this function.
    header_end = len(parts)

    # --- Vulnerability Description ---------------------------------------------------------
    # Class-appropriate explanation of the weakness, plus WHERE it was observed derived only
    # from counts this block itself lists below. The scanner's own description text, when the
    # row has one, is appended verbatim and attributed -- never replaced by our prose.
    #
    # `curated_text` is MBS-authored prose for a reviewed template, looked up here and passed
    # on its OWN parameter so narrative.description can attribute it separately. It is used
    # only when the scanner supplied no description, and it is deliberately NOT written into
    # the group dict or back to `vulnerabilities.description`: a NULL description stays NULL,
    # and nothing MBS wrote is ever presented as scanner output.
    parts += _narrative_subsection(
        "Vulnerability Description",
        N.description(
            weakness,
            location_count=len(endpoints),
            host_count=len(by_host),
            inference=inference,
            scanner_text=g.get("description"),
            curated_text=curated_description(g.get("template_id")),
        ),
        styles, Paragraph, mm,
    )

    # --- Security Impact -------------------------------------------------------------------
    # THE ACCURACY BOUNDARY. The heading itself states whether the impact is CONFIRMED by
    # evidence or POTENTIAL, and narrative.impact gates the wording on the verification state
    # so an unproven finding can never be described as a confirmed compromise.
    parts += _narrative_subsection(
        N.impact_heading(_ver), N.impact(weakness, _ver), styles, Paragraph, mm
    )

    # --- Exploitation Context --------------------------------------------------------------
    parts += _narrative_subsection(
        "Exploitation Context",
        N.exploitation_context(weakness, inference=inference),
        styles, Paragraph, mm,
    )

    # --- Verification & Confidence ---------------------------------------------------------
    # States the evidence position in words. Evidence provenance ONLY: it does not modify
    # severity, CVSS, business risk or the security score, and an unverified CVSS 9.8 is still
    # reported as a CVSS 9.8 (see verification.py).
    # Phase 4.1: the STATE is now stated on the assurance chips above, so this subsection
    # carries the analyst guidance rather than repeating "Partially Verified · Low" a second
    # time. verification_note is the classifier's own one-line position on what the state means
    # for the reader; the value itself is not reprinted here.
    ver_lines = [verification_note(_ver)]
    if inference:
        ver_lines.append(
            "The match is inference-based (a timing or out-of-band signal), which is a weaker "
            "class of evidence than directly observed output; this is reflected in the "
            "confidence rating and does not alter the finding's severity or CVSS."
        )
    parts += _narrative_subsection("Verification & Confidence", ver_lines, styles, Paragraph, mm)

    # --- Risk Assessment -------------------------------------------------------------------
    # Keeps TECHNICAL severity and BUSINESS risk visibly separate. A single "risk 10.0" line
    # let a MEDIUM CVSS 5.5 on a critical asset read as Critical: 5.5 x 2.0 = 11.0 capped to
    # 10.0 is indistinguishable from a genuine CVSS 9.8 x 2.0 = 19.6 -> 10.0. Both the CVSS
    # band and the pre-cap product are therefore stated explicitly.
    #
    # PRESENTATION ONLY. Nothing here recomputes or writes risk: cvss_severity_band is a pure
    # function of the CVSS the row already carries, and the uncapped product is re-derived
    # read-only from that score and the weight recorded in the stored rationale.
    risk_lines: list[str] = []
    if g["final_risk_score"] is not None:
        # Recover the criticality/weight from the stored rationale rather than re-deriving it:
        # the report layer has no asset-criticality column, and the rationale is the value the
        # risk engine itself recorded at compute time.
        weight_match = re.search(r"weight ([0-9.]+)", g["risk_rationale"] or "")
        crit_match = re.search(r"criticality '([^']+)'", g["risk_rationale"] or "")
        risk_line = f"Business risk score: {g['final_risk_score']:.1f}/10"
        if crit_match:
            risk_line += f" · Asset criticality: {crit_match.group(1)}"
        if weight_match and cvss_val is not None:
            uncapped = round(cvss_val * float(weight_match.group(1)), 1)
            if uncapped > g["final_risk_score"]:
                risk_line += f" · Uncapped: {uncapped} (capped at 10.0)"
        risk_lines.append(risk_line)
        if band and band not in ("None",):
            risk_lines.append(
                f"Asset criticality adjusts business risk only; this finding's technical "
                f"severity remains CVSS {band}."
            )
    if g["risk_rationale"]:
        risk_lines.append(
            "Risk rationale (recorded by the risk engine, not observed evidence): "
            + _sanitise_risk_rationale(g["risk_rationale"], g["final_risk_score"])
        )
    if risk_lines:
        parts += _narrative_subsection("Risk Assessment", risk_lines, styles, Paragraph, mm)

    # --- Affected Locations ----------------------------------------------------------------
    # Listed once per DISTINCT location under the single finding, grouped by host, so one issue
    # across many endpoints reads as one vulnerability with a breadth count -- not as many
    # separate vulnerabilities. Every distinct location is printed exactly once.
    parts.append(Paragraph("Affected Location(s)", styles["Label"]))
    if endpoints:
        host_note = f" across {len(by_host)} host(s)" if len(by_host) > 1 else ""
        parts.append(
            Paragraph(f"{len(endpoints)} location(s){host_note}:", styles["Small"])
        )
        # --- Display cap (Phase 4.2) -------------------------------------------------------
        #
        # WHY A CAP. One template can legitimately match hundreds of URLs; at 400 locations the
        # block measured 6,728mm -- 26 pages of near-identical mono lines for ONE finding,
        # burying the description, evidence and remediation that a reader actually needs.
        #
        # WHY THIS CAP IS NOT TRUNCATION. Nothing is hidden: the total is printed ABOVE the
        # list (unchanged), the omitted count is stated explicitly below it, and every location
        # remains in the report -- the appendix location index lists the full set. The cap is
        # generous enough (60) that the overwhelming majority of findings are unaffected and
        # print exactly as before.
        #
        # The per-host counts stay TRUE counts: a host header says how many locations that host
        # really has, not how many were printed.
        shown = 0
        omitted = 0
        for host, paths in by_host:
            if host:
                parts.append(Paragraph(f"{_esc(host)} ({len(paths)}):", styles["Small"]))
            for loc in paths:
                if shown >= _MAX_LOCATIONS_SHOWN:
                    omitted += 1
                    continue
                parts.append(Paragraph(f"• {_esc(loc)}", styles["Mono"]))
                shown += 1
        if omitted:
            parts.append(
                Paragraph(
                    f"• (+{omitted} further location(s) not listed here — every affected "
                    f"location for this finding is listed in the Appendix location index)",
                    styles["Small"],
                )
            )
        # Occurrences with no matched_at are still real findings; say so rather than drop them.
        if g["unlocated_count"]:
            parts.append(
                Paragraph(
                    f"• (+{g['unlocated_count']} occurrence(s) with no recorded location)",
                    styles["Small"],
                )
            )
    else:
        parts.append(
            Paragraph(
                "No specific location was recorded for this finding in the scan evidence.",
                styles["Small"],
            )
        )
    if assets:
        parts.append(Paragraph(f"Inventoried asset(s): {_esc(', '.join(assets))}", styles["Small"]))
    parts.append(Spacer(1, 2 * mm))

    # --- Evidence --------------------------------------------------------------------------
    # Each artifact is labelled with its evidence TYPE so a tool log is not mistaken for proof
    # of exploitation, and the store note makes clear that an s3:// key is a reference into the
    # evidence store rather than something the reader can open from this document.
    parts.append(Paragraph("Evidence", styles["Label"]))
    # Phase 3.2: prefer the RECORDS, which carry each artifact's id, capture timestamp and
    # SHA-256 digest. The two older shapes remain as fallbacks, in order, so a group built by
    # legacy code or a test double renders exactly as it did before.
    evidence_records = [r for r in (g.get("evidence_records") or [])
                        if r.evidence_type != "screenshot"]
    typed_evidence = g.get("evidence_items") or []
    if evidence_records:
        parts.append(
            Paragraph(f"{len(evidence_records)} stored artifact(s):", styles["Small"])
        )
        for record in evidence_records:
            parts.append(
                Paragraph(
                    f"[{_esc(_evidence_type_label(record.evidence_type))}] "
                    f"{_esc(record.artifact_id)} · captured {_esc(record.captured_label())}",
                    styles["Small"],
                )
            )
            parts.append(Paragraph(f"• {_esc(record.storage_uri)}", styles["Mono"]))
            parts.append(Paragraph(f"  {_esc(record.checksum_label())}", styles["Mono"]))
        # Scope note for tool-run-granular artefacts (see N.EVIDENCE_SHARED_SCOPE_NOTE).
        # Emitted only when one is actually listed, so a finding whose evidence is entirely
        # per-finding never carries a caveat that does not apply to it.
        if any(r.evidence_type == "log_excerpt" for r in evidence_records):
            parts.append(Paragraph(N.EVIDENCE_SHARED_SCOPE_NOTE, styles["Small"]))
        parts.append(Paragraph(N.EVIDENCE_INTEGRITY_NOTE, styles["Small"]))
        parts.append(Paragraph(N.EVIDENCE_STORE_NOTE, styles["Small"]))
    elif typed_evidence:
        parts.append(Paragraph(f"{len(typed_evidence)} stored artifact(s):", styles["Small"]))
        for etype, uri in typed_evidence:
            parts.append(Paragraph(f"[{_esc(_evidence_type_label(etype))}]", styles["Small"]))
            parts.append(Paragraph(f"• {_esc(uri)}", styles["Mono"]))
        if any((etype or "").strip().lower() == "log_excerpt" for etype, _ in typed_evidence):
            parts.append(Paragraph(N.EVIDENCE_SHARED_SCOPE_NOTE, styles["Small"]))
        parts.append(Paragraph(N.EVIDENCE_STORE_NOTE, styles["Small"]))
    elif g["evidence_uris"]:
        parts.append(Paragraph(f"{len(g['evidence_uris'])} stored artifact(s):", styles["Small"]))
        for uri in g["evidence_uris"]:
            parts.append(Paragraph(f"• {_esc(uri)}", styles["Mono"]))
        parts.append(Paragraph(N.EVIDENCE_STORE_NOTE, styles["Small"]))
    else:
        parts.append(
            Paragraph(
                "No evidence artifact was captured for this finding. The finding rests on the "
                "scanning engine's pattern match alone.",
                styles["Small"],
            )
        )

    # Visual evidence, embedded under the finding it belongs to. Fail-soft at every step:
    # a screenshot that cannot be fetched or decoded is simply omitted (the finding and the
    # rest of the report still render), and nothing is drawn when there are none.
    for uri, checksum in g.get("screenshots") or []:
        image = _screenshot_flowable(uri, mm)
        if image is None:
            continue
        parts.append(Paragraph(f"Screenshot (sha {_esc(checksum[:12])}):", styles["Small"]))
        parts.append(image)
    parts.append(Spacer(1, 2 * mm))

    # --- Remediation -----------------------------------------------------------------------
    # Pipeline-produced guidance is rendered VERBATIM under a label naming its origin. When the
    # pipeline produced none, standard controls for the weakness class are shown instead, under
    # a label that states explicitly that they are NOT derived from scan evidence -- so a reader
    # can always tell which of the two they are looking at.
    rem_summary = (g.get("remediation_summary") or "").strip()
    # Already normalised to list[str] by _finding_groups; a raw value never reaches .strip().
    rem_steps = _normalise_steps(g.get("remediation_steps"))
    rem_refs = g.get("remediation_references") or []
    if rem_summary or rem_steps or rem_refs:
        parts.append(Paragraph(N.PIPELINE_REMEDIATION_LABEL, styles["Label"]))
        if rem_summary:
            parts.append(Paragraph(_esc(rem_summary), styles["Body"]))
        for step in rem_steps:
            parts.append(Paragraph(f"• {_esc(step)}", styles["Body"]))
        for ref in rem_refs:
            parts.append(Paragraph(f"• {_esc(str(ref))}", styles["Endpoint"]))
    else:
        parts.append(Paragraph(N.GENERATED_CONTROLS_LABEL, styles["Label"]))
        for control in N.controls(weakness):
            parts.append(Paragraph(f"• {_esc(control)}", styles["Body"]))
    parts.append(Spacer(1, 2 * mm))

    # --- References ------------------------------------------------------------------------
    # CWE / CVSS vector / compliance controls, plus the severity-vs-CVSS clarification when
    # the two genuinely differ. The note EXPLAINS two values that are already displayed; it
    # reclassifies nothing.
    ref_bits: list[str] = []
    if g.get("category"):
        ref_bits.append(str(g["category"]).upper())
    for ref in weakness.references:
        if ref not in ref_bits:
            ref_bits.append(ref)
    cve = _recover_cve(g.get("template_id"), g.get("title"))
    if cve:
        ref_bits.append(cve.upper())
    if g["cvss_vector"]:
        ref_bits.append(str(g["cvss_vector"]))
    if g["compliance"]:
        ref_bits.append(
            "; ".join(f"{framework_name(fw)} {cid}" for (fw, cid, _) in g["compliance"])
        )
    if ref_bits:
        parts.append(Paragraph("References", styles["Label"]))
        parts.append(Paragraph(_esc(" · ".join(ref_bits)), styles["Small"]))
    sev_note = N.severity_cvss_note(g["severity"], cvss_val, band)
    if sev_note:
        parts.append(Paragraph(_esc(sev_note), styles["Small"]))

    # --- Pagination (Phase 4.2) ------------------------------------------------------------
    #
    # THE DEFECT. This function used to return `KeepTogether(parts)` -- the ENTIRE finding as
    # one atomic flowable. Measured against the 255mm usable frame, a finding block is 369mm at
    # a SINGLE location and grows from there (695mm at 20 locations, 6,728mm at 400). So the
    # constraint was NEVER satisfiable for any finding: ReportLab pushed each block to a fresh
    # page, failed to fit it there too, and then split it anyway at an arbitrary point -- the
    # worst of both worlds, paying a page break for a guarantee it could not deliver.
    #
    # THE FIX, TARGETED. Keep together only the group that must not be separated -- the title,
    # identity line, fact card and assurance chips, i.e. everything a reader needs to know WHAT
    # finding they are looking at. That group is small enough to actually fit a frame, so the
    # guarantee is real. The narrative, locations, evidence and remediation that follow are
    # allowed to flow across pages, which is normal and expected for long-form content.
    #
    # Pagination control is NOT globally disabled: `keepWithNext` on the header group still
    # prevents a heading stranded at a page foot, and every other KeepTogether in this module
    # (remediation buckets, evidence cards, compliance/ATT&CK cards, the manifest) is untouched.
    # `header_end` is captured right after the assurance panel is appended, rather than being a
    # hard-coded index, so inserting or removing a flowable above cannot silently move the
    # boundary and split the card away from its chips.
    header = KeepTogether(parts[:header_end])
    body = parts[header_end:]
    # Bind the header to whatever follows it so the card cannot sit alone at a page bottom.
    header.keepWithNext = True
    return [header, *body]


def _screenshot_flowable(storage_uri: str, mm):
    """Fetch a stored screenshot and return a reportlab Image scaled to the page width.

    Returns None on ANY problem -- missing object, storage outage, unreadable bytes -- so a
    broken image can never break report generation. Reading happens here, at render time;
    the capture itself ran during the scan (see scanner_engine/screenshot.py)."""
    from io import BytesIO

    try:
        from reportlab.platypus import Image as RLImage

        from apps.api.core.config import get_settings
        from apps.api.scanner_engine.storage_provider import get_storage_provider

        # s3://bucket/key -> key. Anything else is not a fetchable evidence object.
        if not storage_uri.startswith("s3://"):
            return None
        _, _, rest = storage_uri.partition("s3://")
        bucket, _, key = rest.partition("/")
        if not key:
            return None

        # The BUCKET must be the evidence bucket, checked here rather than trusted from the
        # stored string. Every writer derives the URI from evidence_store, which hardcodes
        # `s3_bucket_evidence` -- so today this cannot diverge, and this is a defence in depth
        # rather than a live exploit. But the check belongs here because this is the one place
        # the report turns a stored STRING into a fetch: without it, an `evidence.storage_uri`
        # that ever came to read `s3://mbs-reports/<other-tenant>/...` (a future ingest path, a
        # migration, a direct DB write) would be fetched and EMBEDDED in a rendered PDF, and
        # the row's own workspace scoping would not stop it -- tenancy scopes which evidence
        # ROWS this report may read, not which bucket a row's text points at.
        #
        # Fails closed by returning None, the same way every other failure in this function
        # does, so an out-of-bucket URI renders no image instead of raising.
        settings = get_settings()
        if bucket != settings.s3_bucket_evidence:
            return None

        data = get_storage_provider(bucket).get(key)
        if not data:
            return None

        img = RLImage(BytesIO(data))

        # --- Fit the image to the page, preserving aspect ratio (Phase 4.2) ----------------
        #
        # TWO DEFECTS THIS REPLACES:
        #
        #  1. The old test was `img.imageWidth > max_width`, comparing a PIXEL count against a
        #     POINT value (160*mm == 453pt). Any capture narrower than 453px was left at its
        #     native pixel size, and -- because ReportLab treats those units as points -- a
        #     1920px-wide screenshot only ever scaled DOWN by luck of that mismatch.
        #  2. Only the WIDTH was ever constrained. A tall capture (a full-page screenshot of a
        #     long document) scaled to 160mm wide could compute a height of 400mm+ inside a
        #     255mm frame, so the image could not fit any page and ReportLab had to scale or
        #     clip it at draw time.
        #
        # Both are fixed by scaling on whichever axis binds first, always by the SAME ratio, so
        # the aspect ratio is exact. The height budget is deliberately well under the frame:
        # an image shares its page with the finding's heading and evidence lines, and a picture
        # that exactly fills the frame forces everything around it onto another page.
        native_w = float(img.imageWidth or 0)
        native_h = float(img.imageHeight or 0)
        if native_w > 0 and native_h > 0:
            max_width = 160.0 * mm
            max_height = 170.0 * mm  # ~2/3 of the 255mm frame; leaves room for its caption
            ratio = min(max_width / native_w, max_height / native_h, 1.0)
            img.drawWidth = native_w * ratio
            img.drawHeight = native_h * ratio
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
        # --- MBS.PT report typography -----------------------------------------------------
        # Widened from the single _BRAND colour to a named set, so cover / section / finding
        # / footer text are styled consistently instead of ad hoc at each call site.
        "CoverBrand": ParagraphStyle(
            "CoverBrand", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=30,
            textColor=colors.HexColor(B.DARK), leading=34, spaceAfter=2,
        ),
        "CoverTitle": ParagraphStyle(
            "CoverTitle", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=17,
            textColor=colors.HexColor(B.DARK), leading=21,
        ),
        "CoverSub": ParagraphStyle(
            "CoverSub", parent=base["Normal"], fontSize=11.5,
            textColor=colors.HexColor(B.MUTED), leading=15, spaceBefore=2,
        ),
        "Section": ParagraphStyle(
            "Section", parent=base["Heading1"], fontSize=14.5,
            textColor=colors.HexColor(B.DARK), spaceBefore=0, spaceAfter=3,
        ),
        "SubSection": ParagraphStyle(
            "SubSection", parent=base["Heading2"], fontSize=11,
            textColor=colors.HexColor(B.DARK), spaceBefore=5, spaceAfter=2,
        ),
        "FindingTitle": ParagraphStyle(
            "FindingTitle", parent=base["Heading2"], fontSize=11.5,
            textColor=colors.HexColor(B.INK), spaceBefore=3, spaceAfter=1,
        ),
        "Label": ParagraphStyle(
            "Label", parent=base["Normal"], fontSize=8.5, fontName="Helvetica-Bold",
            textColor=colors.HexColor(B.MUTED), leading=11,
        ),
        # Long URLs/endpoints: 7.5pt Courier with a small leading, and CJK-style wrapping so a
        # single unbroken URL wraps mid-token instead of overflowing the frame.
        "Endpoint": ParagraphStyle(
            "Endpoint", parent=base["Normal"], fontName="Courier", fontSize=7.5, leading=10,
            wordWrap="CJK", textColor=colors.HexColor(B.INK),
        ),
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


def render_risk_assessment(model: "ReportModel", assessment) -> bytes:
    """Client Risk Assessment PDF, rendered from an ISSUED assessment's FROZEN snapshot.

    Deliberately NOT a second report pipeline: it uses the same reportlab setup, the same
    `_styles`/`_table_style` helpers, the same `_score_band` and the same document conventions
    as the executive report. The ONE difference that matters is the data source -- every number
    below is read out of `assessment.summary`, the snapshot frozen at issue time, NOT
    recomputed from today's findings. That is what makes a re-render of a March assessment in
    June still say what it said in March.

    `data` is still passed so the project name and the shared chrome match the other reports;
    its live figures are deliberately not printed as the assessment's numbers.
    """
    model = _as_model(model)

    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

    summary = assessment.summary or {}
    styles = _styles(getSampleStyleSheet, ParagraphStyle, colors)
    buf = BytesIO()
    story = []

    # --- Phase 4.5: the SHARED MBS.PT document chrome -------------------------------------
    #
    # This renderer previously used a bare SimpleDocTemplate: no cover, no Table of Contents,
    # no running header/footer, no page numbers, no bookmarks -- and its H1 read "MBS.SC",
    # branding retired everywhere else in the suite. One of three report types looked like a
    # different product.
    #
    # It now builds through _cover_story / _toc_story / _section / _build_document, the SAME
    # path the Executive and Technical reports use, so it inherits the canonical logo, cover,
    # classification line, contact block, running header/footer, "Page N of M" (Phase 4.4) and
    # PDF outline automatically. No second branding or chrome implementation is introduced.
    story += _cover_story("Client Risk Assessment", model, styles, colors, mm)
    story += _toc_story(styles, mm)

    # --- 1. Assessment Details ------------------------------------------------------------
    story += _section(1, "Assessment Details", styles, colors, mm)
    detail_rows: list[tuple[str, object]] = [
        ("Project", model.project_name),
        ("Assessment", assessment.title),
    ]
    if assessment.period_start and assessment.period_end:
        detail_rows.append((
            "Period",
            f"{assessment.period_start:%Y-%m-%d} to {assessment.period_end:%Y-%m-%d}",
        ))
    if assessment.issued_at:
        # ISSUE date, not render date: the document describes a fixed point in time, so
        # stamping "now" would misrepresent a re-download as a fresh assessment.
        detail_rows.append(("Issued", f"{assessment.issued_at:%Y-%m-%d %H:%M UTC}"))
    story.append(_card(detail_rows, styles, colors, mm, accent=B.CYAN))
    story.append(
        Paragraph(
            "Every figure in this document is read from the snapshot frozen when this "
            "assessment was issued. It does not change as new scans run, which is what lets "
            "an assessment re-downloaded months later still state what it stated on the "
            "issue date.",
            styles["Small"],
        )
    )
    story.append(Spacer(1, 5 * mm))

    # --- 2. Security Posture ----------------------------------------------------------------
    score = summary.get("security_score")
    band = summary.get("score_band") or (_score_band(score) if score is not None else "N/A")
    story += _section(2, "Security Posture", styles, colors, mm)

    # Posture panel in the SAME shape the Executive report uses, but fed entirely from the
    # FROZEN summary -- no live value is read and nothing is recomputed. The score band comes
    # from the snapshot when it has one, falling back to the ONE canonical _score_band (R-04:
    # "Fair", never "Moderate"); the colour comes from the canonical score-band palette.
    posture_cells = [
        ("SECURITY SCORE", f"{score}/100" if score is not None else "N/A", band,
         B.score_band_color(band)),
        ("UNIQUE ISSUES", str(summary.get("unresolved_issue_count", 0)),
         f"{summary.get('active_findings', 0)} recorded finding(s)", B.INK),
        ("AFFECTED ASSETS", str(len(summary.get("affected_assets") or [])),
         f"{summary.get('affected_endpoint_count', 0)} endpoint(s)", B.INK),
    ]
    panel = Table(
        [[
            Paragraph(
                f"<font size=6 color='{B.MUTED}'>{_esc(caption)}</font><br/>"
                f"<font size=15 color='{ink}'><b>{_esc(value)}</b></font><br/>"
                f"<font size=6.5 color='{B.MUTED}'>{_esc(sub)}</font>",
                styles["Cell"],
            )
            for caption, value, sub, ink in posture_cells
        ]],
        colWidths=[56.6 * mm] * 3,
        hAlign="LEFT",
    )
    panel.setStyle(
        TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(B.PAPER_TINT)),
            ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor(B.RULE)),
            ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor(B.RULE)),
            ("LINEBEFORE", (0, 0), (0, -1), 2.4, colors.HexColor(B.score_band_color(band))),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ])
    )
    story.append(panel)
    story.append(
        Paragraph(
            # R-01 vocabulary, identical to the other two reports: an issue is the thing that
            # gets fixed, a finding is one observed location of it.
            "“Unique issues” counts distinct problems; “recorded findings” counts the "
            "individual locations at which they were observed. One issue seen at several "
            "locations is remediated once. Findings are detections produced by the security "
            "pipeline and are not all confirmed vulnerabilities.",
            styles["Small"],
        )
    )
    story.append(Spacer(1, 5 * mm))

    # --- 3. Severity Distribution -----------------------------------------------------------
    story += _section(3, "Severity Distribution", styles, colors, mm)
    active_by_sev = summary.get("active_severity_counts") or {}

    # Severity bar in the canonical SEVERITY palette, built from the FROZEN counts. Same visual
    # language as the Executive report; values are the snapshot's, never recomputed.
    _order = [s for s in _SEVERITY_ORDER if active_by_sev.get(s, 0) > 0]
    _total = sum(active_by_sev.get(s, 0) for s in _order)
    if _total:
        widths, labels, bar_style = [], [], [
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]
        for idx, sev in enumerate(_order):
            n = active_by_sev.get(sev, 0)
            widths.append(max(12.0, 170.0 * n / _total))
            labels.append(
                Paragraph(f"<font size=8 color='#ffffff'><b>{n}</b></font>", styles["Cell"])
            )
            bar_style.append(
                ("BACKGROUND", (idx, 0), (idx, 0), colors.HexColor(B.severity_color(sev)))
            )
        _scale = 170.0 / sum(widths)
        bar = Table([labels], colWidths=[w * _scale * mm for w in widths], hAlign="LEFT")
        bar.setStyle(TableStyle(bar_style))
        story.append(bar)
        story.append(
            Paragraph(
                "<font size=7>"
                + " · ".join(
                    f"<font color='{B.severity_color(s)}'>&#9632;</font> "
                    f"{s.capitalize()} {active_by_sev.get(s, 0)}"
                    for s in _order
                )
                + f"</font>  <font size=7 color='{B.MUTED}'>— active recorded findings by "
                f"severity ({_total} total), frozen at issue time</font>",
                styles["Small"],
            )
        )
        story.append(Spacer(1, 3 * mm))

    sev_rows = [["Severity", "Active recorded findings"]]
    for sev in _SEVERITY_ORDER:
        sev_rows.append([sev.capitalize(), str(active_by_sev.get(sev, 0))])
    tbl = Table(sev_rows, colWidths=[80 * mm, 60 * mm])
    tbl.setStyle(_table_style(colors))
    story.append(tbl)
    story.append(Spacer(1, 5 * mm))

    # --- 4. Affected Assets -----------------------------------------------------------------
    story += _section(4, "Affected Assets", styles, colors, mm)
    frozen_assets = summary.get("affected_assets") or []
    if frozen_assets:
        shown = ", ".join(_esc(a) for a in frozen_assets[:15])
        more = f" (+{len(frozen_assets) - 15} more)" if len(frozen_assets) > 15 else ""
        story.append(
            Paragraph(
                f"{len(frozen_assets)} inventoried asset/host(s) were affected at issue time: "
                f"{shown}{more}. {summary.get('affected_endpoint_count', 0)} distinct "
                "endpoint(s) were recorded across them — an asset is the scanned system, an "
                "endpoint is a specific location on it.",
                styles["Body"],
            )
        )
    else:
        story.append(
            Paragraph(
                "No inventoried assets were recorded as affected at issue time.",
                styles["Body"],
            )
        )
    story.append(Spacer(1, 5 * mm))

    top_risks = summary.get("top_risks") or []
    story += _section(5, "Key Risks", styles, colors, mm)
    if top_risks:
        rows = [["Issue", "Severity", "Business risk", "CVSS", "Occurrences"]]
        for g in top_risks:
            rows.append([
                Paragraph(_esc(g.get("title")), styles["Cell"]),
                _esc(g.get("severity")),
                # N/A, never 0.0 -- "not scored" and "scored zero" stay distinct exactly as
                # they do everywhere else in the reporting layer.
                "N/A" if g.get("max_risk") is None else str(g["max_risk"]),
                "N/A" if g.get("max_cvss") is None else str(g["max_cvss"]),
                str(g.get("endpoint_count", 0)),
            ])
        tbl = Table(rows, colWidths=[64 * mm, 22 * mm, 28 * mm, 20 * mm, 26 * mm])
        tbl.setStyle(_table_style(colors))
        story.append(tbl)
        story.append(
            Paragraph(
                # Same column vocabulary the Executive report uses, so the two documents can
                # never be read as counting different things.
                "One row per unique issue, highest business risk first. “Occurrences” is how "
                "many recorded findings each issue aggregates — not a count of distinct "
                "vulnerabilities. “N/A” means no score was derived, which is unassessed rather "
                "than low risk.",
                styles["Small"],
            )
        )
    else:
        story.append(Paragraph("No active risks were outstanding at issue time.", styles["Body"]))
    story.append(Spacer(1, 5 * mm))

    progress = summary.get("remediation_progress") or {}
    story += _section(6, "Remediation Progress", styles, colors, mm)
    prog_rows = [["Metric", "Count"]]
    for label, key in (
        ("Total items", "total"), ("Proposed", "proposed"), ("Accepted", "accepted"),
        ("In progress", "in_progress"), ("Awaiting verification", "awaiting_verification"),
        ("Verified", "verified"), ("Closed", "closed"), ("Risk accepted", "risk_accepted"),
        ("Overdue", "overdue"),
    ):
        prog_rows.append([label, str(progress.get(key, 0))])
    tbl = Table(prog_rows, colWidths=[80 * mm, 60 * mm])
    tbl.setStyle(_table_style(colors))
    story.append(tbl)
    story.append(
        Paragraph(
            f"Remediation completion: <b>{progress.get('completion_percent', 0)}%</b> "
            f"({progress.get('resolved', 0)} of {progress.get('total', 0)} item(s) resolved), "
            "as recorded at issue time.",
            styles["Body"],
        )
    )
    story.append(Spacer(1, 5 * mm))

    # --- 7. Management Summary --------------------------------------------------------------
    # The issued narrative, VERBATIM. It is authored content frozen onto the assessment; the
    # report never rewrites, summarises or generates it.
    if assessment.narrative:
        story += _section(7, "Management Summary & Recommendations", styles, colors, mm)
        for line in str(assessment.narrative).split("\n"):
            if line.strip():
                story.append(Paragraph(_esc(line), styles["Body"]))
        story.append(Spacer(1, 4 * mm))
        story.append(
            Paragraph(
                "Prepared and issued by "
                f"{B.BRAND_NAME} · {B.CONTACT_EMAIL} · {B.CONTACT_PHONE}",
                styles["Small"],
            )
        )

    # Built through the SAME document builder as the other two reports: cover template, running
    # header/footer, two-pass TOC with real page numbers, PDF outline and "Page N of M".
    _build_document(buf, f"Risk Assessment — {model.project_name}", "Client Risk Assessment",
                    model.project_name, story)
    return buf.getvalue()


def render(report_type: str, data: ReportData, assessment=None) -> bytes:
    """Render a report from canonical `ReportData`.

    Step 4: this is the DATA -> MODEL -> RENDER seam. The public signature is unchanged -- it
    still takes `ReportData`, so `reports.service` and every existing caller are untouched --
    but the model is built here and the renderers below consume ONLY the model. That keeps the
    architecture honest without breaking a production import path.

    A caller that already holds a `ReportModel` can bypass this and call the render_* functions
    directly; that is the intended contract going forward."""
    from apps.api.modules.reports.model import build_report_model

    model = build_report_model(data)

    if report_type == "executive":
        return render_executive(model)
    if report_type == "technical":
        return render_technical(model)
    if report_type == "risk_assessment":
        # An assessment PDF is meaningless without the frozen snapshot it renders -- refuse
        # rather than silently falling back to live data, which would defeat the freeze.
        if assessment is None:
            raise ValueError("risk_assessment reports require the issued assessment to render")
        return render_risk_assessment(model, assessment)
    raise ValueError(f"Unknown report type: {report_type}")
