"""PDF rendering for reports. reportlab is imported lazily inside the render
functions so importing this module (e.g. for the service/CRUD path) doesn't
require reportlab to be installed."""

import html
import re
from datetime import datetime, timezone

from apps.api.modules.compliance.catalog import framework_name
from apps.api.modules.reports.data import _ACTIVE_STATUSES, _SEVERITY_ORDER, ReportData
from apps.api.modules.reports import _branding as B
from apps.api.modules.reports.classification import _recover_cve, classify_row
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


def _remediation_plan_story(data, styles, colors, mm):
    """Remediation Plan: existing findings, bucketed by their existing severity.

    Contains no invented guidance. Each row states the finding id, title, severity, business
    risk and how many locations it affects -- all values already computed elsewhere. Where the
    pipeline HAS produced remediation text it is surfaced in the finding's own block, verbatim;
    it is never synthesised here."""
    from reportlab.platypus import KeepTogether, Paragraph, Spacer

    groups = _finding_groups([v for v in data.vulns if v.status in _ACTIVE_STATUSES])
    by_sev: dict[str, list[dict]] = {}
    for g in groups:
        by_sev.setdefault((g["severity"] or "").lower(), []).append(g)

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
        for g in sorted(bucket, key=lambda x: -(x["final_risk_score"] or -1.0)):
            risk = f"{g['final_risk_score']:.1f}" if g["final_risk_score"] is not None else "N/A"
            locs = len(g["matched_ats"]) or g["occurrence_count"]
            rows.append((
                g.get("finding_id") or "N/A",
                Paragraph(
                    f"{_esc(g['title'])}<br/><font size=7.5 color='{B.MUTED}'>"
                    f"risk {risk} · {locs} location(s)</font>",
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


def _evidence_story(data, styles, colors, mm):
    """Evidence & Screenshots: the artifacts actually stored for these findings.

    Lists only what the evidence store holds -- nothing is fabricated, and a finding with no
    artifacts is simply not listed. Screenshots are embedded where they can be fetched and
    decoded; a screenshot that cannot be retrieved is skipped rather than shown as a broken
    placeholder."""
    from reportlab.platypus import KeepTogether, Paragraph, Spacer

    out: list = []
    listed = 0
    for g in _finding_groups(data.vulns):
        items = g.get("evidence_items") or []
        shots = g.get("screenshots") or []
        if not items and not shots:
            continue
        listed += 1
        rows = [
            ("Finding ID", g.get("finding_id") or "N/A"),
            ("Title", g["title"]),
            ("Asset", (g.get("asset_values") or ["N/A"])[0] if g.get("asset_values") else "N/A"),
        ]
        loc = (g["matched_ats"] or ["N/A"])[0]
        rows.append(("Endpoint", Paragraph(_esc(loc), styles["Endpoint"])))
        for etype, uri in items:
            rows.append((_evidence_type_label(etype), Paragraph(_esc(uri), styles["Endpoint"])))
        # Screenshots are INDEXED here, not re-embedded: the image itself is already shown in
        # the finding's own block, and fetching it a second time would double the object-store
        # reads for every screenshot in the report. This section states that visual evidence
        # exists, its checksum, and which finding it belongs to.
        for _uri, checksum in shots:
            rows.append(
                ("Screenshot", f"captured · sha {str(checksum)[:12]} (shown with the finding)")
            )
        out.append(
            KeepTogether([
                _card(rows, styles, colors, mm, accent=B.severity_color(g["severity"])),
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


def _compliance_cards(data, styles, colors, mm):
    """Compliance coverage as one card per framework, listing its mapped controls.

    Same mappings, same counts -- only the layout changes. Nothing is added to or removed from
    the compliance catalogue."""
    from reportlab.platypus import KeepTogether, Paragraph, Spacer

    per_fw: dict[str, dict[str, str]] = {}
    for v in data.vulns:
        for framework, control_id, desc in v.compliance or []:
            per_fw.setdefault(framework, {})[control_id] = desc

    if not per_fw:
        return [Paragraph("No findings mapped to compliance controls.", styles["Body"])]

    out = []
    for framework in sorted(per_fw):
        controls = per_fw[framework]
        rows = [(cid, controls[cid] or "—") for cid in sorted(controls)]
        out.append(
            KeepTogether([
                Paragraph(f"{framework_name(framework)} — {len(controls)} control(s)",
                          styles["SubSection"]),
                Spacer(1, 1.5 * mm),
                _card(rows, styles, colors, mm, accent=B.CYAN, label_w=34),
                Spacer(1, 4 * mm),
            ])
        )
    return out


def _attack_cards(data, styles, colors, mm):
    """MITRE ATT&CK coverage grouped by tactic. Counts and mappings are unchanged."""
    from reportlab.platypus import KeepTogether, Paragraph, Spacer

    if not data.attack_techniques:
        return [Paragraph("No active issues mapped to ATT&amp;CK techniques.", styles["Body"])]

    by_tactic: dict[str, list[tuple[str, str, int]]] = {}
    for tactic, tech_id, tech_name, count in data.attack_techniques:
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


def _technical_metadata_rows(g: dict) -> list[tuple[str, str]]:
    """(label, value) rows for the Technical Report's metadata block, in a fixed order.

    P2-4. Every value is taken VERBATIM from the group; missing values become "N/A" so the
    block has a stable shape and a reader can tell "not recorded" from "not applicable".
    Optional fields (Category, CVE) are omitted entirely when absent rather than padded with
    N/A, so the block does not grow noise for findings that never had them.

    Nothing here is derived, inferred or scored -- it is provenance, not assessment."""
    rows: list[tuple[str, str]] = [
        ("Tool", ", ".join(g.get("tools") or []) or "N/A"),
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
                "remediation_steps": getattr(rep, "remediation_steps", None),
                "remediation_references": list(getattr(rep, "remediation_references", None) or []),
                "compliance": sorted(compliance),
                "evidence_uris": evidence_uris,
                "evidence_items": evidence_items,
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
        key = f"sec-{abs(hash(raw)) & 0xFFFFFFFF:08x}"

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


def _esc(text) -> str:
    return html.escape(str(text)) if text is not None else ""


def _cover_story(report_title: str, data: ReportData, styles, colors, mm):
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
            ["Project", _esc(data.project_name)],
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
    try:
        doc.multiBuild(story)
    except Exception:
        # A TOC that cannot resolve must not cost the reader the whole report.
        doc.build(story)


def render_executive(data: ReportData) -> bytes:
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
    story += _cover_story("Executive Report", data, styles, colors, mm)
    story += _toc_story(styles, mm)

    story += _section(1, "Executive Summary", styles, colors, mm)

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
    # STEP 4 -- how many of those findings actually move the score. Without this an executive
    # reads "157 findings, score 25" and cannot tell that 152 of them are informational and
    # cost nothing. States the count only; it does not reinterpret or reweight anything.
    story.append(
        Paragraph(
            f"Of these, <b>{_score_impacting_count(data)}</b> finding(s) affect the security "
            "score. Informational findings and technology detections are reported for "
            "visibility and carry no score penalty.",
            styles["Body"],
        )
    )
    story.append(Spacer(1, 6 * mm))

    # STEP 4 -- VERIFICATION summary. Severity says how bad a finding would be; verification says
    # how much evidence supports it. Executives were shown only severity, so 157 detections read
    # as 157 confirmed vulnerabilities. Both axes are now stated, and the sentence below names
    # the distinction explicitly rather than leaving it to be inferred.
    story += _section(2, "Findings Summary", styles, colors, mm)
    story.append(Paragraph("Findings by verification status", styles["SubSection"]))
    ver_counts = _verification_summary(data)
    ver_rows = [["Verification", "Count"]]
    for state in (VERIFIED, PARTIALLY_VERIFIED, UNVERIFIED):
        ver_rows.append([verification_label(state), str(ver_counts[state])])
    vtbl = Table(ver_rows, colWidths=[80 * mm, 40 * mm])
    vtbl.setStyle(_table_style(colors))
    story.append(vtbl)
    story.append(
        Paragraph(
            "Findings are detections produced by the security pipeline; verification status "
            "indicates the level of evidence supporting each finding. Severity describes "
            "potential impact and is independent of verification: an unverified finding is not "
            "necessarily a false positive, and a high-severity finding is not confirmed "
            "exploitation unless its verification status says so.",
            styles["Small"],
        )
    )
    story.append(Spacer(1, 6 * mm))

    # Severity summary table
    story.append(Paragraph("Findings by severity", styles["SubSection"]))
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
    story += _section(3, "Affected Assets & Endpoints", styles, colors, mm)
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
    story += _section(4, "Key Risks", styles, colors, mm)
    story.append(Paragraph("Ranked by business risk score", styles["SubSection"]))
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
    story += _section(5, "Compliance Coverage", styles, colors, mm)
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
    story += _section(6, "MITRE ATT&CK Coverage", styles, colors, mm)
    if data.attack_techniques:
        att_rows = [["Tactic", "Technique", "ID", "Issues"]]
        for tactic, tid, tname, count in data.attack_techniques[:15]:
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

    story += _section(7, "Conclusion", styles, colors, mm)
    story.append(
        Paragraph(
            f"This assessment recorded {data.active_vulns} active finding(s) across "
            f"{data.total_vulns} total, producing a security score of "
            f"{data.security_score}/100 ({band}). Findings are detections produced by the "
            "security pipeline; verification status indicates the level of evidence "
            "supporting each one. Remediation should follow the priority order in Key Risks, "
            "highest business risk first. Full technical detail, evidence and reproduction "
            "metadata are provided in the accompanying Technical Report.",
            styles["Body"],
        )
    )

    _build_document(buf, f"Executive Report — {data.project_name}", "Executive Report",
                    data.project_name, story)
    return buf.getvalue()


def render_technical(data: ReportData) -> bytes:
    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

    styles = _styles(getSampleStyleSheet, ParagraphStyle, colors)
    buf = BytesIO()
    story = []

    story += _cover_story("Technical Report", data, styles, colors, mm)
    story += _toc_story(styles, mm)

    # --- 1. Assessment Overview ----------------------------------------------------------
    story += _section(1, "Assessment Overview", styles, colors, mm)
    story.append(
        Paragraph(
            f"Security score {data.security_score}/100 · {data.total_vulns} finding(s) "
            f"({data.active_vulns} active).",
            styles["Body"],
        )
    )
    story.append(Paragraph(_findings_summary(data), styles["Small"]))
    story.append(Spacer(1, 3 * mm))
    ver = _verification_summary(data)
    story.append(
        Paragraph(
            f"Verification of active findings — Verified: {ver[VERIFIED]} · "
            f"Partially Verified: {ver[PARTIALLY_VERIFIED]} · Unverified: {ver[UNVERIFIED]}. "
            f"{_score_impacting_count(data)} finding(s) affect the security score.",
            styles["Small"],
        )
    )

    # --- 2. Scope & Methodology ----------------------------------------------------------
    # Describes ONLY what the pipeline actually does; no methodology is claimed that the
    # system does not perform.
    story += _section(2, "Scope & Methodology", styles, colors, mm)
    tools = sorted({v.tool_name for v in data.vulns if getattr(v, "tool_name", None) and v.tool_name != "N/A"})
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
    sev_rows = [["Severity", "All findings", "Active"]]
    for sev in ("critical", "high", "medium", "low", "info"):
        sev_rows.append([
            sev.capitalize(),
            str(data.severity_counts.get(sev, 0)),
            str(data.active_severity_counts.get(sev, 0)),
        ])
    stbl = Table(sev_rows, colWidths=[60 * mm, 45 * mm, 45 * mm])
    stbl.setStyle(_table_style(colors))
    story.append(stbl)

    if not data.vulns:
        story.append(Spacer(1, 4 * mm))
        story.append(Paragraph("No findings recorded for this project.", styles["Body"]))
        _build_document(buf, f"Technical Report — {data.project_name}", "Technical Report",
                        data.project_name, story)
        return buf.getvalue()

    # --- 4. Detailed Findings ------------------------------------------------------------
    # One block per VULNERABILITY, not per row: a template observed at many URLs is a single
    # finding with its affected locations listed, instead of the same severity/CVSS/risk text
    # repeated once per location. Presentation only -- see _finding_groups.
    story += _section(4, "Detailed Findings", styles, colors, mm)
    for i, g in enumerate(_finding_groups(data.vulns), 1):
        story.append(_finding_block(i, g, styles, colors, Paragraph, Table, TableStyle, mm))
        story.append(Spacer(1, 4 * mm))

    # --- 5. Evidence & Screenshots -------------------------------------------------------
    story += _section(5, "Evidence & Screenshots", styles, colors, mm)
    story += _evidence_story(data, styles, colors, mm)

    # --- 6. Compliance Coverage ----------------------------------------------------------
    story += _section(6, "Compliance Coverage", styles, colors, mm)
    story += _compliance_cards(data, styles, colors, mm)

    # --- 7. MITRE ATT&CK -----------------------------------------------------------------
    story += _section(7, "MITRE ATT&CK Coverage", styles, colors, mm)
    story += _attack_cards(data, styles, colors, mm)

    # --- 8. Remediation Plan -------------------------------------------------------------
    story += _section(8, "Remediation Plan", styles, colors, mm)
    story += _remediation_plan_story(data, styles, colors, mm)

    # --- 9. Appendix ---------------------------------------------------------------------
    story += _section(9, "Appendix", styles, colors, mm)
    story.append(
        Paragraph(
            "Finding identifiers (MBS-XXXXXXXX) are derived from each finding's stored "
            "identity and remain stable across report regenerations, so they can be quoted "
            "in correspondence. Fields shown as N/A were not present in the scan evidence "
            "and have not been inferred.",
            styles["Small"],
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(
        Paragraph(
            f"Report produced by {B.BRAND_NAME} · {B.CONTACT_EMAIL} · {B.CONTACT_PHONE}",
            styles["Small"],
        )
    )

    _build_document(buf, f"Technical Report — {data.project_name}", "Technical Report",
                    data.project_name, story)
    return buf.getvalue()


def _finding_block(idx, g: dict, styles, colors, Paragraph, Table, TableStyle, mm):
    """Render ONE vulnerability (a group from _finding_groups), with its affected locations
    listed once at the end instead of the whole block repeating per location."""
    from reportlab.platypus import KeepTogether, Spacer

    color = _SEVERITY_COLORS.get(g["severity"], "#374151")
    # Detection vs vulnerability, stated in the heading so a technology/WAF/version DETECTION
    # is never read as a confirmed vulnerability. Presentation only -- identity, grouping and
    # scoring are unchanged (see classification.py).
    kind_label = "DETECTION" if g.get("classification") == "detection" else "VULNERABILITY"
    parts = [
        Paragraph(f"{idx}. {_esc(g['title'])}", styles["FindingTitle"]),
        # Stable identifier first: it is what a client quotes back, so it must be visible
        # before any of the technical detail.
        Paragraph(f"Finding ID: {_esc(g.get('finding_id') or 'N/A')}  ·  Type: {kind_label}",
                  styles["Small"]),
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
    # Verification + confidence, stated immediately under the severity line so a scanner MATCH
    # is never read as a demonstrated exploit. This is evidence provenance ONLY: it does not
    # modify severity, CVSS, final_risk_score or the security score, and an unverified CVSS 9.8
    # is still reported as a CVSS 9.8 (see verification.py).
    _ver = g.get("verification") or UNVERIFIED
    _conf = g.get("confidence") or CONFIDENCE_MEDIUM
    parts.append(
        Paragraph(
            f"Verification: {verification_label(_ver)} · Confidence: {confidence_label(_conf)}",
            styles["Small"],
        )
    )
    parts.append(Paragraph(_esc(verification_note(_ver)), styles["Small"]))
    parts.append(Spacer(1, 2 * mm))

    # FACT CARD. The same fields as before (identity, severity, risk, verification, status,
    # asset, endpoint, tool/template/matcher/CVE), presented as one scannable label/value block
    # with a severity-coloured edge instead of a run of loose lines. Values are printed EXACTLY
    # as stored; a missing one renders "N/A" and is never inferred.
    endpoints = g["matched_ats"]
    assets = g.get("asset_values") or []
    card_rows: list[tuple[str, object]] = [
        ("Finding ID", g.get("finding_id") or "N/A"),
        ("Severity", (g["severity"] or "N/A").upper()),
        ("CVSS", f"{g['cvss_score']}" if g["cvss_score"] is not None else "N/A"),
        (
            "Risk",
            f"{g['final_risk_score']:.1f}/10" if g["final_risk_score"] is not None else "N/A",
        ),
        ("Verification", f"{verification_label(_ver)} · {confidence_label(_conf)} confidence"),
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
    if g["cvss_vector"]:
        card_rows.append(("CVSS vector", g["cvss_vector"]))
    parts.append(_card(card_rows, styles, colors, mm, accent=color))
    parts.append(Spacer(1, 2.5 * mm))

    # DESCRIPTION -- the scanner's own account of the finding, rendered VERBATIM.
    # The `vulnerabilities.description` column has always been populated for most findings but
    # was never loaded into the report, so Detailed Findings could show only a bare title.
    # Nothing here is generated, summarised or inferred: when the column is empty the block
    # says the text was not present in the scan evidence rather than inventing one.
    description = (g.get("description") or "").strip()
    parts.append(Paragraph("Description", styles["Label"]))
    parts.append(
        Paragraph(
            _esc(description) if description else "Not available in scan evidence.",
            styles["Body"] if description else styles["Small"],
        )
    )

    # REMEDIATION -- shown ONLY when the pipeline actually produced guidance for this finding.
    # Rendered verbatim; never generated, paraphrased or inferred. When absent the block says
    # so plainly, which is the honest answer for a dataset where no remediation text exists.
    rem_summary = (g.get("remediation_summary") or "").strip()
    rem_steps = (g.get("remediation_steps") or "").strip()
    rem_refs = g.get("remediation_references") or []
    if rem_summary or rem_steps or rem_refs:
        parts.append(Paragraph("Recommendation", styles["Label"]))
        if rem_summary:
            parts.append(Paragraph(_esc(rem_summary), styles["Body"]))
        if rem_steps:
            parts.append(Paragraph(_esc(rem_steps), styles["Small"]))
        for ref in rem_refs:
            parts.append(Paragraph(f"• {_esc(str(ref))}", styles["Endpoint"]))
        parts.append(Spacer(1, 2 * mm))

    # --- Risk breakdown: keep TECHNICAL severity and BUSINESS risk visibly separate ---------
    # A single "risk 10.0" line let a MEDIUM CVSS 5.5 on a critical asset read as a Critical
    # vulnerability: 5.5 x 2.0 = 11.0, capped to 10.0, printed as a bare 10.0 that is
    # indistinguishable from a genuine CVSS 9.8 x 2.0 = 19.6 -> 10.0. Both the CVSS band and
    # the pre-cap product are therefore stated explicitly.
    #
    # PRESENTATION ONLY. Nothing here recomputes or writes risk: cvss_severity_band is a pure
    # function of the CVSS base score the row already carries, and the uncapped product is
    # re-derived read-only from that score and the weight recorded in the stored rationale.
    # final_risk_score is printed exactly as persisted.
    cvss_val = g["cvss_score"]
    band = cvss_severity_band(cvss_val)
    parts.append(
        Paragraph(
            f"CVSS base score: {cvss_val if cvss_val is not None else 'N/A'}"
            f" · CVSS severity: {band or 'N/A'}",
            styles["Small"],
        )
    )
    if g["final_risk_score"] is not None:
        # Recover the criticality/weight from the stored rationale rather than re-deriving it:
        # the report layer has no asset-criticality column, and the rationale is the value the
        # risk engine itself recorded at compute time.
        weight_match = re.search(r"weight ([0-9.]+)", g["risk_rationale"] or "")
        crit_match = re.search(r"criticality '([^']+)'", g["risk_rationale"] or "")
        risk_line = f"Adjusted risk score: {g['final_risk_score']:.1f}/10"
        if crit_match:
            risk_line += f" · Asset criticality: {crit_match.group(1)}"
        if weight_match and cvss_val is not None:
            uncapped = round(cvss_val * float(weight_match.group(1)), 1)
            if uncapped > g["final_risk_score"]:
                risk_line += f" · Uncapped: {uncapped} (CAPPED at 10.0)"
        parts.append(Paragraph(risk_line, styles["Small"]))
        # Stated in words so the distinction survives even if a reader skims the numbers.
        if band and band not in ("None",):
            parts.append(
                Paragraph(
                    f"Asset criticality adjusts business risk only; this finding's technical "
                    f"severity remains CVSS {band}.",
                    styles["Small"],
                )
            )
    if g["risk_rationale"]:
        parts.append(
            Paragraph(
                f"Risk rationale: {_esc(_sanitise_risk_rationale(g['risk_rationale'], g['final_risk_score']))}",
                styles["Small"],
            )
        )
    if g["compliance"]:
        controls = "; ".join(f"{framework_name(fw)} {cid}" for (fw, cid, _) in g["compliance"])
        parts.append(Paragraph(f"Compliance: {_esc(controls)}", styles["Small"]))

    # WHERE the finding was observed. Listed once per DISTINCT location under the single
    # finding, so one issue across many endpoints reads as one vulnerability with a breadth
    # count -- not as many separate vulnerabilities. Long URLs word-wrap in the mono style.
    locations = g["matched_ats"]
    if locations:
        # P2-2: group the (already deduplicated, already sorted) locations BY HOST so a finding
        # spanning many paths on one host reads as one host with N paths, instead of a flat wall
        # of near-identical URLs. Nothing is hidden or merged away: every distinct location is
        # still printed exactly once, and the total count is stated up front.
        by_host = _group_locations_by_host(locations)
        host_note = f" across {len(by_host)} host(s)" if len(by_host) > 1 else ""
        parts.append(
            Paragraph(f"Affected locations ({len(locations)}{host_note}):", styles["Small"])
        )
        for host, paths in by_host:
            if host:
                parts.append(Paragraph(f"{_esc(host)} ({len(paths)}):", styles["Small"]))
            for loc in paths:
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

    # P2-3: label each artifact with its evidence TYPE so a tool log is not mistaken for proof
    # of exploitation. The URI is preserved verbatim -- it is the reference an analyst uses to
    # retrieve the artifact from object storage. Falls back to the untyped list when a row
    # carries no typed items (legacy rows / test doubles), so evidence is never dropped.
    typed_evidence = g.get("evidence_items") or []
    if typed_evidence:
        parts.append(Paragraph(f"Evidence ({len(typed_evidence)}):", styles["Small"]))
        for etype, uri in typed_evidence:
            parts.append(Paragraph(f"[{_esc(_evidence_type_label(etype))}]", styles["Small"]))
            parts.append(Paragraph(f"• {_esc(uri)}", styles["Mono"]))
    elif g["evidence_uris"]:
        parts.append(Paragraph(f"Evidence ({len(g['evidence_uris'])}):", styles["Small"]))
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


def render_risk_assessment(data: ReportData, assessment) -> bytes:
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
    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table

    summary = assessment.summary or {}
    styles = _styles(getSampleStyleSheet, ParagraphStyle, colors)
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title=f"Risk Assessment — {data.project_name}")
    story = []

    story.append(Paragraph("MBS.SC — Client Risk Assessment", styles["H1"]))
    story.append(Paragraph(f"Project: {_esc(data.project_name)}", styles["Meta"]))
    story.append(Paragraph(f"Assessment: {_esc(assessment.title)}", styles["Meta"]))
    if assessment.period_start and assessment.period_end:
        story.append(
            Paragraph(
                f"Period: {assessment.period_start:%Y-%m-%d} to {assessment.period_end:%Y-%m-%d}",
                styles["Meta"],
            )
        )
    if assessment.issued_at:
        # ISSUE date, not render date: the document describes a fixed point in time, so
        # stamping "now" would misrepresent a re-download as a fresh assessment.
        story.append(Paragraph(f"Issued: {assessment.issued_at:%Y-%m-%d %H:%M UTC}", styles["Meta"]))
    story.append(Spacer(1, 8 * mm))

    score = summary.get("security_score")
    band = summary.get("score_band") or (_score_band(score) if score is not None else "N/A")
    story.append(
        Paragraph(
            f"Security Score: <b>{score if score is not None else 'N/A'}/100</b> ({band})",
            styles["Score"],
        )
    )
    story.append(
        Paragraph(
            f"{summary.get('active_findings', 0)} active finding(s) across "
            f"{summary.get('unresolved_issue_count', 0)} distinct issue(s), affecting "
            f"{len(summary.get('affected_assets') or [])} asset(s) and "
            f"{summary.get('affected_endpoint_count', 0)} endpoint(s). These figures are frozen "
            "as of the issue date above and do not change as new scans run.",
            styles["Body"],
        )
    )
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("Active findings by severity", styles["H2"]))
    active_by_sev = summary.get("active_severity_counts") or {}
    sev_rows = [["Severity", "Active"]]
    for sev in _SEVERITY_ORDER:
        sev_rows.append([sev.capitalize(), str(active_by_sev.get(sev, 0))])
    tbl = Table(sev_rows, colWidths=[80 * mm, 40 * mm])
    tbl.setStyle(_table_style(colors))
    story.append(tbl)
    story.append(Spacer(1, 6 * mm))

    top_risks = summary.get("top_risks") or []
    story.append(Paragraph("Top risks", styles["H2"]))
    if top_risks:
        rows = [["Issue", "Severity", "Risk", "CVSS", "Locations"]]
        for g in top_risks:
            rows.append([
                Paragraph(_esc(g.get("title")), styles["Small"]),
                _esc(g.get("severity")),
                # N/A, never 0.0 -- "not scored" and "scored zero" stay distinct exactly as
                # they do everywhere else in the reporting layer.
                "N/A" if g.get("max_risk") is None else str(g["max_risk"]),
                "N/A" if g.get("max_cvss") is None else str(g["max_cvss"]),
                str(g.get("endpoint_count", 0)),
            ])
        tbl = Table(rows, colWidths=[70 * mm, 22 * mm, 20 * mm, 20 * mm, 24 * mm])
        tbl.setStyle(_table_style(colors))
        story.append(tbl)
    else:
        story.append(Paragraph("No active risks were outstanding at issue time.", styles["Body"]))
    story.append(Spacer(1, 6 * mm))

    progress = summary.get("remediation_progress") or {}
    story.append(Paragraph("Remediation progress", styles["H2"]))
    prog_rows = [["Metric", "Count"]]
    for label, key in (
        ("Total items", "total"), ("Proposed", "proposed"), ("Accepted", "accepted"),
        ("In progress", "in_progress"), ("Awaiting verification", "awaiting_verification"),
        ("Verified", "verified"), ("Closed", "closed"), ("Risk accepted", "risk_accepted"),
        ("Overdue", "overdue"),
    ):
        prog_rows.append([label, str(progress.get(key, 0))])
    tbl = Table(prog_rows, colWidths=[80 * mm, 40 * mm])
    tbl.setStyle(_table_style(colors))
    story.append(tbl)
    story.append(
        Paragraph(
            f"Remediation completion: {progress.get('completion_percent', 0)}% "
            f"({progress.get('resolved', 0)} of {progress.get('total', 0)} item(s) resolved).",
            styles["Body"],
        )
    )
    story.append(Spacer(1, 6 * mm))

    if assessment.narrative:
        story.append(Paragraph("Management summary and recommendations", styles["H2"]))
        for line in str(assessment.narrative).split("\n"):
            if line.strip():
                story.append(Paragraph(_esc(line), styles["Body"]))

    doc.build(story)
    return buf.getvalue()


def render(report_type: str, data: ReportData, assessment=None) -> bytes:
    if report_type == "executive":
        return render_executive(data)
    if report_type == "technical":
        return render_technical(data)
    if report_type == "risk_assessment":
        # An assessment PDF is meaningless without the frozen snapshot it renders -- refuse
        # rather than silently falling back to live data, which would defeat the freeze.
        if assessment is None:
            raise ValueError("risk_assessment reports require the issued assessment to render")
        return render_risk_assessment(data, assessment)
    raise ValueError(f"Unknown report type: {report_type}")
