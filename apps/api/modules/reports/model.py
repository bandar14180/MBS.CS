"""The ReportModel: the stable contract between data collection and PDF rendering.

Phase 5.0.

WHY THIS MODULE EXISTS
----------------------
`ReportData` (data.py) is the DATA-COLLECTION result: what the queries returned, plus the
derived accessors that answer questions about that population. It is correct and canonical, and
Phase 5.0 does not replace it.

What was missing is the layer ABOVE it. The renderer held every report-shaped aggregation --
`_finding_groups`, `_top_risk_groups`, `_verification_summary`, `_key_themes`,
`_recommendations`, `_score_band` -- inside a 3,189-line PDF module. Two consequences, both
real rather than theoretical:

  * `assessment/service.py` imports `_score_band` and `_top_risk_groups` FROM THE RENDERER to
    build a frozen snapshot. A domain service reaches into PDF code for domain facts, and
    importing that module drags in reportlab.
  * Nothing could answer "what does this report say?" without rendering a PDF. Every assertion
    about report content had to go through layout.

`ReportModel` closes that: one frozen object carrying the presentation-ready facts of a report,
assembled from the canonical functions and consumed by the renderers.

WHAT THIS MODULE IS NOT
-----------------------
  * NOT a second database model. It holds no session, runs no query, and imports no ORM entity.
  * NOT a second implementation of any security algorithm. Every value is produced by the
    existing canonical function -- scoring.compute_security_score, scoring.group_issues,
    scoring.is_scorable, scoring.issue_key, classification.classify_row,
    verification.classify_verification_row, the compliance catalogue, the ATT&CK tally --
    and merely CARRIED here. If a number in this model is wrong, the bug is upstream.
  * NOT a place for drawing logic. It contains no reportlab import and no layout decision.

IMMUTABILITY
------------
Every dataclass here is `frozen=True`. A renderer cannot mutate an assessment fact while
painting a page. There is NO escape hatch: the model carries no reference to the live
`ReportData`, so a renderer cannot reach around the contract.

MIGRATION (complete)
--------------------
Step 4 migrated the renderers: `render_executive`, `render_technical` and
`render_risk_assessment` now take a `ReportModel` and read only its fields. The public
`render(report_type, data, assessment)` entry point still accepts `ReportData` -- it builds the
model itself -- so `reports.service` and every existing caller are untouched.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime

from apps.api.modules.reports.data import EvidenceRecord, ReportData

# --- Counts ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class CountUnits:
    """R-01's two units, carried together so they can never be confused for one another.

    A vulnerability ROW is one OCCURRENCE at one location (the dedup identity is
    `(project_id, fingerprint)` and a fingerprint encodes `matched_at`). An ISSUE is the thing
    that actually gets fixed. Both numbers are correct; stating either alone is what created
    the "7 active findings, 3 finding blocks" confusion R-01 fixed.

    `issues` values come from ReportData's accessors, which delegate to scoring.issue_key /
    scoring.group_issues. Nothing is recounted here."""

    total_issues: int
    total_findings: int
    active_issues: int
    active_findings: int
    scorable_issues: int
    scorable_findings: int

    @property
    def issues_exceed_findings(self) -> bool:
        """Always False for real data -- an issue cannot have fewer than one occurrence.

        Exposed as an explicit invariant so a parity test can assert the units were not
        transposed during assembly."""
        return self.total_issues > self.total_findings


@dataclass(frozen=True)
class SeverityDistribution:
    """Severity tallies over both populations, in RECORDED FINDINGS (R-01's occurrence unit).

    `all_statuses` is the complete record including fixed/false-positive rows; `active` is the
    subset the security score describes. Kept as two separate maps because collapsing them is
    precisely the defect that let a fixed critical read as a live one."""

    all_statuses: dict[str, int]
    active: dict[str, int]

    def active_total(self) -> int:
        return sum(self.active.values())


# --- Scope ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanScope:
    """What the report covers (R-03). Empty `scans` means project-wide -- the documented
    `ReportCreate.scan_ids` contract ("Optional; empty = whole project"), unchanged.

    Values are the authorised `scans` rows the data layer already loaded; nothing is invented,
    and a scan with no recorded timestamp contributes no window rather than a fabricated one."""

    scans: tuple[dict, ...] = ()
    targets: tuple[str, ...] = ()
    window_start: datetime | None = None
    window_end: datetime | None = None

    @property
    def is_scoped(self) -> bool:
        return bool(self.scans)

    @property
    def scan_count(self) -> int:
        return len(self.scans)


# --- Findings -------------------------------------------------------------------------------


@dataclass(frozen=True)
class FindingRecord:
    """One ISSUE as the report presents it -- the `_finding_groups` contract, made explicit.

    `finding_id` is the CANONICAL identifier (`MBS-XXXXXXXX`, derived from the vulnerability's
    database identity). `issue_key` is scoring.issue_key. Neither is minted here: this type
    carries what the canonical grouping already decided, including its ORDER, so navigation
    anchors and display ordinals stay exactly as Phase 4.4 established them.

    `verification`/`confidence` are verification.py's own outputs and remain two distinct
    axes (Phase 4.1). `ai_confidence` is deliberately absent -- it is the AI's rating of its own
    output, never an evidence statement, and must never reach a report."""

    finding_id: str
    issue_key: str
    title: str
    severity: str
    status: str
    classification: str
    verification: str
    confidence: str
    cvss_score: float | None
    cvss_vector: str | None
    business_risk: float | None
    category: str | None
    template_id: str | None
    locations: tuple[str, ...] = ()
    unlocated_count: int = 0
    occurrence_count: int = 0
    assets: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    # The same producing tools, each paired with the version it actually ran at ("nuclei
    # 3.2.9"), or the bare name when no version was recorded. Built from the per-row
    # (tool_name, tool_version) pair, so a version is never attributed to a tool that did not
    # report it. Provenance only: nothing here is scored, inferred or fabricated.
    tool_versions: tuple[str, ...] = ()
    # Matchers that fired for this issue, sorted+deduped. PROVENANCE, and also the input to
    # render._is_inference_match -- which gates the inference wording on the assurance panel --
    # so omitting it silently changed both the Matcher row and that narrative.
    matcher_names: tuple[str, ...] = ()
    evidence: tuple[EvidenceRecord, ...] = ()
    screenshots: tuple[tuple[str, str], ...] = ()
    compliance: tuple[tuple[str, str, str], ...] = ()
    # Verbatim pipeline text. Rendered exactly as stored and NEVER generated, rewritten or
    # summarised by the report -- `description` is the scanner's own wording and the
    # remediation trio is the pipeline's. A finding with none of them renders an explicit
    # "not available" rather than invented prose.
    description: str | None = None
    risk_rationale: str | None = None
    remediation_summary: str | None = None
    remediation_steps: tuple[str, ...] = ()
    remediation_references: tuple[str, ...] = ()
    # Untyped artifact URIs, retained as the pre-Phase-3.2 fallback the renderer still uses
    # when a group carries no typed evidence records.
    evidence_uris: tuple[str, ...] = ()
    # (evidence_type, storage_uri) for the NON-screenshot artifacts. Carried from the group
    # rather than derived from `evidence`: a row predating Phase 3.2 has evidence_items but no
    # typed EvidenceRecord, and deriving would drop those artifacts entirely.
    evidence_items: tuple[tuple[str, str], ...] = ()

    @property
    def location_count(self) -> int:
        return len(self.locations)

    @property
    def is_detection(self) -> bool:
        return self.classification == "detection"

    # --- Legacy group-dict view (Step 4 migration aid) ------------------------------------
    #
    # `render._finding_block` reads its finding through ~37 `g["key"]` / `g.get("key")`
    # lookups. Rewriting every one of them by hand, inside the single largest and most
    # behaviour-critical function in the reporting layer, is exactly the kind of change that
    # silently alters a rendered value -- and Phases 2.1-4.5 are already approved against its
    # current output.
    #
    # So the RECORD exposes the read-only mapping shape that function already speaks. This is
    # a translation layer, not a second source of truth: every value is returned from this
    # frozen dataclass's own fields, nothing is recomputed, and there is no setter -- a
    # renderer still cannot mutate an assessment fact.
    #
    # It exists to keep the migration behaviour-preserving. It is the natural thing to delete
    # once `_finding_block` is converted to attribute access in a future, separately-approved
    # change whose whole purpose is that conversion.

    _GROUP_KEYS = {
        "key": "issue_key",
        "finding_id": "finding_id",
        "title": "title",
        "severity": "severity",
        "status": "status",
        "classification": "classification",
        "verification": "verification",
        "confidence": "confidence",
        "cvss_score": "cvss_score",
        "cvss_vector": "cvss_vector",
        "final_risk_score": "business_risk",
        "category": "category",
        "template_id": "template_id",
        "matched_ats": "locations",
        "unlocated_count": "unlocated_count",
        "occurrence_count": "occurrence_count",
        "asset_values": "assets",
        "tools": "tools",
        "tool_versions": "tool_versions",
        "matcher_names": "matcher_names",
        "evidence_records": "evidence",
        "screenshots": "screenshots",
        "compliance": "compliance",
        "description": "description",
        "risk_rationale": "risk_rationale",
        "remediation_summary": "remediation_summary",
        "remediation_steps": "remediation_steps",
        "remediation_references": "remediation_references",
        "evidence_uris": "evidence_uris",
        "evidence_items": "evidence_items",
    }



    def __getitem__(self, key: str):
        """`record["severity"]` -> the field the old group dict exposed under that name."""
        try:
            attr = self._GROUP_KEYS[key]
        except KeyError:
            raise KeyError(key) from None
        value = getattr(self, attr)
        # The old dicts held lists; callers index and len() them. Tuples satisfy both, but a
        # few sites concatenate, so hand back a list for the sequence-valued keys.
        return list(value) if isinstance(value, tuple) else value

    def get(self, key: str, default=None):
        try:
            return self[key]
        except KeyError:
            return default


@dataclass(frozen=True)
class RiskEntry:
    """One row of Executive Key Risks -- the `_top_risk_groups` contract.

    `max_risk`/`max_cvss` stay `None` when unscored: "not scored" and "scored zero" are
    different facts everywhere else in the reporting layer and must stay different here."""

    title: str
    severity: str
    issue_key: str
    occurrence_count: int
    max_risk: float | None
    max_cvss: float | None


# --- Assurance / coverage -------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationSummary:
    """Active findings by verification state, in RECORDED FINDINGS.

    Deliberately occurrence-based: verification is a property of an OBSERVATION, and one issue
    can be demonstrated at one location and merely suspected at another. Collapsing it to the
    issue level would discard exactly the distinction it exists to show."""

    verified: int = 0
    partially_verified: int = 0
    unverified: int = 0

    @property
    def total(self) -> int:
        return self.verified + self.partially_verified + self.unverified

    @property
    def unproven(self) -> int:
        """Findings not independently confirmed. Never described as false positives."""
        return self.partially_verified + self.unverified


@dataclass(frozen=True)
class ComplianceControl:
    """One mapped control and the findings that caused it to appear (R-02)."""

    control_id: str
    description: str
    finding_ids: tuple[str, ...]


@dataclass(frozen=True)
class ComplianceFramework:
    framework: str
    controls: tuple[ComplianceControl, ...]

    @property
    def control_count(self) -> int:
        return len(self.controls)


@dataclass(frozen=True)
class AttackTechnique:
    """One ATT&CK technique and the number of DISTINCT scorable issues hitting it.

    The count is the data layer's tally, which uses scoring.is_scorable + scoring.issue_key --
    the same population the security score uses, and the same one attack.aggregation serves the
    API from. Carried, never recomputed."""

    tactic: str
    technique_id: str
    technique_name: str
    issue_count: int


@dataclass(frozen=True)
class AssetExposure:
    assets: tuple[str, ...] = ()
    endpoint_count: int = 0

    @property
    def asset_count(self) -> int:
        return len(self.assets)


@dataclass(frozen=True)
class WeaknessTheme:
    """One weakness CLASS and how much of the estate it accounts for (Phase 4.3).

    Answers what a per-issue risk table cannot: three SQL-injection templates and two XSS
    templates is a different management conversation from five unrelated one-offs.

    The class name comes from narrative.classify_weakness_row -- the SAME classifier the
    Technical report's per-finding prose uses, so the two documents can never name a weakness
    differently. Identity is scoring.issue_key over the scoring.is_scorable population."""

    name: str
    issue_count: int
    finding_count: int


@dataclass(frozen=True)
class Recommendation:
    """One (priority, action) pair for the Executive report (Phase 4.3).

    Every line restates a figure already in the report, expressed as an action. The priority
    vocabulary is render._REMEDIATION_BUCKETS', so the Executive and Technical reports sequence
    work identically. Nothing is invented: a bucket with no findings produces no entry."""

    priority: str
    action: str


@dataclass(frozen=True)
class RemediationBucket:
    """Findings grouped into one delivery priority by their EXISTING severity (Technical §8).

    Ordering only. This maps a finding's already-assessed severity onto a delivery sequence; it
    does not change, re-derive or reweight severity, CVSS, risk or the security score."""

    label: str
    severity: str
    guidance: str
    findings: tuple[FindingRecord, ...]


# --- The model ------------------------------------------------------------------------------


@dataclass(frozen=True)
class ReportModel:
    """Presentation-ready facts for one report. Frozen; assembled by `build_report_model`."""

    project_name: str
    security_score: int
    score_band: str
    counts: CountUnits
    severity: SeverityDistribution
    scope: ScanScope
    exposure: AssetExposure
    findings: tuple[FindingRecord, ...] = ()
    # Step 4: the ACTIVE-only grouping the Technical remediation plan renders. A SEPARATE
    # grouping, not a filter of `findings`: _finding_groups over active rows can pick a
    # different representative member (and therefore a different CVSS/risk/rationale) than the
    # same grouping over all rows, so deriving one from the other would silently change what
    # the remediation plan prints.
    active_findings: tuple[FindingRecord, ...] = ()
    key_risks: tuple[RiskEntry, ...] = ()
    verification: VerificationSummary = field(default_factory=VerificationSummary)
    compliance: tuple[ComplianceFramework, ...] = ()
    attack: tuple[AttackTechnique, ...] = ()
    attack_graph: dict = field(default_factory=dict)
    # Step 4: Executive rollups (Phase 4.3) and the Technical scope line's tool inventory.
    themes: tuple[WeaknessTheme, ...] = ()
    recommendations: tuple[Recommendation, ...] = ()
    remediation_buckets: tuple[RemediationBucket, ...] = ()
    # Producing scanner tools across the report's findings, sorted+deduped. "N/A" entries are
    # dropped at assembly, exactly as the renderer's own expression did.
    tools: tuple[str, ...] = ()
    # The same inventory with each tool's recorded version ("nuclei 3.2.9"). Assembled from the
    # per-finding (tool_name, tool_version) pair. A tool that ran at two versions across the
    # report appears once per version -- that IS the truth about the run, and collapsing it
    # would assert a single version that was never the case.
    tool_versions: tuple[str, ...] = ()

    @property
    def evidence_manifest(self) -> tuple[tuple[str, EvidenceRecord], ...]:
        """(finding_id, artifact) for EVERY stored artifact, in finding order then capture
        order -- the Phase 3.2 manifest, as data rather than as a table.

        Deterministic by construction: `findings` preserves the canonical grouping order and
        each finding's `evidence` preserves the data layer's `ORDER BY created_at, id`."""
        out: list[tuple[str, EvidenceRecord]] = []
        seen: set[tuple[str, str, str | None]] = set()
        for finding in self.findings:
            for record in finding.evidence:
                key = (finding.finding_id, record.storage_uri, record.checksum)
                if key in seen:
                    continue
                seen.add(key)
                out.append((finding.finding_id, record))
        return tuple(out)

    @property
    def verified_artifact_count(self) -> int:
        """Artifacts carrying a usable SHA-256. Uses EvidenceRecord.has_checksum, which
        validates length and hex-ness, so a truncated value is never counted as verifiable."""
        return sum(1 for _fid, record in self.evidence_manifest if record.has_checksum)

    def finding_by_id(self, finding_id: str) -> FindingRecord | None:
        """Resolve a canonical id to its finding, or None when it is not in this report.

        The navigation-safety primitive: a scoped report returns None for an excluded finding
        rather than producing a destination that cannot resolve."""
        for finding in self.findings:
            if finding.finding_id == finding_id:
                return finding
        return None

    @property
    def finding_ids(self) -> tuple[str, ...]:
        return tuple(f.finding_id for f in self.findings)


def build_report_model(data: ReportData) -> ReportModel:
    """Assemble a `ReportModel` from a canonical `ReportData`.

    PURE and side-effect free: no session, no query, no clock, no network. Every value is
    produced by an existing canonical function and copied; this function implements no scoring,
    grouping, classification, verification or compliance rule of its own.

    Imports are local to avoid an import cycle -- render.py imports data.py, and the grouping
    helpers currently live in render.py (see the module docstring on why they were not moved in
    this phase)."""
    from apps.api.modules.reports.render import (
        _ACTIVE_STATUSES,
        _REMEDIATION_BUCKETS,
        _finding_groups,
        _key_themes,
        _recommendations,
        _score_band,
        _score_impacting_count,
        _top_risk_groups,
        _verification_summary,
    )

    def _to_record(g: dict) -> FindingRecord:
        return FindingRecord(
            finding_id=g.get("finding_id") or "MBS-UNKNOWN",
            issue_key=g["key"],
            title=g["title"],
            severity=g["severity"],
            status=g.get("status") or "",
            classification=g.get("classification") or "vulnerability",
            verification=g.get("verification") or "unverified",
            confidence=g.get("confidence") or "medium",
            cvss_score=g.get("cvss_score"),
            cvss_vector=g.get("cvss_vector"),
            business_risk=g.get("final_risk_score"),
            category=g.get("category"),
            template_id=g.get("template_id"),
            locations=tuple(g.get("matched_ats") or ()),
            unlocated_count=g.get("unlocated_count", 0),
            occurrence_count=g.get("occurrence_count", 0),
            assets=tuple(g.get("asset_values") or ()),
            tools=tuple(g.get("tools") or ()),
            tool_versions=tuple(g.get("tool_versions") or ()),
            matcher_names=tuple(g.get("matcher_names") or ()),
            evidence=tuple(g.get("evidence_records") or ()),
            screenshots=tuple(g.get("screenshots") or ()),
            compliance=tuple(g.get("compliance") or ()),
            description=g.get("description"),
            risk_rationale=g.get("risk_rationale"),
            remediation_summary=g.get("remediation_summary"),
            remediation_steps=tuple(g.get("remediation_steps") or ()),
            remediation_references=tuple(g.get("remediation_references") or ()),
            evidence_uris=tuple(g.get("evidence_uris") or ()),
            evidence_items=tuple(g.get("evidence_items") or ()),
        )

    # The FULL record (Technical Detailed Findings) and the ACTIVE-only grouping (remediation
    # plan). Two separate _finding_groups calls, exactly as the renderer makes them -- see the
    # note on ReportModel.active_findings for why one cannot be derived from the other.
    groups = _finding_groups(data.vulns)
    findings = tuple(_to_record(g) for g in groups)

    active_groups = _finding_groups([v for v in data.vulns if v.status in _ACTIVE_STATUSES])
    active_findings = tuple(_to_record(g) for g in active_groups)

    by_severity: dict[str, list[FindingRecord]] = {}
    for record in active_findings:
        by_severity.setdefault((record.severity or "").lower(), []).append(record)
    remediation_buckets = tuple(
        RemediationBucket(
            label=label, severity=severity, guidance=guidance,
            findings=tuple(by_severity.get(severity, ())),
        )
        for label, severity, guidance in _REMEDIATION_BUCKETS
        if by_severity.get(severity)
    )

    key_risks = tuple(
        RiskEntry(
            title=g["title"],
            severity=g["severity"],
            issue_key=g["issue_key"],
            occurrence_count=g["endpoint_count"],
            max_risk=g["max_risk"],
            max_cvss=g["max_cvss"],
        )
        for g in _top_risk_groups(data.vulns)
    )

    ver = _verification_summary(data)
    window_start, window_end = data.scope_window()

    base = ReportModel(
        project_name=data.project_name,
        security_score=data.security_score,
        # THE one banding function (R-04: "Fair", never "Moderate").
        score_band=_score_band(data.security_score),
        counts=CountUnits(
            total_issues=data.total_issue_count(),
            total_findings=data.total_vulns,
            active_issues=data.active_issue_count(),
            active_findings=data.active_vulns,
            scorable_issues=data.scorable_issue_count(),
            scorable_findings=_score_impacting_count(data),
        ),
        severity=SeverityDistribution(
            all_statuses=dict(data.severity_counts),
            active=dict(data.active_severity_counts),
        ),
        scope=ScanScope(
            scans=tuple(data.scope_scans),
            targets=tuple(data.scope_targets()),
            window_start=window_start,
            window_end=window_end,
        ),
        exposure=AssetExposure(
            assets=tuple(data.affected_assets()),
            endpoint_count=data.affected_endpoint_count(),
        ),
        findings=findings,
        active_findings=active_findings,
        remediation_buckets=remediation_buckets,
        tools=tuple(sorted({
            v.tool_name for v in data.vulns
            if getattr(v, "tool_name", None) and v.tool_name != "N/A"
        })),
        tool_versions=tuple(sorted({
            f"{v.tool_name} {tv}"
            if (tv := str(getattr(v, "tool_version", None) or "").strip())
            else v.tool_name
            for v in data.vulns
            if getattr(v, "tool_name", None) and v.tool_name != "N/A"
        })),
        key_risks=key_risks,
        verification=VerificationSummary(
            verified=ver.get("verified", 0),
            partially_verified=ver.get("partially_verified", 0),
            unverified=ver.get("unverified", 0),
        ),
        compliance=tuple(
            ComplianceFramework(
                framework=framework,
                controls=tuple(
                    ComplianceControl(control_id=cid, description=desc,
                                      finding_ids=tuple(ids))
                    for cid, desc, ids in controls
                ),
            )
            for framework, controls in data.compliance_coverage()
        ),
        attack=tuple(
            AttackTechnique(tactic=tactic, technique_id=tid, technique_name=tname,
                            issue_count=count)
            for tactic, tid, tname, count in data.attack_techniques
        ),
        attack_graph=dict(data.attack_graph or {}),
    )

    # The two Phase 4.3 rollups read the ASSEMBLED findings, so they are derived from the
    # finished model rather than from raw rows. `dataclasses.replace` keeps the model frozen --
    # a new instance is produced, never a mutation of the first.
    return replace(
        base,
        themes=tuple(
            WeaknessTheme(name=name, issue_count=issues, finding_count=occurrences)
            for name, issues, occurrences in _key_themes(base)
        ),
        recommendations=tuple(
            Recommendation(priority=priority, action=action)
            for priority, action in _recommendations(base)
        ),
    )
