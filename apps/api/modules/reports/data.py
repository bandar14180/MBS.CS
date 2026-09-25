import uuid
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.observability import record_verification_outcome
from apps.api.modules.assets.models import Asset
from apps.api.modules.attack.models import AttackMapping
from apps.api.modules.compliance.models import ComplianceMapping
from apps.api.modules.projects.models import Project
from apps.api.modules.reports.scoring import ACTIVE_STATUSES, compute_security_score, is_scorable, issue_key
from apps.api.modules.reports.classification import classify_row
from apps.api.modules.reports.verification import classify_verification_row
from apps.api.modules.risk.models import RiskScore
from apps.api.modules.vulnerabilities.models import Vulnerability
from apps.api.scanner_engine.models import Evidence

# Statuses that still count against a project's security posture. A finding
# that's fixed / false-positive / accepted-risk no longer subtracts from the score.
# Single source of truth lives in scoring.ACTIVE_STATUSES; re-exported here (as a set,
# unchanged in meaning) because render.py and the severity tallies below import it from
# this module.
_ACTIVE_STATUSES = set(ACTIVE_STATUSES)
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _parse_fingerprint(fingerprint: str | None) -> tuple[str | None, str | None, str | None]:
    """Recover (template_id, matcher_name, matched_at) from a finding's fingerprint.

    Nuclei fingerprints are built as `template_id|matcher|matched_at` (see
    nuclei_runner.parse_vulnerabilities). Only the LAST field -- matched_at -- can itself
    contain a `|`: an injection payload like `?lang=|dir` puts a pipe inside the URL, so a
    real fingerprint can read `windows-command-injection|time-based|https://h/?lang=|dir`
    (four segments). So this splits at most TWICE (maxsplit=2): the first two pipes delimit
    template and matcher, and everything after is the full matched_at, pipes intact.

    Backward-compatible and defensive: a None/empty/malformed fingerprint (fewer than two
    pipes, e.g. an older non-nuclei finding whose fingerprint is a bare hash) yields None for
    the missing parts rather than raising -- the report renders those as N/A. This reads the
    EXISTING fingerprint only; it does not change how fingerprints are built or deduped."""
    if not fingerprint:
        return None, None, None
    parts = fingerprint.split("|", 2)
    template_id = parts[0] or None if len(parts) >= 1 else None
    matcher_name = parts[1] or None if len(parts) >= 2 else None
    matched_at = parts[2] or None if len(parts) >= 3 else None
    return template_id, matcher_name, matched_at


def _normalise_steps(steps) -> list[str]:
    """Remediation steps as a list of non-empty strings, whatever shape the column holds.

    `remediations.steps` is a JSON list column, but the value read back can legitimately be a
    list, a single string (older rows written before the column was JSON), or None. Returning
    one consistent shape is what lets the renderer emit bullets without type-testing, and is
    the fix for the AttributeError that a list value used to raise there.

    Order is preserved and entries are stripped; empties are dropped so a trailing "" in the
    stored JSON does not render as an empty bullet. Nothing is rewritten or summarised."""
    if steps is None:
        return []
    if isinstance(steps, str):
        text = steps.strip()
        return [text] if text else []
    try:
        items = list(steps)
    except TypeError:
        text = str(steps).strip()
        return [text] if text else []
    out: list[str] = []
    for item in items:
        text = str(item).strip()
        if text:
            out.append(text)
    return out


@dataclass(frozen=True)
class EvidenceRecord:
    """One stored evidence artifact, with the integrity metadata needed to audit it.

    Phase 3.2. Every field is read VERBATIM from an `evidence` row; none is computed, inferred
    or defaulted by the report. The columns have existed since the evidence store was built --
    `checksum` (SHA-256 over the uploaded bytes, see scanner_engine.evidence_store) and
    `created_at` (server CURRENT_TIMESTAMP(6) at capture) -- but the report only ever selected
    `storage_uri`/`evidence_type`, and kept the checksum for screenshots alone. A reader could
    therefore not tell WHEN an artifact was captured or verify it had not changed since.

    Frozen because an evidence record is a statement about a past capture: nothing downstream
    of the query should be able to edit it.

    `checksum` is stored as bare hex with no algorithm prefix; `checksum_label()` renders it
    with its algorithm named, so the report never implies an algorithm the data does not state.
    A row whose checksum is absent is reported as unavailable rather than shown as verified."""

    evidence_id: uuid.UUID | None
    evidence_type: str
    storage_uri: str
    checksum: str | None
    captured_at: datetime | None
    tool_run_id: uuid.UUID | None = None

    #: The algorithm scanner_engine.evidence_store and remediation.evidence_service both use.
    #: Named here so the renderer never hard-codes it at a display site.
    CHECKSUM_ALGORITHM = "SHA-256"

    @property
    def has_checksum(self) -> bool:
        """A usable integrity value: present, and the right length for a hex SHA-256 digest.

        Length-checked rather than trusted: a truncated or placeholder value must not be
        presented as if it were a verifiable digest."""
        value = (self.checksum or "").strip()
        return len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value)

    def checksum_label(self) -> str:
        """Full digest, algorithm named -- or an explicit statement that none was recorded."""
        if not self.has_checksum:
            return "not recorded"
        return f"{self.CHECKSUM_ALGORITHM}:{(self.checksum or '').strip().lower()}"

    def checksum_short(self) -> str:
        """First 16 hex chars, for tables where the full 64 would not fit. Still prefixed with
        the algorithm so a truncated digest is never mistaken for a complete one."""
        if not self.has_checksum:
            return "not recorded"
        return f"{self.CHECKSUM_ALGORITHM}:{(self.checksum or '').strip().lower()[:16]}…"

    def captured_label(self) -> str:
        """Capture timestamp in UTC, or an explicit absence. Never substitutes 'now'."""
        if self.captured_at is None:
            return "not recorded"
        return f"{self.captured_at:%Y-%m-%d %H:%M:%S UTC}"

    @property
    def artifact_id(self) -> str:
        """Stable, quotable id for ONE artifact, e.g. "EV-3F9A2C71".

        Derived from the evidence row's DATABASE identity, exactly as VulnRow.finding_id is
        derived from the vulnerability's -- so the same artifact carries the same id across
        re-renders. The EV- prefix keeps it distinguishable from a finding's MBS- id while
        staying in the identifier style the report already established; no new identity system
        and nothing persisted."""
        raw = str(self.evidence_id or "").replace("-", "").upper()
        return f"EV-{raw[:8]}" if raw else "EV-UNKNOWN"


@dataclass
class VulnRow:
    id: uuid.UUID
    title: str
    severity: str
    status: str
    category: str | None
    cvss_score: float | None
    cvss_vector: str | None
    final_risk_score: float | None
    risk_rationale: str | None
    compliance: list[tuple[str, str, str]]  # (framework, control_id, description)
    evidence_uris: list[str]
    # Visual evidence captured during the scan: [(storage_uri, sha256)] for this
    # finding's evidence_type='screenshot' rows. Empty when capture was disabled,
    # ineligible (info severity / non-HTTP location) or failed -- the report then
    # simply shows no image. Defaults to an empty list so every existing VulnRow
    # construction site keeps working unchanged.
    screenshots: list[tuple[str, str]] = field(default_factory=list)
    # P2-3: [(evidence_type, storage_uri)] for the NON-screenshot artifacts, e.g.
    # ("log_excerpt", "s3://mbs-evidence/tool-runs/<id>/raw-output.txt"). Parallel to
    # `evidence_uris`, which keeps its list[str] shape so no existing caller changes. Defaults
    # to empty, so a row built without it (legacy call site, test double) renders exactly as
    # before -- the renderer falls back to the untyped list. Presentation metadata only: it is
    # never read by scoring, classification or verification.
    evidence_items: list[tuple[str, str]] = field(default_factory=list)
    # Phase 3.2: the SAME artifacts as `evidence_items`, carrying the integrity metadata that
    # the evidence table has always stored but the report discarded -- SHA-256 checksum,
    # capture timestamp, the evidence row's own id, and the producing tool run.
    #
    # A THIRD parallel list rather than a widened `evidence_items`, deliberately: that field's
    # (type, uri) 2-tuple shape is asserted verbatim by existing tests and consumed by
    # `_finding_groups`, so widening it would break callers for no benefit. Same discipline
    # that added `evidence_items` alongside `evidence_uris`.
    #
    # Presentation/provenance only. Never read by scoring, classification or verification, and
    # nothing here is computed by the report -- every value is read back from the row written
    # at capture time (scanner_engine.evidence_store hashes the bytes it uploads).
    evidence_records: list["EvidenceRecord"] = field(default_factory=list)
    # Where the finding was observed, recovered from the fingerprint (Phase 1: report clarity
    # only -- no new column, no schema change). Lets the report distinguish many findings that
    # share a title/severity/evidence but hit different URLs/params. Any may be None (older or
    # non-nuclei findings); the renderer shows N/A.
    template_id: str | None = None
    matcher_name: str | None = None
    matched_at: str | None = None
    # The inventoried asset/host this finding is anchored to (assets.value), recovered via the
    # EXISTING Vulnerability.asset_id -> assets FK (read-only join; no schema change). None when
    # the finding was never linked to an inventoried asset -- the report must NOT imply an asset
    # is affected in that case. Distinct from matched_at: asset_value is the host/asset, matched_at
    # is the exact endpoint/URL observed.
    asset_value: str | None = None
    # Which scanner tool produced this finding (tool_runs.tool_name via VulnerabilityEvidence.
    # tool_run_id -- read-only join, no schema change). "N/A" when no linkage exists (older
    # rows). Shown in the Technical Report so an analyst can see e.g. nuclei-dast vs nuclei.
    tool_name: str = "N/A"
    # The producing tool's VERSION (tool_runs.tool_version), read from the same tool_runs row
    # as `tool_name`. None -- never a placeholder string -- when no linkage exists or the
    # stored version is blank, so "version not recorded" stays distinguishable from a real
    # version. Completes the Tool -> Tool Version link of the finding lineage chain at the
    # report boundary; presentation/provenance only, never read by scoring, classification or
    # verification, and never fabricated by the report.
    tool_version: str | None = None
    # Nuclei classification metadata, when the caller has it. NEITHER is a column on
    # `vulnerabilities` (the runner's finding metadata is consumed by sync_attack_mappings and
    # then discarded), so gather_report_data leaves both None and classify_row recovers the CVE
    # from template_id/title instead. They exist so a caller that DOES hold the metadata can
    # pass the strongest vulnerability signals straight through, rather than the classifier
    # silently losing them -- see classification.classify_row.
    cve: str | None = None
    tags: list[str] | None = None
    # Reporting-layer classification: "vulnerability" or "detection" (see classification.py).
    # Derived from template_id/cvss/category/cve/tags -- NOT from severity alone, and never
    # changes identity, grouping, or the stored row. Detections are labelled as such so the
    # report stops presenting a technology/WAF/version DETECTION as a vulnerability, and are
    # excluded from the security score (scoring.is_scorable).
    classification: str = "vulnerability"
    # Reporting-layer verification state + confidence (see verification.py). Derived from the
    # row's own evidence/template/matcher metadata -- NEVER from severity, CVSS or risk, and
    # they never modify any of those. A scanner match is not a proof, so a generic detection
    # defaults to unverified/medium and VERIFIED is reachable only from explicit evidence.
    # Deliberately NOT `vulnerabilities.ai_confidence`, which is the AI triage model's rating
    # of its own output and answers a different question entirely.
    verification: str = "unverified"
    confidence: str = "medium"
    # The scanner's own description text (vulnerabilities.description). Rendered VERBATIM in
    # Detailed Findings and never rewritten, summarised or generated -- if it is None the
    # report says so rather than inventing prose. Defaults to None so any row built without
    # it (legacy call site, test double) behaves exactly as before.
    description: str | None = None
    # Remediation guidance produced by the pipeline (vulnerabilities remediations table), when
    # it exists. All three are rendered VERBATIM and are never generated, inferred or
    # summarised by the report. A finding with NO pipeline remediation instead receives
    # standard controls for its weakness class, rendered under an explicit label that says
    # they are not derived from scan evidence (see narrative.GENERATED_CONTROLS_LABEL).
    remediation_summary: str | None = None
    # `remediations.steps` is a JSON **list** column (remediation_models.Remediation.steps),
    # not text. It was previously typed `str | None` here and `.strip()`ed by the renderer,
    # which raised AttributeError and failed the WHOLE technical report for any finding that
    # actually had steps -- latent only because the table is empty on the current dataset.
    # Typed and normalised as a list now; `_normalise_steps` accepts either shape so a legacy
    # string value still renders.
    remediation_steps: list[str] = field(default_factory=list)
    remediation_references: list[str] = field(default_factory=list)

    @property
    def finding_id(self) -> str:
        """Stable, human-quotable identifier for one finding, e.g. "MBS-4A2F9C1B".

        Derived from the row's DATABASE identity (`vulnerabilities.id`), NOT from a loop index:
        the same finding therefore carries the same id across re-renders, re-orderings and
        separate reports, so a client can quote "MBS-4A2F9C1B" back and it still resolves.
        Presentation only -- nothing is persisted and no schema changes."""
        raw = str(getattr(self, "id", "") or "").replace("-", "").upper()
        return f"MBS-{raw[:8]}" if raw else "MBS-UNKNOWN"


@dataclass
class ReportData:
    project_name: str
    security_score: int
    # Severity tally over ALL findings regardless of status -- the "Findings by severity"
    # table is the full record. Do NOT use it to describe what reduces the score: a fixed or
    # false-positive high still appears here. Use active_severity_counts for that.
    severity_counts: dict[str, int]
    total_vulns: int
    active_vulns: int
    # Severity tally over ACTIVE findings only (status in _ACTIVE_STATUSES). The per-severity
    # breakdown was already computed while building the rows but only its SUM (active_vulns)
    # used to be exposed, which forced the executive summary to describe active findings using
    # the all-status severity_counts above -- two different populations, and a fixed high was
    # then reported as reducing a score it does not touch. Defaults to an empty dict so every
    # existing ReportData(...) construction keeps working; _findings_summary treats a missing
    # entry as 0.
    active_severity_counts: dict[str, int] = field(default_factory=dict)
    vulns: list[VulnRow] = field(default_factory=list)
    # MITRE ATT&CK coverage across the project: (tactic_name, technique_id,
    # technique_name, finding_count), most-hit first.
    attack_techniques: list[tuple[str, str, str, int]] = field(default_factory=list)
    # Autonomous-engagement attack graph (M4.4.6), aggregated across the project's
    # agent scans. Empty for projects with no autonomous engagement (fail-soft). Keys:
    # has_data, engagement_count, node_counts{type:n}, confirmed_access[{target,
    # access_state, module}]. Only evidence-backed states appear (no invented
    # privilege escalation / lateral movement).
    attack_graph: dict = field(default_factory=dict)
    # --- ASSESSMENT SCOPE (R-03) ----------------------------------------------------------
    # What this report actually covers, so the document is auditable and a reader can tell a
    # scan-scoped report from a project-wide one. EMPTY means project-wide -- the long-standing
    # ReportCreate.scan_ids contract ("Optional; empty = whole project"), unchanged.
    #
    # Every entry is REAL data read from the `scans` rows the caller already authorised; nothing
    # is invented. A scan with no started_at/completed_at simply contributes no timestamp rather
    # than a fabricated one. Defaults to an empty list so every existing ReportData(...)
    # construction site keeps working untouched.
    #
    # Shape per scan: {"id", "scan_type", "status", "target", "started_at", "completed_at"}.
    scope_scans: list[dict] = field(default_factory=list)

    def is_scan_scoped(self) -> bool:
        """True when this report covers specific scans rather than the whole project."""
        return bool(self.scope_scans)

    def scope_window(self) -> tuple[datetime | None, datetime | None]:
        """(earliest start, latest completion) across the scoped scans, or (None, None).

        Derived from the scans' OWN timestamps; a missing timestamp contributes nothing, so an
        in-flight or never-started scan cannot invent a window."""
        starts: list[datetime] = [
            s["started_at"] for s in self.scope_scans if s.get("started_at") is not None
        ]
        ends: list[datetime] = [
            s["completed_at"] for s in self.scope_scans if s.get("completed_at") is not None
        ]
        return (min(starts) if starts else None, max(ends) if ends else None)

    def scope_targets(self) -> list[str]:
        """Distinct target values across the scoped scans, sorted. Empty when unknown."""
        return sorted({str(s["target"]) for s in self.scope_scans if s.get("target")})

    def _currently_affecting(self):
        """The findings that justify a PRESENT-TENSE "is affected" claim.

        The Executive report says assets/endpoints "are affected", so the population must be
        the one that is still true: ACTIVE status and an actual scorable weakness. Both
        conditions come from scoring.is_scorable -- the SAME predicate the Security Score
        uses -- so there is exactly one definition of "counts against posture" in the
        codebase (it composes ACTIVE_STATUSES with the info-severity and DETECTION
        exclusions). Deliberately not a second status list.

        Previously every row counted regardless of status, so a fully remediated project
        still reported "N asset(s) are affected" beside a 100/100 score and an empty Top
        Risks table -- and a FALSE POSITIVE, which never affected anything, was counted too."""
        from apps.api.modules.reports.scoring import is_scorable

        return [v for v in self.vulns if is_scorable(v)]

    def affected_assets(self) -> list[str]:
        """Distinct inventoried asset/host values (assets.value) that are CURRENTLY affected,
        sorted. Only non-null asset links -- a finding with no asset_id contributes nothing, so
        the Executive report never implies an asset is affected when the linkage is absent.
        Only active, scorable findings count (see _currently_affecting): a fixed,
        false-positive, accepted-risk, informational or detection-only row does not make a
        host "affected". Pure (derived from self.vulns), so it adds no query and is directly
        testable."""
        return sorted({v.asset_value for v in self._currently_affecting() if v.asset_value})

    def affected_endpoint_count(self) -> int:
        """How many DISTINCT endpoints (matched_at) are CURRENTLY affected. Endpoint is the
        exact URL/location -- distinct from an asset/host -- so this can exceed the asset count
        when one host exposes many affected endpoints. Same active/scorable population as
        affected_assets, so the two numbers always describe the same set of findings. Findings
        without a matched_at (older/non-nuclei) don't count."""
        return len({v.matched_at for v in self._currently_affecting() if v.matched_at})

    # --- ISSUE COUNTS (R-01) --------------------------------------------------------------
    # A vulnerability ROW is one OCCURRENCE AT ONE LOCATION: per vulnerabilities/models.py the
    # dedup identity is (project_id, fingerprint), and per nuclei_runner.py a fingerprint is
    # `template_id|matcher|matched_at`. So `total_vulns`/`active_vulns`/`severity_counts`/the
    # verification tally are all OCCURRENCE counts -- correct, and deliberately kept that way.
    #
    # But the score, Executive Key Risks, Technical Detailed Findings and the MITRE tally all
    # count distinct ISSUES (scoring.issue_key). Both units are right; neither was labelled, so
    # a reader who counted "7 active findings" against one rendered finding block could only
    # conclude that six findings had been dropped.
    #
    # These three methods expose the missing ISSUE unit so every summary can state both. They
    # are METHODS deriving from self.vulns -- exactly like affected_assets/affected_endpoint_count
    # above -- rather than constructor fields, so all existing ReportData(...) construction
    # sites keep working untouched and the two units can never be passed in disagreeing.
    #
    # Each uses the CANONICAL scoring.issue_key, unchanged; none re-derives identity, and none
    # reads or alters severity, CVSS, risk, verification or the security score.

    def total_issue_count(self) -> int:
        """Distinct issues across ALL findings, any status.

        The population `render._finding_groups` renders: the Technical Report's Detailed
        Findings is the FULL record, so fixed/false-positive/accepted-risk issues each still
        appear as a block. This is therefore the number that reconciles with the block count
        in that section, and it pairs with `total_vulns` (its occurrence count)."""
        return len({issue_key(v) for v in self.vulns})

    def active_issue_count(self) -> int:
        """Distinct issues among ACTIVE findings (status in ACTIVE_STATUSES).

        The population `render._top_risk_groups` buckets, so this is the number that
        reconciles with the Executive Report's Key Risks table, and it pairs with
        `active_vulns` (its occurrence count). Deliberately NOT filtered by is_scorable:
        Key Risks shows every active issue, including informational and detection-only ones,
        so filtering here would under-report what that table actually lists."""
        return len({issue_key(v) for v in self.vulns if v.status in _ACTIVE_STATUSES})

    def scorable_issue_count(self) -> int:
        """Distinct issues that actually move the security score.

        Delegates to scoring.group_issues -- the score's OWN grouping -- rather than
        re-deriving the rule, so this can never drift from the score it explains. It is the
        same population the MITRE tally counts (active, not info, not a detection), which is
        what lets the ATT&CK "Issues" column and this number agree by construction.

        This is the issue-unit counterpart of render._score_impacting_count (the occurrence
        count of the same population)."""
        from apps.api.modules.reports.scoring import group_issues

        return len(group_issues(self.vulns))

    # --- COMPLIANCE COVERAGE (R-02) -------------------------------------------------------

    def compliance_coverage(self) -> list[tuple[str, list[tuple[str, str, list[str]]]]]:
        """Framework -> control -> the finding IDs that caused the control to appear.

        THE POPULATION (this is the R-02 fix)
        -------------------------------------
        `scoring.is_scorable` -- the SAME predicate the Security Score, the MITRE tally
        (attack.aggregation) and `_currently_affecting` already use. It composes THREE
        independent exclusions: non-active status (fixed / false_positive / accepted_risk),
        `info` severity, and a DETECTION classification.

        Previously every surface that rendered compliance iterated `self.vulns` UNFILTERED, so
        a finding the customer had already fixed -- or one dismissed as a FALSE POSITIVE, which
        never existed -- still produced a PCI DSS / ISO 27001 control card. A project with
        nothing active and a 100/100 score still claimed framework coverage, while the MITRE
        section beside it correctly reported nothing. That is an affirmative misstatement in
        precisely the context where a client is least forgiving.

        `is_scorable` is deliberately NOT the same thing as "status is active": an ACTIVE
        `info` finding and an ACTIVE technology detection are both is_active=True but
        is_scorable=False. Using the scorable predicate keeps compliance describing the same
        set of real, current weaknesses the score and ATT&CK describe, rather than a third,
        divergent population.

        WHAT IS NOT CHANGED
        -------------------
        The catalogue (compliance/catalog.py), the CWE -> control mapping semantics, the
        stored `compliance_mappings` rows and every framework remain exactly as they were.
        This filters WHICH FINDINGS are read at render time -- the same read-time-filter
        discipline attack.aggregation uses for stale mappings -- and adds the contributing
        finding IDs. It writes nothing and needs no backfill.

        RETURN SHAPE
        ------------
        [(framework, [(control_id, description, [finding_id, ...]), ...]), ...], frameworks
        sorted by key and controls sorted by id, so the rendering is deterministic. Finding IDs
        are the report's EXISTING canonical identifier (VulnRow.finding_id -> "MBS-XXXXXXXX",
        derived from the database id) -- no new identity system -- deduped and sorted, so a
        control implicated by one issue at many locations lists that finding once."""
        from apps.api.modules.reports.scoring import is_scorable

        # framework -> control_id -> (description, {finding_id})
        acc: dict[str, dict[str, tuple[str, set[str]]]] = {}
        for v in self.vulns:
            if not is_scorable(v):
                continue
            fid = v.finding_id
            for framework, control_id, desc in v.compliance or []:
                controls = acc.setdefault(framework, {})
                prev_desc, ids = controls.get(control_id, ("", set()))
                # Keep the first non-empty description: the catalogue gives one control the
                # same text everywhere, so this only guards against a blank stored value.
                controls[control_id] = (prev_desc or desc or "", ids | {fid})

        return [
            (
                framework,
                [
                    (control_id, desc, sorted(ids))
                    for control_id, (desc, ids) in sorted(acc[framework].items())
                ],
            )
            for framework in sorted(acc)
        ]

    def compliance_frameworks(self) -> list[str]:
        """Framework keys with at least one control mapped from a CURRENT finding, sorted.

        Same population and same contract as compliance_coverage(), so the Executive summary
        line and the Technical cards can never describe different sets of frameworks."""
        return [framework for framework, _controls in self.compliance_coverage()]


async def _gather_attack_graph(
    db: AsyncSession, project_id: uuid.UUID, scan_ids: list[uuid.UUID] | None = None
) -> dict:
    """Aggregate the persisted attack graph(s) from the project's autonomous
    engagements (M4.4.6). Reads the ACTUAL EngagementState.attack_graph -- never
    recomputes. Fail-soft: returns has_data=False if there is no engagement. Only
    evidence-backed access states are surfaced (privilege escalation / lateral
    movement appear only if a module ever produces that evidence)."""
    from apps.api.modules.agent.models import EngagementState
    from apps.api.modules.scans.models import Scan

    # R-03: the attack graph is a finding-derived section and must obey the SAME scan scope as
    # everything else, or a scoped report would show an Executive summary from scans A/B beside
    # an attack graph aggregated over every engagement in the project. It already joins Scan,
    # so the scope is one extra predicate on that join -- no new relationship is introduced.
    engagement_query = (
        select(EngagementState).join(Scan, Scan.id == EngagementState.scan_id)
        .where(Scan.project_id == project_id)
    )
    if scan_ids:
        engagement_query = engagement_query.where(Scan.id.in_(list(scan_ids)))

    engagements = list(await db.scalars(engagement_query))
    node_counts: dict[str, int] = {}
    confirmed_access: list[dict] = []
    for eng in engagements:
        graph = eng.attack_graph or {}
        for node in graph.get("nodes", []):
            ntype = node.get("type")
            if ntype:
                node_counts[ntype] = node_counts.get(ntype, 0) + 1
            if ntype == "access":
                attrs = node.get("attributes") or {}
                # node id is "access:<target>:<access_type>" -> recover the target.
                parts = str(node.get("id", "")).split(":")
                target = parts[1] if len(parts) >= 3 else (parts[1] if len(parts) == 2 else "?")
                confirmed_access.append(
                    {"target": target, "access_state": attrs.get("access_state"), "module": attrs.get("module")}
                )
    return {
        "has_data": bool(engagements) and bool(node_counts),
        "engagement_count": len(engagements),
        "node_counts": node_counts,
        "confirmed_access": confirmed_access,
    }


async def gather_report_data(
    db: AsyncSession, project_id: uuid.UUID, scan_ids: list[uuid.UUID] | None = None
) -> ReportData:
    """Build the report population for a project, optionally narrowed to specific scans.

    SCAN SCOPE (R-03)
    -----------------
    `scan_ids=None` (or an empty list) means the WHOLE PROJECT -- the long-standing contract
    stated verbatim on ReportCreate.scan_ids ("Optional; empty = whole project"). Preserved
    exactly; only an explicit, non-empty list narrows anything.

    The scope is applied HERE, on the single vulnerability query every other figure is derived
    from, rather than at render time. That ordering is the requirement: classification,
    verification, scoring, the severity tallies, MITRE, compliance, affected assets,
    remediation and evidence all read `rows`/`vuln_ids` computed below, so scoping this one
    query scopes every downstream section by construction -- there is no second filter to keep
    in step and no way for one section to describe a different population than another.

    THE SCAN -> FINDING RELATIONSHIP
    --------------------------------
    `Vulnerability.last_seen_scan_id` -- the CANONICAL "findings this scan produced" link,
    already used by attack.service (the ATT&CK matrix and kill chain), remediation.verification,
    scans.service and the orchestrator. It is written on EVERY ingest, both when a fingerprint
    is new and when an existing one is re-detected (vulnerabilities.service.upsert), so it
    always names the scan that most recently observed the finding.

    Deliberately NOT `first_detected_scan_id`: a vulnerability row is deduped per
    (project_id, fingerprint) and therefore OUTLIVES the scan that first saw it, so
    first_detected names a historical event rather than membership. Scoping by it would omit a
    finding that scan B re-detected merely because scan A saw it first -- the opposite of what
    "report on scan B" means. The two columns together are a first/last RANGE, not a
    membership set, and `last_seen_scan_id` is the one the rest of the codebase already treats
    as "this scan's findings".

    AUTHORIZATION
    -------------
    Not performed here. `scan_ids` must already have been validated by the caller against the
    workspace AND project (reports.service.create_report uses scans.service.get_scan, the
    canonical helper, which 404s on an unknown or out-of-scope scan). This function is an
    internal data-layer call that also runs from trusted contexts; duplicating the check would
    create a second authorization model, which the brief forbids. The `project_id` predicate
    below is retained regardless, so even a hypothetical unvalidated scan id from another
    project cannot pull that project's rows into this report."""
    project = await db.get(Project, project_id)
    project_name = project.name if project else str(project_id)

    # Normalised once: None and [] are the same "no explicit scope" signal, and everything
    # below tests this single value rather than re-deriving the emptiness rule.
    scope_scan_ids = list(scan_ids or [])

    vuln_query = select(Vulnerability).where(Vulnerability.project_id == project_id)
    if scope_scan_ids:
        vuln_query = vuln_query.where(Vulnerability.last_seen_scan_id.in_(scope_scan_ids))

    vulns = list(
        await db.scalars(
            vuln_query
            # Phase 0 MySQL cutover: nullslast() dropped -- see the identical comment in
            # apps/api/modules/vulnerabilities/service.py's list_vulnerabilities; MySQL/
            # MariaDB already put NULLs last on a plain DESC, and NULLS LAST syntax itself
            # isn't supported on MariaDB.
            .order_by(Vulnerability.cvss_score.desc(), Vulnerability.created_at)
        )
    )
    vuln_ids = [v.id for v in vulns]

    # Bulk-load risk, compliance, and evidence for those vulns, then stitch.
    risk_by_vuln: dict[uuid.UUID, RiskScore] = {}
    compliance_by_vuln: dict[uuid.UUID, list[tuple[str, str, str]]] = {}
    evidence_by_vuln: dict[uuid.UUID, list[str]] = {}
    # P2-3: vulnerability_id -> [(evidence_type, storage_uri)] for NON-screenshot evidence.
    # Parallel to evidence_by_vuln so that list keeps its list[str] contract untouched.
    evidence_items_by_vuln: dict[uuid.UUID, list[tuple[str, str]]] = {}
    # Phase 3.2: vulnerability_id -> [EvidenceRecord] for EVERY artifact (screenshots too),
    # carrying checksum/timestamp/ids. Parallel to the two lists above, which keep their exact
    # shapes for existing consumers.
    evidence_records_by_vuln: dict[uuid.UUID, list[EvidenceRecord]] = {}
    # vulnerability_id -> [(storage_uri, checksum)] for evidence_type='screenshot'.
    screenshot_by_vuln: dict[uuid.UUID, list[tuple[str, str]]] = {}
    # Remediation guidance, when the pipeline has generated any. Read-only: the report never
    # writes, derives or invents this text -- a vulnerability with no remediation row simply
    # renders "Not available in scan evidence." (the table is empty on the current dataset).
    remediation_by_vuln: dict[uuid.UUID, tuple[str | None, list[str], list[str]]] = {}
    attack_counts: dict[tuple[str, str, str], int] = {}
    # vulnerability_id -> {(tactic_name, technique_id, technique_name)}. Raw per-row mappings,
    # rolled up into attack_counts below once issue identity is available.
    techniques_by_vuln: dict[uuid.UUID, set[tuple[str, str, str]]] = {}
    # asset_id -> assets.value, for the vulns that ARE linked to an inventoried asset. Loaded
    # via the existing Vulnerability.asset_id FK (read-only; no schema change). A vuln whose
    # asset_id is NULL simply never appears here, so its VulnRow.asset_value stays None.
    asset_value_by_id: dict[uuid.UUID, str] = {}
    # vulnerability_id -> producing tool name (tool_runs.tool_name via the existing
    # VulnerabilityEvidence.tool_run_id FK; read-only join, no schema change).
    tool_name_by_vuln: dict[uuid.UUID, str] = {}
    # vulnerability_id -> the producing tool's VERSION (tool_runs.tool_version), taken from the
    # SAME tool_runs row the name is taken from, in the same pass, so the two can never
    # describe different runs. Read-only; the column is NOT NULL and has always been written
    # by both execution planes (orchestrator sets it from `runner.version`; scanner_manager
    # derives it from TOOL_REGISTRY rather than trusting the worker -- see result_sink.py).
    #
    # WHY IT MATTERS FOR TRUTHFULNESS. "nuclei found this" is not a reproducible statement:
    # the same template id can match under one tool release and not the next, so a finding
    # attributed to a tool without its version cannot be re-run against the thing that
    # produced it. The report already carried the tool; dropping the version broke the
    # Tool -> Tool Version link of the lineage chain at the report boundary, even though the
    # value was sitting in the row being joined.
    tool_version_by_vuln: dict[uuid.UUID, str] = {}
    if vuln_ids:
        for r in await db.scalars(select(RiskScore).where(RiskScore.vulnerability_id.in_(vuln_ids))):
            risk_by_vuln[r.vulnerability_id] = r
        for m in await db.scalars(select(ComplianceMapping).where(ComplianceMapping.vulnerability_id.in_(vuln_ids))):
            compliance_by_vuln.setdefault(m.vulnerability_id, []).append(
                (m.framework, m.control_id, m.control_description or "")
            )
        # Collect the techniques PER VULNERABILITY here; the per-technique tally is computed
        # further down, once the VulnRows (and therefore issue identity + classification)
        # exist. Counting at this point could only ever count raw mapping ROWS.
        for a in await db.scalars(select(AttackMapping).where(AttackMapping.vulnerability_id.in_(vuln_ids))):
            techniques_by_vuln.setdefault(a.vulnerability_id, set()).add(
                (a.tactic_name, a.technique_id, a.technique_name)
            )
        # Remediation guidance for these vulnerabilities, when any exists. READ-ONLY join --
        # the report presents this text verbatim and never generates it. On a dataset where
        # the pipeline has produced none, every finding simply reports it as unavailable.
        try:
            from apps.api.modules.vulnerabilities.remediation_models import Remediation

            for rem in await db.scalars(
                select(Remediation).where(Remediation.vulnerability_id.in_(vuln_ids))
            ):
                links = rem.reference_links
                if isinstance(links, str):
                    links = [links] if links.strip() else []
                remediation_by_vuln[rem.vulnerability_id] = (
                    rem.summary,
                    # Normalised to list[str] here, at the boundary, so every consumer sees one
                    # shape. `rem.steps` is a JSON list column; passing it through raw is what
                    # used to crash the renderer.
                    _normalise_steps(rem.steps),
                    list(links or []),
                )
        except Exception:
            # Remediation content is optional enrichment; its absence must never cost the
            # report the findings themselves.
            pass

        # vulnerability_evidence -> evidence.storage_uri
        from apps.api.modules.vulnerabilities.models import VulnerabilityEvidence

        # Phase 3.2: `id`, `created_at` and `tool_run_id` are now selected alongside the three
        # columns this query already read. All four have existed since the evidence store was
        # built; the report simply never loaded them, which is why no artifact could be dated
        # or integrity-checked. Same single query -- no extra round trip, no schema change.
        evidence_rows = await db.execute(
            select(
                VulnerabilityEvidence.vulnerability_id,
                Evidence.storage_uri,
                Evidence.evidence_type,
                Evidence.checksum,
                Evidence.id,
                Evidence.created_at,
                Evidence.tool_run_id,
            )
            .join(Evidence, Evidence.id == VulnerabilityEvidence.evidence_id)
            .where(VulnerabilityEvidence.vulnerability_id.in_(vuln_ids))
            # Deterministic artifact ordering: oldest capture first, then by id so rows sharing
            # a timestamp cannot reorder between renders of identical data.
            .order_by(Evidence.created_at, Evidence.id)
        )
        # Screenshots are split out from the log/raw-output evidence so the Technical Report
        # can embed the image while still listing the textual artifacts. The checksum rides
        # along so the renderer can drop byte-identical duplicates without fetching them.
        for vid, uri, etype, checksum, ev_id, created_at, tool_run_id in evidence_rows.all():
            # Phase 3.2: EVERY artifact -- screenshots included -- gets a record carrying its
            # integrity metadata. Built before the screenshot branch so the manifest is the
            # complete inventory of what the evidence store holds for these findings, rather
            # than repeating the split the display sections make for layout reasons.
            record = EvidenceRecord(
                evidence_id=ev_id,
                evidence_type=etype or "unknown",
                storage_uri=uri,
                checksum=checksum,
                captured_at=created_at,
                tool_run_id=tool_run_id,
            )
            records = evidence_records_by_vuln.setdefault(vid, [])
            if record not in records:
                records.append(record)

            if etype == "screenshot":
                shots = screenshot_by_vuln.setdefault(vid, [])
                if (uri, checksum) not in shots:
                    shots.append((uri, checksum))
                continue
            uris = evidence_by_vuln.setdefault(vid, [])
            if uri not in uris:
                uris.append(uri)
            # P2-3: keep the TYPE alongside the URI. `evidence_type` was already selected above
            # and then discarded for everything except screenshots, so the report could only
            # print a bare `s3://.../raw-output.txt` and the reader had no way to tell a tool
            # log from any other artifact. Recorded in a PARALLEL list so `evidence_uris` keeps
            # its exact list[str] shape for every existing consumer and test.
            items = evidence_items_by_vuln.setdefault(vid, [])
            if (etype, uri) not in items:
                items.append((etype or "unknown", uri))

        # Producing tool per vulnerability. One vuln can link to several tool_runs across
        # re-scans; take the most recent by tool_runs.started_at so the report shows the
        # tool that last produced it. Read-only; no schema change.
        #
        # NULLABLE-tool_run AUDIT: `evidence.tool_run_id` became nullable for human-uploaded
        # remediation proof, but this join is on VULNERABILITY_EVIDENCE.tool_run_id, which is
        # still NOT NULL (a scanner finding is always produced by a tool run) -- and
        # remediation proof is never linked into vulnerability_evidence at all. So this inner
        # join cannot drop a row it used to return, and no LEFT JOIN is needed here. The
        # evidence_uris/screenshot query above joins on evidence.ID, not on tool_run_id, so it
        # is likewise unaffected.
        from apps.api.scanner_engine.models import ToolRun

        tool_rows = await db.execute(
            select(
                VulnerabilityEvidence.vulnerability_id,
                ToolRun.tool_name,
                ToolRun.tool_version,
                ToolRun.started_at,
            )
            .join(ToolRun, ToolRun.id == VulnerabilityEvidence.tool_run_id)
            .where(VulnerabilityEvidence.vulnerability_id.in_(vuln_ids))
        )
        _tool_seen: dict[uuid.UUID, object] = {}
        for vid, tname, tversion, started in tool_rows.all():
            prev = _tool_seen.get(vid)
            if tname and (prev is None or (started is not None and started >= prev)):
                tool_name_by_vuln[vid] = tname
                # Name and version are taken from the SAME winning row, together, so the
                # report can never pair one run's tool with another run's version. A blank
                # version (historical rows written before the registry lookup, which stores
                # "" rather than NULL) is left absent rather than substituted.
                if tversion and str(tversion).strip():
                    tool_version_by_vuln[vid] = str(tversion).strip()
                else:
                    tool_version_by_vuln.pop(vid, None)
                _tool_seen[vid] = started

        # Resolve asset_id -> assets.value for the linked findings only.
        asset_ids = [v.asset_id for v in vulns if v.asset_id is not None]
        if asset_ids:
            for aid, value in (
                await db.execute(select(Asset.id, Asset.value).where(Asset.id.in_(asset_ids)))
            ).all():
                asset_value_by_id[aid] = value

    severity_counts = {sev: 0 for sev in _SEVERITY_ORDER}
    active_counts = {sev: 0 for sev in _SEVERITY_ORDER}
    rows: list[VulnRow] = []
    # vulnerability_id -> its VulnRow, so the ATT&CK tally below can reach each finding's
    # issue identity and classification without rebuilding either.
    row_by_vuln_id: dict[uuid.UUID, VulnRow] = {}
    for v in vulns:
        sev = v.severity if v.severity in severity_counts else "info"
        severity_counts[sev] += 1
        if v.status in _ACTIVE_STATUSES:
            active_counts[sev] += 1
        risk = risk_by_vuln.get(v.id)
        row = VulnRow(
            id=v.id,
            title=v.title,
            severity=v.severity,
            status=v.status,
            category=v.category,
            cvss_score=v.cvss_score,
            cvss_vector=v.cvss_vector,
            # The scanner's own description of the finding. The column has always existed and
            # is populated for the large majority of rows, but the report never loaded it --
            # so Detailed Findings could show only a bare title. Passed through VERBATIM; the
            # report never rewrites, summarises or generates this text.
            description=v.description,
            **dict(zip(
                ("remediation_summary", "remediation_steps", "remediation_references"),
                remediation_by_vuln.get(v.id, (None, [], [])),
                strict=True,
            )),
            final_risk_score=risk.final_risk_score if risk else None,
            risk_rationale=risk.rationale if risk else None,
            compliance=sorted(compliance_by_vuln.get(v.id, [])),
            evidence_uris=evidence_by_vuln.get(v.id, []),
            evidence_items=evidence_items_by_vuln.get(v.id, []),
            evidence_records=evidence_records_by_vuln.get(v.id, []),
            screenshots=screenshot_by_vuln.get(v.id, []),
            asset_value=asset_value_by_id.get(v.asset_id) if v.asset_id else None,
            tool_name=tool_name_by_vuln.get(v.id, "N/A"),
            tool_version=tool_version_by_vuln.get(v.id),
            **dict(zip(("template_id", "matcher_name", "matched_at"),
                       _parse_fingerprint(v.fingerprint), strict=True)),
        )
        # Derived from the row's own template_id/cvss/category -- see classification.py.
        row.classification = classify_row(row)
        # Set AFTER classification: verification reads it (a detection is never "verified
        # exploitation"). Purely derived; touches no stored value -- see verification.py.
        row.verification, row.confidence = classify_verification_row(row)
        # Prompt 33: observe the verification MIX. Emitted here because this is the one place
        # every reported finding passes through with its final state resolved. Counting only --
        # the recorder cannot influence the value it observes, and both labels are closed
        # vocabularies (verification.py's own states/bands), so no finding, target, project or
        # tenant identity can reach the metrics endpoint.
        record_verification_outcome(row.verification, row.confidence)
        rows.append(row)
        row_by_vuln_id[v.id] = row

    # --- MITRE ATT&CK tally ---------------------------------------------------------------
    # Counts DISTINCT LOGICAL ISSUES per technique, over the SAME population the Security
    # Score uses (scoring.is_scorable -> active status, not info severity, not a detection).
    #
    # It previously counted raw AttackMapping ROWS over every project finding, which meant:
    # one issue observed at 20 URLs counted 20 times, and fixed / false-positive /
    # accepted-risk / informational findings all contributed. On a realistic dataset that
    # reported 29 where the Security Score saw 1 distinct issue.
    #
    # Identity is scoring.issue_key -- the canonical function the score and both report
    # groupings already use -- so "one issue" means the same thing on every surface. A single
    # issue mapped to several techniques still counts once PER TECHNIQUE (each technique is a
    # separate row), and two distinct issues sharing one technique count as two.
    #
    # The identical rule is applied to the ATT&CK API endpoints via attack.aggregation, which
    # is the shared source of truth for "how many issues hit a technique". The loop below
    # stays here (rather than calling that module) only because this path already holds fully
    # built VulnRows -- richer objects than the ORM rows the API adapts -- so it can reuse
    # them directly instead of re-deriving identity. Both paths call the SAME
    # scoring.is_scorable / scoring.issue_key, which is what makes the numbers agree; the
    # parity is pinned by test_attack_api_matches_pdf_* in test_reports.py.
    issue_keys_by_technique: dict[tuple[str, str, str], set[str]] = {}
    for vuln_id, technique_set in techniques_by_vuln.items():
        row = row_by_vuln_id.get(vuln_id)
        if row is None or not is_scorable(row):
            continue
        key = issue_key(row)
        for technique in technique_set:
            issue_keys_by_technique.setdefault(technique, set()).add(key)

    attack_counts = {t: len(keys) for t, keys in issue_keys_by_technique.items()}
    attack_techniques = sorted(
        [(tactic, tid, tname, count) for (tactic, tid, tname), count in attack_counts.items()],
        key=lambda x: (-x[3], x[0], x[1]),
    )

    attack_graph = await _gather_attack_graph(db, project_id, scope_scan_ids)

    # R-03 scope metadata. Read from the `scans` rows themselves -- the caller has already
    # authorised every id against this workspace AND project -- so the Assessment Scope section
    # states real recorded values and never fabricates a window or a target. The project_id
    # predicate is repeated here as defence in depth: even an unvalidated id cannot pull a row
    # belonging to another project into this report's metadata.
    scope_scans: list[dict] = []
    if scope_scan_ids:
        from apps.api.modules.projects.models import Target
        from apps.api.modules.scans.models import Scan

        scope_rows = (
            await db.execute(
                select(Scan, Target.value)
                .outerjoin(Target, Target.id == Scan.target_id)
                .where(Scan.id.in_(scope_scan_ids), Scan.project_id == project_id)
                .order_by(Scan.created_at)
            )
        ).all()
        scope_scans = [
            {
                "id": scan.id,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "target": target_value,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
            }
            for scan, target_value in scope_rows
        ]

    return ReportData(
        project_name=project_name,
        security_score=compute_security_score(rows),
        severity_counts=severity_counts,
        total_vulns=len(vulns),
        active_vulns=sum(active_counts.values()),
        active_severity_counts=active_counts,
        vulns=rows,
        attack_techniques=attack_techniques,
        attack_graph=attack_graph,
        scope_scans=scope_scans,
    )
