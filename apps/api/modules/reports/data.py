import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.assets.models import Asset
from apps.api.modules.attack.models import AttackMapping
from apps.api.modules.compliance.models import ComplianceMapping
from apps.api.modules.projects.models import Project
from apps.api.modules.reports.scoring import ACTIVE_STATUSES, compute_security_score, is_scorable, issue_key
from apps.api.modules.reports.classification import classify_row
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


async def _gather_attack_graph(db: AsyncSession, project_id: uuid.UUID) -> dict:
    """Aggregate the persisted attack graph(s) from the project's autonomous
    engagements (M4.4.6). Reads the ACTUAL EngagementState.attack_graph -- never
    recomputes. Fail-soft: returns has_data=False if there is no engagement. Only
    evidence-backed access states are surfaced (privilege escalation / lateral
    movement appear only if a module ever produces that evidence)."""
    from apps.api.modules.agent.models import EngagementState
    from apps.api.modules.scans.models import Scan

    engagements = list(
        await db.scalars(
            select(EngagementState).join(Scan, Scan.id == EngagementState.scan_id).where(Scan.project_id == project_id)
        )
    )
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


async def gather_report_data(db: AsyncSession, project_id: uuid.UUID) -> ReportData:
    project = await db.get(Project, project_id)
    project_name = project.name if project else str(project_id)

    vulns = list(
        await db.scalars(
            select(Vulnerability)
            .where(Vulnerability.project_id == project_id)
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
    # vulnerability_id -> [(storage_uri, checksum)] for evidence_type='screenshot'.
    screenshot_by_vuln: dict[uuid.UUID, list[tuple[str, str]]] = {}
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
        # vulnerability_evidence -> evidence.storage_uri
        from apps.api.modules.vulnerabilities.models import VulnerabilityEvidence

        evidence_rows = await db.execute(
            select(
                VulnerabilityEvidence.vulnerability_id,
                Evidence.storage_uri,
                Evidence.evidence_type,
                Evidence.checksum,
            )
            .join(Evidence, Evidence.id == VulnerabilityEvidence.evidence_id)
            .where(VulnerabilityEvidence.vulnerability_id.in_(vuln_ids))
        )
        # Screenshots are split out from the log/raw-output evidence so the Technical Report
        # can embed the image while still listing the textual artifacts. The checksum rides
        # along so the renderer can drop byte-identical duplicates without fetching them.
        for vid, uri, etype, checksum in evidence_rows.all():
            if etype == "screenshot":
                shots = screenshot_by_vuln.setdefault(vid, [])
                if (uri, checksum) not in shots:
                    shots.append((uri, checksum))
                continue
            uris = evidence_by_vuln.setdefault(vid, [])
            if uri not in uris:
                uris.append(uri)

        # Producing tool per vulnerability. One vuln can link to several tool_runs across
        # re-scans; take the most recent by tool_runs.started_at so the report shows the
        # tool that last produced it. Read-only; no schema change.
        from apps.api.scanner_engine.models import ToolRun

        tool_rows = await db.execute(
            select(VulnerabilityEvidence.vulnerability_id, ToolRun.tool_name, ToolRun.started_at)
            .join(ToolRun, ToolRun.id == VulnerabilityEvidence.tool_run_id)
            .where(VulnerabilityEvidence.vulnerability_id.in_(vuln_ids))
        )
        _tool_seen: dict[uuid.UUID, object] = {}
        for vid, tname, started in tool_rows.all():
            prev = _tool_seen.get(vid)
            if tname and (prev is None or (started is not None and started >= prev)):
                tool_name_by_vuln[vid] = tname
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
            final_risk_score=risk.final_risk_score if risk else None,
            risk_rationale=risk.rationale if risk else None,
            compliance=sorted(compliance_by_vuln.get(v.id, [])),
            evidence_uris=evidence_by_vuln.get(v.id, []),
            screenshots=screenshot_by_vuln.get(v.id, []),
            asset_value=asset_value_by_id.get(v.asset_id) if v.asset_id else None,
            tool_name=tool_name_by_vuln.get(v.id, "N/A"),
            **dict(zip(("template_id", "matcher_name", "matched_at"),
                       _parse_fingerprint(v.fingerprint), strict=True)),
        )
        # Derived from the row's own template_id/cvss/category -- see classification.py.
        row.classification = classify_row(row)
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

    attack_graph = await _gather_attack_graph(db, project_id)

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
    )
