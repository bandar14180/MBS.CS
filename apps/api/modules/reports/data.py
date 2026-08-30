import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.assets.models import Asset
from apps.api.modules.attack.models import AttackMapping
from apps.api.modules.compliance.models import ComplianceMapping
from apps.api.modules.projects.models import Project
from apps.api.modules.risk.models import RiskScore
from apps.api.modules.vulnerabilities.models import Vulnerability
from apps.api.scanner_engine.models import Evidence

# Statuses that still count against a project's security posture. A finding
# that's fixed / false-positive / accepted-risk no longer subtracts from the score.
_ACTIVE_STATUSES = {"open", "confirmed", "reopened"}
# Score penalty per active finding, by severity.
_SEVERITY_PENALTY = {"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 0}
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


@dataclass
class ReportData:
    project_name: str
    security_score: int
    severity_counts: dict[str, int]
    total_vulns: int
    active_vulns: int
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

    def affected_assets(self) -> list[str]:
        """Distinct inventoried asset/host values (assets.value) across the findings, sorted.
        Only non-null asset links -- a finding with no asset_id contributes nothing, so the
        Executive report never implies an asset is affected when the linkage is absent. Pure
        (derived from self.vulns), so it adds no query and is directly testable."""
        return sorted({v.asset_value for v in self.vulns if v.asset_value})

    def affected_endpoint_count(self) -> int:
        """How many DISTINCT endpoints (matched_at) the findings were observed at. Endpoint is
        the exact URL/location -- distinct from an asset/host -- so this can exceed the asset
        count when one host exposes many affected endpoints. Findings without a matched_at
        (older/non-nuclei) don't count."""
        return len({v.matched_at for v in self.vulns if v.matched_at})


def compute_security_score(active_severity_counts: dict[str, int]) -> int:
    penalty = sum(_SEVERITY_PENALTY.get(sev, 0) * n for sev, n in active_severity_counts.items())
    return max(0, 100 - penalty)


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
    attack_counts: dict[tuple[str, str, str], int] = {}
    # asset_id -> assets.value, for the vulns that ARE linked to an inventoried asset. Loaded
    # via the existing Vulnerability.asset_id FK (read-only; no schema change). A vuln whose
    # asset_id is NULL simply never appears here, so its VulnRow.asset_value stays None.
    asset_value_by_id: dict[uuid.UUID, str] = {}
    if vuln_ids:
        for r in await db.scalars(select(RiskScore).where(RiskScore.vulnerability_id.in_(vuln_ids))):
            risk_by_vuln[r.vulnerability_id] = r
        for m in await db.scalars(select(ComplianceMapping).where(ComplianceMapping.vulnerability_id.in_(vuln_ids))):
            compliance_by_vuln.setdefault(m.vulnerability_id, []).append(
                (m.framework, m.control_id, m.control_description or "")
            )
        for a in await db.scalars(select(AttackMapping).where(AttackMapping.vulnerability_id.in_(vuln_ids))):
            key = (a.tactic_name, a.technique_id, a.technique_name)
            attack_counts[key] = attack_counts.get(key, 0) + 1
        # vulnerability_evidence -> evidence.storage_uri
        from apps.api.modules.vulnerabilities.models import VulnerabilityEvidence

        evidence_rows = await db.execute(
            select(VulnerabilityEvidence.vulnerability_id, Evidence.storage_uri)
            .join(Evidence, Evidence.id == VulnerabilityEvidence.evidence_id)
            .where(VulnerabilityEvidence.vulnerability_id.in_(vuln_ids))
        )
        for vid, uri in evidence_rows.all():
            uris = evidence_by_vuln.setdefault(vid, [])
            if uri not in uris:
                uris.append(uri)

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
    for v in vulns:
        sev = v.severity if v.severity in severity_counts else "info"
        severity_counts[sev] += 1
        if v.status in _ACTIVE_STATUSES:
            active_counts[sev] += 1
        risk = risk_by_vuln.get(v.id)
        rows.append(
            VulnRow(
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
                asset_value=asset_value_by_id.get(v.asset_id) if v.asset_id else None,
                **dict(zip(("template_id", "matcher_name", "matched_at"),
                           _parse_fingerprint(v.fingerprint), strict=True)),
            )
        )

    attack_techniques = sorted(
        [(tactic, tid, tname, count) for (tactic, tid, tname), count in attack_counts.items()],
        key=lambda x: (-x[3], x[0], x[1]),
    )

    attack_graph = await _gather_attack_graph(db, project_id)

    return ReportData(
        project_name=project_name,
        security_score=compute_security_score(active_counts),
        severity_counts=severity_counts,
        total_vulns=len(vulns),
        active_vulns=sum(active_counts.values()),
        vulns=rows,
        attack_techniques=attack_techniques,
        attack_graph=attack_graph,
    )
