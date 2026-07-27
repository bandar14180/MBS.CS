import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

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


@dataclass
class ReportData:
    project_name: str
    security_score: int
    severity_counts: dict[str, int]
    total_vulns: int
    active_vulns: int
    vulns: list[VulnRow] = field(default_factory=list)


def compute_security_score(active_severity_counts: dict[str, int]) -> int:
    penalty = sum(_SEVERITY_PENALTY.get(sev, 0) * n for sev, n in active_severity_counts.items())
    return max(0, 100 - penalty)


async def gather_report_data(db: AsyncSession, project_id: uuid.UUID) -> ReportData:
    project = await db.get(Project, project_id)
    project_name = project.name if project else str(project_id)

    vulns = list(
        await db.scalars(
            select(Vulnerability)
            .where(Vulnerability.project_id == project_id)
            .order_by(Vulnerability.cvss_score.desc().nullslast(), Vulnerability.created_at)
        )
    )
    vuln_ids = [v.id for v in vulns]

    # Bulk-load risk, compliance, and evidence for those vulns, then stitch.
    risk_by_vuln: dict[uuid.UUID, RiskScore] = {}
    compliance_by_vuln: dict[uuid.UUID, list[tuple[str, str, str]]] = {}
    evidence_by_vuln: dict[uuid.UUID, list[str]] = {}
    if vuln_ids:
        for r in await db.scalars(select(RiskScore).where(RiskScore.vulnerability_id.in_(vuln_ids))):
            risk_by_vuln[r.vulnerability_id] = r
        for m in await db.scalars(select(ComplianceMapping).where(ComplianceMapping.vulnerability_id.in_(vuln_ids))):
            compliance_by_vuln.setdefault(m.vulnerability_id, []).append(
                (m.framework, m.control_id, m.control_description or "")
            )
        # vulnerability_evidence -> evidence.storage_uri
        from apps.api.modules.vulnerabilities.models import VulnerabilityEvidence

        rows = await db.execute(
            select(VulnerabilityEvidence.vulnerability_id, Evidence.storage_uri)
            .join(Evidence, Evidence.id == VulnerabilityEvidence.evidence_id)
            .where(VulnerabilityEvidence.vulnerability_id.in_(vuln_ids))
        )
        for vid, uri in rows.all():
            uris = evidence_by_vuln.setdefault(vid, [])
            if uri not in uris:
                uris.append(uri)

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
            )
        )

    return ReportData(
        project_name=project_name,
        security_score=compute_security_score(active_counts),
        severity_counts=severity_counts,
        total_vulns=len(vulns),
        active_vulns=sum(active_counts.values()),
        vulns=rows,
    )
