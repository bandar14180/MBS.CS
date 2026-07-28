import uuid

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.vulnerabilities.models import Vulnerability
from apps.api.modules.dashboard.schemas import (
    DashboardSummary,
    Recommendation,
    RecentScan,
    ScanStats,
    SeverityCounts,
    VulnerabilityStats,
)

# Highest-attention active statuses, ordered severity rank for prioritization.
_ACTIVE = ("open", "confirmed", "reopened")
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Vulnerability lifecycle states that still demand attention.
_ACTIVE_STATUSES = ("open", "confirmed", "reopened")
_KNOWN_SCAN_STATUSES = {"queued", "running", "completed", "failed"}
_KNOWN_SEVERITIES = {"critical", "high", "medium", "low", "info"}


async def get_summary(db: AsyncSession, workspace_id: uuid.UUID) -> DashboardSummary:
    """Workspace-wide rollup for the dashboard landing page. Every count is
    scoped to `workspace_id` explicitly (belt-and-braces with RLS)."""

    projects_count = await db.scalar(
        select(func.count()).select_from(Project).where(Project.workspace_id == workspace_id)
    )

    targets_count = await db.scalar(
        select(func.count())
        .select_from(Target)
        .join(Project, Project.id == Target.project_id)
        .where(Project.workspace_id == workspace_id)
    )

    # Scans carry a denormalized workspace_id, so no join needed.
    scan_rows = await db.execute(
        select(Scan.status, func.count())
        .where(Scan.workspace_id == workspace_id)
        .group_by(Scan.status)
    )
    scans = ScanStats()
    for status_value, count in scan_rows:
        scans.total += count
        if status_value in _KNOWN_SCAN_STATUSES:
            setattr(scans, status_value, count)

    # Vulnerabilities are project-scoped; join to filter by workspace.
    vuln_total = await db.scalar(
        select(func.count())
        .select_from(Vulnerability)
        .join(Project, Project.id == Vulnerability.project_id)
        .where(Project.workspace_id == workspace_id)
    )
    sev_rows = await db.execute(
        select(Vulnerability.severity, func.count())
        .join(Project, Project.id == Vulnerability.project_id)
        .where(Project.workspace_id == workspace_id, Vulnerability.status.in_(_ACTIVE_STATUSES))
        .group_by(Vulnerability.severity)
    )
    by_severity = SeverityCounts()
    active_total = 0
    for severity, count in sev_rows:
        active_total += count
        if severity in _KNOWN_SEVERITIES:
            setattr(by_severity, severity, count)
    vulnerabilities = VulnerabilityStats(
        total=vuln_total or 0, active=active_total, by_severity=by_severity
    )

    recent_rows = await db.execute(
        select(Scan.id, Scan.project_id, Project.name, Target.value, Scan.scan_type, Scan.status, Scan.created_at)
        .join(Project, Project.id == Scan.project_id)
        .join(Target, Target.id == Scan.target_id)
        .where(Scan.workspace_id == workspace_id)
        .order_by(Scan.created_at.desc())
        .limit(5)
    )
    recent_scans = [
        RecentScan(
            id=row[0],
            project_id=row[1],
            project_name=row[2],
            target_value=row[3],
            scan_type=row[4],
            status=row[5],
            created_at=row[6],
        )
        for row in recent_rows
    ]

    return DashboardSummary(
        projects=projects_count or 0,
        targets=targets_count or 0,
        scans=scans,
        vulnerabilities=vulnerabilities,
        recent_scans=recent_scans,
    )


async def get_recommendations(
    db: AsyncSession, workspace_id: uuid.UUID, limit: int = 6
) -> list[Recommendation]:
    """The highest-priority active findings to fix next, workspace-wide, ordered
    by severity then CVSS. This is the dashboard's 'Recommendations' surface."""
    severity_order = case(
        (Vulnerability.severity == "critical", 0),
        (Vulnerability.severity == "high", 1),
        (Vulnerability.severity == "medium", 2),
        (Vulnerability.severity == "low", 3),
        else_=4,
    )
    rows = await db.execute(
        select(
            Vulnerability.id,
            Vulnerability.project_id,
            Project.name,
            Vulnerability.title,
            Vulnerability.severity,
            Vulnerability.cvss_score,
            Vulnerability.category,
        )
        .join(Project, Project.id == Vulnerability.project_id)
        .where(Project.workspace_id == workspace_id, Vulnerability.status.in_(_ACTIVE))
        .order_by(severity_order, Vulnerability.cvss_score.desc().nullslast())
        .limit(limit)
    )
    return [
        Recommendation(
            vulnerability_id=r[0],
            project_id=r[1],
            project_name=r[2],
            title=r[3],
            severity=r[4],
            cvss_score=r[5],
            category=r[6],
        )
        for r in rows
    ]
