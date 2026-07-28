import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.vulnerabilities.models import Vulnerability, VulnerabilityEvidence
from apps.api.scanner_engine.tool_runners.base import VulnerabilityFinding

# Nominal CVSS base scores by severity, used only when the tool doesn't report a
# score (so ranking still works). Not an AI estimate -- just a severity floor.
_SEVERITY_SCORE = {"info": 0.0, "low": 3.1, "medium": 5.5, "high": 7.5, "critical": 9.5}

# Statuses an analyst may set via the API. "reopened"/"open" are also reachable
# automatically by the engine on re-detection.
SETTABLE_STATUSES = {"open", "confirmed", "false_positive", "fixed", "accepted_risk"}
# Analyst decisions the engine must not silently override when a finding recurs.
_STICKY_STATUSES = {"false_positive", "accepted_risk"}


def _score_for(finding: VulnerabilityFinding) -> float | None:
    if finding.cvss_score is not None:
        return finding.cvss_score
    return _SEVERITY_SCORE.get(finding.severity)


async def ingest_finding(
    db: AsyncSession,
    project_id: uuid.UUID,
    scan_id: uuid.UUID,
    finding: VulnerabilityFinding,
    tool_run_id: uuid.UUID,
    evidence_id: uuid.UUID,
    asset_id: uuid.UUID | None = None,
) -> Vulnerability:
    """Dedupe a finding into the vulnerabilities table and link its evidence.

    New fingerprint -> create as `open`. Recurring fingerprint -> refresh
    metadata + last_seen, and if it had been marked `fixed`, flip to `reopened`
    (it came back). Analyst decisions (`false_positive`/`accepted_risk`) stick.
    Every ingest appends a vulnerability_evidence row (blueprint §1)."""
    now = datetime.now(timezone.utc)
    existing = await db.scalar(
        select(Vulnerability).where(
            Vulnerability.project_id == project_id, Vulnerability.fingerprint == finding.fingerprint
        )
    )

    if existing is None:
        vuln = Vulnerability(
            project_id=project_id,
            asset_id=asset_id,
            first_detected_scan_id=scan_id,
            last_seen_scan_id=scan_id,
            fingerprint=finding.fingerprint,
            title=finding.title,
            category=finding.category,
            description=finding.description,
            severity=finding.severity,
            cvss_vector=finding.cvss_vector,
            cvss_score=_score_for(finding),
            status="open",
        )
        db.add(vuln)
        await db.flush()
    else:
        vuln = existing
        vuln.last_seen_scan_id = scan_id
        vuln.title = finding.title
        vuln.description = finding.description
        vuln.severity = finding.severity
        vuln.cvss_vector = finding.cvss_vector
        vuln.cvss_score = _score_for(finding)
        if asset_id is not None:
            vuln.asset_id = asset_id
        if vuln.status == "fixed":
            vuln.status = "reopened"  # regression: it's back
        # open/confirmed/reopened stay; sticky analyst decisions stay untouched.

    db.add(
        VulnerabilityEvidence(
            vulnerability_id=vuln.id, evidence_id=evidence_id, tool_run_id=tool_run_id
        )
    )
    await db.flush()
    return vuln


async def list_vulnerabilities(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    severity: str | None = None,
    status_filter: str | None = None,
) -> list[Vulnerability]:
    query = select(Vulnerability).where(Vulnerability.project_id == project_id)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if status_filter:
        query = query.where(Vulnerability.status == status_filter)
    result = await db.scalars(query.order_by(Vulnerability.cvss_score.desc().nullslast(), Vulnerability.created_at))
    return list(result)


async def get_vulnerability(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, vuln_id: uuid.UUID
) -> Vulnerability:
    vuln = await db.scalar(
        select(Vulnerability).where(Vulnerability.id == vuln_id, Vulnerability.project_id == project_id)
    )
    if vuln is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Vulnerability not found")
    return vuln


async def set_status(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    vuln_id: uuid.UUID,
    new_status: str,
    justification: str,
    changed_by: uuid.UUID,
) -> Vulnerability:
    if new_status not in SETTABLE_STATUSES:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Status must be one of: {', '.join(sorted(SETTABLE_STATUSES))}",
        )
    vuln = await get_vulnerability(db, workspace_id, project_id, vuln_id)
    vuln.status = new_status
    vuln.status_justification = justification
    vuln.status_changed_by = changed_by
    vuln.status_changed_at = datetime.now(timezone.utc)

    from apps.api.modules.audit import service as audit

    await audit.record(
        db, workspace_id, changed_by, "vulnerability.status_changed", "vulnerability",
        resource_id=vuln_id, detail=f"{new_status}: {justification}",
    )
    await db.commit()
    await db.refresh(vuln)
    return vuln
