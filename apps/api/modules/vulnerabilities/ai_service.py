import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.vulnerabilities.models import Vulnerability
from apps.api.modules.vulnerabilities.remediation_models import Remediation
from apps.api.modules.vulnerabilities.service import get_vulnerability

_AI_STATUSES = {"open", "confirmed", "reopened"}


def _location_hint(fingerprint: str) -> str | None:
    # Nuclei fingerprint is "template-id|matcher|matched-at"; the last segment is
    # the observed location. Best-effort -- returns None if there's no delimiter.
    return fingerprint.rsplit("|", 1)[-1] if "|" in fingerprint else None


def _finding_dict(v: Vulnerability) -> dict:
    return {
        "id": str(v.id),
        "title": v.title,
        "severity": v.severity,
        "category": v.category,
        "status": v.status,
        "cvss_score": v.cvss_score,
        "location": _location_hint(v.fingerprint),
    }


async def generate_remediation(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, vuln_id: uuid.UUID
) -> Remediation:
    vuln = await get_vulnerability(db, workspace_id, project_id, vuln_id)

    from starlette.concurrency import run_in_threadpool

    from apps.api.ai_agent.remediation_writer import RemediationWriter

    try:
        # Off the event loop -- the provider call is synchronous.
        result = await run_in_threadpool(
            lambda: RemediationWriter().write(
                title=vuln.title,
                severity=vuln.severity,
                category=vuln.category,
                matched_at=_location_hint(vuln.fingerprint),
                cvss_score=vuln.cvss_score,
                description=vuln.description,
            )
        )
    except RuntimeError as exc:  # no provider key configured
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))

    # Phase 0 MySQL cutover: pg_insert(...).on_conflict_do_update(constraint=...) ->
    # mysql_insert(...).on_duplicate_key_update(...) -- see risk/service.py's
    # upsert_risk_score for the fuller explanation of why no constraint name is needed.
    stmt = mysql_insert(Remediation.__table__).values(
        vulnerability_id=vuln_id,
        summary=result.summary,
        steps=result.steps,
        reference_links=result.references,
        generated_by="ai",
        model_version=result.model_version,
        prompt_version=result.prompt_version,
    )
    stmt = stmt.on_duplicate_key_update(
        summary=result.summary,
        steps=result.steps,
        reference_links=result.references,
        generated_by="ai",
        model_version=result.model_version,
        prompt_version=result.prompt_version,
    )
    await db.execute(stmt)
    await db.commit()
    return await get_remediation(db, workspace_id, project_id, vuln_id)


async def get_remediation(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, vuln_id: uuid.UUID
) -> Remediation:
    await get_vulnerability(db, workspace_id, project_id, vuln_id)
    rem = await db.scalar(select(Remediation).where(Remediation.vulnerability_id == vuln_id))
    if rem is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No remediation generated for this vulnerability")
    return rem


async def fp_analysis(db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID):
    """AI suggestions for which of the project's active findings are likely
    false positives. Suggestions only -- acting on one goes through the existing
    audited `PATCH .../status` (justification required)."""
    vulns = list(
        await db.scalars(
            select(Vulnerability).where(
                Vulnerability.project_id == project_id, Vulnerability.status.in_(_AI_STATUSES)
            )
        )
    )
    findings = [_finding_dict(v) for v in vulns]

    from starlette.concurrency import run_in_threadpool

    from apps.api.ai_agent.fp_reducer import FPReducer

    try:
        return await run_in_threadpool(FPReducer().assess, findings)  # off the event loop
    except RuntimeError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
