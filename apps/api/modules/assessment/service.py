"""Client Risk Assessment service: draft, issue (freeze), compare.

THE ONE THING TO UNDERSTAND HERE
--------------------------------
`_build_snapshot` computes NOTHING. Every number it returns is read out of the EXISTING
reporting pipeline -- `gather_report_data` (which itself calls `compute_security_score`),
`_score_band`, `_top_risk_groups`, `group_issues`, `is_scorable` -- and copied. That is what
makes assessment/report parity a structural property rather than a coincidence that has to be
maintained by hand, and it is why the parity test can assert exact equality.

If a metric is ever needed that the report does not already produce, the correct move is to add
it to the reporting layer and read it here -- never to compute it in this module.
"""

import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status as http_status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.pagination import MAX_LIMIT, Pagination, paginate
from apps.api.modules.assessment.models import (
    RiskAssessment,
    RiskAssessmentFinding,
    STATUS_DRAFT,
    STATUS_ISSUED,
)
from apps.api.modules.audit import service as audit
from apps.api.modules.projects.service import get_project


async def _build_snapshot(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID
) -> tuple[dict, list[dict]]:
    """Read today's posture out of the reporting pipeline. Returns (summary, findings).

    Nothing here is persisted yet -- a draft can be previewed repeatedly, and only `issue()`
    freezes the result."""
    # THE existing aggregation. It runs compute_security_score internally, so the score here is
    # by construction the same integer the Executive PDF prints for the same data.
    from apps.api.modules.remediation.risk_service import active_acceptance_vuln_ids
    from apps.api.modules.remediation.service import progress_for_project
    from apps.api.modules.reports.data import gather_report_data
    from apps.api.modules.reports.render import _score_band, _top_risk_groups
    from apps.api.modules.reports.scoring import group_issues, is_scorable, issue_key

    data = await gather_report_data(db, project_id)
    progress = await progress_for_project(db, workspace_id, project_id)
    accepted_vuln_ids = await active_acceptance_vuln_ids(db, workspace_id, project_id)

    # Remediation status per ISSUE, so a frozen finding can show where its work stood. Keyed by
    # issue_key -- the same identity the findings themselves use.
    from apps.api.modules.remediation.models import RemediationItem

    remediation_status_by_key = {
        key: st
        for key, st in (
            await db.execute(
                select(RemediationItem.issue_key, RemediationItem.status).where(
                    RemediationItem.project_id == project_id,
                    RemediationItem.workspace_id == workspace_id,
                )
            )
        ).all()
    }

    issues = group_issues(data.vulns)
    top_risks = _top_risk_groups(data.vulns)

    summary = {
        # --- copied verbatim from the report pipeline -------------------------------------
        "security_score": data.security_score,
        "score_band": _score_band(data.security_score),
        "severity_counts": dict(data.severity_counts),
        "active_severity_counts": dict(data.active_severity_counts),
        "total_findings": data.total_vulns,
        "active_findings": data.active_vulns,
        "affected_assets": data.affected_assets(),
        "affected_endpoint_count": data.affected_endpoint_count(),
        # Distinct ISSUES, the unit the score is actually computed over -- so a client reading
        # "5 issues" and a 62-row finding list is not looking at a contradiction.
        "unresolved_issue_count": len(issues),
        "top_risks": [
            {
                "title": g["title"],
                "severity": g["severity"],
                "max_risk": g["max_risk"],
                "max_cvss": g["max_cvss"],
                "endpoint_count": g["endpoint_count"],
            }
            for g in top_risks[:10]
        ],
        # --- from the remediation workflow ------------------------------------------------
        "remediation_progress": progress,
        "risk_accepted_count": len(accepted_vuln_ids),
    }

    # One frozen row per SCORABLE finding, carrying its issue's identity. Row-level (not
    # issue-level) because a client report lists findings, while the issue_key on each row
    # keeps them groupable back to exactly the units the score used.
    findings: list[dict] = []
    location_count_by_key = {i.key: i.location_count for i in issues}
    for row in data.vulns:
        if not is_scorable(row):
            continue
        key = issue_key(row)
        findings.append(
            {
                "issue_key": key,
                "vulnerability_id": row.id,
                "frozen_title": row.title,
                "frozen_severity": row.severity,
                "frozen_cvss_score": row.cvss_score,
                "frozen_final_risk_score": row.final_risk_score,
                "frozen_vulnerability_status": row.status,
                "frozen_remediation_status": remediation_status_by_key.get(key),
                "risk_accepted": row.id in accepted_vuln_ids,
                "location_count": location_count_by_key.get(key, 1),
            }
        )
    return summary, findings


async def create_assessment(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    title: str,
    period_start: datetime,
    period_end: datetime,
) -> RiskAssessment:
    """Create a DRAFT. Drafts hold no frozen numbers -- they are taken at issue time, so a
    draft prepared on Monday and issued on Friday reports Friday's posture, not Monday's."""
    await get_project(db, workspace_id, project_id)
    start = _as_utc(period_start)
    end = _as_utc(period_end)
    if end <= start:
        raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "period_end must be after period_start")

    assessment = RiskAssessment(
        workspace_id=workspace_id,
        project_id=project_id,
        title=title,
        period_start=start,
        period_end=end,
        status=STATUS_DRAFT,
        summary={},
        created_by=actor_user_id,
    )
    db.add(assessment)
    await audit.record(
        db, workspace_id, actor_user_id, "assessment.created", "risk_assessment",
        detail=f"project={project_id} title={title}",
    )
    await db.commit()
    await db.refresh(assessment)
    return assessment


def _as_utc(value: datetime) -> datetime:
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


async def issue_assessment(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    assessment_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    *,
    generate_report: bool = True,
) -> RiskAssessment:
    """FREEZE the assessment: take the snapshot, write the findings, mark it issued.

    After this returns, the assessment is immutable -- every mutating function in this module
    refuses to touch a row whose status is `issued`, and nothing anywhere updates a
    RiskAssessmentFinding after insert."""
    assessment = await get_assessment(db, workspace_id, project_id, assessment_id)
    if assessment.status == STATUS_ISSUED:
        raise HTTPException(
            http_status.HTTP_409_CONFLICT,
            "This assessment has already been issued and is immutable.",
        )

    summary, findings = await _build_snapshot(db, workspace_id, project_id)

    # Link to the PREVIOUS ISSUED assessment for the same scope. Resolved at issue time and
    # then fixed, so a trend computed later compares two immutable snapshots -- never this
    # snapshot against mutable live state.
    previous = await db.scalar(
        select(RiskAssessment)
        .where(
            RiskAssessment.workspace_id == workspace_id,
            RiskAssessment.project_id == project_id,
            RiskAssessment.status == STATUS_ISSUED,
            RiskAssessment.id != assessment.id,
        )
        .order_by(RiskAssessment.issued_at.desc(), RiskAssessment.id)
        .limit(1)
    )

    from apps.api.modules.assessment.narrative import build_narrative

    assessment.security_score = summary["security_score"]
    assessment.score_band = summary["score_band"]
    assessment.summary = summary
    assessment.previous_assessment_id = previous.id if previous else None
    assessment.narrative = build_narrative(summary, previous.summary if previous else None)
    # `system`, not `ai`: build_narrative is deterministic template logic over real numbers, so
    # labelling it AI-authored would be as wrong as labelling AI text human-authored.
    assessment.narrative_source = "system"
    assessment.status = STATUS_ISSUED
    assessment.issued_by = actor_user_id
    assessment.issued_at = datetime.now(timezone.utc)

    for finding in findings:
        db.add(
            RiskAssessmentFinding(
                workspace_id=workspace_id, assessment_id=assessment.id, **finding
            )
        )

    await audit.record(
        db, workspace_id, actor_user_id, "assessment.issued", "risk_assessment",
        resource_id=assessment.id,
        detail=f"score={assessment.security_score} band={assessment.score_band} findings={len(findings)}",
    )
    await db.commit()
    await db.refresh(assessment)

    if generate_report:
        # Uses the EXISTING reports pipeline (reports.service.create_report -> render.render),
        # with `risk_assessment` as a new report TYPE. No second renderer, no second PDF path.
        # Best-effort: a storage outage must not undo an already-issued, already-audited
        # assessment -- the report can be regenerated, the frozen snapshot cannot be retaken.
        try:
            from apps.api.modules.reports import service as report_service

            report = await report_service.create_report(
                db, workspace_id, project_id, "risk_assessment", [], actor_user_id,
                assessment_id=assessment.id,
            )
            assessment.report_id = report.id
            await db.commit()
            await db.refresh(assessment)
        except Exception:  # noqa: BLE001 -- see above; the assessment itself is already durable
            import logging

            logging.getLogger("mbs.assessment").warning(
                "assessment.report_generation_failed assessment=%s", assessment.id, exc_info=True
            )
    return assessment


async def get_assessment(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, assessment_id: uuid.UUID
) -> RiskAssessment:
    assessment = await db.scalar(
        select(RiskAssessment).where(
            RiskAssessment.id == assessment_id,
            RiskAssessment.workspace_id == workspace_id,
            RiskAssessment.project_id == project_id,
        )
    )
    if assessment is None:
        raise HTTPException(http_status.HTTP_404_NOT_FOUND, "Assessment not found")
    return assessment


async def list_assessments(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, page: Pagination | None = None
) -> tuple[list[RiskAssessment], int]:
    await get_project(db, workspace_id, project_id)
    query = (
        select(RiskAssessment)
        .where(
            RiskAssessment.workspace_id == workspace_id, RiskAssessment.project_id == project_id
        )
        .order_by(RiskAssessment.created_at.desc(), RiskAssessment.id)
    )
    return await paginate(db, query, page or Pagination(limit=MAX_LIMIT, offset=0))


async def list_findings(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, assessment_id: uuid.UUID
) -> list[RiskAssessmentFinding]:
    await get_assessment(db, workspace_id, project_id, assessment_id)
    return list(
        await db.scalars(
            select(RiskAssessmentFinding)
            .where(
                RiskAssessmentFinding.assessment_id == assessment_id,
                RiskAssessmentFinding.workspace_id == workspace_id,
            )
            .order_by(RiskAssessmentFinding.frozen_severity, RiskAssessmentFinding.frozen_title)
        )
    )


async def preview_snapshot(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID
) -> dict:
    """What an assessment issued RIGHT NOW would say. Read-only; writes nothing. Lets the UI
    show live posture on the draft screen without creating a row."""
    await get_project(db, workspace_id, project_id)
    summary, _findings = await _build_snapshot(db, workspace_id, project_id)
    return summary


def compare(current: dict, previous: dict | None) -> dict:
    """Trend between two IMMUTABLE snapshots. Pure, so it is testable without a database and
    cannot accidentally read live state.

    `None` for a delta means "no basis for comparison" (no previous assessment, or the metric
    was absent from an older snapshot) and is deliberately distinct from a delta of 0, which
    means "measured, and unchanged"."""
    if not previous:
        return {"has_previous": False}

    def _delta(key: str, path: tuple[str, ...] = ()) -> int | None:
        cur, prev = current, previous
        for part in path:
            cur = (cur or {}).get(part) or {}
            prev = (prev or {}).get(part) or {}
        a, b = (cur or {}).get(key), (prev or {}).get(key)
        if a is None or b is None:
            return None
        return a - b

    score_delta = _delta("security_score")
    return {
        "has_previous": True,
        "previous_security_score": previous.get("security_score"),
        "security_score_delta": score_delta,
        # Direction is stated explicitly so a client never has to infer whether "up" is good.
        "direction": (
            "improved" if (score_delta or 0) > 0
            else "declined" if (score_delta or 0) < 0
            else "unchanged"
        ) if score_delta is not None else None,
        "active_findings_delta": _delta("active_findings"),
        "unresolved_issue_delta": _delta("unresolved_issue_count"),
        "critical_delta": _delta("critical", ("active_severity_counts",)),
        "high_delta": _delta("high", ("active_severity_counts",)),
        "remediation_completion_delta": _delta("completion_percent", ("remediation_progress",)),
    }


async def comparison_for(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, assessment_id: uuid.UUID
) -> dict:
    """Historical comparison for one issued assessment, against its recorded predecessor."""
    assessment = await get_assessment(db, workspace_id, project_id, assessment_id)
    if assessment.previous_assessment_id is None:
        return {"has_previous": False}
    previous = await db.scalar(
        select(RiskAssessment).where(
            RiskAssessment.id == assessment.previous_assessment_id,
            RiskAssessment.workspace_id == workspace_id,
        )
    )
    return compare(assessment.summary or {}, previous.summary if previous else None)
