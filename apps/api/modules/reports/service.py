import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.projects.service import get_project
from apps.api.core.pagination import MAX_LIMIT, Pagination, paginate
from apps.api.modules.reports import render, storage
from apps.api.modules.reports.data import gather_report_data
from apps.api.modules.reports.models import Report
from apps.api.modules.scans.models import Scan

# The scan states a report may be generated over: a completed assessment, with or without
# a degraded tool. Named rather than inlined so the gate is one definition, not a literal
# repeated at each call site.
REPORTABLE_SCAN_STATUSES = ("completed", "completed_with_errors")


async def create_report(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    report_type: str,
    scan_ids: list[str],
    generated_by: uuid.UUID,
    assessment_id: uuid.UUID | None = None,
) -> Report:
    await get_project(db, workspace_id, project_id)  # 404s if project isn't in this workspace

    # Report generation is gated on a real, successful assessment: never a report over a
    # failed or non-existent one (blueprint: no report unless the pipeline passed).
    #
    # Both SUCCESSFUL terminal states count. The pipeline is no longer strictly fail-fast:
    # a scan whose tools all ran but where one degraded (e.g. a tool that returned partial
    # output) terminalises as 'completed_with_errors', which is a completed assessment with
    # a caveat, not a failed one -- its findings are fully persisted and are exactly what a
    # report describes. Accepting only 'completed' made such a scan unreportable, which is
    # the opposite of what the gate is for. 'failed', 'cancelled', 'running' and 'queued'
    # are still rejected, so the gate is unchanged for every state that has no trustworthy
    # assessment behind it.
    completed = await db.scalar(
        select(Scan.id)
        .where(Scan.project_id == project_id, Scan.status.in_(REPORTABLE_SCAN_STATUSES))
        .limit(1)
    )
    # A risk_assessment PDF re-renders an ALREADY ISSUED snapshot. Re-checking for a completed
    # scan here would make an issued assessment un-renderable once its scans were
    # retention-swept -- the snapshot is the record, and it was frozen from real data at issue
    # time. The assessment's own issued-status check below is the equivalent gate.
    if completed is None and report_type != "risk_assessment":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "No completed scan to report on. Run a scan that finishes successfully "
            "before generating a report.",
        )

    # --- R-03: validate and apply the requested scan scope --------------------------------
    # `scan_ids` was accepted and stored but never applied, so a scoped request silently
    # produced a project-wide PDF and the stored scan_ids misdescribed the document.
    #
    # AUTHORIZATION. `scans` is deliberately EXEMPT from automatic tenancy filtering
    # (core.tenancy.EXEMPT_TABLES: the Celery worker must read a scan row to bootstrap its
    # workspace), so a client-supplied scan id MUST be checked explicitly at the call site.
    # scans.service.get_scan is the canonical helper that does exactly that -- it matches on
    # id AND workspace_id AND project_id and raises 404 otherwise -- so an unknown scan, a scan
    # from another project, and a scan from another workspace are all rejected identically and
    # indistinguishably. Reusing it means no second authorization model, and it is what makes
    # "unknown scan must not silently fall back to project-wide" true: the request fails
    # outright rather than degrading to a wider population.
    scoped_scan_ids: list[uuid.UUID] = []
    if scan_ids:
        from apps.api.modules.scans.service import get_scan

        for raw in scan_ids:
            scan = await get_scan(db, workspace_id, project_id, uuid.UUID(str(raw)))
            scoped_scan_ids.append(scan.id)

    # Generate synchronously (fast for typical projects). If reports grow heavy
    # this can move to a Celery task like scans, without changing the API shape.
    #
    # The scope is handed to the DATA layer, not applied after the fact: gather_report_data
    # narrows the single vulnerability query every other figure derives from, so the score,
    # severity tallies, verification, MITRE, compliance, assets, remediation and evidence all
    # describe the same scoped population by construction. An empty list stays project-wide,
    # preserving the documented ReportCreate.scan_ids contract.
    data = await gather_report_data(db, project_id, scoped_scan_ids)

    # A `risk_assessment` report renders an ISSUED assessment's FROZEN snapshot, not today's
    # live findings -- so the assessment row is loaded here and handed to the SAME renderer
    # entry point. No second pipeline: `render.render` dispatches on type exactly as it
    # already did for executive/technical.
    assessment = None
    if report_type == "risk_assessment":
        if assessment_id is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "A risk_assessment report requires the assessment it renders (assessment_id).",
            )
        from apps.api.modules.assessment.models import RiskAssessment, STATUS_ISSUED

        assessment = await db.scalar(
            select(RiskAssessment).where(
                RiskAssessment.id == assessment_id,
                RiskAssessment.workspace_id == workspace_id,
                RiskAssessment.project_id == project_id,
            )
        )
        if assessment is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Assessment not found")
        if assessment.status != STATUS_ISSUED:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "Only an issued assessment can be rendered -- a draft has no frozen snapshot yet.",
            )

    pdf_bytes = render.render(report_type, data, assessment)

    report = Report(
        project_id=project_id,
        type=report_type,
        format="pdf",
        scan_ids=scan_ids or [],
        generated_by=generated_by,
    )
    db.add(report)
    await db.flush()  # need report.id for the storage key
    report.storage_uri = storage.store_report(report.id, pdf_bytes)
    await db.commit()
    await db.refresh(report)
    return report


async def list_reports(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, page: Pagination | None = None
) -> tuple[list[Report], int]:
    await get_project(db, workspace_id, project_id)
    query = select(Report).where(Report.project_id == project_id).order_by(Report.generated_at.desc(), Report.id)
    return await paginate(db, query, page or Pagination(limit=MAX_LIMIT, offset=0))


async def get_report(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, report_id: uuid.UUID
) -> Report:
    await get_project(db, workspace_id, project_id)
    report = await db.scalar(
        select(Report).where(Report.id == report_id, Report.project_id == project_id)
    )
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    return report


async def download_report(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, report_id: uuid.UUID
) -> tuple[bytes, str]:
    report = await get_report(db, workspace_id, project_id, report_id)
    if not report.storage_uri:
        raise HTTPException(status.HTTP_409_CONFLICT, "Report has no stored file")
    return storage.fetch_report(report.storage_uri), f"{report.type}-report-{report.id}.pdf"
