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


async def create_report(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    report_type: str,
    scan_ids: list[str],
    generated_by: uuid.UUID,
) -> Report:
    await get_project(db, workspace_id, project_id)  # 404s if project isn't in this workspace

    # Report generation is gated on a real, successful assessment. Under the
    # fail-fast pipeline a scan reaches "completed" only if EVERY tool succeeded,
    # so requiring one completed scan means: never a report over a failed or
    # non-existent assessment (blueprint: no report unless the pipeline passed).
    completed = await db.scalar(
        select(Scan.id).where(Scan.project_id == project_id, Scan.status == "completed").limit(1)
    )
    if completed is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "No completed scan to report on. Run a scan that finishes successfully "
            "before generating a report.",
        )

    # Generate synchronously (fast for typical projects). If reports grow heavy
    # this can move to a Celery task like scans, without changing the API shape.
    data = await gather_report_data(db, project_id)
    pdf_bytes = render.render(report_type, data)

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
