import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.authorization_scope.service import require_verified_target
from apps.api.modules.projects.service import get_target
from apps.api.modules.scans.models import Scan
from apps.api.scanner_engine.models import Evidence, ToolRun
from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY


async def create_scan(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    initiated_by: uuid.UUID,
    target_id: uuid.UUID,
    scan_type: str,
    requested_modules: list[str],
) -> Scan:
    await get_target(db, workspace_id, project_id, target_id)  # 404s if target isn't in this project/workspace

    unknown = [m for m in requested_modules if m not in TOOL_REGISTRY]
    if unknown:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown tool module(s): {', '.join(unknown)}")

    # The guardrail: no verified authorization scope, no scan. See
    # authorization_scope.service.require_verified_target.
    scope = await require_verified_target(db, workspace_id, project_id, target_id)

    # Active-testing tools (nuclei/...) may only be requested when the scope
    # explicitly permits active testing -- block at the API layer, not just at
    # execution (blueprint §7). The orchestrator re-checks in case authorization
    # is revoked before the scan runs.
    if not scope.active_testing_allowed:
        active = [m for m in requested_modules if TOOL_REGISTRY[m].requires_active_testing]
        if active:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Active testing not authorized for this target; requested active module(s): {', '.join(active)}",
            )

    scan = Scan(
        workspace_id=workspace_id,
        project_id=project_id,
        target_id=target_id,
        initiated_by=initiated_by,
        scan_type=scan_type,
        status="queued",
        config={"requested_modules": requested_modules},
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Imported here, not at module load: celery_app.worker importing back
    # through apps.api.main at import time is a needless coupling risk, and
    # this keeps the API process from needing a live Celery/Redis connection
    # just to import the scans module.
    from apps.api.celery_app.tasks.scan_tasks import run_scan_task

    async_result = run_scan_task.delay(str(scan.id))
    scan.celery_task_id = async_result.id
    await db.commit()
    await db.refresh(scan)

    return scan


async def list_scans(db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID) -> list[Scan]:
    result = await db.scalars(
        select(Scan)
        .where(Scan.workspace_id == workspace_id, Scan.project_id == project_id)
        .order_by(Scan.created_at.desc())
    )
    return list(result)


async def get_scan(db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, scan_id: uuid.UUID) -> Scan:
    scan = await db.scalar(
        select(Scan).where(
            Scan.id == scan_id, Scan.workspace_id == workspace_id, Scan.project_id == project_id
        )
    )
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return scan


async def cancel_scan(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, scan_id: uuid.UUID
) -> Scan:
    scan = await get_scan(db, workspace_id, project_id, scan_id)

    if scan.status in ("completed", "failed", "cancelled"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Scan already {scan.status}, cannot cancel")

    if scan.celery_task_id:
        from apps.api.celery_app.worker import celery_app

        celery_app.control.revoke(scan.celery_task_id, terminate=True)

    scan.status = "cancelled"
    scan.completed_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(scan)
    return scan


async def list_tool_runs(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, scan_id: uuid.UUID
) -> list[ToolRun]:
    await get_scan(db, workspace_id, project_id, scan_id)
    result = await db.scalars(select(ToolRun).where(ToolRun.scan_id == scan_id).order_by(ToolRun.started_at))
    return list(result)


async def list_evidence(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    scan_id: uuid.UUID,
    tool_run_id: uuid.UUID,
) -> list[Evidence]:
    await get_scan(db, workspace_id, project_id, scan_id)
    tool_run = await db.scalar(select(ToolRun).where(ToolRun.id == tool_run_id, ToolRun.scan_id == scan_id))
    if tool_run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tool run not found")

    result = await db.scalars(
        select(Evidence).where(Evidence.tool_run_id == tool_run_id).order_by(Evidence.created_at)
    )
    return list(result)


async def get_ai_plan(db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, scan_id: uuid.UUID):
    from apps.api.ai_agent.models import AIPlan

    await get_scan(db, workspace_id, project_id, scan_id)
    plan = await db.scalar(
        select(AIPlan).where(AIPlan.scan_id == scan_id).order_by(AIPlan.created_at.desc()).limit(1)
    )
    if plan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No AI plan for this scan (AI planning may be disabled)")
    return plan
