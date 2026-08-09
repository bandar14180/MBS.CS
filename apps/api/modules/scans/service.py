import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.pagination import MAX_LIMIT, Pagination, paginate
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
    use_ai_planner: bool = False,
    use_agent: bool = False,
    exploitation_enabled: bool = False,
    approved_hosts: list[str] | None = None,
) -> Scan:
    target = await get_target(db, workspace_id, project_id, target_id)  # 404s if not in this project/workspace

    from apps.api.scanner_engine import capabilities

    # Refuse target types with no scanner engine -- otherwise the scan would
    # "complete" having run nothing. The capability registry is the source of truth.
    if not capabilities.is_supported(target.type):
        supported = sorted(capabilities.supported_target_types())
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Target type '{target.type}' is not supported for scanning yet "
            f"(supported: {', '.join(supported) or 'none'}). Refusing to start a scan "
            f"that would assess nothing.",
        )

    from apps.api.modules.billing import service as billing

    await billing.enforce_scan_quota(db, workspace_id)

    unknown = [m for m in requested_modules if m not in TOOL_REGISTRY]
    if unknown:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown tool module(s): {', '.join(unknown)}")

    # AI planning needs a configured key. Reject at creation time with a clear
    # message rather than letting the scan fail-fast at runtime with a confusing
    # "all stages skipped" result. (Fail-fast, but at the right layer.)
    if use_ai_planner:
        from apps.api.core.config import get_settings

        settings = get_settings()
        if not settings.ai_enabled:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"AI planner requires an API key for the configured AI provider "
                f"('{settings.ai_provider}'). Turn off 'Use AI planner' to run the scan "
                f"without AI, or set the provider's API key.",
            )

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
        config={
            "requested_modules": requested_modules,
            "use_ai_planner": use_ai_planner,
            "use_agent": use_agent,
            "exploitation_enabled": exploitation_enabled,
            "approved_hosts": approved_hosts or [],
        },
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Imported here, not at module load: celery_app.worker importing back
    # through apps.api.main at import time is a needless coupling risk, and
    # this keeps the API process from needing a live Celery/Redis connection
    # just to import the scans module.
    from apps.api.celery_app.tasks.scan_tasks import run_scan_task
    from apps.api.core.observability import get_correlation_id

    # Propagate the request correlation id (Phase 4.1) so the worker's scan logs can be
    # joined to the API request that created the scan. For a scheduled dispatch (worker/beat
    # context, no request) this is the ambient "-", which the task replaces with a fresh id.
    async_result = run_scan_task.delay(str(scan.id), correlation_id=get_correlation_id())
    scan.celery_task_id = async_result.id

    from apps.api.modules.audit import service as audit

    await audit.record(
        db, workspace_id, initiated_by, "scan.created", "scan",
        resource_id=scan.id, detail=f"{scan_type}: {', '.join(requested_modules)}",
    )
    await db.commit()
    await db.refresh(scan)

    return scan


async def list_scans(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, page: Pagination | None = None
) -> tuple[list[Scan], int]:
    query = (
        select(Scan)
        .where(Scan.workspace_id == workspace_id, Scan.project_id == project_id)
        .order_by(Scan.created_at.desc(), Scan.id)
    )
    return await paginate(db, query, page or Pagination(limit=MAX_LIMIT, offset=0))


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


async def get_scan_timeline(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, scan_id: uuid.UUID, page: Pagination
) -> tuple[list[dict], int]:
    """Chronological scan event stream (Phase 1.3): scan started, tool executions,
    findings, agent decisions/actions, scan completed. Ownership is enforced by
    get_scan (404 out-of-scope); the underlying tool_runs / agent_steps /
    vulnerabilities are FORCE-RLS, so the request's workspace GUC scopes them too.
    Bounded per scan; paginated in memory over the merged, time-ordered events."""
    from apps.api.modules.agent.models import AgentStep
    from apps.api.modules.vulnerabilities.models import Vulnerability

    scan = await get_scan(db, workspace_id, project_id, scan_id)
    events: list[dict] = []
    if scan.started_at:
        events.append({"ts": scan.started_at, "event": "scan.started", "tool": None, "status": "running", "detail": None})
    for tr in await db.scalars(select(ToolRun).where(ToolRun.scan_id == scan_id)):
        events.append({"ts": tr.started_at, "event": "tool.executed", "tool": tr.tool_name,
                       "status": tr.status, "detail": (tr.error_message or None) and tr.error_message[:300]})
    for st in await db.scalars(select(AgentStep).where(AgentStep.scan_id == scan_id)):
        events.append({"ts": st.created_at, "event": f"agent.{st.action_type}", "tool": st.tool_or_module,
                       "status": st.status, "detail": (st.result_summary or None) and st.result_summary[:300]})
    for v in await db.scalars(select(Vulnerability).where(Vulnerability.last_seen_scan_id == scan_id)):
        events.append({"ts": v.created_at, "event": "finding.generated", "tool": None,
                       "status": v.severity, "detail": (v.title or "")[:300]})
    if scan.completed_at:
        events.append({"ts": scan.completed_at, "event": "scan.completed", "tool": None,
                       "status": scan.status, "detail": None})

    _epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    events.sort(key=lambda e: e["ts"] or _epoch)
    total = len(events)
    window = events[page.offset: page.offset + page.limit]
    return window, total


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
