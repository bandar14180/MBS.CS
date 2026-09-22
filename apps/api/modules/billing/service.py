import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.billing.plans import PLANS, SELECTABLE_TIERS, Plan, get_plan
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.workspaces.models import Workspace


def _month_start(now: datetime | None = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    return datetime(now.year, now.month, 1, tzinfo=timezone.utc)


async def _plan_for(db: AsyncSession, workspace_id: uuid.UUID) -> Plan:
    tier = await db.scalar(select(Workspace.plan_tier).where(Workspace.id == workspace_id))
    return get_plan(tier)


async def _plan_for_update(db: AsyncSession, workspace_id: uuid.UUID) -> Plan:
    """The workspace's plan, read under a ROW LOCK on that workspace row.

    THE RACE THIS CLOSES (Phase 3). Every quota check was
        SELECT COUNT(*) -> compare to limit -> caller INSERTs -> COMMIT
    with nothing serialising the gap. The app runs at READ COMMITTED (see
    apps/api/core/db.py::_mysql_isolation_level), where a plain SELECT takes NO locks, so N
    concurrent requests all read the same pre-limit count and all proceed. Measured against
    real MySQL before this fix: 8 concurrent create_project calls on the FREE plan
    (max_projects=2) produced 8 rows -- a 4x quota bypass.

    `SELECT ... FOR UPDATE` on the single `workspaces` row makes each tenant's quota check
    serial: the second concurrent request blocks until the first COMMITs, then re-counts and
    sees the row the first one inserted. The lock is held until the caller's transaction ends,
    which is exactly the window that must be protected (check -> insert -> commit).

    WHY THE WORKSPACE ROW. It is the natural per-tenant mutex: every quota in this module is
    scoped to one workspace, and the row already has to be read to resolve the plan, so this
    adds no extra round trip. Locking is therefore PER TENANT -- workspace A's quota check
    never blocks workspace B (no global lock, no cross-tenant lock, no table lock), and
    lock ordering cannot deadlock because only ever one workspace row is locked per request.

    Fail-open on a missing row is preserved: get_plan(None) returns the unlimited default, so
    a workspace that vanished mid-request is not retroactively capped.
    """
    tier = await db.scalar(
        select(Workspace.plan_tier).where(Workspace.id == workspace_id).with_for_update()
    )
    return get_plan(tier)


async def _count_projects(db: AsyncSession, workspace_id: uuid.UUID) -> int:
    return await db.scalar(
        select(func.count()).select_from(Project).where(Project.workspace_id == workspace_id)
    ) or 0


async def _count_targets(db: AsyncSession, workspace_id: uuid.UUID) -> int:
    return await db.scalar(
        select(func.count())
        .select_from(Target)
        .join(Project, Project.id == Target.project_id)
        .where(Project.workspace_id == workspace_id)
    ) or 0


async def _count_scans_this_month(db: AsyncSession, workspace_id: uuid.UUID) -> int:
    return await db.scalar(
        select(func.count())
        .select_from(Scan)
        .where(Scan.workspace_id == workspace_id, Scan.created_at >= _month_start())
    ) or 0


def _over(current: int, limit: int | None) -> bool:
    return limit is not None and current >= limit


async def enforce_project_quota(db: AsyncSession, workspace_id: uuid.UUID) -> None:
    # _plan_for_update (not _plan_for): takes the per-workspace row lock so this count and the
    # caller's INSERT cannot interleave with a concurrent request. See _plan_for_update.
    plan = await _plan_for_update(db, workspace_id)
    if _over(await _count_projects(db, workspace_id), plan.max_projects):
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            f"Project limit reached for the {plan.name} plan ({plan.max_projects}). Upgrade to add more.",
        )


async def enforce_target_quota(db: AsyncSession, workspace_id: uuid.UUID) -> None:
    plan = await _plan_for_update(db, workspace_id)
    if _over(await _count_targets(db, workspace_id), plan.max_targets):
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            f"Target limit reached for the {plan.name} plan ({plan.max_targets}). Upgrade to add more.",
        )


async def enforce_scan_quota(db: AsyncSession, workspace_id: uuid.UUID) -> None:
    plan = await _plan_for_update(db, workspace_id)
    if _over(await _count_scans_this_month(db, workspace_id), plan.max_scans_per_month):
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            f"Monthly scan limit reached for the {plan.name} plan "
            f"({plan.max_scans_per_month}/month). Upgrade for more.",
        )


async def get_usage(db: AsyncSession, workspace_id: uuid.UUID) -> dict:
    plan = await _plan_for(db, workspace_id)
    return {
        "plan_tier": plan.tier,
        "plan_name": plan.name,
        "price_usd_month": plan.price_usd_month,
        "usage": {
            "projects": await _count_projects(db, workspace_id),
            "targets": await _count_targets(db, workspace_id),
            "scans_this_month": await _count_scans_this_month(db, workspace_id),
        },
        "limits": {
            "projects": plan.max_projects,
            "targets": plan.max_targets,
            "scans_per_month": plan.max_scans_per_month,
        },
    }


async def set_plan(
    db: AsyncSession, workspace_id: uuid.UUID, tier: str, actor_user_id: uuid.UUID | None = None
) -> dict:
    if tier not in SELECTABLE_TIERS:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Plan must be one of: {', '.join(SELECTABLE_TIERS)}",
        )
    workspace = await db.get(Workspace, workspace_id)
    if workspace is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")
    previous = workspace.plan_tier
    workspace.plan_tier = tier

    from apps.api.modules.audit import service as audit

    await audit.record(
        db, workspace_id, actor_user_id, "plan.changed", "workspace",
        resource_id=workspace_id, detail=f"{previous} -> {tier}",
    )
    await db.commit()
    return await get_usage(db, workspace_id)


def plan_catalog() -> list[dict]:
    """Public plan list for pricing UIs."""
    return [
        {
            "tier": p.tier,
            "name": p.name,
            "price_usd_month": p.price_usd_month,
            "max_projects": p.max_projects,
            "max_targets": p.max_targets,
            "max_scans_per_month": p.max_scans_per_month,
        }
        for p in (PLANS[t] for t in SELECTABLE_TIERS)
    ]
