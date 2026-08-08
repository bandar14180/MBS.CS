import logging
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.projects.service import get_target
from apps.api.modules.schedules.models import ScanSchedule

logger = logging.getLogger(__name__)

# Guardrails on how often a schedule may fire (protect the platform + targets).
MIN_INTERVAL_MINUTES = 5
MAX_INTERVAL_MINUTES = 60 * 24 * 30  # 30 days


def compute_next_run(from_time: datetime, interval_minutes: int) -> datetime:
    return from_time + timedelta(minutes=interval_minutes)


async def create_schedule(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    created_by: uuid.UUID,
    target_id: uuid.UUID,
    scan_type: str,
    requested_modules: list[str],
    interval_minutes: int,
    use_ai_planner: bool = False,
) -> ScanSchedule:
    if not (MIN_INTERVAL_MINUTES <= interval_minutes <= MAX_INTERVAL_MINUTES):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"interval_minutes must be between {MIN_INTERVAL_MINUTES} and {MAX_INTERVAL_MINUTES}",
        )
    # 404s if the target isn't in this project/workspace (RLS + explicit check).
    await get_target(db, workspace_id, project_id, target_id)

    now = datetime.now(timezone.utc)
    schedule = ScanSchedule(
        workspace_id=workspace_id,
        project_id=project_id,
        target_id=target_id,
        created_by=created_by,
        scan_type=scan_type,
        requested_modules=requested_modules,
        use_ai_planner=use_ai_planner,
        interval_minutes=interval_minutes,
        enabled=True,
        next_run_at=compute_next_run(now, interval_minutes),
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    return schedule


async def list_schedules(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID
) -> list[ScanSchedule]:
    result = await db.scalars(
        select(ScanSchedule)
        .where(ScanSchedule.workspace_id == workspace_id, ScanSchedule.project_id == project_id)
        .order_by(ScanSchedule.created_at.desc())
    )
    return list(result)


async def get_schedule(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, schedule_id: uuid.UUID
) -> ScanSchedule:
    schedule = await db.scalar(
        select(ScanSchedule).where(
            ScanSchedule.id == schedule_id,
            ScanSchedule.workspace_id == workspace_id,
            ScanSchedule.project_id == project_id,
        )
    )
    if schedule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    return schedule


async def update_schedule(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    schedule_id: uuid.UUID,
    enabled: bool | None,
    interval_minutes: int | None,
) -> ScanSchedule:
    schedule = await get_schedule(db, workspace_id, project_id, schedule_id)
    if interval_minutes is not None:
        if not (MIN_INTERVAL_MINUTES <= interval_minutes <= MAX_INTERVAL_MINUTES):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"interval_minutes must be between {MIN_INTERVAL_MINUTES} and {MAX_INTERVAL_MINUTES}",
            )
        schedule.interval_minutes = interval_minutes
    if enabled is not None:
        schedule.enabled = enabled
        # Re-enabling: schedule the next run one interval out from now.
        if enabled:
            schedule.next_run_at = compute_next_run(datetime.now(timezone.utc), schedule.interval_minutes)
    await db.commit()
    await db.refresh(schedule)
    return schedule


async def delete_schedule(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, schedule_id: uuid.UUID
) -> None:
    schedule = await get_schedule(db, workspace_id, project_id, schedule_id)
    await db.delete(schedule)
    await db.commit()


async def run_due_schedules(db: AsyncSession, now: datetime | None = None) -> int:
    """Called by Celery beat. Finds enabled schedules whose next_run_at has
    passed, launches a scan for each (bootstrapping RLS from the trusted
    workspace_id), and advances next_run_at. A failure on one schedule (quota,
    revoked scope, ...) is recorded on that row and never blocks the others.
    Returns the number of scans launched."""
    now = now or datetime.now(timezone.utc)
    candidates = list(
        await db.scalars(
            select(ScanSchedule).where(
                ScanSchedule.enabled.is_(True), ScanSchedule.next_run_at <= now
            )
        )
    )
    launched = 0
    from apps.api.modules.scans.service import create_scan

    for sched in candidates:
        next_run = compute_next_run(now, sched.interval_minutes)
        # ATOMIC CLAIM (mirrors the scan atomic claim): a single conditional UPDATE advances
        # next_run_at/last_run_at ONLY if the schedule is still due. Two concurrent runners
        # (overlapping beat ticks / acks_late redelivery) race here -- exactly ONE matches
        # (RETURNING a row); the loser gets 0 rows and skips, so a due occurrence is never
        # dispatched twice. Commit immediately to make the claim durable + visible.
        claimed = (
            await db.execute(
                text(
                    "UPDATE scan_schedules SET last_run_at = :now, next_run_at = :next "
                    "WHERE id = :id AND enabled = true AND next_run_at <= :now RETURNING id"
                ),
                {"now": now, "next": next_run, "id": sched.id},
            )
        ).first() is not None
        await db.commit()
        if not claimed:
            continue  # another runner already claimed this occurrence

        try:
            # Bootstrap RLS to this schedule's workspace before touching
            # projects/targets (FORCE RLS) via create_scan.
            await db.execute(
                text("SELECT set_config('app.current_workspace_id', :wid, false)"),
                {"wid": str(sched.workspace_id)},
            )
            scan = await create_scan(
                db,
                workspace_id=sched.workspace_id,
                project_id=sched.project_id,
                initiated_by=sched.created_by,
                target_id=sched.target_id,
                scan_type=sched.scan_type,
                requested_modules=list(sched.requested_modules or []),
                use_ai_planner=sched.use_ai_planner,
            )
            # Record success on the already-claimed row (raw UPDATE: the ORM `sched` is stale
            # after the claim, and next_run_at must NOT be reverted).
            await db.execute(
                text("UPDATE scan_schedules SET last_scan_id = :sid, last_error = NULL WHERE id = :id"),
                {"sid": scan.id, "id": sched.id},
            )
            await db.commit()
            launched += 1
            logger.info("schedule.fired schedule=%s -> scan=%s", sched.id, scan.id)
        except Exception as exc:  # quota/scope/dispatch/etc. -- record, keep going (last_error preserved)
            await db.rollback()  # discard any partial create_scan session state
            await db.execute(
                text("UPDATE scan_schedules SET last_error = :err WHERE id = :id"),
                {"err": f"{type(exc).__name__}: {exc}"[:1000], "id": sched.id},
            )
            await db.commit()
            logger.warning("schedule.skipped schedule=%s error=%s", sched.id, exc)

    return launched
