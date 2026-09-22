import logging
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.projects.service import get_project
from apps.api.core import tenancy
from apps.api.core.observability import record_schedule_launched
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
    # 404s if the target isn't in this project/workspace (tenancy.py's filter + explicit check).
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
    # AUDIT-010: verify the project EXISTS IN THIS WORKSPACE before listing.
    #
    # The query below is correctly scoped, so a cross-tenant project id never leaked data --
    # it returned `200 []`. But `200 []` and `404` are different answers to the same
    # question, and this API already answers it with 404 everywhere else (the single-resource
    # getters, and the reports/targets list endpoints, which call get_project for exactly
    # this reason). An empty 200 says "this project is yours and has nothing"; the truth is
    # "this project is not yours". Beyond the inconsistency, it is a weak existence oracle:
    # a caller could tell a real foreign project id from a random UUID if the two ever
    # diverged, and it hides genuine client bugs behind a success response.
    await get_project(db, workspace_id, project_id)
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
    passed, launches a scan for each (bootstrapping the workspace binding from the trusted
    workspace_id), and advances next_run_at. A failure on one schedule (quota,
    revoked scope, ...) is recorded on that row and never blocks the others.
    Returns the number of scans launched."""
    now = now or datetime.now(timezone.utc)
    # Explicit deleting-workspace guard (defence in depth): tenant deletion already deactivates a
    # workspace's schedules (enabled=False) before teardown, but joining to workspaces.status here
    # ensures a schedule is never dispatched for a workspace being torn down even in the narrow
    # window between the flip and the deactivation commit.
    from apps.api.modules.workspaces.models import Workspace

    candidates = list(
        await db.scalars(
            select(ScanSchedule)
            .join(Workspace, Workspace.id == ScanSchedule.workspace_id)
            .where(
                ScanSchedule.enabled.is_(True),
                ScanSchedule.next_run_at <= now,
                Workspace.status != "deleting",
            )
        )
    )
    launched = 0
    from apps.api.modules.scans.service import create_scan

    for sched in candidates:
        # Snapshot the identifiers we need in the ERROR path BEFORE doing anything that can
        # roll back. `db.rollback()` in the `except` below EXPIRES every ORM object in this
        # session (expire_on_commit=False only suppresses expiry on COMMIT, never on
        # ROLLBACK), so reading `sched.id` after it would trigger a lazy refresh -- which in
        # async SQLAlchemy raises MissingGreenlet and takes down the whole beat tick instead
        # of recording last_error and moving on. Found while proving that an over-quota
        # workspace cannot gain scans through the scheduler: create_scan correctly raised 402,
        # and this handler then crashed on `sched.id`.
        sched_id = sched.id
        next_run = compute_next_run(now, sched.interval_minutes)
        # ATOMIC CLAIM (mirrors the scan atomic claim): a single conditional UPDATE advances
        # next_run_at/last_run_at ONLY if the schedule is still due. Two concurrent runners
        # (overlapping beat ticks / acks_late redelivery) race here -- exactly ONE matches
        # (rowcount == 1); the loser gets 0 rows and skips, so a due occurrence is never
        # dispatched twice. Commit immediately to make the claim durable + visible.
        # Phase 0 MySQL cutover: RETURNING replaced with rowcount (MySQL has no RETURNING);
        # exact here because of CLIENT_FOUND_ROWS (core/db.py's _mysql_connect_args) --
        # matters more here than most call sites, since a same-microsecond re-claim COULD
        # otherwise leave next_run_at/last_run_at unchanged despite matching the WHERE.
        result = await db.execute(
            text(
                "UPDATE scan_schedules SET last_run_at = :now, next_run_at = :next "
                "WHERE id = :id AND enabled = true AND next_run_at <= :now"
            ),
            {"now": now, "next": next_run, "id": sched.id},
        )
        claimed = result.rowcount == 1
        await db.commit()
        if not claimed:
            continue  # another runner already claimed this occurrence

        try:
            # Phase 0 MySQL cutover: bind workspace-isolation context (tenancy.py)
            # before touching projects/targets via create_scan.
            #
            # AUDIT-004: SCOPED, not a bare bind. This loop iterates due schedules across ALL
            # tenants, so a bare bind left tenant N's workspace bound while tenant N+1 was
            # processed, and -- because create_scan can raise -- left it bound while the
            # `except` branch below recorded last_error, and after the whole dispatch returned.
            # The scope restores the previous context on every path.
            with tenancy.workspace_scope(sched.workspace_id):
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
                record_schedule_launched("launched")
                logger.info("schedule.fired schedule=%s -> scan=%s", sched.id, scan.id)
        except Exception as exc:  # quota/scope/dispatch/etc. -- record, keep going (last_error preserved)
            await db.rollback()  # discard any partial create_scan session state
            await db.execute(
                text("UPDATE scan_schedules SET last_error = :err WHERE id = :id"),
                # sched_id, not sched.id -- the rollback above expired the ORM object.
                {"err": f"{type(exc).__name__}: {exc}"[:1000], "id": sched_id},
            )
            await db.commit()
            record_schedule_launched("failed")
            logger.warning("schedule.skipped schedule=%s error=%s", sched_id, exc)

    return launched
