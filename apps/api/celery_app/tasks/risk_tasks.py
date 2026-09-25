"""Scheduled expiry of risk acceptances.

WHY THIS TASK EXISTS: an acceptance carries a mandatory `expires_at`, and without something
that actually enforces it the field would be decoration -- an acceptance would stay `active`
forever and the expiry date would be a promise nobody keeps. This is the enforcement.

Follows the ESTABLISHED per-tenant pattern used by the retention sweep and the schedule
dispatcher: iterate workspaces from the `workspaces` anchor and bind each one before touching
tenant-scoped tables, because the app-layer tenancy filter (apps/api/core/tenancy.py) fails
CLOSED on an unbound query rather than returning rows. It does NOT use admin_bypass: expiry is
ordinary per-tenant work, not a genuine cross-tenant system query.

Unlike the retention purge this is NOT gated behind a feature flag. Retention DELETES data, so
it ships double-gated off; this only flips a status a human already scheduled, and leaving it
off would silently break the guarantee the acceptance UI makes.
"""
import asyncio
import logging

from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.celery_app.worker import celery_app
from apps.api.core.config import get_settings

logger = logging.getLogger("mbs.risk")

_rs = get_settings()
_soft = _rs.retention_task_soft_time_limit_seconds
_hard = _rs.retention_task_time_limit_seconds
if _soft and _hard <= _soft:
    _hard = _soft + 300


async def _expire_all_workspaces() -> int:
    """Expire due acceptances across every workspace. Returns the total expired.

    Commits PER WORKSPACE (inside expire_due_acceptances), so a soft timeout part-way through
    leaves the workspaces already processed correctly expired and the next run picks up the
    rest -- the same partial-progress property the retention sweep relies on."""
    from apps.api.core import tenancy
    from apps.api.core.db import make_worker_engine
    from apps.api.modules.remediation.risk_service import expire_due_acceptances

    engine = make_worker_engine()
    maker = async_sessionmaker(engine, expire_on_commit=False)
    total = 0
    try:
        async with maker() as session:
            # `workspaces` is GLOBAL_SCOPED, so this anchor query needs no binding -- same
            # entry point retention.repo.list_workspace_ids uses.
            rows = await session.execute(text("SELECT id FROM workspaces ORDER BY created_at, id"))
            workspace_ids = [r[0] for r in rows.fetchall()]

        for workspace_id in workspace_ids:
            async with maker() as session:
                # workspace_scope (not a bare bind) so the context is always reset even if one
                # workspace raises -- a single bad tenant must not leak its binding into the next.
                with tenancy.workspace_scope(workspace_id):
                    try:
                        total += await expire_due_acceptances(session, workspace_id)
                    except Exception:  # noqa: BLE001 -- one tenant must not stop the sweep
                        logger.warning(
                            "risk.expiry_failed workspace=%s", workspace_id, exc_info=True,
                            extra={"event": "risk.expiry_failed"},
                        )
    finally:
        await engine.dispose()
    return total


@celery_app.task(
    name="risk.expire_acceptances",
    soft_time_limit=_soft or None,
    time_limit=_hard or None,
)
def expire_risk_acceptances_task() -> dict:
    """Flip every `active` risk acceptance whose expiry has passed to `expired`."""
    try:
        expired = asyncio.run(_expire_all_workspaces())
    except SoftTimeLimitExceeded:
        logger.warning(
            "risk.expiry_soft_timeout soft_limit=%ss -- partial progress committed per-workspace",
            _soft, extra={"event": "risk.expiry_soft_timeout"},
        )
        return {"status": "timeout", "expired": 0}

    logger.info(
        "risk.expiry.completed expired=%d", expired,
        extra={"event": "risk.expiry.completed", "expired": expired},
    )
    return {"status": "ok", "expired": expired}
