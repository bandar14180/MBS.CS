"""Async tenant (workspace) deletion task.

Thin Celery shim over workspaces.tenant_service.perform_workspace_deletion. Runs on its own
short-lived worker engine (like the reaper/relay tasks). The body is idempotent and retry-safe:
a re-run after partial completion converges (a missing workspace row -> no-op). Object cleanup is
best-effort after the DB commit.

The deletion audit is DATABASE-BACKED: perform_workspace_deletion writes a `tenant.delete.completed`
row into `platform_audit_events` in the same transaction as the workspace DELETE. That table has no
foreign key to `workspaces`, so the record is not cascade-removed and survives the deletion.

On failure this task writes a durable `tenant.delete.failed` row on a FRESH session (the failed
one may be poisoned) before re-raising for Celery retry. That audit write is best-effort by
design -- it must never mask the original error -- so if it also fails we fall back to a
`tenant.delete.failed_audit_write_failed` warning log. `security_event` is emitted alongside as an
ADDITIONAL log signal, never as the record of truth.
"""
import asyncio
import logging

from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.celery_app.worker import celery_app
from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.core.db import make_worker_engine

logger = logging.getLogger("mbs.tenant")


async def _run(workspace_id: str, actor_id: str) -> bool:
    import uuid

    from apps.api.modules.auth.mfa_guard import security_event
    from apps.api.modules.workspaces.tenant_service import perform_workspace_deletion

    settings = get_settings()
    engine = make_worker_engine(settings.database_url)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_maker() as session:
            # Deletion spans every workspace table incl. tenancy.EXEMPT_TABLES ones; use
            # tenancy.admin_bypass() and rely on
            # the explicit workspace_id filters / FK cascade inside tenant_service.
            with tenancy.admin_bypass():
                return await perform_workspace_deletion(
                    session, uuid.UUID(workspace_id), uuid.UUID(actor_id)
                )
    except Exception:
        # Durable failure record on a FRESH session (the failed one may be poisoned), best-effort
        # -- an audit-write failure must never mask the original error. Then the log signal, then
        # re-raise so Celery can retry.
        try:
            from apps.api.modules.audit import service as audit_service

            async with session_maker() as audit_session:
                with tenancy.admin_bypass():
                    await audit_service.record_platform_event(
                        audit_session, uuid.UUID(workspace_id), uuid.UUID(actor_id),
                        "tenant.delete.failed",
                    )
                    await audit_session.commit()
        except Exception:  # noqa: BLE001 -- never let the failure-audit mask the real failure
            logger.warning("tenant.delete.failed_audit_write_failed workspace=%s", workspace_id, exc_info=True)
        security_event("tenant.delete.failed", user_id=actor_id, workspace_id=workspace_id)
        logger.warning("tenant.delete.failed workspace=%s", workspace_id, exc_info=True)
        raise
    finally:
        await engine.dispose()


@celery_app.task(
    name="tenant.delete",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    acks_late=True,
)
def delete_workspace_task(self, workspace_id: str, actor_id: str) -> dict:
    """Delete a workspace and all its data. Idempotent: a retry after partial completion
    converges to the same final state (a missing workspace row is treated as done)."""
    try:
        deleted = asyncio.run(_run(workspace_id, actor_id))
        return {"workspace_id": workspace_id, "deleted": deleted}
    except Exception as exc:  # noqa: BLE001 -- retry transient faults; _run already audited the failure
        raise self.retry(exc=exc)
