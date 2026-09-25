import asyncio

from sqlalchemy.ext.asyncio import async_sessionmaker

from apps.api.celery_app.worker import celery_app
from apps.api.core.config import get_settings
from apps.api.core.db import make_worker_engine
from apps.api.modules.schedules.service import run_due_schedules


async def _run() -> int:
    # Fresh engine bound to this task's loop, StaticPool so the connection state survives
    # the per-schedule commits (same rationale as scan_tasks).
    settings = get_settings()
    engine = make_worker_engine(settings.database_url)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_maker() as session:  # -> AsyncSession (inferred)
            return await run_due_schedules(session)
    finally:
        await engine.dispose()


@celery_app.task(name="schedules.enqueue_due")
def enqueue_due_schedules() -> int:
    """Beat tick: launch any schedules that are due. Returns count launched."""
    return asyncio.run(_run())
