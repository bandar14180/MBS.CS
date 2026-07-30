import asyncio
import uuid

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.celery_app.worker import celery_app
from apps.api.core.config import get_settings
from apps.api.scanner_engine.orchestrator import run_scan


async def _run(scan_id: str) -> None:
    # A fresh engine bound to THIS task's event loop. Reusing the API's
    # module-level engine here fails with "Future attached to a different loop"
    # because Celery runs each task under a new asyncio.run() loop while the
    # pooled asyncpg connections belong to whichever loop first opened them.
    #
    # StaticPool pins the whole task to ONE physical connection. The
    # orchestrator sets the workspace RLS GUC once (session-level,
    # is_local=false) and then commits several times; with a normal pool each
    # commit returns the connection and the next op could check out a
    # different one WITHOUT the GUC set -- FORCE RLS would then block the
    # worker's own writes to tool_runs/evidence/assets. One persistent
    # connection keeps the GUC alive across those commits.
    settings = get_settings()
    # Honor enterprise proxy / custom-CA settings for the scanner tools + AI calls
    # made during the scan (mirrors them into the process env). Idempotent.
    from apps.api.core.config import configure_networking

    configure_networking(settings)
    engine = create_async_engine(settings.database_url, poolclass=StaticPool)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_maker() as session:  # type: AsyncSession
            await run_scan(session, uuid.UUID(scan_id))
    finally:
        await engine.dispose()


@celery_app.task(name="scans.run_scan")
def run_scan_task(scan_id: str) -> str:
    asyncio.run(_run(scan_id))
    return scan_id
