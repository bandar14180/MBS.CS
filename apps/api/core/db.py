import logging
from collections.abc import AsyncGenerator

from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from apps.api.core.config import get_settings

logger = logging.getLogger("mbs.db")

settings = get_settings()


def _mysql_connect_args(url: str) -> dict:
    """CLIENT_FOUND_ROWS, for every engine this app creates against MySQL.

    Without it, PyMySQL/aiomysql's rowcount on an UPDATE reports rows CHANGED, not rows
    MATCHED by the WHERE clause -- a well-known MySQL client-library quirk that doesn't
    exist on Postgres (whose driver-level rowcount is always "matched"). This codebase's
    atomic claim/fencing pattern (`scanner_engine/orchestrator.py`'s `_claim_scan`,
    `_finalize_status`, `reap_orphaned_scans`; `celery_app/shutdown.py`'s `requeue_scan`;
    `modules/schedules/service.py`'s due-schedule claim) all replaced Postgres's
    `RETURNING id` with a `result.rowcount == 1` check (MySQL has no RETURNING at all).
    Every one of those specific UPDATEs happens to always change a value when its WHERE
    matches (verified individually when they were ported), so today's behavior is correct
    either way -- but relying on that per-statement coincidence forever, in a codebase this
    size, is a bug waiting to be introduced by someone's next atomic-UPDATE pattern. Setting
    CLIENT_FOUND_ROWS at the connection level makes rowcount mean "matched" everywhere,
    permanently, matching what every RETURNING-based check here actually meant."""
    if make_url(url).get_backend_name() != "mysql":
        return {}
    from pymysql.constants import CLIENT

    return {"client_flag": CLIENT.FOUND_ROWS}


def _mysql_isolation_level(url: str) -> dict:
    """READ COMMITTED, for every engine this app creates against MySQL.

    Found the same way as the CLIENT_FOUND_ROWS gotcha just above: a live-MySQL test run,
    not a read-through. MySQL/MariaDB's default transaction isolation is REPEATABLE READ,
    which takes its consistent snapshot at a transaction's FIRST read and does not see any
    other transaction's commits made after that point, for the rest of the transaction.
    Postgres's default is READ COMMITTED -- a fresh snapshot on every statement, so a SELECT
    always sees whatever's committed so far, even from a different connection's transaction
    that committed moments ago. This codebase's cooperative-shutdown / atomic-claim
    machinery is written against that assumption explicitly (see
    `apps/api/scanner_engine/orchestrator.py`'s `_execution_stop_reason` docstring: "under
    READ COMMITTED it sees commits made on other [transactions]"): `shutdown.requeue_scan`
    clears `execution_token` from its OWN short-lived connection while the executor's
    long-lived scan session is expected to observe that write on its very next stop-check
    read. Under MySQL's REPEATABLE READ default that write is invisible until the
    executor's transaction ends, so the cooperative stop silently stops working -- caught by
    `test_revoked_executor_stops_before_launching_another_tool` launching all three stub
    tools instead of stopping after the first. Setting the isolation level to READ COMMITTED
    on every engine restores the semantics this code was actually written against. (The
    MySQL server itself should also be provisioned with `transaction-isolation =
    READ-COMMITTED` as the deployment default -- see docs/architecture -- since any ad-hoc
    engine created outside this module, e.g. in a one-off script, would otherwise fall back
    to the server's REPEATABLE READ default.)"""
    if make_url(url).get_backend_name() != "mysql":
        return {}
    return {"isolation_level": "READ COMMITTED"}


def _fix_aiomysql_pre_ping(engine: AsyncEngine) -> None:
    """Work around a real SQLAlchemy/aiomysql incompatibility in `pool_pre_ping`, found by
    actually running this app's tests against a live MySQL server (not a theoretical concern):
    every request failed with `TypeError: AsyncAdapt_aiomysql_connection.ping() missing 1
    required positional argument: 'reconnect'`.

    Root cause: SQLAlchemy's generic `MySQLDialect_pymysql.do_ping` decides whether to call
    `dbapi_connection.ping()` or `dbapi_connection.ping(False)` by inspecting the SIGNATURE of
    `pymysql.connections.Connection.ping` (which has `reconnect=True`, a default) via its
    `_send_false_to_ping` memoized property -- so it picks the no-args form. But for the
    aiomysql dialect, `dbapi_connection` at ping time isn't that pymysql class at all; it's
    SQLAlchemy's own `AsyncAdapt_aiomysql_connection` wrapper, whose `ping(self, reconnect)`
    has NO default (an async ping can't transparently reconnect mid-await the way a sync one
    can, so the wrapper deliberately asserts the caller passes `reconnect=False` explicitly).
    The inspection and the actual call target disagree, purely for the aiomysql driver.

    Fix: pre-seed the dialect instance's `_send_false_to_ping` (a memoized_property -- setting
    the instance attribute directly pre-empts the first-access computation) to True, so
    `do_ping` always takes the `dbapi_connection.ping(False)` branch. Verified against SQLAlchemy
    2.0.35 and 2.0.43 -- both still require this. Confined to aiomysql-backed engines; a no-op
    otherwise (`_send_false_to_ping` simply isn't touched, leaving the dialect's own correct
    default in effect)."""
    if engine.dialect.driver == "aiomysql":
        engine.sync_engine.dialect._send_false_to_ping = True


def make_worker_engine(database_url: str | None = None) -> AsyncEngine:
    """Shared factory for the short-lived, StaticPool, worker-side engines used across
    celery_app/* and retention/service.py -- each of those needs its OWN engine (the
    process-wide `engine` below is bound to whichever event loop first used it, so it must
    not be borrowed from a different `asyncio.run()`), but they all need the same
    CLIENT_FOUND_ROWS connect_args, so that requirement lives in exactly one place."""
    from sqlalchemy.pool import StaticPool

    url = database_url or settings.database_url
    eng = create_async_engine(
        url, poolclass=StaticPool, connect_args=_mysql_connect_args(url), **_mysql_isolation_level(url)
    )
    _fix_aiomysql_pre_ping(eng)
    return eng

# Phase 0 MySQL cutover pool settings. Two MySQL-specific gotchas that don't exist on
# Postgres, both silent until they bite in production:
#
#   pool_recycle: MySQL's `wait_timeout` (default 28800s / 8h on most managed MySQL, far
#   lower -- sometimes 60-300s -- on some shared/serverless tiers) closes idle server-side
#   connections without telling the client. A pooled SQLAlchemy connection that outlives
#   that window fails on next use with "MySQL server has gone away" / "Lost connection to
#   MySQL server during query". pool_recycle forces the pool to silently discard and
#   reopen a connection older than this, before that happens. Set well under the most
#   conservative wait_timeout we'd expect to run against; override via DB_POOL_RECYCLE_
#   SECONDS if a specific host needs tighter.
#
#   pool_pre_ping: already set (carried over from the Postgres config) -- issues a
#   lightweight liveness check before handing out a pooled connection, so a connection
#   that died for some OTHER reason (network blip, MySQL restart) is caught and replaced
#   rather than surfacing as a mid-request failure. Cheap insurance on top of pool_recycle,
#   not a replacement for it (pre_ping can't see a connection that's about to be closed by
#   the server for being idle -- only one that's already dead).
engine = create_async_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_recycle=settings.db_pool_recycle_seconds,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_pool_max_overflow,
    connect_args=_mysql_connect_args(settings.database_url),
    **_mysql_isolation_level(settings.database_url),
)
_fix_aiomysql_pre_ping(engine)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with SessionLocal() as session:
        yield session


async def check_database_connection() -> bool:
    """Graceful startup connectivity check -- logs success/failure instead of letting an
    unhelpful driver traceback be the first thing an operator sees. Never raises: the
    caller (main.py's lifespan / run_startup_security_checks) decides whether a failed
    connection should abort startup; this function's job is only to make the outcome
    legible in the logs either way."""
    try:
        async with engine.connect() as conn:
            await conn.exec_driver_sql("SELECT 1")
        logger.info(
            "db.connected host=%s db=%s pool_recycle=%ss",
            engine.url.host,
            engine.url.database,
            settings.db_pool_recycle_seconds,
        )
        return True
    except Exception as exc:  # noqa: BLE001 -- deliberately broad: this is a diagnostic, not a handler
        logger.error("db.connect_failed host=%s db=%s error=%s", engine.url.host, engine.url.database, exc)
        return False
