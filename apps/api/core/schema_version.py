"""AUDIT-002 -- database schema-version gate.

THE PROBLEM
-----------
Both the startup security checks and the `/ready` probe proved the database only with
`SELECT 1`. That answers "is a database listening?", not "is it the database this code was
written against?". A deploy that ships new application code but whose migration step failed,
was skipped, or was rolled back therefore came up fully "healthy": the process started, the
load balancer saw a 200 on /ready and sent it live traffic, and requests then failed at the
first query touching a column or table the code expects and the schema does not have --
500s, partial writes, and in the worst case rows written against a half-migrated shape.

Verified on this repo before the fix: against a database pinned two revisions behind head
(missing `risk_assessments` entirely), `SELECT 1` returned 1 and readiness reported
`database: ok`.

WHAT THIS MODULE DOES
---------------------
Compares the revision recorded in the live database's `alembic_version` table against the
head revision of the migration scripts THIS BUILD ships, and classifies the result:

    MATCH       -- DB is exactly at the application's head. The only healthy state.
    BEHIND      -- DB is an ancestor of head: migrations have not been run. The code expects
                   schema that does not exist yet.
    AHEAD       -- DB carries a revision this build does not know. Usually a rollback of the
                   app without a rollback of the database, or a newer node having migrated.
    UNKNOWN     -- alembic_version is missing, empty, has multiple rows, or names a revision
                   absent from this build's script directory.
    UNAVAILABLE -- the database could not be reached or queried at all.

POLICY: FAIL CLOSED IN PRODUCTION
---------------------------------
In production every non-MATCH state is fatal. That deliberately includes AHEAD: this project
has no forward-compatibility contract -- nothing declares which future revisions a given build
tolerates, and no test exercises old-code-against-new-schema -- so treating AHEAD as healthy
would be an assumption, not a verified property. A rolled-back deploy is exactly when a
dropped column silently corrupts writes. It is also the recoverable direction: roll the app
forward, or roll the database back deliberately.

Outside production the same comparison runs and logs a loud WARNING, but does not stop the
process: a developer mid-migration should not be locked out of their own machine.

DELIBERATE NON-GOALS
--------------------
* This does NOT run migrations. Applying schema changes from application startup is how two
  replicas race each other into a half-applied schema.
* This does NOT replace the connectivity probe, and it is kept SEPARATE from the Redis check
  in `/ready` -- a schema problem and a broken cache are different failures with different
  remediations, and the response reports them independently.
"""
from __future__ import annotations

import enum
import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = logging.getLogger("mbs.startup")

# db/migrations, resolved from this file so it works regardless of the process's cwd
# (the API container's WORKDIR is not the repo root).
_MIGRATIONS_DIR = Path(__file__).resolve().parents[3] / "db" / "migrations"


class SchemaState(str, enum.Enum):
    MATCH = "match"
    BEHIND = "behind"
    AHEAD = "ahead"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class SchemaStatus:
    """Outcome of one schema-version comparison."""

    state: SchemaState
    db_revision: str | None
    head_revision: str | None
    detail: str

    @property
    def is_healthy(self) -> bool:
        return self.state is SchemaState.MATCH


class SchemaVersionError(RuntimeError):
    """Raised to REFUSE production startup when the database schema is not the one this
    build was written against (fail closed)."""


class _MigrationsUnavailable(RuntimeError):
    """The migration scripts are not present in this image/checkout."""


@lru_cache(maxsize=1)
def _script_directory():
    """Alembic's ScriptDirectory for the migrations THIS BUILD ships.

    Cached: the script directory is immutable for the life of the process, and both the
    startup check and every /ready call would otherwise re-walk the whole versions/ tree.
    """
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    if not _MIGRATIONS_DIR.is_dir():
        raise _MigrationsUnavailable(f"migrations directory not found at {_MIGRATIONS_DIR}")
    cfg = Config()
    cfg.set_main_option("script_location", str(_MIGRATIONS_DIR))
    return ScriptDirectory.from_config(cfg)


def application_head_revision() -> str:
    """The single head revision of the migration scripts in this build.

    Determined PROGRAMMATICALLY from the scripts themselves -- never hardcoded, which would
    just create a second thing to forget to update. Multiple heads means the migration graph
    has an unmerged branch; that is itself a deployment defect, so it is reported rather than
    silently resolved by picking one.
    """
    heads = _script_directory().get_heads()
    if len(heads) != 1:
        raise SchemaVersionError(
            f"expected exactly one migration head, found {len(heads)}: {sorted(heads)}. "
            "The migration graph has an unmerged branch -- run `alembic merge` before deploying."
        )
    return heads[0]


async def _read_db_revision(engine: AsyncEngine) -> list[str]:
    """Every row in `alembic_version`. Empty list when the table does not exist."""
    async with engine.connect() as conn:
        exists = await conn.scalar(
            text(
                "SELECT COUNT(*) FROM information_schema.tables "
                "WHERE table_schema = DATABASE() AND table_name = 'alembic_version'"
            )
        )
        if not exists:
            return []
        rows = await conn.execute(text("SELECT version_num FROM alembic_version"))
        return [r[0] for r in rows.fetchall() if r[0]]


async def check_schema_version(engine: AsyncEngine) -> SchemaStatus:
    """Compare the live database's revision against this build's head. Never raises."""
    try:
        head = application_head_revision()
    except _MigrationsUnavailable as exc:
        # No migration scripts in the image: we cannot form an opinion. Report UNKNOWN rather
        # than inventing a healthy verdict.
        return SchemaStatus(SchemaState.UNKNOWN, None, None, f"migration scripts unavailable: {exc}")
    except SchemaVersionError as exc:
        return SchemaStatus(SchemaState.UNKNOWN, None, None, str(exc))

    try:
        db_revisions = await _read_db_revision(engine)
    except Exception as exc:  # noqa: BLE001 -- any driver/network error means "cannot verify"
        return SchemaStatus(
            SchemaState.UNAVAILABLE, None, head,
            f"could not read alembic_version: {type(exc).__name__}",
        )

    if not db_revisions:
        return SchemaStatus(
            SchemaState.UNKNOWN, None, head,
            "the database has no alembic_version row -- it has never been migrated, or is "
            "not the application's database",
        )
    if len(db_revisions) > 1:
        return SchemaStatus(
            SchemaState.UNKNOWN, ",".join(sorted(db_revisions)), head,
            f"alembic_version holds {len(db_revisions)} rows (an unmerged branch was applied)",
        )

    db_rev = db_revisions[0]
    if db_rev == head:
        return SchemaStatus(SchemaState.MATCH, db_rev, head, "database schema is at the application head")

    # Is the DB revision an ANCESTOR of head (behind) or unknown to this build (ahead)?
    script = _script_directory()
    try:
        script.get_revision(db_rev)
    except Exception:  # noqa: BLE001 -- alembic raises its own ResolutionError subclasses
        return SchemaStatus(
            SchemaState.AHEAD, db_rev, head,
            f"the database is at revision {db_rev}, which this build does not contain -- the "
            "database was migrated by a NEWER release than the code now running",
        )

    ancestry = {rev.revision for rev in script.iterate_revisions(head, "base")}
    if db_rev in ancestry:
        pending = [
            rev.revision for rev in script.iterate_revisions(head, db_rev)
            if rev.revision != db_rev
        ]
        return SchemaStatus(
            SchemaState.BEHIND, db_rev, head,
            f"the database is at revision {db_rev}, {len(pending)} migration(s) behind the "
            f"application head {head} -- run `alembic upgrade head` before serving traffic",
        )
    return SchemaStatus(
        SchemaState.AHEAD, db_rev, head,
        f"the database is at revision {db_rev}, which is not an ancestor of this build's head "
        f"{head} -- the schema belongs to a different or newer release",
    )


async def enforce_schema_version(engine: AsyncEngine, *, is_production: bool) -> SchemaStatus:
    """The GATE. Fail closed in production on anything other than an exact match.

    Returns the status so callers can log or surface it; raises SchemaVersionError in
    production when the schema is not the one this build expects.
    """
    status = await check_schema_version(engine)

    if status.is_healthy:
        logger.info(
            "schema_version.ok",
            extra={"event": "schema_version.ok", "db_revision": status.db_revision,
                   "head_revision": status.head_revision},
        )
        return status

    message = (
        f"DATABASE SCHEMA MISMATCH ({status.state.value}): {status.detail}. "
        f"db_revision={status.db_revision!r} application_head={status.head_revision!r}"
    )
    if is_production:
        # Fail closed. A process that cannot prove its schema must not serve traffic.
        logger.error(
            "schema_version.rejected",
            extra={"event": "schema_version.rejected", "state": status.state.value,
                   "db_revision": status.db_revision, "head_revision": status.head_revision},
        )
        raise SchemaVersionError(
            message + ". Refusing to start in production -- serving traffic against an "
            "unverified schema risks 500s and writes against a half-migrated shape."
        )
    logger.warning(
        "schema_version.mismatch: %s. Continuing because this is not production; production "
        "would REFUSE to start.", message,
        extra={"event": "schema_version.mismatch", "state": status.state.value},
    )
    return status
