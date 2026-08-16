import warnings

import pytest
from fastapi.testclient import TestClient

from apps.api.main import app


@pytest.fixture(autouse=True)
def _reset_db():
    """Per-test DB isolation.

    The suite writes directly to the shared Postgres with no cleanup, so rows ACCUMULATE across
    tests/runs and global-scope logic (e.g. run_due_schedules processes ALL due schedules) plus
    global-count assertions become nondeterministic on a reused DB -- the source of the flaky
    schedule-dispatch failures. This clears every volatile application table BEFORE each test so each
    one starts from a clean slate. Test-harness only; touches no application code.

    Mechanism (deliberate): a SHORT-LIVED synchronous psycopg2 connection, independent of the
    session-scoped TestClient's async engine/event loop (which stays unchanged), that DELETEs from
    the volatile tables. Not a transaction wrapper -- several tests open their own async engines and
    COMMIT via independent connections, which a wrapping transaction could not roll back.

    PRESERVED tables (never cleared): `alembic_version` (schema state) and the migration-seeded RBAC
    reference data -- `roles`, `permissions`, `role_permissions` (system rows have workspace_id IS
    NULL). The app REQUIRES these (e.g. create_workspace looks up the system "owner" role), so wiping
    them would 400 every workspace-creating test.

    Why DELETE (not TRUNCATE): a PRESERVED seed table (`roles`) has an FK to a cleared table
    (`workspaces`), so `TRUNCATE workspaces` demands CASCADE -- which would re-wipe the seed --
    and `session_replication_role` does NOT relax TRUNCATE's structural FK-dependency check. DELETE
    has no such restriction; running it under `session_replication_role = replica` (scoped to this
    short-lived connection) disables the FK-enforcing triggers so the volatile tables can be cleared
    in ANY order without dependency sorting. No orphans result -- the app only ever creates system
    roles (workspace_id NULL), never workspace-scoped ones.

    Error handling is scoped: a psycopg2.OperationalError means the backing Postgres is unreachable
    (the environment-specific case -- e.g. a DB-less runner); that is surfaced as a RuntimeWarning
    and the test proceeds (DB-backed tests then fail on their own with clear errors). Any OTHER
    error (privilege, lock timeout, SQL error) is NOT swallowed -- it propagates so a real problem
    with the isolation stays diagnosable.
    """
    import psycopg2
    from psycopg2 import sql

    from apps.api.core.config import get_settings

    _PRESERVE = ("alembic_version", "roles", "permissions", "role_permissions")

    dsn = get_settings().database_url.replace("+asyncpg", "")
    try:
        conn = psycopg2.connect(dsn, connect_timeout=5)
    except psycopg2.OperationalError as exc:  # DB unreachable: the only environment case we handle
        warnings.warn(f"per-test DB isolation skipped -- Postgres unreachable: {exc}", RuntimeWarning)
        yield
        return

    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            # Fail fast (diagnosably) instead of hanging if a leaked lock blocks a DELETE.
            cur.execute("SET lock_timeout = '5s'")
            cur.execute(
                "SELECT tablename FROM pg_tables "
                "WHERE schemaname = 'public' AND tablename <> ALL(%s)",
                (list(_PRESERVE),),
            )
            tables = [r[0] for r in cur.fetchall()]
            if tables:
                # replica => FK-enforcing triggers off, so order-independent DELETEs are safe and the
                # preserved-seed FK (roles -> workspaces) never blocks clearing workspaces.
                cur.execute("SET session_replication_role = replica")
                try:
                    for table in tables:
                        cur.execute(sql.SQL("DELETE FROM {}").format(sql.Identifier("public", table)))
                finally:
                    cur.execute("SET session_replication_role = origin")
    finally:
        conn.close()

    yield


@pytest.fixture(scope="session")
def client():
    # Session-scoped and NOT re-created per test module: our async SQLAlchemy
    # engine (apps/api/core/db.py) is a process-wide singleton, and its asyncpg
    # connections are bound to whichever event loop first opened them. Each
    # `with TestClient(app) as c:` spins up its own loop, so two separate
    # TestClient instances in the same pytest run means the second one's first
    # request reuses a pooled connection from the first's (now-closed) loop --
    # "Future attached to a different loop". One fixture for the whole session
    # keeps everything on a single loop.
    with TestClient(app) as c:
        yield c
