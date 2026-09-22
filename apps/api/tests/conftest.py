import os
import warnings
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from apps.api.main import app


# P0-2: name + timeout for the cross-process test-isolation advisory lock (see _reset_db).
# The name is namespaced so it cannot collide with an application lock; the timeout bounds
# how long one pytest process waits for another to finish a single test.
_RESET_LOCK_NAME = "mbs_test_reset_lock"
_RESET_LOCK_TIMEOUT_S = 120


def _env_truthy(val: str | None) -> bool:
    return str(val or "").strip().lower() in {"1", "true", "yes", "on"}


def _assert_wipe_allowed(dsn: str) -> None:
    """Refuse to run the destructive per-test reset against a non-test database.

    The autouse `_reset_db` fixture DELETEs every volatile table before each test, so pointing
    DATABASE_URL at a real database destroys its data (this suite has, historically, emptied the
    shared `mbs` DB used by the app and the DR backups). The wipe is permitted ONLY when the
    target is clearly disposable:
      * the database name ends in `_test`, or
      * MBS_ALLOW_DB_WIPE is explicitly truthy (CI sets this against an ephemeral throwaway DB).
    Otherwise we stop the WHOLE session immediately with an actionable message rather than
    silently clearing real data -- fail closed, since even read/write tests would pollute it."""
    if _env_truthy(os.environ.get("MBS_ALLOW_DB_WIPE")):
        return
    db_name = urlparse(dsn).path.lstrip("/").split("?")[0]
    if db_name.endswith("_test"):
        return
    pytest.exit(
        "Refusing to run: the test suite wipes every table in the target database, but "
        f"DATABASE_URL points at '{db_name or '(unknown)'}', which is not a test database. "
        "Point DATABASE_URL at a database whose name ends in '_test', or set MBS_ALLOW_DB_WIPE=1 "
        "to override (CI does this against a disposable database).",
        returncode=1,
    )


@pytest.fixture(scope="session", autouse=True)
def _mysql_read_committed():
    """Set this MySQL server's GLOBAL isolation level to READ COMMITTED for the whole test
    session, once, before anything else runs.

    Same requirement as apps/api/core/db.py's `_mysql_isolation_level()` (this codebase's
    atomic-claim / cooperative-shutdown machinery assumes Postgres's READ COMMITTED default,
    not MySQL's REPEATABLE READ default) and the identical step in .github/workflows/ci.yml --
    but that per-connection app-level fix only covers engines built through
    apps.api.core.db's own factories. Several tests here (test_scan_shutdown.py,
    test_schedule_dispatch.py, test_business_logic_coverage.py and others) open their OWN
    ad-hoc `create_async_engine(...)` directly against DATABASE_URL, which inherits whatever
    the SERVER's default is -- so without this, "due schedule fires a scan" / "reaper sees a
    row another connection just committed" style assertions fail nondeterministically
    depending on server config, exactly the shape of failure this was found from (`launched
    >= 1` / `reaped >= 1` asserting 0 against a real MySQL 8 server whose GLOBAL default was
    never changed from REPEATABLE READ).

    Previously this required a developer to manually run `SET GLOBAL transaction_isolation=
    'READ-COMMITTED'` in a client (e.g. MySQL Workbench) before every session -- a setting
    that resets on every MySQL server restart, so it silently reverts and the failures come
    back for anyone who didn't know to redo it. This fixture does that automatically instead,
    same as CI's own workflow step, once per test session.

    Best-effort, matching `_reset_db` below: a test user without SUPER / SYSTEM_VARIABLES_ADMIN
    can't SET GLOBAL, and a DB-less runner can't connect at all -- both degrade to a warning,
    not a hard failure, since the tests that actually depend on this will then fail on their
    own with a clear assertion rather than an opaque setup error. MySQL 8 names the variable
    `transaction_isolation`; MariaDB (and old MySQL 5.7) uses `tx_isolation` -- try the modern
    name first, fall back to the legacy one."""
    import pymysql
    from sqlalchemy.engine import make_url

    from apps.api.core.config import get_settings

    url = make_url(get_settings().database_url)
    if url.get_backend_name() != "mysql":
        yield
        return
    try:
        conn = pymysql.connect(
            host=url.host or "localhost", port=url.port or 3306,
            user=url.username, password=url.password or "", connect_timeout=5,
        )
    except pymysql.err.OperationalError as exc:
        warnings.warn(f"could not set GLOBAL isolation level -- MySQL unreachable: {exc}", RuntimeWarning)
        yield
        return
    try:
        with conn.cursor() as cur:
            for var_name in ("transaction_isolation", "tx_isolation"):
                try:
                    cur.execute(f"SET GLOBAL {var_name} = 'READ-COMMITTED'")
                    break
                except pymysql.err.OperationalError:
                    continue  # unknown variable name on this server version -- try the other
            else:
                warnings.warn(
                    "could not set GLOBAL isolation level -- neither 'transaction_isolation' "
                    "nor 'tx_isolation' was accepted by this server", RuntimeWarning,
                )
    except pymysql.err.OperationalError as exc:
        # Most likely: insufficient privilege (SUPER / SYSTEM_VARIABLES_ADMIN) to SET GLOBAL.
        warnings.warn(
            f"could not set GLOBAL isolation level ({exc}) -- if the DB user lacks privilege "
            "to SET GLOBAL, run this once yourself in a MySQL client instead: "
            "SET GLOBAL transaction_isolation='READ-COMMITTED'; (or tx_isolation on MariaDB). "
            "Tests relying on read-your-writes across separate connections may fail without it.",
            RuntimeWarning,
        )
    finally:
        conn.close()
    yield


@pytest.fixture(autouse=True)
def _reset_db():
    """Per-test DB isolation.

    The suite writes directly to the shared MySQL with no cleanup, so rows ACCUMULATE across
    tests/runs and global-scope logic (e.g. run_due_schedules processes ALL due schedules) plus
    global-count assertions become nondeterministic on a reused DB -- the source of the flaky
    schedule-dispatch failures. This clears every volatile application table BEFORE each test so each
    one starts from a clean slate. Test-harness only; touches no application code.

    Mechanism (deliberate): a SHORT-LIVED synchronous PyMySQL connection, independent of the
    session-scoped TestClient's async engine/event loop (which stays unchanged), that DELETEs from
    the volatile tables. Not a transaction wrapper -- several tests open their own async engines and
    COMMIT via independent connections, which a wrapping transaction could not roll back.

    PRESERVED tables (never cleared): `alembic_version` (schema state) and the migration-seeded RBAC
    reference data -- `roles`, `permissions`, `role_permissions` (system rows have workspace_id IS
    NULL). The app REQUIRES these (e.g. create_workspace looks up the system "owner" role), so wiping
    them would 400 every workspace-creating test.

    Phase 0 MySQL cutover: was a psycopg2 connection using `session_replication_role = replica` to
    disable FK-enforcing triggers for order-independent DELETEs (Postgres has no simpler knob for
    this). MySQL's equivalent is the session variable `FOREIGN_KEY_CHECKS = 0`, which serves the same
    purpose -- the PRESERVED seed table (`roles`) has an FK to a cleared table (`workspaces`), so
    deleting in an arbitrary order would otherwise violate it. Table identifiers here come only from
    `information_schema.tables` (the DB's own catalog, not user input), so backtick-quoting them
    (doubling any embedded backtick, the standard MySQL identifier-escaping rule) is safe -- PyMySQL,
    unlike psycopg2, has no `sql.Identifier` composer to lean on instead.

    Error handling is scoped: a PyMySQL OperationalError means the backing MySQL is unreachable
    (the environment-specific case -- e.g. a DB-less runner); that is surfaced as a RuntimeWarning
    and the test proceeds (DB-backed tests then fail on their own with clear errors). Any OTHER
    error (privilege, lock timeout, SQL error) is NOT swallowed -- it propagates so a real problem
    with the isolation stays diagnosable.

    CONCURRENCY (P0-2). The wipe above is destructive and the test database is SHARED, so two
    pytest processes pointed at the same DATABASE_URL will corrupt each other: one process's
    reset lands mid-test in the other, deleting the users/workspaces that test is actively
    using. Observed symptom: `401 User not found or inactive`, or an FK 1452 on a child insert,
    in tests that pass 100%% in isolation -- with a DIFFERENT failure set on every run.
    (Reproduced deliberately: running two suites concurrently against one database failed 4
    tests in one process and 2 in the other; each suite passes fully alone.)

    This fixture therefore holds a NAMED ADVISORY LOCK (`GET_LOCK`) for the whole test --
    taken before the wipe, released after the test body. Concurrent runs serialize per test
    rather than interleaving destructive resets, which is what makes the suite's failure set
    deterministic. A single-process run is unaffected beyond two trivial statements per test.

    GET_LOCK specifically (rather than a file lock or a table row) because it is server-side:
    it works across processes, across containers, and from a different host, which a
    filesystem lock does not -- and the lock is released automatically if a process dies,
    so a crashed run cannot wedge every subsequent one.
    """
    import pymysql
    from sqlalchemy.engine import make_url

    from apps.api.core.config import get_settings

    _PRESERVE = ("alembic_version", "roles", "permissions", "role_permissions")

    database_url = get_settings().database_url
    # Fail closed BEFORE connecting: never wipe a database that isn't a disposable test DB.
    _assert_wipe_allowed(database_url)
    url = make_url(database_url)
    try:
        conn = pymysql.connect(
            host=url.host or "localhost", port=url.port or 3306,
            user=url.username, password=url.password or "", database=url.database,
            connect_timeout=5,
        )
    except pymysql.err.OperationalError as exc:  # DB unreachable: the only environment case we handle
        warnings.warn(f"per-test DB isolation skipped -- MySQL unreachable: {exc}", RuntimeWarning)
        yield
        return

    try:
        conn.autocommit(True)
        with conn.cursor() as cur:
            # CROSS-PROCESS SERIALIZATION (see the docstring). Held from before the wipe until
            # after the test body, so a concurrent run cannot reset the database out from under
            # a test in flight. The timeout is generous enough for the slowest single test in
            # the suite but still bounded, so a genuinely stuck holder surfaces as a clear
            # error instead of hanging the run forever.
            cur.execute("SELECT GET_LOCK(%s, %s)", (_RESET_LOCK_NAME, _RESET_LOCK_TIMEOUT_S))
            got = cur.fetchone()[0]
            if got != 1:
                # 0 = timed out waiting, NULL = error. Either way the wipe below would race a
                # concurrent run, so fail loudly rather than proceed into nondeterminism.
                raise RuntimeError(
                    f"could not acquire the test-isolation lock '{_RESET_LOCK_NAME}' within "
                    f"{_RESET_LOCK_TIMEOUT_S}s (GET_LOCK returned {got!r}). Another pytest "
                    "process is probably using the same DATABASE_URL; run suites against "
                    "separate databases or serialize them."
                )

            # Fail fast (diagnosably) instead of hanging if a leaked lock blocks a DELETE.
            cur.execute("SET SESSION innodb_lock_wait_timeout = 5")
            cur.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' "
                "AND table_name NOT IN %s",
                (_PRESERVE,),
            )
            tables = [r[0] for r in cur.fetchall()]
            if tables:
                # FOREIGN_KEY_CHECKS=0 => order-independent DELETEs are safe and the preserved-seed
                # FK (roles -> workspaces) never blocks clearing workspaces.
                cur.execute("SET FOREIGN_KEY_CHECKS = 0")
                try:
                    for table in tables:
                        quoted = table.replace("`", "``")
                        cur.execute(f"DELETE FROM `{quoted}`")
                finally:
                    cur.execute("SET FOREIGN_KEY_CHECKS = 1")

        # The test runs HERE, still holding the lock -- that is the whole point.
        yield
    finally:
        # RELEASE_LOCK on the same connection that took it, then close. Wrapped so a failure
        # to release can never mask the test's own outcome; closing the connection would free
        # the lock anyway (MySQL drops session locks on disconnect).
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT RELEASE_LOCK(%s)", (_RESET_LOCK_NAME,))
        except Exception:  # noqa: BLE001 -- best effort; the close below frees it regardless
            pass
        conn.close()


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


@pytest.fixture(autouse=True)
def _dev_auto_authorize_targets_off(monkeypatch):
    """Pin DEV_AUTO_AUTHORIZE_TARGETS to its secure default (False) for every test.

    This is a LOCAL DEVELOPMENT convenience flag (core/config.py) that a developer flips on
    in their own untracked .env to skip the authorization-scope UI flow while manually
    testing scans -- and pydantic-settings' env_file=".env" means a plain `pytest` run from
    this same directory would otherwise inherit it too, silently defeating every test in
    test_scans.py / test_vulnerabilities.py / test_authorization_scope.py that asserts the
    guardrail actually blocks an unauthorized target. An individual test can still opt in
    via its own monkeypatch.setattr(get_settings(), "dev_auto_authorize_targets", True).

    Two separate overrides are needed: a real env var (beats the .env file's value, per
    pydantic-settings precedence) for any test that constructs a FRESH Settings(...) directly
    (several deployment-config / hardened-production-config tests do), plus patching the
    attribute on get_settings()'s cached (@lru_cache) singleton, since that instance was
    already constructed once earlier in the session and the env var can't retroactively
    change it."""
    from apps.api.core.config import get_settings

    monkeypatch.setenv("DEV_AUTO_AUTHORIZE_TARGETS", "false")
    monkeypatch.setattr(get_settings(), "dev_auto_authorize_targets", False)


@pytest.fixture
def no_celery_dispatch(monkeypatch):
    """Stops create_scan from actually queueing to Celery/Redis -- we only want
    to test the API/gate/persistence layer here, not tool execution (that's
    verified live against the worker + naabu). Returns a fake AsyncResult.

    Lives in conftest so it is auto-discovered by every test module without a
    cross-module import (which previously required a `# noqa: F401` and tripped F811)."""
    from apps.api.celery_app.tasks import scan_tasks

    class _FakeResult:
        id = "fake-task-id"

    monkeypatch.setattr(scan_tasks.run_scan_task, "delay", lambda *a, **k: _FakeResult())
    # MBS.SC: scan dispatch now uses apply_async(queue=...) so it can route a private scan
    # to its own per-site queue (scanner_engine/scan_routing.py). Stub it alongside `delay` --
    # otherwise creating a scan in a test would try to reach a real broker.
    monkeypatch.setattr(scan_tasks.run_scan_task, "apply_async", lambda *a, **k: _FakeResult())
