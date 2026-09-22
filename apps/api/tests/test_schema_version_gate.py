"""AUDIT-002 -- the database schema-version gate.

THE GAP
-------
Startup and `/ready` proved the database with `SELECT 1`. That answers "is a database
listening", not "is it the schema this build was written against". Measured on this repo
before the fix: against a database pinned two revisions behind head -- with no
`risk_assessments` table at all -- `SELECT 1` returned 1 and readiness reported
`database: ok`. The node would have been sent live traffic and 500ed on the first query
touching the missing schema.

The five cases the finding requires are each covered below against a REAL MySQL database
built into the state under test (behind / at head / ahead / no alembic_version), plus an
unreachable DSN for the connection-failure case. Production must fail closed on every
non-match state; development warns and continues.

`AHEAD` is rejected deliberately. This project publishes no forward-compatibility contract:
nothing declares which future revisions a build tolerates and no test exercises old code
against new schema, so treating AHEAD as healthy would be an assumption rather than a
verified property -- and a rolled-back app against a migrated database is exactly when a
dropped column corrupts writes.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import urlparse

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from apps.api.core.config import get_settings
from apps.api.core.schema_version import (
    SchemaState,
    SchemaVersionError,
    application_head_revision,
    check_schema_version,
    enforce_schema_version,
)

REPO_ROOT = Path(__file__).resolve().parents[3]


# --------------------------------------------------------------------------------------------
# Scratch-database helpers. Every database created here is disposable and named `*_test`, and
# is dropped again at the end of the fixture -- production DSNs are never touched.
# --------------------------------------------------------------------------------------------

def _admin_url() -> str:
    """The suite's own DSN, which already points at a disposable test database."""
    return get_settings().database_url


def _sync_url(dsn: str) -> str:
    return dsn.replace("+aiomysql", "+pymysql")


def _server_root(dsn: str) -> str:
    """The same server, no database selected."""
    parsed = urlparse(_sync_url(dsn))
    return _sync_url(dsn).rsplit("/", 1)[0] + "/" if parsed.path else _sync_url(dsn)


def _exec(dsn_no_db: str, statement: str) -> None:
    import sqlalchemy

    eng = sqlalchemy.create_engine(dsn_no_db, isolation_level="AUTOCOMMIT")
    try:
        with eng.connect() as conn:
            conn.exec_driver_sql(statement)
    finally:
        eng.dispose()


def _alembic_upgrade(db_name: str, revision: str) -> subprocess.CompletedProcess:
    """Run the real alembic CLI against a scratch database."""
    base = _admin_url().rsplit("/", 1)[0]
    env = {**os.environ, "DATABASE_URL": f"{base}/{db_name}", "PYTHONPATH": str(REPO_ROOT)}
    return subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", revision],
        cwd=REPO_ROOT / "db", env=env, capture_output=True, text=True,
    )


@pytest.fixture
def scratch_db():
    """Create a disposable database, yield (name, async_dsn), then drop it."""
    created: list[str] = []
    base = _admin_url().rsplit("/", 1)[0]
    root = _server_root(_admin_url())

    def _make(suffix: str) -> tuple[str, str]:
        name = f"mbs_sv_{suffix}_{uuid.uuid4().hex[:8]}_test"
        try:
            _exec(root, f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"cannot create a scratch database on this server: {exc}")
        created.append(name)
        return name, f"{base}/{name}"

    yield _make

    for name in created:
        try:
            _exec(root, f"DROP DATABASE IF EXISTS `{name}`")
        except Exception:  # noqa: BLE001 -- cleanup is best-effort
            pass


def _status(dsn: str):
    async def _run():
        eng = create_async_engine(dsn)
        try:
            return await check_schema_version(eng)
        finally:
            await eng.dispose()

    return asyncio.run(_run())


def _enforce(dsn: str, *, is_production: bool):
    async def _run():
        eng = create_async_engine(eng_url := dsn)  # noqa: F841
        try:
            return await enforce_schema_version(eng, is_production=is_production)
        finally:
            await eng.dispose()

    return asyncio.run(_run())


# --------------------------------------------------------------------------------------------
# The head revision is derived from the scripts, not hardcoded.
# --------------------------------------------------------------------------------------------

def test_head_revision_is_determined_from_the_migration_scripts():
    """Hardcoding the head would just create a second thing to forget to update."""
    head = application_head_revision()
    assert isinstance(head, str) and head
    versions = REPO_ROOT / "db" / "migrations" / "versions"
    if versions.is_dir():
        contents = "\n".join(
            p.read_text(encoding="utf-8") for p in versions.glob("*.py")
        )
        assert f"revision: str = '{head}'" in contents or f'revision: str = "{head}"' in contents


def test_head_revision_matches_alembic_cli():
    """Cross-check against alembic's own CLI -- two independent derivations must agree."""
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "heads"],
        cwd=REPO_ROOT / "db", env=env, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"alembic CLI unavailable: {proc.stderr[-300:]}")
    assert application_head_revision() in proc.stdout


# --------------------------------------------------------------------------------------------
# CASE B -- DB exactly at the application head -> healthy, production starts.
# --------------------------------------------------------------------------------------------

def test_db_at_head_is_healthy_and_production_starts(scratch_db):
    name, dsn = scratch_db("head")
    proc = _alembic_upgrade(name, "head")
    assert proc.returncode == 0, f"alembic upgrade failed: {proc.stderr[-500:]}"

    status = _status(dsn)
    assert status.state is SchemaState.MATCH, status.detail
    assert status.db_revision == application_head_revision()
    assert status.is_healthy

    # production must START -- the gate must not be a blanket refusal
    result = _enforce(dsn, is_production=True)
    assert result.is_healthy


# --------------------------------------------------------------------------------------------
# CASE A -- DB behind the application head -> production fails closed.
# --------------------------------------------------------------------------------------------

def test_db_behind_head_fails_closed_in_production(scratch_db):
    """THE HEADLINE CASE: this is the state that previously reported `database: ok`."""
    name, dsn = scratch_db("behind")
    # Migrate to the revision BEFORE head, so the DB is a genuine ancestor.
    from apps.api.core.schema_version import _script_directory

    script = _script_directory()
    head = application_head_revision()
    parents = script.get_revision(head).down_revision
    previous = parents if isinstance(parents, str) else list(parents)[0]

    proc = _alembic_upgrade(name, previous)
    assert proc.returncode == 0, f"alembic upgrade failed: {proc.stderr[-500:]}"

    status = _status(dsn)
    assert status.state is SchemaState.BEHIND, status.detail
    assert status.db_revision == previous
    assert status.head_revision == head
    assert not status.is_healthy

    with pytest.raises(SchemaVersionError) as exc:
        _enforce(dsn, is_production=True)
    assert "behind" in str(exc.value).lower()


def test_db_behind_head_only_warns_in_development(scratch_db):
    """A developer mid-migration must not be locked out of their own machine."""
    name, dsn = scratch_db("behinddev")
    from apps.api.core.schema_version import _script_directory

    script = _script_directory()
    parents = script.get_revision(application_head_revision()).down_revision
    previous = parents if isinstance(parents, str) else list(parents)[0]
    assert _alembic_upgrade(name, previous).returncode == 0

    status = _enforce(dsn, is_production=False)   # must NOT raise
    assert status.state is SchemaState.BEHIND


# --------------------------------------------------------------------------------------------
# CASE C -- DB ahead of the application head -> rejected (no forward-compat contract).
# --------------------------------------------------------------------------------------------

def test_db_ahead_of_head_is_rejected_in_production(scratch_db):
    name, dsn = scratch_db("ahead")
    assert _alembic_upgrade(name, "head").returncode == 0
    # Stamp a revision this build does not contain.
    _exec(_sync_url(dsn), "UPDATE alembic_version SET version_num = 'zz99future999'")

    status = _status(dsn)
    assert status.state is SchemaState.AHEAD, status.detail
    assert status.db_revision == "zz99future999"

    with pytest.raises(SchemaVersionError):
        _enforce(dsn, is_production=True)


# --------------------------------------------------------------------------------------------
# CASE D -- missing / invalid alembic_version -> production fails closed.
# --------------------------------------------------------------------------------------------

def test_missing_alembic_version_table_fails_closed(scratch_db):
    """An empty database is not a healthy one."""
    _name, dsn = scratch_db("norev")
    status = _status(dsn)
    assert status.state is SchemaState.UNKNOWN, status.detail
    assert status.db_revision is None

    with pytest.raises(SchemaVersionError):
        _enforce(dsn, is_production=True)


def test_empty_alembic_version_table_fails_closed(scratch_db):
    """The table exists but holds no row -- e.g. a truncated/half-restored database."""
    name, dsn = scratch_db("emptyrev")
    assert _alembic_upgrade(name, "head").returncode == 0
    _exec(_sync_url(dsn), "DELETE FROM alembic_version")

    status = _status(dsn)
    assert status.state is SchemaState.UNKNOWN
    with pytest.raises(SchemaVersionError):
        _enforce(dsn, is_production=True)


def test_multiple_alembic_version_rows_fail_closed(scratch_db):
    """Two rows means an unmerged branch was applied -- ambiguous, so refuse."""
    name, dsn = scratch_db("tworev")
    assert _alembic_upgrade(name, "head").returncode == 0
    _exec(_sync_url(dsn), "INSERT INTO alembic_version (version_num) VALUES ('zz99other999')")

    status = _status(dsn)
    assert status.state is SchemaState.UNKNOWN, status.detail
    with pytest.raises(SchemaVersionError):
        _enforce(dsn, is_production=True)


# --------------------------------------------------------------------------------------------
# CASE E -- DB connection failure -> production fails closed (never "assume healthy").
# --------------------------------------------------------------------------------------------

def test_connection_failure_fails_closed_in_production():
    dsn = "mysql+aiomysql://nobody:nobody@127.0.0.1:59999/does_not_exist"
    status = _status(dsn)
    assert status.state is SchemaState.UNAVAILABLE, status.detail
    assert not status.is_healthy

    with pytest.raises(SchemaVersionError):
        _enforce(dsn, is_production=True)


# --------------------------------------------------------------------------------------------
# Wiring: the gate is actually reachable from startup and readiness (a gate nobody calls is
# not a gate), and schema stays SEPARATE from the Redis check.
# --------------------------------------------------------------------------------------------

def test_gate_is_wired_into_startup_checks():
    src = (REPO_ROOT / "apps" / "api" / "core" / "startup_checks.py").read_text(encoding="utf-8")
    assert "enforce_schema_version" in src, (
        "run_startup_security_checks must enforce the schema version, or a stale-schema node "
        "still starts"
    )


def test_gate_is_wired_into_readiness_and_reported_separately():
    src = (REPO_ROOT / "apps" / "api" / "main.py").read_text(encoding="utf-8")
    assert "check_schema_version" in src, "/ready must verify the schema version"
    assert 'checks["schema"]' in src, "schema must be reported as its own readiness component"
    assert 'checks["redis"]' in src, "the Redis check must remain independent of schema"


def test_readiness_reports_schema_ok_against_the_suite_database(client):
    """End-to-end: the running app's /ready reports a healthy schema against the test DB,
    which the suite keeps at head."""
    resp = client.get("/ready")
    body = resp.json()
    assert "schema" in body["checks"], f"no schema component in readiness: {body}"
    assert body["checks"]["schema"] == "ok", (
        f"the suite database is expected to be at head; readiness said {body['checks']}"
    )


def test_readiness_does_not_leak_revisions_on_the_unauthenticated_probe(client):
    """The probe is unauthenticated: it may report a state name, never revision ids."""
    body = client.get("/ready").json()
    rendered = str(body)
    assert application_head_revision() not in rendered, (
        "/ready must not disclose migration revision ids to anonymous callers"
    )
