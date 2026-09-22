"""DR backup/restore against a REAL mysqldump + mysql client and a REAL MySQL server.

WHY THIS FILE EXISTS (please don't replace it with fakes): every other DR test injects
`FakeMySQLRunner`, so no test ever ran the actual `mysqldump` binary. That gap let a total
DR failure ship green -- MariaDB's mysqldump (the client `default-mysql-client` installs in
infra/docker/Dockerfile.worker) verifies the server certificate BY DEFAULT and aborted every
backup against the mysql:8.0 image's auto-generated self-signed certificate with
`TLS/SSL error: self-signed certificate in certificate chain`, producing an EMPTY dump.
The fakes cannot see that class of bug: it lives entirely in how the real client is invoked.
See apps/api/core/config.py's backup_mysql_ssl_mode for the full analysis.

These tests SKIP (never fail) when the pieces aren't present -- no MySQL client binaries on
PATH, or DATABASE_URL not pointing at a reachable MySQL -- so a laptop checkout and the
existing unit suite are unaffected. They RUN in CI and in the worker image, which is exactly
where the real client lives.

SAFETY: the restore test never touches the configured database. It creates its own scratch
database, restores into that, and drops it in a finally block.
"""
import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest
from sqlalchemy.engine import make_url

from apps.api.core.config import get_settings
from apps.api.dr.mysql import (
    SSL_MODE_DISABLED,
    SSL_MODE_REQUIRED,
    SSL_MODE_VERIFY_IDENTITY,
    BackupError,
    MySQLRunner,
    backup_mysql,
    verify_mysql_archive,
)


def _database_url() -> str:
    return os.environ.get("DATABASE_URL") or get_settings().database_url


def _require_real_mysql_stack() -> str:
    """Skip unless BOTH client binaries exist AND the server is actually reachable."""
    settings = get_settings()
    for cmd in (settings.backup_mysqldump_cmd, settings.backup_mysql_cmd):
        if shutil.which(cmd) is None:
            pytest.skip(f"{cmd} not on PATH; real-client DR tests need the MySQL client tools")

    url = _database_url()
    if make_url(url).get_backend_name() != "mysql":
        pytest.skip("DATABASE_URL is not a MySQL URL")

    try:
        import pymysql
    except ImportError:  # pragma: no cover - pymysql is a hard dependency
        pytest.skip("pymysql not installed")

    u = make_url(url)
    try:
        pymysql.connect(
            host=u.host, port=u.port or 3306, user=u.username,
            password=u.password or "", connect_timeout=5,
        ).close()
    except Exception as exc:  # noqa: BLE001 -- any connect failure means "no server here"
        pytest.skip(f"MySQL not reachable at {u.host}:{u.port or 3306} ({type(exc).__name__})")
    return url


def _runner(ssl_mode: str = SSL_MODE_REQUIRED, ssl_ca: str = "") -> MySQLRunner:
    s = get_settings()
    return MySQLRunner(s.backup_mysqldump_cmd, s.backup_mysql_cmd, ssl_mode, ssl_ca)


# --- the regression this file was written for ---------------------------------------------

@pytest.mark.parametrize("ssl_mode", [SSL_MODE_REQUIRED, SSL_MODE_DISABLED])
def test_real_mysqldump_produces_a_valid_dump(tmp_path, ssl_mode):
    """The exact failure that shipped: this raised BackupError (empty dump) for every mode
    before backup_mysql_ssl_mode existed, because the client verified a self-signed cert."""
    url = _require_real_mysql_stack()

    info = backup_mysql(tmp_path, database_url=url, runner=_runner(ssl_mode))

    dump = tmp_path / "db.sql"
    assert dump.exists(), "mysqldump reported success but wrote no file"
    # Guards the original symptom directly: exit 2 left a 0-byte file behind.
    assert dump.stat().st_size > 1024, f"suspiciously small dump: {dump.stat().st_size} bytes"
    assert info["bytes"] == dump.stat().st_size
    # The same cheap magic gate the service layer applies before trusting a set.
    assert verify_mysql_archive(dump) is True
    assert b"CREATE TABLE" in dump.read_bytes()[:200_000]


def test_real_dump_round_trips_through_a_real_restore(tmp_path):
    """A dump is only 'valid' if `mysql` can actually load it. Restores into a scratch
    database (never the configured one) and confirms the schema landed."""
    url = _require_real_mysql_stack()
    import pymysql

    backup_mysql(tmp_path, database_url=url, runner=_runner())
    src = make_url(url)
    scratch = f"mbs_drtest_{uuid.uuid4().hex[:12]}"
    admin = pymysql.connect(
        host=src.host, port=src.port or 3306, user=src.username,
        password=src.password or "", autocommit=True,
    )
    try:
        with admin.cursor() as cur:
            cur.execute(f"CREATE DATABASE `{scratch}`")
        try:
            # render_as_string(hide_password=False), NOT str(url): SQLAlchemy's __str__
            # masks the password as '***', which would reach the client as a literal
            # password and fail with 'Access denied'.
            scratch_url = src.set(database=scratch).render_as_string(hide_password=False)
            _runner().restore(scratch_url, tmp_path / "db.sql")
            with admin.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = %s",
                    (scratch,),
                )
                restored_tables = cur.fetchone()[0]
            # The dump carries the app schema; an empty restore would mean a silently
            # truncated or empty dump -- the failure mode this whole file guards.
            assert restored_tables > 10, f"restore produced only {restored_tables} tables"
        finally:
            with admin.cursor() as cur:
                cur.execute(f"DROP DATABASE IF EXISTS `{scratch}`")
    finally:
        admin.close()


def test_verify_identity_against_the_servers_own_ca_is_configurable(tmp_path):
    """`verify_identity` is a real, reachable code path -- not dead configuration. The
    mysql:8.0 auto-generated certificate cannot pass hostname verification (its CN is
    'MySQL_Server_..._Auto_Generated_Server_Certificate'), so with a CA that does not match
    the host this must fail LOUDLY rather than silently downgrading to an unverified
    connection."""
    url = _require_real_mysql_stack()
    ca = tmp_path / "not-the-real-ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\nnot a real ca\n-----END CERTIFICATE-----\n")

    with pytest.raises(BackupError):
        _runner(SSL_MODE_VERIFY_IDENTITY, str(ca)).dump(url, tmp_path / "db.sql")


# --- client-family option mapping (no server needed) --------------------------------------

@pytest.mark.parametrize(
    ("ssl_mode", "mariadb", "expected", "forbidden"),
    [
        # MariaDB understands ssl-verify-server-cert and rejects ssl-mode; Oracle is the
        # exact mirror image. Emitting the wrong spelling makes the client abort with
        # `unknown variable` (exit 7) and write an EMPTY dump -- so this mapping is the
        # difference between a working backup and a silent one. Both directions asserted.
        (SSL_MODE_REQUIRED, True, "ssl-verify-server-cert=0", "ssl-mode"),
        (SSL_MODE_REQUIRED, False, "ssl-mode=REQUIRED", "ssl-verify-server-cert"),
        (SSL_MODE_DISABLED, True, "ssl=0", "ssl-mode"),
        (SSL_MODE_DISABLED, False, "ssl-mode=DISABLED", "ssl-verify-server-cert"),
    ],
)
def test_ssl_options_use_the_spelling_the_client_family_accepts(
    ssl_mode, mariadb, expected, forbidden
):
    from apps.api.dr.mysql import _ssl_options

    opts = _ssl_options(ssl_mode, "", mariadb)
    assert expected in opts
    assert not any(o.startswith(forbidden) for o in opts)


def test_verify_identity_maps_to_both_families(tmp_path):
    from apps.api.dr.mysql import _ssl_options

    ca = str(tmp_path / "ca.pem")
    assert _ssl_options(SSL_MODE_VERIFY_IDENTITY, ca, True) == [
        f"ssl-ca={ca}", "ssl-verify-server-cert=1",
    ]
    assert _ssl_options(SSL_MODE_VERIFY_IDENTITY, ca, False) == [
        f"ssl-ca={ca}", "ssl-mode=VERIFY_IDENTITY",
    ]


def test_client_family_is_detected_from_the_binary():
    """The detection that picks the spelling above. Runs against whichever real client is
    installed; skips when there is none."""
    from apps.api.dr.mysql import _is_mariadb_client

    cmd = get_settings().backup_mysqldump_cmd
    if shutil.which(cmd) is None:
        pytest.skip(f"{cmd} not on PATH")
    detected = _is_mariadb_client(cmd)
    banner = subprocess.run([cmd, "--version"], capture_output=True).stdout.decode(errors="replace")
    assert detected == ("mariadb" in banner.lower())
    # A binary that does not exist must not raise -- it falls back to the Oracle spelling.
    assert _is_mariadb_client("definitely-not-a-real-mysql-client-xyz") is False


# --- configuration guards (no server needed) ----------------------------------------------

def test_verify_identity_without_a_ca_is_rejected_before_connecting(tmp_path):
    with pytest.raises(BackupError, match="backup_mysql_ssl_ca"):
        MySQLRunner(ssl_mode=SSL_MODE_VERIFY_IDENTITY).dump(
            "mysql+pymysql://u:p@127.0.0.1:3306/x", tmp_path / "db.sql"
        )


def test_unknown_ssl_mode_is_rejected(tmp_path):
    with pytest.raises(BackupError, match="unknown backup_mysql_ssl_mode"):
        MySQLRunner(ssl_mode="totally-wrong").dump(
            "mysql+pymysql://u:p@127.0.0.1:3306/x", tmp_path / "db.sql"
        )


def test_credentials_never_reach_argv(monkeypatch, tmp_path):
    """The option-file design is a security property (a password on argv is world-readable
    via ps/proc), so assert it rather than trusting it stays true."""
    seen: dict = {}

    def _fake_run(cmd, **kwargs):
        # The runner probes `<client> --version` first to pick the right TLS option spelling
        # (see _is_mariadb_client); answer that as MariaDB and let the real dump call below
        # be the one this test inspects.
        if len(cmd) == 2 and cmd[1] == "--version":
            return subprocess.CompletedProcess(cmd, 0, b"mysqldump from 11.8.6-MariaDB", b"")
        seen["cmd"] = cmd
        cnf = next(a.split("=", 1)[1] for a in cmd if str(a).startswith("--defaults-extra-file="))
        seen["cnf"] = Path(cnf).read_text(encoding="utf-8")
        Path(tmp_path / "db.sql").write_bytes(b"-- MySQL dump" + b" " * 200)
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    MySQLRunner().dump("mysql+pymysql://u:sup3rs3cret@h:3306/d", tmp_path / "db.sql")

    assert "sup3rs3cret" not in " ".join(str(a) for a in seen["cmd"])
    assert "password=sup3rs3cret" in seen["cnf"]
    # The fix itself: the TLS option must actually reach the client's option file. The fake
    # above answers the probe as MariaDB, so this is the spelling that must appear.
    assert "ssl-verify-server-cert=0" in seen["cnf"]
