"""Phase 1.6 -- MySQL backup / restore / verify for the DR system.

Phase 0 MySQL cutover: replaces the Postgres pg_dump/pg_restore module (apps/api/dr/postgres.py,
removed -- clean cutover, no dual-support). Uses `mysqldump` (plain SQL text, NOT --databases,
so the dump contains no CREATE DATABASE/USE statements and can be restored into any target
database name via the `mysql` client) and the `mysql` client for restore. The external commands
run through an injectable `MySQLRunner` seam, so the surrounding logic (naming, integrity checks,
error paths) is unit-testable without a real MySQL client.

Why not pg_dump -Fc's binary custom format: MySQL has no equivalent compressed/selective-restore
archive format built into the standard client tools. A plain SQL dump is the portable, universally
restorable choice (`mysql < db.sql`), consistent with mysqldump's own default output. Cheap
corruption detection mirrors the old PG_MAGIC check: a well-formed dump carries a `-- MySQL dump`
or `-- MariaDB dump` header comment near the top (verified empirically against both Oracle MySQL's
and MariaDB's mysqldump -- MariaDB additionally prepends a `/*M!999999...*/` sandbox-mode line
before it, so the check scans the first KB rather than requiring byte offset 0); the sha256
sidecar (written by the service layer, same as before) is the actual integrity proof -- this
magic check is just an early, cheap sanity gate.

Credentials never touch argv: mysqldump/mysql read them from a `--defaults-extra-file` temp file
(mode 0600, deleted immediately after the subprocess exits) instead of a `-p<password>` argument,
which would otherwise be visible to any other process via `ps`/`/proc`. Nothing here is logged.
"""
import os
import re
import subprocess
import tempfile
from pathlib import Path

from sqlalchemy.engine import make_url

# Scanned as a "does the header appear near the top" check, not a byte-0 prefix match -- see the
# module docstring for why (MariaDB's sandbox-mode preamble line).
MYSQL_DUMP_MAGIC = (b"-- MySQL dump", b"-- MariaDB dump")
_MAGIC_SCAN_BYTES = 1024
DB_DUMP = "db.sql"


class BackupError(Exception):
    """A backup/restore step failed in a way that must abort that component."""


def db_url_identity(database_url: str) -> str:
    """Normalize a SQLAlchemy database URL to host+port+database (credentials and driver tag
    stripped) so two URLs can be compared for 'same database' purposes. Replaces the old
    pg_uri()-based string comparison (pg.pg_uri(a) == pg.pg_uri(b)); parses properly instead of
    string-replacing driver suffixes, so it's robust to whichever MySQL driver tag is in use
    (+aiomysql, +pymysql, or none)."""
    url = make_url(database_url)
    return f"{url.host}:{url.port or 3306}/{url.database}"


def _connect_parts(database_url: str) -> dict:
    url = make_url(database_url)
    return {
        "host": url.host or "localhost",
        "port": str(url.port or 3306),
        "user": url.username or "",
        "password": url.password or "",
        "database": url.database or "",
    }


def _redact(text: str) -> str:
    """Strip userinfo from any URI-shaped substring in `text` -- defensive, in case an error
    message ever echoes a connection string. The primary protection is that credentials are
    passed via --defaults-extra-file, never on argv, so there is normally nothing to redact."""
    return re.sub(r"://[^@/\s]*@", "://<redacted>@", text)


SSL_MODE_REQUIRED = "required"
SSL_MODE_VERIFY_IDENTITY = "verify_identity"
SSL_MODE_DISABLED = "disabled"
SSL_MODES = (SSL_MODE_REQUIRED, SSL_MODE_VERIFY_IDENTITY, SSL_MODE_DISABLED)


def _is_mariadb_client(cmd: str) -> bool:
    """True if `cmd` is MariaDB's client rather than Oracle's, decided by asking the binary.

    This matters because the two families spell their TLS options DIFFERENTLY and each one
    hard-rejects the other's spelling (`unknown variable`, exit 7, empty output) rather than
    ignoring it -- verified against both clients in this project's own stack:

        option                       MariaDB 11.8 client   Oracle MySQL 8.0.46 client
        ssl-verify-server-cert=0     accepted              REJECTED (unknown variable)
        ssl-mode=PREFERRED           REJECTED              accepted

    So there is no single spelling that works everywhere and no way to emit both. Which
    client is present is an environment fact, not a config choice: Debian's
    `default-mysql-client` (infra/docker/Dockerfile.worker) is MariaDB-backed, while CI
    installs Oracle's `mysql-client`. Hence: detect, don't assume.

    Detection is `--version`, whose output contains "MariaDB" for that family. Failures
    (missing binary, non-zero exit) fall back to False -- the Oracle spelling -- and the
    caller surfaces any real problem as a normal BackupError from the actual dump."""
    try:
        out = subprocess.run([cmd, "--version"], capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return b"mariadb" in (out.stdout + out.stderr).lower()


def _ssl_options(ssl_mode: str, ssl_ca: str, mariadb: bool) -> list[str]:
    """The `[client]` option-file lines that put mysqldump/mysql into `ssl_mode`.

    Exists because the MySQL CLI clients do NOT share the app engine's TLS configuration --
    aiomysql negotiates its own (core/db.py), so a DR backup can fail on TLS while the API
    is happily connected to the very same server. See config.backup_mysql_ssl_mode for the
    full writeup of the two concrete failures this addresses, and `_is_mariadb_client` for
    why the spelling has to vary by client family."""
    if ssl_mode == SSL_MODE_DISABLED:
        return ["ssl=0"] if mariadb else ["ssl-mode=DISABLED"]
    if ssl_mode == SSL_MODE_VERIFY_IDENTITY:
        if not ssl_ca:
            raise BackupError(
                "backup_mysql_ssl_mode='verify_identity' requires backup_mysql_ssl_ca to point at "
                "the CA PEM that issued the server's certificate."
            )
        if mariadb:
            return [f"ssl-ca={ssl_ca}", "ssl-verify-server-cert=1"]
        return [f"ssl-ca={ssl_ca}", "ssl-mode=VERIFY_IDENTITY"]
    if ssl_mode == SSL_MODE_REQUIRED:
        # Encrypt, but do not verify the chain/hostname. Deliberately still passes ssl-ca when
        # one is configured: it costs nothing and keeps the trust store consistent if the mode
        # is later tightened to verify_identity.
        opts = ["ssl-verify-server-cert=0"] if mariadb else ["ssl-mode=REQUIRED"]
        if ssl_ca:
            opts.insert(0, f"ssl-ca={ssl_ca}")
        return opts
    raise BackupError(
        f"unknown backup_mysql_ssl_mode {ssl_mode!r}; expected one of {', '.join(SSL_MODES)}"
    )


def _write_defaults_file(
    parts: dict,
    ssl_mode: str = SSL_MODE_REQUIRED,
    ssl_ca: str = "",
    mariadb: bool = False,
) -> str:
    """Write a short-lived MySQL option file so credentials never appear on argv/ps/proc.
    Caller is responsible for deleting it (see MySQLRunner.dump/restore)."""
    # before mkstemp: raises without leaking a file
    ssl_lines = _ssl_options(ssl_mode, ssl_ca, mariadb)
    fd, path = tempfile.mkstemp(prefix="mbsdr-my-", suffix=".cnf")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("[client]\n")
            fh.write(f"host={parts['host']}\n")
            fh.write(f"port={parts['port']}\n")
            if parts["user"]:
                fh.write(f"user={parts['user']}\n")
            if parts["password"]:
                fh.write(f"password={parts['password']}\n")
            for line in ssl_lines:
                fh.write(f"{line}\n")
        os.chmod(path, 0o600)
    except Exception:
        os.unlink(path)
        raise
    return path


def _run(cmd: list, *, stdin=None, stdout=None) -> None:
    """Run a mysqldump/mysql command and, on failure, raise BackupError CARRYING ITS STDERR
    (bare CalledProcessError only has the exit status; the actual reason is on stderr)."""
    proc = subprocess.run(cmd, stdin=stdin, stdout=stdout, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", "replace").strip() or "<no stderr>"
        raise BackupError(f"{Path(cmd[0]).name} failed (exit {proc.returncode}): {_redact(err)}")


class MySQLRunner:
    """Thin seam around mysqldump / mysql. Injected in tests with a fake that writes a
    synthetic dump, so no MySQL client is needed to exercise the DR flow."""

    def __init__(
        self,
        dump_cmd: str = "mysqldump",
        restore_cmd: str = "mysql",
        ssl_mode: str = SSL_MODE_REQUIRED,
        ssl_ca: str = "",
    ):
        self.dump_cmd = dump_cmd
        self.restore_cmd = restore_cmd
        self.ssl_mode = ssl_mode
        self.ssl_ca = ssl_ca
        self._family: dict[str, bool] = {}   # cmd -> is-MariaDB, memoized per instance

    def _is_mariadb(self, cmd: str) -> bool:
        if cmd not in self._family:
            self._family[cmd] = _is_mariadb_client(cmd)
        return self._family[cmd]

    def dump(self, database_url: str, out_path: Path) -> None:
        # Deliberately NOT --set-gtid-purged=OFF: that flag is MySQL-only (unrecognized by
        # MariaDB's mysqldump, "unknown variable", exit 7 -- verified empirically). Dropping it
        # keeps this portable across both; the cost is a possible `SET @@GLOBAL.GTID_PURGED=...`
        # line in the dump on a MySQL server with GTID mode on (off by default), which a plain
        # `mysql < dump` restore onto a differently-provisioned target could reject -- acceptable
        # for this restore-into-any-target design (mirrors mysqldump's own plain-text defaults).
        parts = _connect_parts(database_url)
        cnf = _write_defaults_file(parts, self.ssl_mode, self.ssl_ca, self._is_mariadb(self.dump_cmd))
        try:
            with open(out_path, "wb") as fh:
                _run(
                    [
                        self.dump_cmd,
                        f"--defaults-extra-file={cnf}",
                        "--single-transaction",
                        "--routines",
                        "--triggers",
                        parts["database"],
                    ],
                    stdout=fh,
                )
        finally:
            os.unlink(cnf)

    def restore(self, database_url: str, dump_path: Path) -> None:
        parts = _connect_parts(database_url)
        cnf = _write_defaults_file(parts, self.ssl_mode, self.ssl_ca, self._is_mariadb(self.restore_cmd))
        try:
            with open(dump_path, "rb") as fh:
                _run(
                    [self.restore_cmd, f"--defaults-extra-file={cnf}", parts["database"]],
                    stdin=fh,
                )
        finally:
            os.unlink(cnf)


def _has_dump_magic(fh) -> bool:
    head = fh.read(_MAGIC_SCAN_BYTES)
    return any(magic in head for magic in MYSQL_DUMP_MAGIC)


def backup_mysql(dest_dir, *, database_url: str, runner: MySQLRunner) -> dict:
    """Dump the database into dest_dir/db.sql and sanity-check the produced file.
    Raises BackupError if mysqldump yielded a missing/tiny/malformed file."""
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / DB_DUMP
    runner.dump(database_url, out)
    if not out.exists() or out.stat().st_size < 64:
        raise BackupError(f"mysqldump produced a missing/too-small dump: {out}")
    with open(out, "rb") as fh:
        if not _has_dump_magic(fh):
            raise BackupError("mysqldump output does not contain the expected header")
    return {"path": str(out), "bytes": out.stat().st_size}


def verify_mysql_archive(dump_path) -> bool:
    """Integrity/corruption check on a db.sql: it must exist, be non-trivial, and carry the
    mysqldump/mariadb-dump header near the top. (Checksum validation is layered on top in the
    service.)"""
    p = Path(dump_path)
    if not p.exists() or p.stat().st_size < 64:
        return False
    try:
        with open(p, "rb") as fh:
            return _has_dump_magic(fh)
    except OSError:
        return False


def restore_mysql(dump_path, *, database_url: str, runner: MySQLRunner) -> None:
    """Restore db.sql into the target database. Verifies the file exists first."""
    p = Path(dump_path)
    if not p.exists():
        raise BackupError(f"backup archive not found: {p}")
    runner.restore(database_url, p)
