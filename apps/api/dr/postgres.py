"""Phase 1.6 -- PostgreSQL backup / restore / verify for the DR system.

Uses pg_dump custom format (-Fc): compressed, supports selective/parallel restore, and
carries a 'PGDMP' magic header used here for cheap integrity + corruption detection. The
external pg commands run through an injectable `PgRunner` seam, so the surrounding logic
(naming, integrity checks, error paths) is unit-testable without the postgres client.
"""
import subprocess
from pathlib import Path

PG_MAGIC = b"PGDMP"   # custom-format archive header (pg_dump -Fc)
DB_DUMP = "db.dump"


class BackupError(Exception):
    """A backup/restore step failed in a way that must abort that component."""


def pg_uri(database_url: str) -> str:
    """Convert the app's SQLAlchemy async URL to a libpq URI pg_dump/pg_restore accept
    (strip the +asyncpg / +psycopg driver tag). Credentials stay inside the URI, never on
    argv beyond what libpq itself needs; nothing here is logged."""
    return database_url.replace("+asyncpg", "").replace("+psycopg2", "").replace("+psycopg", "")


class PgRunner:
    """Thin seam around pg_dump / pg_restore. Injected in tests with a fake that writes a
    synthetic archive, so no postgres client is needed to exercise the DR flow."""

    def __init__(self, dump_cmd: str = "pg_dump", restore_cmd: str = "pg_restore"):
        self.dump_cmd = dump_cmd
        self.restore_cmd = restore_cmd

    def dump(self, database_url: str, out_path: Path) -> None:
        with open(out_path, "wb") as fh:
            subprocess.run(
                [self.dump_cmd, "-Fc", "-d", pg_uri(database_url)],
                stdout=fh, stderr=subprocess.PIPE, check=True,
            )

    def restore(self, database_url: str, dump_path: Path) -> None:
        subprocess.run(
            [self.restore_cmd, "--no-owner", "--no-privileges", "-d", pg_uri(database_url), str(dump_path)],
            stderr=subprocess.PIPE, check=True,
        )


def backup_postgres(dest_dir, *, database_url: str, runner: PgRunner) -> dict:
    """Dump the database into dest_dir/db.dump and sanity-check the produced archive.
    Raises BackupError if pg_dump yielded a missing/tiny/non-custom-format file."""
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / DB_DUMP
    runner.dump(database_url, out)
    if not out.exists() or out.stat().st_size < 64:
        raise BackupError(f"pg_dump produced a missing/too-small archive: {out}")
    with open(out, "rb") as fh:
        if fh.read(len(PG_MAGIC)) != PG_MAGIC:
            raise BackupError("pg_dump output is not a valid custom-format (PGDMP) archive")
    return {"path": str(out), "bytes": out.stat().st_size}


def verify_postgres_archive(dump_path) -> bool:
    """Integrity/corruption check on a db.dump: it must exist, be non-trivial, and start
    with the PGDMP magic. (Checksum validation is layered on top in the service.)"""
    p = Path(dump_path)
    if not p.exists() or p.stat().st_size < 64:
        return False
    try:
        with open(p, "rb") as fh:
            return fh.read(len(PG_MAGIC)) == PG_MAGIC
    except OSError:
        return False


def restore_postgres(dump_path, *, database_url: str, runner: PgRunner) -> None:
    """Restore db.dump into the target database. Verifies the archive exists first."""
    p = Path(dump_path)
    if not p.exists():
        raise BackupError(f"backup archive not found: {p}")
    runner.restore(database_url, p)
