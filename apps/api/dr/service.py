"""Phase 1.6 -- disaster-recovery orchestration.

Ties the postgres + objects components together with checksums, a set-level MANIFEST.json,
age-based retention that ALWAYS keeps >= min_keep newest sets and never the newest, metrics,
and structured logging. Pure-Python around injectable seams -> fully testable.
"""
import hashlib
import json
import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from apps.api.dr import metrics as m
from apps.api.dr import objects as obj
from apps.api.dr import postgres as pg

MANIFEST = "MANIFEST.json"
_CHUNK = 1 << 20


@dataclass
class BackupResult:
    set_dir: Path
    ok: bool
    manifest: dict


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _sidecar(path: Path) -> Path:
    return Path(str(path) + ".sha256")


def _write_checksum(path: Path) -> str:
    digest = _sha256(path)
    _sidecar(path).write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return digest


def _checksum_matches(path: Path) -> bool:
    """True if there is no sidecar (checksum optional) OR the recomputed digest matches.
    A present-but-mismatching checksum -> False (corruption detected)."""
    side = _sidecar(path)
    if not side.exists():
        return True
    want = side.read_text(encoding="utf-8").split()
    return bool(want) and want[0] == _sha256(path)


# --- Backup -------------------------------------------------------------------------------

def run_backup(settings, *, store=None, runner=None) -> BackupResult:
    """Create ONE timestamped backup set: pg dump + object archive + checksums + manifest,
    then (optionally) verify it and run retention cleanup. Never overwrites (unique TS).
    Component failures are captured in the manifest and metrics without aborting the rest."""
    started = time.monotonic()
    set_dir = Path(settings.backup_directory) / _now_ts()
    set_dir.mkdir(parents=True, exist_ok=True)
    m.logger.info(
        "backup.started set=%s", set_dir.name,
        extra={"event": "backup.started", "set": set_dir.name, "path": str(set_dir)},
    )

    manifest: dict = {"timestamp": set_dir.name, "components": {}, "status": "in_progress"}
    ok = True
    runner = runner or pg.PgRunner(settings.backup_pg_dump_cmd, settings.backup_pg_restore_cmd)

    # 1) PostgreSQL
    t0 = time.monotonic()
    try:
        info = pg.backup_postgres(set_dir, database_url=settings.database_url, runner=runner)
        info["sha256"] = _write_checksum(set_dir / pg.DB_DUMP)
        manifest["components"]["postgres"] = info
        m.record_backup("postgres", success=True, duration_s=time.monotonic() - t0)
    except Exception as exc:  # noqa: BLE001
        ok = False
        manifest["components"]["postgres"] = {"error": str(exc)[:500]}
        m.record_backup("postgres", success=False, duration_s=time.monotonic() - t0)
        m.logger.error(
            "backup.failed component=postgres set=%s", set_dir.name,
            extra={"event": "backup.failed", "component": "postgres", "set": set_dir.name,
                   "reason": type(exc).__name__},
            exc_info=True,
        )

    # 2) Object storage
    if settings.backup_include_objects:
        t1 = time.monotonic()
        try:
            store = store or obj.BotoObjectStore(settings)
            oinfo = obj.backup_objects(set_dir, store, compress=settings.backup_compression)
            oinfo["sha256"] = _write_checksum(obj.archive_path(set_dir))
            manifest["components"]["objects"] = oinfo
            m.record_backup("objects", success=True, duration_s=time.monotonic() - t1)
        except Exception as exc:  # noqa: BLE001
            ok = False
            manifest["components"]["objects"] = {"error": str(exc)[:500]}
            m.record_backup("objects", success=False, duration_s=time.monotonic() - t1)
            m.logger.error(
                "backup.failed component=objects set=%s", set_dir.name,
                extra={"event": "backup.failed", "component": "objects", "set": set_dir.name,
                       "reason": type(exc).__name__},
                exc_info=True,
            )

    manifest["status"] = "completed" if ok else "failed"
    (set_dir / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    # 3) Verify (does not touch production data)
    if ok and settings.backup_verification_enabled:
        ok = verify_backup(set_dir)

    duration = time.monotonic() - started
    m.record_backup("full", success=ok, duration_s=duration)
    m.logger.info(
        "backup.completed set=%s ok=%s duration=%.2fs", set_dir.name, ok, duration,
        extra={"event": "backup.completed" if ok else "backup.failed", "set": set_dir.name,
               "status": manifest["status"], "duration_s": round(duration, 2)},
    )

    # 4) Retention cleanup (never removes the newest / last good set)
    cleanup_old_backups(settings)
    return BackupResult(set_dir, ok, manifest)


# --- Verification -------------------------------------------------------------------------

def verify_backup(set_dir) -> bool:
    """Integrity-check a backup set WITHOUT touching production data: manifest present,
    each component's archive readable + magic/tar valid + checksum matches."""
    set_dir = Path(set_dir)
    manifest_path = set_dir / MANIFEST
    if not manifest_path.exists():
        m.record_verification("full", success=False)
        m.logger.warning(
            "verification.completed set=%s ok=False (manifest missing)", set_dir.name,
            extra={"event": "verification.completed", "set": set_dir.name, "ok": False},
        )
        return False

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    comps = manifest.get("components", {})
    ok = True

    if "postgres" in comps and "error" not in comps["postgres"]:
        dump = set_dir / pg.DB_DUMP
        db_ok = pg.verify_postgres_archive(dump) and _checksum_matches(dump)
        m.record_verification("postgres", success=db_ok)
        ok = ok and db_ok

    if "objects" in comps and "error" not in comps["objects"]:
        o_ok = obj.verify_objects_archive(set_dir) and _checksum_matches(obj.archive_path(set_dir))
        m.record_verification("objects", success=o_ok)
        ok = ok and o_ok

    m.record_verification("full", success=ok)
    m.logger.info(
        "verification.completed set=%s ok=%s", set_dir.name, ok,
        extra={"event": "verification.completed", "set": set_dir.name, "ok": ok},
    )
    return ok


# --- Restore ------------------------------------------------------------------------------

def run_restore(settings, set_dir, *, target_database_url=None, store=None, runner=None,
                include_objects=False) -> bool:
    """Restore a backup set. Verifies the set exists and (if enabled) passes verification
    BEFORE mutating anything, restores PostgreSQL (and optionally objects), logs, and
    returns True/False (the CLI maps this to an exit code)."""
    set_dir = Path(set_dir)
    m.logger.info(
        "restore.started set=%s", set_dir.name,
        extra={"event": "restore.started", "set": set_dir.name},
    )

    if not set_dir.exists() or not (set_dir / MANIFEST).exists():
        m.record_restore("full", success=False)
        m.logger.error(
            "restore.failed set=%s reason=missing_backup", set_dir.name,
            extra={"event": "restore.failed", "set": set_dir.name, "reason": "missing_backup"},
        )
        return False

    if settings.backup_verification_enabled and not verify_backup(set_dir):
        m.record_restore("full", success=False)
        m.logger.error(
            "restore.failed set=%s reason=verification_failed", set_dir.name,
            extra={"event": "restore.failed", "set": set_dir.name, "reason": "verification_failed"},
        )
        return False

    ok = True
    runner = runner or pg.PgRunner(settings.backup_pg_dump_cmd, settings.backup_pg_restore_cmd)
    try:
        pg.restore_postgres(
            set_dir / pg.DB_DUMP,
            database_url=target_database_url or settings.database_url,
            runner=runner,
        )
        m.record_restore("postgres", success=True)
    except Exception as exc:  # noqa: BLE001
        ok = False
        m.record_restore("postgres", success=False)
        m.logger.error(
            "restore.failed component=postgres set=%s", set_dir.name,
            extra={"event": "restore.failed", "component": "postgres", "set": set_dir.name,
                   "reason": type(exc).__name__},
            exc_info=True,
        )

    if include_objects and settings.backup_include_objects:
        try:
            store = store or obj.BotoObjectStore(settings)
            obj.restore_objects(set_dir, store)
            m.record_restore("objects", success=True)
        except Exception as exc:  # noqa: BLE001
            ok = False
            m.record_restore("objects", success=False)
            m.logger.error(
                "restore.failed component=objects set=%s", set_dir.name,
                extra={"event": "restore.failed", "component": "objects", "set": set_dir.name,
                       "reason": type(exc).__name__},
                exc_info=True,
            )

    m.record_restore("full", success=ok)
    m.logger.info(
        "restore.completed set=%s ok=%s", set_dir.name, ok,
        extra={"event": "restore.completed" if ok else "restore.failed", "set": set_dir.name, "ok": ok},
    )
    return ok


# --- Cleanup / retention ------------------------------------------------------------------

def list_backup_sets(settings) -> list[Path]:
    """All backup sets, oldest -> newest (timestamp names sort chronologically)."""
    root = Path(settings.backup_directory)
    if not root.exists():
        return []
    return sorted((d for d in root.iterdir() if d.is_dir()), key=lambda p: p.name)


def cleanup_old_backups(settings) -> list[str]:
    """Delete sets older than retention_days, but ALWAYS keep the newest max(min_keep, 1)
    sets -- so the newest set is never deleted and a burst of failures can't erase the last
    good backup. Returns the names deleted."""
    sets = list_backup_sets(settings)
    keep = max(int(settings.backup_min_keep), 1)   # never let min_keep drop below the newest
    if len(sets) <= keep:
        return []
    candidates = sets[:-keep]                       # everything except the newest `keep`
    cutoff = time.time() - int(settings.backup_retention_days) * 86400
    deleted: list[str] = []
    for d in candidates:
        if d.stat().st_mtime < cutoff:
            shutil.rmtree(d, ignore_errors=True)
            deleted.append(d.name)
    if deleted:
        m.logger.info(
            "cleanup.completed deleted=%d kept=%d", len(deleted), len(sets) - len(deleted),
            extra={"event": "cleanup.completed", "deleted_count": len(deleted),
                   "kept_count": len(sets) - len(deleted), "retention_days": settings.backup_retention_days},
        )
    return deleted
