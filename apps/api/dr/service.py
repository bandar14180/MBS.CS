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

def run_backup(settings, *, store=None, runner=None, offsite=None) -> BackupResult:
    """Create ONE timestamped backup set: pg dump + object archive + checksums + manifest,
    then (optionally) encrypt at rest, verify it, replicate off-site, and run retention cleanup.
    Never overwrites (unique TS). Component failures are captured in the manifest and metrics
    without aborting the rest. Encryption (DR-2) and off-site replication (DR-3) are opt-in and
    default OFF, so a disabled deployment behaves exactly as before."""
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

    # DR-2: encrypt the data artifacts at rest (in place) BEFORE the manifest is written, so the
    # manifest records the encryption state and verify/restore can detect it. Only on a clean set
    # (a partially-failed set is already marked failed and is not encrypted). Re-checksum over the
    # ciphertext so the sidecar validates the bytes actually stored on disk.
    if ok and getattr(settings, "backup_encryption_enabled", False):
        from apps.api.dr import crypto

        key = crypto.load_backup_key(settings)
        crypto.encrypt_file(set_dir / pg.DB_DUMP, key)
        _write_checksum(set_dir / pg.DB_DUMP)
        objs = manifest["components"].get("objects")
        if settings.backup_include_objects and objs and "error" not in objs:
            arc = obj.archive_path(set_dir)
            crypto.encrypt_file(arc, key)
            _write_checksum(arc)
        manifest["encryption"] = {"enabled": True, "alg": "AES-256-GCM"}

    manifest["status"] = "completed" if ok else "failed"
    (set_dir / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    # 3) Verify (does not touch production data)
    if ok and settings.backup_verification_enabled:
        ok = verify_backup(set_dir, settings=settings)

    duration = time.monotonic() - started
    m.record_backup("full", success=ok, duration_s=duration)
    # F4 / DR-4: reliability signals exposed via the API /metrics ReliabilityCollector (best-effort).
    from apps.api.core.observability import record_backup_failure, record_backup_success

    if ok:
        record_backup_success()  # DR-4: stamps last-success time -> mbs_backup_age_seconds
    else:
        record_backup_failure()
        # E4: best-effort email alert on backup failure (never raises; gated OFF unless enabled).
        try:
            from apps.api.modules.notifications.alerts import email_system_alert

            email_system_alert(
                "backup_failed", "Backup run failed",
                "A scheduled backup run did not complete successfully. See the DR runbook "
                "(docs/runbooks/disaster-recovery.md) to investigate.",
            )
        except Exception:  # noqa: BLE001
            pass
    m.logger.info(
        "backup.completed set=%s ok=%s duration=%.2fs", set_dir.name, ok, duration,
        extra={"event": "backup.completed" if ok else "backup.failed", "set": set_dir.name,
               "status": manifest["status"], "duration_s": round(duration, 2)},
    )

    # 4) DR-3: off-site replication of the verified set (best-effort; a failure here never fails
    # the backup itself -- the local set is already good). Opt-in and default OFF.
    if ok and getattr(settings, "backup_offsite_enabled", False):
        _replicate_offsite(settings, set_dir, offsite)

    # 5) Retention cleanup (never removes the newest / last good set)
    cleanup_old_backups(settings)
    return BackupResult(set_dir, ok, manifest)


def _replicate_offsite(settings, set_dir, offsite=None) -> None:
    """DR-3 helper: push a completed set to the configured off-site target. Best-effort --
    records a metric + structured log and swallows the error so replication trouble never
    aborts an otherwise-good backup."""
    try:
        if offsite is None:
            from apps.api.dr.offsite import get_offsite_target

            offsite = get_offsite_target(settings)
        count = offsite.replicate_set(set_dir)
        m.record_offsite(success=True)
        m.logger.info(
            "offsite.completed set=%s files=%d", set_dir.name, count,
            extra={"event": "offsite.completed", "set": set_dir.name, "files": count},
        )
    except Exception as exc:  # noqa: BLE001 -- off-site is best-effort, never fatal to the backup
        m.record_offsite(success=False)
        m.logger.error(
            "offsite.failed set=%s", set_dir.name,
            extra={"event": "offsite.failed", "set": set_dir.name, "reason": type(exc).__name__},
            exc_info=True,
        )


# --- Verification -------------------------------------------------------------------------

def _backup_key(settings):
    """Load the backup encryption key (DR-2). Falls back to get_settings() when a caller (e.g. a
    test invoking verify_backup directly) didn't pass settings."""
    from apps.api.core.config import get_settings
    from apps.api.dr import crypto

    return crypto.load_backup_key(settings or get_settings())


def _decrypt_objects_view(set_dir, key):
    """Materialize a DECRYPTED, plaintext view of the objects component (archive + metadata) in a
    fresh temp dir, so the existing obj.* functions operate unchanged. Returns the temp dir, or
    None if decryption fails (wrong key / corruption). Caller removes the dir."""
    import tempfile

    from apps.api.dr import crypto

    set_dir = Path(set_dir)
    arc = obj.archive_path(set_dir)
    man = set_dir / obj.OBJECTS_MANIFEST
    try:
        data = crypto.decrypt_bytes(arc.read_bytes(), key)
    except crypto.DecryptionError:
        return None
    view = Path(tempfile.mkdtemp(prefix="mbsdr-obj-"))
    (view / arc.name).write_bytes(data)
    if man.exists():
        shutil.copy2(man, view / obj.OBJECTS_MANIFEST)
    return view


def _verify_postgres_component(set_dir, encrypted, key) -> bool:
    dump = set_dir / pg.DB_DUMP
    if not _checksum_matches(dump):  # at-rest integrity of the bytes actually stored
        return False
    if not encrypted:
        return pg.verify_postgres_archive(dump)
    from apps.api.dr import crypto

    try:
        tmp = crypto.decrypt_to_temp(dump, key)  # fails closed on wrong key / corruption
    except crypto.DecryptionError:
        return False
    try:
        return pg.verify_postgres_archive(tmp)
    finally:
        tmp.unlink(missing_ok=True)


def _verify_objects_component(set_dir, encrypted, key) -> bool:
    if not _checksum_matches(obj.archive_path(set_dir)):
        return False
    if not encrypted:
        return obj.verify_objects_archive(set_dir)
    view = _decrypt_objects_view(set_dir, key)
    if view is None:
        return False
    try:
        return obj.verify_objects_archive(view)
    finally:
        shutil.rmtree(view, ignore_errors=True)


def verify_backup(set_dir, *, settings=None) -> bool:
    """Integrity-check a backup set WITHOUT touching production data: manifest present,
    each component's archive readable + magic/tar valid + checksum matches. DR-2: an encrypted
    set (manifest.encryption.enabled) is decrypted to a temp view for the structural check while
    the on-disk (ciphertext) checksum still proves at-rest integrity; a wrong key fails closed."""
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
    encrypted = bool(manifest.get("encryption", {}).get("enabled"))
    key = _backup_key(settings) if encrypted else None
    ok = True

    if "postgres" in comps and "error" not in comps["postgres"]:
        db_ok = _verify_postgres_component(set_dir, encrypted, key)
        m.record_verification("postgres", success=db_ok)
        ok = ok and db_ok

    if "objects" in comps and "error" not in comps["objects"]:
        o_ok = _verify_objects_component(set_dir, encrypted, key)
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

    if settings.backup_verification_enabled and not verify_backup(set_dir, settings=settings):
        m.record_restore("full", success=False)
        m.logger.error(
            "restore.failed set=%s reason=verification_failed", set_dir.name,
            extra={"event": "restore.failed", "set": set_dir.name, "reason": "verification_failed"},
        )
        return False

    manifest = json.loads((set_dir / MANIFEST).read_text(encoding="utf-8"))
    encrypted = bool(manifest.get("encryption", {}).get("enabled"))  # DR-2
    key = _backup_key(settings) if encrypted else None

    ok = True
    runner = runner or pg.PgRunner(settings.backup_pg_dump_cmd, settings.backup_pg_restore_cmd)
    try:
        dump = set_dir / pg.DB_DUMP
        if encrypted:
            from apps.api.dr import crypto

            tmp = crypto.decrypt_to_temp(dump, key)  # DecryptionError -> caught below (fail closed)
            try:
                pg.restore_postgres(tmp, database_url=target_database_url or settings.database_url, runner=runner)
            finally:
                tmp.unlink(missing_ok=True)
        else:
            pg.restore_postgres(dump, database_url=target_database_url or settings.database_url, runner=runner)
        m.record_restore("postgres", success=True)
    except Exception as exc:  # noqa: BLE001
        ok = False
        m.record_restore("postgres", success=False)
        m.logger.error(
            "restore.failed component=postgres set=%s error=%s", set_dir.name, exc,
            extra={"event": "restore.failed", "component": "postgres", "set": set_dir.name,
                   "reason": type(exc).__name__, "error": str(exc)},
            exc_info=True,
        )

    if include_objects and settings.backup_include_objects:
        try:
            store = store or obj.BotoObjectStore(settings)
            if encrypted:
                view = _decrypt_objects_view(set_dir, key)
                if view is None:
                    raise pg.BackupError("objects decryption failed (wrong key or corruption)")
                try:
                    obj.restore_objects(view, store)
                finally:
                    shutil.rmtree(view, ignore_errors=True)
            else:
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

DRILLS_SUBDIR = "drills"  # DR-4: evidence artifacts live here; never treated as a backup set


def list_backup_sets(settings) -> list[Path]:
    """All backup sets, oldest -> newest (timestamp names sort chronologically). The DR-4 drills
    evidence directory is excluded so it is never mistaken for (or pruned as) a backup set."""
    root = Path(settings.backup_directory)
    if not root.exists():
        return []
    return sorted(
        (d for d in root.iterdir() if d.is_dir() and d.name != DRILLS_SUBDIR),
        key=lambda p: p.name,
    )


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


# --- DR-4: manual restore drill + recovery evidence ----------------------------------------

@dataclass
class DrillReport:
    set_name: str
    verified: bool
    restored: bool
    checks: dict
    ok: bool
    report_path: str | None


def latest_backup_set(settings):
    """Newest backup set, or None if there are none."""
    sets = list_backup_sets(settings)
    return sets[-1] if sets else None


def _same_database(a: str, b: str) -> bool:
    """True if two DB URLs point at the same database (ignoring the SQLAlchemy driver tag)."""
    return pg.pg_uri(a or "") == pg.pg_uri(b or "")


def default_smoke_checks(target_database_url: str) -> dict:
    """Post-restore smoke checks proving the restored DB is real and policy-complete. Runs
    synchronously via psycopg2 (already a dependency) against the SCRATCH target. Best-effort:
    any error is reported as a failed check rather than raising, so the drill still yields
    evidence. Never connects to anything but the caller-provided scratch URL."""
    checks = {"connect": False, "has_tables": False, "rls_policies_present": False, "force_rls_present": False}
    try:
        import psycopg2

        conn = psycopg2.connect(pg.pg_uri(target_database_url))
        try:
            conn.autocommit = True
            cur = conn.cursor()
            cur.execute("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
            checks["connect"] = True
            checks["has_tables"] = (cur.fetchone()[0] or 0) > 0
            cur.execute("SELECT count(*) FROM pg_policies")
            checks["rls_policies_present"] = (cur.fetchone()[0] or 0) > 0
            cur.execute("SELECT count(*) FROM pg_class WHERE relkind='r' AND relforcerowsecurity")
            checks["force_rls_present"] = (cur.fetchone()[0] or 0) > 0
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 -- record as failed checks; never abort the drill
        m.logger.warning("drill.smoke_error", extra={"event": "drill.smoke_error"}, exc_info=True)
    return checks


def run_drill(settings, *, set_dir=None, target_database_url=None, store=None, runner=None,
              smoke=default_smoke_checks, include_objects=False) -> DrillReport:
    """DR-4: prove recoverability. Restore the latest (or given) VERIFIED set into a SCRATCH
    database, run smoke checks, and write a JSON evidence artifact under <BACKUP_DIRECTORY>/drills.
    Manual only -- never scheduled here. SAFETY: refuses to run without a scratch target and
    refuses a target equal to the live DATABASE_URL, so a drill can never overwrite production."""
    sd = Path(set_dir) if set_dir else latest_backup_set(settings)
    if sd is None:
        raise RuntimeError("no backup set available to drill")

    target = target_database_url or getattr(settings, "backup_drill_database_url", "") or ""
    if not target:
        raise RuntimeError(
            "DR drill requires a scratch target DB (BACKUP_DRILL_DATABASE_URL or --target-db-url); "
            "refusing to touch the live database"
        )
    if _same_database(target, settings.database_url):
        raise RuntimeError("DR drill target must NOT be the live DATABASE_URL")

    m.logger.info("drill.started set=%s", sd.name, extra={"event": "drill.started", "set": sd.name})
    verified = verify_backup(sd, settings=settings)
    restored = False
    if verified:
        restored = run_restore(
            settings, sd, target_database_url=target, store=store, runner=runner,
            include_objects=include_objects,
        )
    checks = smoke(target) if (restored and smoke is not None) else {}
    ok = verified and restored and (all(checks.values()) if checks else True)

    report = {
        "timestamp": _now_ts(), "set": sd.name, "verified": verified,
        "restored": restored, "checks": checks, "ok": ok,
    }
    drills_dir = Path(settings.backup_directory) / DRILLS_SUBDIR
    drills_dir.mkdir(parents=True, exist_ok=True)
    report_path = drills_dir / f"drill-{report['timestamp']}.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    m.record_drill(success=ok)
    m.logger.info(
        "drill.completed set=%s ok=%s", sd.name, ok,
        extra={"event": "drill.completed", "set": sd.name, "ok": ok, "report": str(report_path)},
    )
    return DrillReport(sd.name, verified, restored, checks, ok, str(report_path))
