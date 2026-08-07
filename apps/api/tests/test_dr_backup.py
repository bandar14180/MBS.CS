"""Phase 1.6 -- backup & disaster recovery.

Exercises the full DR flow (backup / restore / verify / cleanup) via injectable seams --
a fake PgRunner that writes a synthetic PGDMP archive and an in-memory ObjectStore -- so no
postgres client or live MinIO is required. Covers success/failure, missing + corrupted
backups, retention policy, verification, metrics, structured logging, and config defaults.
"""
import json
import logging
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from apps.api.dr import metrics as m
from apps.api.dr.objects import ObjMeta
from apps.api.dr.service import (
    cleanup_old_backups,
    run_backup,
    run_restore,
    verify_backup,
)

VALID_DUMP = b"PGDMP" + b"\x00" * 200   # magic + non-trivial size


# --- fakes --------------------------------------------------------------------------------

class FakePgRunner:
    def __init__(self, *, fail_dump=False, fail_restore=False, body=VALID_DUMP):
        self.fail_dump = fail_dump
        self.fail_restore = fail_restore
        self.body = body
        self.restored: list[tuple[str, str]] = []

    def dump(self, database_url, out_path):
        if self.fail_dump:
            raise RuntimeError("pg_dump failed")
        Path(out_path).write_bytes(self.body)

    def restore(self, database_url, dump_path):
        if self.fail_restore:
            raise RuntimeError("pg_restore failed")
        self.restored.append((database_url, str(dump_path)))


class FakeObjectStore:
    def __init__(self):
        self._d: dict[str, dict[str, dict]] = {}

    def put(self, bucket, key, data, *, content_type=None, metadata=None):
        self._d.setdefault(bucket, {})[key] = {
            "data": data, "content_type": content_type, "metadata": metadata or {},
        }

    # ObjectStore protocol
    def buckets(self):
        return list(self._d.keys())

    def list_objects(self, bucket):
        for key, v in self._d.get(bucket, {}).items():
            yield ObjMeta(bucket, key, len(v["data"]), v["content_type"], dict(v["metadata"]))

    def read_object(self, bucket, key):
        return self._d[bucket][key]["data"]

    def ensure_bucket(self, bucket):
        self._d.setdefault(bucket, {})

    def write_object(self, bucket, key, data, meta):
        self._d.setdefault(bucket, {})[key] = {
            "data": data, "content_type": meta.content_type, "metadata": dict(meta.metadata),
        }


def _sample_store():
    fs = FakeObjectStore()
    fs.put("mbs-evidence", "scan1/out.txt", b"hello evidence",
           content_type="text/plain", metadata={"scan": "1"})
    fs.put("mbs-reports", "r1.pdf", b"%PDF-1.4 fake", content_type="application/pdf")
    return fs


def _settings(tmp_path, **over):
    base = dict(
        backup_directory=str(tmp_path / "backups"),
        database_url="postgresql+asyncpg://mbs:mbs@postgres:5432/mbs",
        backup_pg_dump_cmd="pg_dump",
        backup_pg_restore_cmd="pg_restore",
        backup_include_objects=True,
        backup_compression=True,
        backup_verification_enabled=True,
        backup_min_keep=3,
        backup_retention_days=7,
    )
    base.update(over)
    return SimpleNamespace(**base)


# --- backup -------------------------------------------------------------------------------

def test_successful_backup_creates_verified_set(tmp_path):
    res = run_backup(_settings(tmp_path), store=_sample_store(), runner=FakePgRunner())
    assert res.ok is True
    d = res.set_dir
    assert d.name[:8].isdigit()                       # timestamped set name
    assert (d / "db.dump").read_bytes().startswith(b"PGDMP")
    assert (d / "objects.tar.gz").exists() and (d / "objects.meta.json").exists()
    assert (d / "db.dump.sha256").exists() and (d / "objects.tar.gz.sha256").exists()
    man = json.loads((d / "MANIFEST.json").read_text(encoding="utf-8"))
    assert man["status"] == "completed"
    assert man["components"]["postgres"]["bytes"] >= 64
    assert man["components"]["objects"]["count"] == 2


def test_backup_never_overwrites_previous_sets(tmp_path):
    s = _settings(tmp_path)
    first = run_backup(s, store=_sample_store(), runner=FakePgRunner()).set_dir
    time.sleep(1.05)   # ensure a distinct second-resolution timestamp
    second = run_backup(s, store=_sample_store(), runner=FakePgRunner()).set_dir
    assert first != second and first.exists() and second.exists()


def test_failed_backup_records_failure(tmp_path):
    res = run_backup(_settings(tmp_path), store=_sample_store(), runner=FakePgRunner(fail_dump=True))
    assert res.ok is False
    man = json.loads((res.set_dir / "MANIFEST.json").read_text(encoding="utf-8"))
    assert man["status"] == "failed"
    assert "error" in man["components"]["postgres"]


# --- restore ------------------------------------------------------------------------------

def test_successful_restore_roundtrip_preserves_metadata(tmp_path):
    s = _settings(tmp_path)
    res = run_backup(s, store=_sample_store(), runner=FakePgRunner())
    assert res.ok
    target = FakeObjectStore()
    runner = FakePgRunner()
    ok = run_restore(s, res.set_dir, store=target, runner=runner, include_objects=True)
    assert ok is True
    assert runner.restored                             # pg_restore was invoked
    ev = target._d["mbs-evidence"]["scan1/out.txt"]
    assert ev["data"] == b"hello evidence"
    assert ev["content_type"] == "text/plain"          # metadata preserved
    assert ev["metadata"] == {"scan": "1"}


def test_restore_missing_backup_returns_false(tmp_path):
    ok = run_restore(_settings(tmp_path), tmp_path / "backups" / "nope", runner=FakePgRunner())
    assert ok is False


def test_restore_refuses_when_verification_fails(tmp_path):
    s = _settings(tmp_path)
    res = run_backup(s, store=_sample_store(), runner=FakePgRunner())
    (res.set_dir / "db.dump").write_bytes(b"PGDMP" + b"\xff" * 200)   # checksum now mismatches
    runner = FakePgRunner()
    ok = run_restore(s, res.set_dir, runner=runner, include_objects=False)
    assert ok is False and runner.restored == []       # never mutated the target


# --- corruption / verification ------------------------------------------------------------

def test_corrupted_db_dump_fails_verification(tmp_path):
    res = run_backup(_settings(tmp_path), store=_sample_store(), runner=FakePgRunner())
    (res.set_dir / "db.dump").write_bytes(b"PGDMP" + b"\x01" * 200)   # magic ok, checksum mismatch
    assert verify_backup(res.set_dir) is False


def test_corrupted_objects_archive_fails_verification(tmp_path):
    res = run_backup(_settings(tmp_path), store=_sample_store(), runner=FakePgRunner())
    (res.set_dir / "objects.tar.gz").write_bytes(b"not a gzip stream")
    assert verify_backup(res.set_dir) is False


def test_verification_good_set_and_missing_manifest(tmp_path):
    s = _settings(tmp_path)
    res = run_backup(s, store=_sample_store(), runner=FakePgRunner())
    assert verify_backup(res.set_dir) is True
    empty = Path(s.backup_directory) / "emptyset"
    empty.mkdir()
    assert verify_backup(empty) is False


# --- cleanup / retention ------------------------------------------------------------------

def _make_sets(root: Path, names, *, old_names=()):
    root.mkdir(parents=True, exist_ok=True)
    old = time.time() - 30 * 86400
    for n in names:
        p = root / n
        p.mkdir()
        (p / "MANIFEST.json").write_text("{}", encoding="utf-8")
        if n in old_names:
            os.utime(p, (old, old))


def test_cleanup_keeps_min_and_never_deletes_newest(tmp_path):
    s = _settings(tmp_path, backup_min_keep=2, backup_retention_days=7)
    root = Path(s.backup_directory)
    names = [f"2023010{i}T000000Z" for i in range(1, 6)]   # 5 sets, chronological
    _make_sets(root, names, old_names=names[:3])           # 3 oldest are past retention
    deleted = cleanup_old_backups(s)
    remaining = sorted(p.name for p in root.iterdir())
    assert set(deleted) == set(names[:3])                  # only old + beyond min_keep
    assert remaining == names[3:]                          # 2 newest kept
    assert names[-1] in remaining                          # newest never deleted


def test_cleanup_spares_recent_beyond_min_keep(tmp_path):
    s = _settings(tmp_path, backup_min_keep=1, backup_retention_days=7)
    root = Path(s.backup_directory)
    names = [f"2024020{i}T000000Z" for i in range(1, 5)]   # all recent (mtime = now)
    _make_sets(root, names)
    assert cleanup_old_backups(s) == []                    # none past retention despite min_keep=1


def test_cleanup_never_deletes_newest_even_if_all_old(tmp_path):
    s = _settings(tmp_path, backup_min_keep=1, backup_retention_days=1)
    root = Path(s.backup_directory)
    names = [f"2022010{i}T000000Z" for i in range(1, 4)]   # all old
    _make_sets(root, names, old_names=names)
    cleanup_old_backups(s)
    remaining = sorted(p.name for p in root.iterdir())
    assert names[-1] in remaining and len(remaining) >= 1


# --- metrics ------------------------------------------------------------------------------

def test_metrics_increment_and_are_low_cardinality(tmp_path):
    if not m._PROM:
        pytest.skip("prometheus_client not installed; metrics are no-ops")
    b0 = m.BACKUP_SUCCESS.labels("full")._value.get()
    v0 = m.VERIFICATION_SUCCESS.labels("full")._value.get()
    r0 = m.RESTORE_SUCCESS.labels("full")._value.get()
    s = _settings(tmp_path)
    res = run_backup(s, store=_sample_store(), runner=FakePgRunner())
    run_restore(s, res.set_dir, store=FakeObjectStore(), runner=FakePgRunner(), include_objects=True)
    assert m.BACKUP_SUCCESS.labels("full")._value.get() == b0 + 1
    assert m.VERIFICATION_SUCCESS.labels("full")._value.get() >= v0 + 1
    assert m.RESTORE_SUCCESS.labels("full")._value.get() == r0 + 1
    for counter in (m.BACKUP_SUCCESS, m.BACKUP_FAILED, m.BACKUP_DURATION,
                    m.RESTORE_SUCCESS, m.RESTORE_FAILED,
                    m.VERIFICATION_SUCCESS, m.VERIFICATION_FAILED):
        assert counter._labelnames == ("component",)   # never hostname/filename/workspace_id/scan_id


def test_failed_backup_increments_failure_metric(tmp_path):
    if not m._PROM:
        pytest.skip("prometheus_client not installed")
    f0 = m.BACKUP_FAILED.labels("postgres")._value.get()
    run_backup(_settings(tmp_path), store=_sample_store(), runner=FakePgRunner(fail_dump=True))
    assert m.BACKUP_FAILED.labels("postgres")._value.get() == f0 + 1


# --- structured logging -------------------------------------------------------------------

def test_backup_emits_structured_lifecycle_events(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="mbs.backup")
    run_backup(_settings(tmp_path), store=_sample_store(), runner=FakePgRunner())
    events = {getattr(r, "event", None) for r in caplog.records}
    assert {"backup.started", "backup.completed", "verification.completed"} <= events


def test_cleanup_emits_event(tmp_path, caplog):
    s = _settings(tmp_path, backup_min_keep=1, backup_retention_days=1)
    root = Path(s.backup_directory)
    names = [f"2021010{i}T000000Z" for i in range(1, 4)]
    _make_sets(root, names, old_names=names)
    caplog.set_level(logging.INFO, logger="mbs.backup")
    cleanup_old_backups(s)
    assert any(getattr(r, "event", None) == "cleanup.completed" for r in caplog.records)


# --- configuration + wiring ---------------------------------------------------------------

def test_configuration_defaults():
    from apps.api.core.config import Settings

    s = Settings()
    assert s.backup_enabled is False                 # opt-in
    assert s.backup_interval_seconds == 86400
    assert s.backup_retention_days == 7
    assert s.backup_min_keep == 3
    assert s.backup_directory == "/srv/backups"
    assert s.backup_verification_enabled is True


def test_backup_task_registered_and_not_scheduled_when_disabled():
    import apps.api.celery_app.tasks.backup_tasks  # noqa: F401 -- decorator registers backup.run
    from apps.api.celery_app.worker import celery_app

    # The worker process imports this via celery_app.include at startup; here we import it
    # explicitly to confirm the decorator registers the task.
    assert "backup.run" in celery_app.tasks
    # disabled by default -> no beat entry (no needless ticks)
    assert "scheduled-backup" not in celery_app.conf.beat_schedule


def test_scheduled_backup_task_is_noop_when_disabled():
    from apps.api.celery_app.tasks.backup_tasks import scheduled_backup_task

    assert scheduled_backup_task() == "disabled"
