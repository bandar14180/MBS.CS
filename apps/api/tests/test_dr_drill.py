"""DR-4 -- manual DR drill + recovery evidence.

Proves the drill restores a verified set into a SCRATCH DB, writes a JSON evidence artifact,
records pass/fail, and refuses to ever touch the live database.
"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from apps.api.dr.service import (
    list_backup_sets,
    run_backup,
    run_drill,
)
from apps.api.tests.test_dr_backup import FakeObjectStore, FakePgRunner, _sample_store

_LIVE = "postgresql+asyncpg://mbs:mbs@postgres:5432/mbs"
_SCRATCH = "postgresql+asyncpg://mbs:mbs@postgres:5432/mbs_restore"


def _settings(tmp_path, **over):
    base = dict(
        backup_directory=str(tmp_path / "backups"),
        database_url=_LIVE,
        backup_pg_dump_cmd="pg_dump",
        backup_pg_restore_cmd="pg_restore",
        backup_include_objects=True,
        backup_compression=True,
        backup_verification_enabled=True,
        backup_min_keep=3,
        backup_retention_days=7,
        backup_encryption_enabled=False,
        backup_offsite_enabled=False,
        backup_drill_database_url="",
    )
    base.update(over)
    return SimpleNamespace(**base)


def _make_set(s):
    return run_backup(s, store=_sample_store(), runner=FakePgRunner()).set_dir


def _pass_smoke(_target):
    return {"connect": True, "has_tables": True, "rls_policies_present": True, "force_rls_present": True}


def test_drill_restores_into_scratch_and_writes_evidence(tmp_path):
    s = _settings(tmp_path)
    _make_set(s)
    report = run_drill(s, target_database_url=_SCRATCH, store=FakeObjectStore(),
                       runner=FakePgRunner(), smoke=_pass_smoke)
    assert report.verified and report.restored and report.ok is True
    # evidence artifact exists on disk and matches the returned report
    artifact = Path(report.report_path)
    assert artifact.exists() and artifact.parent.name == "drills"
    data = json.loads(artifact.read_text(encoding="utf-8"))
    assert data["ok"] is True and data["set"] == report.set_name and data["checks"]["connect"]


def test_drill_uses_latest_set_when_unspecified(tmp_path):
    s = _settings(tmp_path)
    import time

    _make_set(s)
    time.sleep(1.05)  # distinct second-resolution timestamp
    newest = _make_set(s)
    report = run_drill(s, target_database_url=_SCRATCH, store=FakeObjectStore(),
                       runner=FakePgRunner(), smoke=_pass_smoke)
    assert report.set_name == newest.name


def test_drill_refuses_without_target(tmp_path):
    s = _settings(tmp_path)
    _make_set(s)
    with pytest.raises(RuntimeError, match="scratch target"):
        run_drill(s, store=FakeObjectStore(), runner=FakePgRunner(), smoke=_pass_smoke)


def test_drill_refuses_live_database(tmp_path):
    s = _settings(tmp_path)
    _make_set(s)
    with pytest.raises(RuntimeError, match="live"):
        run_drill(s, target_database_url=_LIVE, store=FakeObjectStore(),
                  runner=FakePgRunner(), smoke=_pass_smoke)


def test_drill_marks_failure_when_smoke_fails(tmp_path):
    s = _settings(tmp_path)
    _make_set(s)
    report = run_drill(s, target_database_url=_SCRATCH, store=FakeObjectStore(),
                       runner=FakePgRunner(), smoke=lambda _t: {"connect": True, "has_tables": False})
    assert report.restored is True and report.ok is False  # a failing check fails the drill


def test_drill_uses_configured_scratch_url(tmp_path):
    s = _settings(tmp_path, backup_drill_database_url=_SCRATCH)
    _make_set(s)
    report = run_drill(s, store=FakeObjectStore(), runner=FakePgRunner(), smoke=_pass_smoke)
    assert report.ok is True


def test_drills_dir_not_treated_as_backup_set(tmp_path):
    s = _settings(tmp_path)
    _make_set(s)
    run_drill(s, target_database_url=_SCRATCH, store=FakeObjectStore(),
              runner=FakePgRunner(), smoke=_pass_smoke)
    # exactly one backup set; the drills/ evidence dir is excluded from set enumeration
    sets = list_backup_sets(s)
    assert len(sets) == 1 and all(p.name != "drills" for p in sets)
