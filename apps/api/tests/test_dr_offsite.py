"""DR-3 -- off-site backup replication (provider-agnostic).

Proves the injectable target contract, the local-directory provider, the factory selection, and
that run_backup replicates a verified set best-effort (a replication failure never fails the
backup itself).
"""
from pathlib import Path
from types import SimpleNamespace

import pytest

from apps.api.dr.offsite import LocalOffsiteTarget, get_offsite_target
from apps.api.dr.service import run_backup
from apps.api.tests.test_dr_backup import FakeMySQLRunner, _sample_store


def _settings(tmp_path, **over):
    base = dict(
        backup_directory=str(tmp_path / "backups"),
        database_url="mysql+aiomysql://mbs:mbs@mysql:3306/mbs",
        backup_mysqldump_cmd="mysqldump",
        backup_mysql_cmd="mysql",
        backup_include_objects=True,
        backup_compression=True,
        backup_verification_enabled=True,
        backup_min_keep=3,
        backup_retention_days=7,
        backup_encryption_enabled=False,
        backup_offsite_enabled=True,
    )
    base.update(over)
    return SimpleNamespace(**base)


class FakeOffsite:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls: list[Path] = []

    def replicate_set(self, set_dir) -> int:
        if self.fail:
            raise RuntimeError("offsite unreachable")
        self.calls.append(Path(set_dir))
        return 3


# --- local provider ------------------------------------------------------------------------

def test_local_offsite_copies_every_file(tmp_path):
    src = tmp_path / "20260101T000000Z"
    src.mkdir(parents=True)
    (src / "db.sql").write_bytes(b"-- MySQL dump ...")
    (src / "MANIFEST.json").write_text("{}")
    dest_base = tmp_path / "offsite"

    n = LocalOffsiteTarget(str(dest_base)).replicate_set(src)
    assert n == 2
    copied = {p.name for p in (dest_base / src.name).iterdir()}
    assert copied == {"db.sql", "MANIFEST.json"}


def test_local_offsite_requires_base_dir():
    with pytest.raises(RuntimeError):
        LocalOffsiteTarget("")


# --- factory -------------------------------------------------------------------------------

def test_factory_selects_local(tmp_path):
    s = SimpleNamespace(backup_offsite_provider="local", backup_offsite_dir=str(tmp_path))
    assert isinstance(get_offsite_target(s), LocalOffsiteTarget)


def test_factory_rejects_unknown_provider():
    with pytest.raises(RuntimeError):
        get_offsite_target(SimpleNamespace(backup_offsite_provider="dropbox"))


# --- integration with run_backup -----------------------------------------------------------

def test_run_backup_replicates_verified_set(tmp_path):
    off = FakeOffsite()
    res = run_backup(_settings(tmp_path), store=_sample_store(), runner=FakeMySQLRunner(), offsite=off)
    assert res.ok is True
    assert off.calls == [res.set_dir]  # the verified set was replicated off-site


def test_offsite_failure_does_not_fail_backup(tmp_path):
    off = FakeOffsite(fail=True)
    res = run_backup(_settings(tmp_path), store=_sample_store(), runner=FakeMySQLRunner(), offsite=off)
    assert res.ok is True  # best-effort: replication failure never fails the backup
    assert (res.set_dir / "MANIFEST.json").exists()


def test_offsite_skipped_when_disabled(tmp_path):
    off = FakeOffsite()
    res = run_backup(_settings(tmp_path, backup_offsite_enabled=False),
                     store=_sample_store(), runner=FakeMySQLRunner(), offsite=off)
    assert res.ok is True
    assert off.calls == []  # disabled -> never called
