"""DR-2 -- backup encryption at rest (AES-256-GCM).

Reuses the Phase 1.6 injectable fakes (no MySQL client/MinIO needed). Proves: an enabled backup
writes ciphertext with the MBS magic header, verifies + restores round-trip, a WRONG key fails
closed, and disabling encryption preserves the exact prior (plaintext) behavior.
"""
from types import SimpleNamespace

import pytest

from apps.api.dr import crypto
from apps.api.dr.crypto import MAGIC, DecryptionError
from apps.api.dr.service import run_backup, run_restore, verify_backup
from apps.api.tests.test_dr_backup import FakeObjectStore, FakeMySQLRunner, _sample_store


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
        backup_encryption_enabled=True,
        backup_encryption_key="unit-test-master-key",
        backup_offsite_enabled=False,
    )
    base.update(over)
    return SimpleNamespace(**base)


# --- crypto unit ---------------------------------------------------------------------------

def test_encrypt_decrypt_file_roundtrip(tmp_path):
    key = crypto.derive_key("k")
    p = tmp_path / "a.bin"
    p.write_bytes(b"mysqldump secret payload")
    crypto.encrypt_file(p, key)
    assert p.read_bytes().startswith(MAGIC)  # in-place ciphertext
    assert crypto.is_encrypted(p)
    assert crypto.decrypt_bytes(p.read_bytes(), key) == b"mysqldump secret payload"


def test_wrong_key_raises_decryption_error(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"top secret")
    crypto.encrypt_file(p, crypto.derive_key("right"))
    with pytest.raises(DecryptionError):
        crypto.decrypt_bytes(p.read_bytes(), crypto.derive_key("wrong"))


def test_encrypt_file_is_idempotent(tmp_path):
    key = crypto.derive_key("k")
    p = tmp_path / "a.bin"
    p.write_bytes(b"data")
    crypto.encrypt_file(p, key)
    first = p.read_bytes()
    crypto.encrypt_file(p, key)  # second call must not double-encrypt
    assert p.read_bytes() == first
    assert crypto.decrypt_bytes(p.read_bytes(), key) == b"data"


# --- end-to-end ----------------------------------------------------------------------------

def test_encrypted_backup_writes_ciphertext_and_verifies(tmp_path):
    s = _settings(tmp_path)
    res = run_backup(s, store=_sample_store(), runner=FakeMySQLRunner())
    assert res.ok is True
    d = res.set_dir
    dump = (d / "db.sql").read_bytes()
    assert dump.startswith(MAGIC) and not dump.startswith(b"-- MySQL dump")  # encrypted, not plaintext
    assert (d / "objects.tar.gz").read_bytes().startswith(MAGIC)
    assert res.manifest["encryption"] == {"enabled": True, "alg": "AES-256-GCM"}
    # verification decrypts to a temp view and passes with the right key.
    assert verify_backup(d, settings=s) is True


def test_encrypted_restore_roundtrip_preserves_objects(tmp_path):
    s = _settings(tmp_path)
    res = run_backup(s, store=_sample_store(), runner=FakeMySQLRunner())
    target_store = FakeObjectStore()
    runner = FakeMySQLRunner()
    ok = run_restore(s, res.set_dir, store=target_store, runner=runner, include_objects=True)
    assert ok is True
    assert runner.restored, "mysql restore should have run against a decrypted temp dump"
    # objects decrypted + re-uploaded faithfully
    assert target_store.read_object("mbs-evidence", "scan1/out.txt") == b"hello evidence"
    assert target_store.read_object("mbs-reports", "r1.pdf") == b"%PDF-1.4 fake"


def test_wrong_key_fails_verification_closed(tmp_path):
    s = _settings(tmp_path)
    res = run_backup(s, store=_sample_store(), runner=FakeMySQLRunner())
    wrong = _settings(tmp_path, backup_encryption_key="a-different-master-key")
    assert verify_backup(res.set_dir, settings=wrong) is False


def test_wrong_key_fails_restore_closed(tmp_path):
    s = _settings(tmp_path)
    res = run_backup(s, store=_sample_store(), runner=FakeMySQLRunner())
    wrong = _settings(tmp_path, backup_encryption_key="nope")
    assert run_restore(wrong, res.set_dir, store=FakeObjectStore(), runner=FakeMySQLRunner(),
                       include_objects=True) is False


def test_unencrypted_backup_unchanged_when_disabled(tmp_path):
    s = _settings(tmp_path, backup_encryption_enabled=False)
    res = run_backup(s, store=_sample_store(), runner=FakeMySQLRunner())
    assert res.ok is True
    assert (res.set_dir / "db.sql").read_bytes().startswith(b"-- MySQL dump")  # plaintext, as before
    assert "encryption" not in res.manifest
    assert verify_backup(res.set_dir, settings=s) is True
