"""MFA foundation unit tests (Sprint 1, Step 1). Pure -- no DB, no login flow. Exercises the
TOTP + Fernet-encryption + recovery-code primitives in apps.api.core.mfa.
"""
import pyotp
import pytest

from apps.api.core import mfa
from apps.api.core.config import get_settings

_KEY = "unit-test-mfa-master-key"


def _set_key(monkeypatch, value=_KEY):
    monkeypatch.setattr(get_settings(), "mfa_encryption_key", value)


# --- TOTP secret ---------------------------------------------------------------------------

def test_generate_totp_secret_is_base32():
    s = mfa.generate_totp_secret()
    assert len(s) >= 16
    assert set(s) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")  # base32 alphabet
    # a fresh call yields a different secret
    assert mfa.generate_totp_secret() != s


def test_verify_totp_accepts_current_code_and_rejects_others(monkeypatch):
    secret = mfa.generate_totp_secret()
    good = pyotp.TOTP(secret).now()
    assert mfa.verify_totp(secret, good) is True
    assert mfa.verify_totp(secret, "000000") is False   # wrong code
    assert mfa.verify_totp(secret, "notacode") is False  # non-numeric
    assert mfa.verify_totp(secret, "") is False          # empty


def test_provisioning_uri_contains_issuer_account_and_secret(monkeypatch):
    secret = mfa.generate_totp_secret()
    uri = mfa.provisioning_uri(secret, account_name="user@example.com")
    assert uri.startswith("otpauth://totp/")
    assert "issuer=MBS.PT" in uri
    # the account label is URL-encoded in the otpauth URI (@ -> %40)
    assert "user%40example.com" in uri
    assert secret in uri


# --- encryption at rest --------------------------------------------------------------------

def test_encrypt_decrypt_round_trip(monkeypatch):
    _set_key(monkeypatch)
    secret = mfa.generate_totp_secret()
    ct = mfa.encrypt_secret(secret)
    assert ct != secret                       # actually encrypted
    assert mfa.decrypt_secret(ct) == secret   # round-trips
    # Fernet is non-deterministic (IV/timestamp) -> two encryptions differ
    assert mfa.encrypt_secret(secret) != ct


def test_decrypt_with_wrong_key_raises(monkeypatch):
    _set_key(monkeypatch, "key-A")
    ct = mfa.encrypt_secret("s3cr3t")
    _set_key(monkeypatch, "key-B")
    with pytest.raises(ValueError):
        mfa.decrypt_secret(ct)


def test_encrypt_without_key_raises(monkeypatch):
    _set_key(monkeypatch, "")
    with pytest.raises(RuntimeError):
        mfa.encrypt_secret("s3cr3t")


# --- recovery codes ------------------------------------------------------------------------

def test_generate_recovery_codes_are_unique_and_formatted():
    codes = mfa.generate_recovery_codes()
    assert len(codes) == 10
    assert len(set(codes)) == 10             # all distinct
    for c in codes:
        assert "-" in c                       # grouped for readability
        assert set(c.replace("-", "")) <= set("0123456789abcdef")  # hex


def test_hash_recovery_code_is_normalized_and_verifiable():
    codes = mfa.generate_recovery_codes(3)
    c = codes[0]
    h = mfa.hash_recovery_code(c)
    # normalization: dashes / case / spaces don't change the hash
    assert mfa.hash_recovery_code(c.replace("-", "")) == h
    assert mfa.hash_recovery_code(f"  {c.upper()}  ") == h
    # different codes -> different hashes
    assert mfa.hash_recovery_code(codes[1]) != h
    # verify helper (constant-time)
    assert mfa.verify_recovery_code(c, h) is True
    assert mfa.verify_recovery_code(codes[1], h) is False


def test_migration_model_registered():
    # the recovery-code model is registered on the ORM metadata (backs the new migration)
    from apps.api.core.db import Base
    assert "mfa_recovery_codes" in Base.metadata.tables
