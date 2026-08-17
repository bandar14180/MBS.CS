"""MFA foundation (Sprint 1, Step 1) -- pure cryptographic + TOTP helpers.

No login/API behavior depends on this yet. It provides the building blocks a later step will
wire into an enrollment + two-step-login flow:

  * TOTP secret generation / verification (RFC 6238, via pyotp)
  * encryption-at-rest of the TOTP secret (Fernet, key derived from settings.mfa_encryption_key)
  * an authenticator provisioning URI (otpauth://)
  * one-time recovery codes + their hashes

The stored MFA secret must NEVER be persisted in plaintext -- callers persist encrypt_secret(...)
into users.mfa_secret_encrypted and decrypt only in-memory to verify a code.
"""
import base64
import hashlib
import hmac
import secrets

import pyotp
from cryptography.fernet import Fernet, InvalidToken

from apps.api.core.config import get_settings

_RECOVERY_CODE_COUNT = 10
_RECOVERY_CODE_BYTES = 8  # 64 bits of entropy per code


def _fernet() -> Fernet:
    """Build a Fernet from settings.mfa_encryption_key. Any non-empty master string is accepted
    (a 32-byte urlsafe-base64 Fernet key is derived from its SHA-256), so operators aren't forced
    to generate a Fernet-formatted key. Raises if MFA is unconfigured."""
    key = get_settings().mfa_encryption_key
    if not key:
        raise RuntimeError(
            "MFA encryption key not configured (set MFA_ENCRYPTION_KEY or MFA_ENCRYPTION_KEY_FILE)"
        )
    derived = base64.urlsafe_b64encode(hashlib.sha256(key.encode("utf-8")).digest())
    return Fernet(derived)


# --- TOTP secret ---------------------------------------------------------------------------

def generate_totp_secret() -> str:
    """A new random base32 TOTP secret (to be encrypted before storage)."""
    return pyotp.random_base32()


def encrypt_secret(plaintext_secret: str) -> str:
    """Encrypt a TOTP secret for at-rest storage (users.mfa_secret_encrypted)."""
    return _fernet().encrypt(plaintext_secret.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a stored TOTP secret. Raises ValueError on a wrong key / corrupt ciphertext."""
    try:
        return _fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("could not decrypt MFA secret (wrong key or corrupt data)") from exc


def provisioning_uri(secret: str, account_name: str, issuer: str | None = None) -> str:
    """otpauth:// URI an authenticator app scans; issuer defaults to settings.mfa_issuer."""
    return pyotp.TOTP(secret).provisioning_uri(
        name=account_name, issuer_name=issuer or get_settings().mfa_issuer
    )


def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    """Verify a 6-digit TOTP against the secret. valid_window=1 tolerates +/-30s clock skew.
    Non-numeric / empty input returns False rather than raising."""
    code = (code or "").strip()
    if not code.isdigit():
        return False
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=valid_window)
    except Exception:  # noqa: BLE001 -- a malformed secret must never crash auth
        return False


# --- recovery codes ------------------------------------------------------------------------

def generate_recovery_codes(n: int = _RECOVERY_CODE_COUNT) -> list[str]:
    """`n` human-typeable one-time recovery codes (grouped hex, e.g. 'a1b2-c3d4-e5f6-0789').
    Return the plaintext ONCE to the user; persist only their hashes."""
    codes: list[str] = []
    for _ in range(n):
        raw = secrets.token_hex(_RECOVERY_CODE_BYTES)
        codes.append("-".join(raw[i:i + 4] for i in range(0, len(raw), 4)))
    return codes


def _normalize_recovery_code(code: str) -> str:
    return code.strip().lower().replace("-", "").replace(" ", "")


def hash_recovery_code(code: str) -> str:
    """SHA-256 of the normalized code -- deterministic, so redemption can look up by hash
    (codes are high-entropy + one-time + rate-limited, so a fast hash is appropriate)."""
    return hashlib.sha256(_normalize_recovery_code(code).encode("utf-8")).hexdigest()


def verify_recovery_code(code: str, code_hash: str) -> bool:
    """Constant-time comparison of a submitted code against a stored hash."""
    return hmac.compare_digest(hash_recovery_code(code), code_hash)
