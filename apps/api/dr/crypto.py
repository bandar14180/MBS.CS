"""DR-2 -- backup encryption at rest (AES-256-GCM).

Encrypts a backup artifact IN PLACE so the rest of the DR system keeps its existing filenames
and set layout (db.dump, objects.tar.gz); only the file *content* becomes ciphertext. An
8-byte magic header marks an MBS-encrypted artifact and lets verify/restore detect it without
a flag. GCM gives authenticated encryption: a wrong key or a single flipped byte fails the tag
check, so `decrypt_*` raises `DecryptionError` and verification fails CLOSED (never silently
"succeeds" on a corrupt/wrong-key backup).

Key handling reuses the app's secret conventions: the master string comes from
BACKUP_ENCRYPTION_KEY (which supports the <NAME>_FILE indirection via _FILE_BACKED_SECRETS)
and is stretched to a 32-byte AES-256 key with SHA-256. Uses the already-present `cryptography`
dependency -- no new runtime requirement.
"""
import hashlib
import os
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"MBSENC1\n"  # 8-byte marker for an MBS-encrypted DR artifact (versioned)
_NONCE_LEN = 12       # 96-bit nonce, the GCM standard


class DecryptionError(Exception):
    """Raised when an artifact cannot be authenticated/decrypted (wrong key or corruption)."""


def derive_key(master: str) -> bytes:
    """Stretch the configured master secret to a 32-byte AES-256 key. Empty -> hard error, so
    encryption can never silently run with a null key."""
    if not master:
        raise RuntimeError("BACKUP_ENCRYPTION_KEY is empty; cannot encrypt/decrypt backups")
    return hashlib.sha256(master.encode("utf-8")).digest()


def load_backup_key(settings) -> bytes:
    return derive_key(getattr(settings, "backup_encryption_key", "") or "")


def is_encrypted(path) -> bool:
    """True if the file begins with the MBS encryption magic header."""
    try:
        with open(path, "rb") as fh:
            return fh.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def encrypt_file(path, key: bytes) -> Path:
    """Encrypt `path` in place: MAGIC || nonce || ciphertext(+tag). Idempotency guard: an
    already-encrypted file is left untouched (re-running a backup step can't double-encrypt)."""
    p = Path(path)
    if is_encrypted(p):
        return p
    data = p.read_bytes()
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    p.write_bytes(MAGIC + nonce + ciphertext)
    return p


def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    if blob[: len(MAGIC)] != MAGIC:
        raise DecryptionError("not an MBS-encrypted artifact (missing magic header)")
    nonce = blob[len(MAGIC) : len(MAGIC) + _NONCE_LEN]
    ciphertext = blob[len(MAGIC) + _NONCE_LEN :]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise DecryptionError("authentication failed (wrong key or corrupted backup)") from exc


def decrypt_to_temp(path, key: bytes) -> Path:
    """Decrypt `path` into a fresh temp file and return it. Caller deletes it. Raises
    DecryptionError on wrong key / corruption (so callers fail closed)."""
    plaintext = decrypt_bytes(Path(path).read_bytes(), key)
    fd, name = tempfile.mkstemp(prefix="mbsdr-")
    os.close(fd)
    out = Path(name)
    out.write_bytes(plaintext)
    return out
