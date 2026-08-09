"""Password hashing (P1-5): direct bcrypt, compatible with existing hashes."""
from apps.api.core.security import hash_password, verify_password

# A bcrypt hash of "correct horse battery staple" generated the way the previous
# passlib(bcrypt) config produced them ($2b$, 12 rounds). It MUST still verify, so
# existing users can log in after the passlib -> bcrypt switch.
_EXISTING_HASH = "$2b$12$dlXr/J4ixvpH8tPAPhDw0eNLzQYQ9lRirdt7p4gdvIZ9jUIu2esmu"


def test_hash_roundtrip() -> None:
    h = hash_password("s3cret-pw")
    assert h.startswith("$2b$")
    assert verify_password("s3cret-pw", h) is True


def test_wrong_password_fails() -> None:
    h = hash_password("right")
    assert verify_password("wrong", h) is False


def test_existing_passlib_bcrypt_hash_still_verifies() -> None:
    assert verify_password("correct horse battery staple", _EXISTING_HASH) is True
    assert verify_password("nope", _EXISTING_HASH) is False


def test_malformed_hash_returns_false_not_error() -> None:
    assert verify_password("anything", "not-a-bcrypt-hash") is False


def test_long_password_truncated_to_72_bytes_like_bcrypt() -> None:
    # bcrypt only considers the first 72 bytes; hashing must not error on longer.
    h = hash_password("a" * 200)
    assert verify_password("a" * 72, h) is True  # same first-72 bytes verify
