"""Centralized log redaction (Data Privacy Hardening).

A single place that scrubs secrets and personal data out of anything on its way to
a log sink, so no call site can accidentally leak a password, token, API key, or
email address. Applied by the log *formatters* (see core/logging.py) -- never by
mutating the LogRecord -- so it affects only the serialized output and never
disturbs in-process assertions (e.g. pytest's caplog reads the record, not our text).

Two layers:
  * key-based   -- a structured field whose NAME looks like a secret is dropped
                   entirely (value never rendered), regardless of its content.
  * value-based -- free text (the message, or a non-sensitive field's string value)
                   has emails / bearer tokens / API-key tokens masked in place.
"""
import re

REDACTED = "[REDACTED]"
REDACTED_EMAIL = "[REDACTED_EMAIL]"
REDACTED_API_KEY = "[REDACTED_API_KEY]"

# Field names that must never have their value rendered. Matched case-insensitively
# on the WHOLE key or on a `_`/`-`/`.`-delimited suffix, so "prompt_tokens" /
# "completion_tokens" (harmless counts) are NOT caught while "auth_token",
# "api_key", "password_hash", "s3_secret_key", "code_hash" are.
_EXACT_SENSITIVE = frozenset(
    {
        "password", "passwd", "pass", "secret", "token", "authorization", "auth",
        "credential", "credentials", "cookie", "session", "otp", "totp",
        "mfa_secret", "api_key", "apikey", "access_key", "secret_key", "private_key",
    }
)
_SENSITIVE_SUFFIXES = (
    "_password", "_passwd", "_secret", "_token", "_hash", "_key", "_apikey",
    "_credential", "_credentials", "_cookie",
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-]+")
_APIKEY_RE = re.compile(r"mbsk_[A-Za-z0-9_\-]+")


def is_sensitive_key(key: object) -> bool:
    k = str(key).lower()
    return k in _EXACT_SENSITIVE or k.endswith(_SENSITIVE_SUFFIXES)


def redact_text(value: str) -> str:
    """Mask secrets/PII inside a free-text string. Order matters: bearer tokens and
    API-key tokens first (they can embed '.'), then bare emails."""
    if not isinstance(value, str):
        return value
    value = _BEARER_RE.sub(r"\1" + REDACTED, value)
    value = _APIKEY_RE.sub(REDACTED_API_KEY, value)
    value = _EMAIL_RE.sub(REDACTED_EMAIL, value)
    return value


def redact_value(key: object, value: object):
    """Scrub one structured field. Sensitive key -> fully redacted; otherwise the
    value is text-scrubbed (recursively for nested dict/list containers)."""
    if is_sensitive_key(key):
        return REDACTED
    return _scrub(value)


def _scrub(value):
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: (REDACTED if is_sensitive_key(k) else _scrub(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub(v) for v in value]
    return value


def redact_mapping(fields: dict) -> dict:
    """Redact a whole {field: value} mapping (used for structured log payloads)."""
    return {k: redact_value(k, v) for k, v in fields.items()}
