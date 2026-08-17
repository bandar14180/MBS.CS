"""Data Privacy Hardening -- centralized log redaction.

Secrets (passwords, tokens, API keys) and PII (emails) must never reach a log sink,
whichever call site emitted them. Redaction runs in the formatters, so it scrubs the
serialized output without disturbing the LogRecord (or in-process assertions).
"""
import json
import logging

from apps.api.core.log_redaction import (
    is_sensitive_key,
    redact_text,
    redact_value,
)
from apps.api.core.logging import JSONLogFormatter, RedactingTextFormatter


def test_sensitive_key_detection_is_precise() -> None:
    for k in (
        "password", "api_key", "apikey", "auth_token", "password_hash",
        "s3_secret_key", "code_hash", "key_hash", "Authorization", "mfa_secret", "cookie",
    ):
        assert is_sensitive_key(k), k
    # Harmless fields that merely CONTAIN a sensitive substring must survive.
    for k in (
        "prompt_tokens", "completion_tokens", "user_id", "correlation_id",
        "provider", "model", "workspace_count", "author",
    ):
        assert not is_sensitive_key(k), k


def test_redact_text_masks_email_bearer_and_apikey() -> None:
    assert redact_text("login for alice@example.com") == "login for [REDACTED_EMAIL]"
    bearer = redact_text("hdr Authorization: Bearer abc.def-123 end")
    assert "abc.def-123" not in bearer and "[REDACTED]" in bearer
    apik = redact_text("using key mbsk_supersecretvalue now")
    assert "mbsk_supersecretvalue" not in apik and "[REDACTED_API_KEY]" in apik


def test_redact_value_key_takes_priority_over_content() -> None:
    assert redact_value("password", "hunter2") == "[REDACTED]"
    assert redact_value("token", "sk-abc123") == "[REDACTED]"
    assert redact_value("prompt_tokens", 42) == 42  # numeric count untouched
    assert redact_value("note", "ping bob@corp.com") == "ping [REDACTED_EMAIL]"


def test_redact_value_recurses_into_containers() -> None:
    out = redact_value("payload", {"secret": "x", "items": ["a@b.com", {"api_key": "k"}]})
    assert out["secret"] == "[REDACTED]"
    assert out["items"][0] == "[REDACTED_EMAIL]"
    assert out["items"][1]["api_key"] == "[REDACTED]"


def _record(msg: str, **extra) -> logging.LogRecord:
    rec = logging.LogRecord("mbs.test", logging.INFO, __file__, 1, msg, None, None)
    for k, v in extra.items():
        setattr(rec, k, v)
    return rec


def test_json_formatter_redacts_message_and_structured_fields() -> None:
    rec = _record(
        "login for admin@corp.com",
        password="hunter2",
        token="sk-secret",
        prompt_tokens=10,
        user_id="u-1",
    )
    out = json.loads(JSONLogFormatter().format(rec))
    assert "admin@corp.com" not in out["message"]
    assert out["message"] == "login for [REDACTED_EMAIL]"
    assert out["password"] == "[REDACTED]"
    assert out["token"] == "[REDACTED]"
    assert out["prompt_tokens"] == 10       # harmless field preserved
    assert out["user_id"] == "u-1"


def test_text_formatter_also_redacts() -> None:
    line = RedactingTextFormatter("%(message)s").format(_record("email carol@x.io"))
    assert "carol@x.io" not in line and "[REDACTED_EMAIL]" in line
