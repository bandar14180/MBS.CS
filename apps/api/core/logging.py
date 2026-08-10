import datetime as _dt
import json
import logging

from apps.api.core.log_redaction import redact_text, redact_value

# Standard LogRecord attributes -- anything NOT in here that a caller passed via
# `logger.info(..., extra={...})` is emitted as a structured field.
_RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename", "module",
    "exc_info", "exc_text", "stack_info", "lineno", "funcName", "created", "msecs",
    "relativeCreated", "thread", "threadName", "processName", "process", "taskName",
}


class _CorrelationFilter(logging.Filter):
    """Attaches the current request's correlation id to every record so logs can
    be joined to a request without each call site passing it explicitly."""

    def filter(self, record: logging.LogRecord) -> bool:
        from apps.api.core.observability import get_correlation_id

        if not hasattr(record, "correlation_id"):
            record.correlation_id = get_correlation_id()
        return True


class JSONLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": _dt.datetime.fromtimestamp(record.created, _dt.timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            # Centralized redaction: never emit a secret/PII, whatever the call site passed.
            "message": redact_text(record.getMessage()),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_") and key not in payload:
                payload[key] = redact_value(key, value)
        if record.exc_info:
            payload["exc_info"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


class RedactingTextFormatter(logging.Formatter):
    """Plain-text (dev) formatter that runs the fully rendered line through the same
    redaction pass as the JSON path, so local logs never leak secrets/PII either."""

    def format(self, record: logging.LogRecord) -> str:
        return redact_text(super().format(record))


def configure_logging(level: str = "INFO", json_output: bool = True) -> None:
    """Idempotent root logging setup. JSON in production for log aggregation; plain
    text locally for readability. Safe to call more than once (e.g. app + worker)."""
    root = logging.getLogger()
    root.setLevel(level.upper())
    for handler in list(root.handlers):
        root.removeHandler(handler)
    handler = logging.StreamHandler()
    handler.addFilter(_CorrelationFilter())
    if json_output:
        handler.setFormatter(JSONLogFormatter())
    else:
        handler.setFormatter(
            RedactingTextFormatter("%(asctime)s %(levelname)s %(name)s [%(correlation_id)s] %(message)s")
        )
    root.addHandler(handler)
