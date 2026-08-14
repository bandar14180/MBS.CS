"""E5 -- Email Alert System metrics (Prometheus, optional-at-import).

Mirrors dr/metrics.py: prometheus_client absent -> every recorder is a no-op. Counters live on
the default registry and are exposed by the worker metrics server (the email task runs on
worker-default), so they surface on the worker scrape target. Low-cardinality labels only
(a bounded `category`); NEVER a recipient, subject, hostname, or workspace id.
"""
try:
    from prometheus_client import Counter, Histogram

    _PROM = True
except Exception:  # noqa: BLE001
    _PROM = False

# Bounded set of alert categories -- anything else is clamped to "other" to guard cardinality.
_ALLOWED = {"scan_failed", "critical_findings", "backup_failed", "reliability_dlq", "other"}


def _cat(category: str) -> str:
    return category if category in _ALLOWED else "other"


if _PROM:
    EMAIL_SENT = Counter("mbs_email_sent_total", "Alert emails sent successfully", ["category"])
    EMAIL_FAILED = Counter("mbs_email_failed_total", "Alert emails that failed to send", ["category"])
    EMAIL_DURATION = Histogram("mbs_email_duration_seconds", "Email send duration in seconds", ["category"])


def record_email_sent(category: str, *, duration_s: float = 0.0) -> None:
    if not _PROM:
        return
    c = _cat(category)
    EMAIL_SENT.labels(c).inc()
    EMAIL_DURATION.labels(c).observe(max(0.0, duration_s))


def record_email_failed(category: str) -> None:
    if not _PROM:
        return
    EMAIL_FAILED.labels(_cat(category)).inc()
