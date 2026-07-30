import contextvars
import uuid

# Prometheus is an optional-at-import dependency: if it's absent, everything here
# degrades to no-ops so observability can never break the app or unit tests.
try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        Counter,
        Histogram,
        generate_latest,
    )

    _PROM = True
except Exception:  # noqa: BLE001
    _PROM = False
    CONTENT_TYPE_LATEST = "text/plain"

_correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar("mbs_correlation_id", default="-")


def set_correlation_id(value: str) -> None:
    _correlation_id.set(value)


def get_correlation_id() -> str:
    return _correlation_id.get()


def new_correlation_id() -> str:
    return uuid.uuid4().hex


if _PROM:
    HTTP_REQUESTS = Counter(
        "mbs_http_requests_total", "HTTP requests", ["method", "path", "status"]
    )
    HTTP_LATENCY = Histogram(
        "mbs_http_request_duration_seconds", "HTTP request latency", ["method", "path"]
    )
    AI_CALLS = Counter("mbs_ai_calls_total", "AI provider calls", ["provider", "model", "agent_role"])
    AI_TOKENS = Counter(
        "mbs_ai_tokens_total", "AI tokens used", ["provider", "model", "direction"]
    )
    AI_COST = Counter("mbs_ai_cost_usd_total", "Estimated AI spend (USD)", ["provider", "model"])
    SCAN_OUTCOMES = Counter("mbs_scan_outcomes_total", "Scan outcomes", ["status"])


def record_http_metrics(method: str, path: str, status: int, duration_s: float) -> None:
    if not _PROM:
        return
    HTTP_REQUESTS.labels(method, path, str(status)).inc()
    HTTP_LATENCY.labels(method, path).observe(duration_s)


def record_ai_usage_metrics(usage) -> None:
    if not _PROM:
        return
    role = usage.agent_role or "unknown"
    AI_CALLS.labels(usage.provider, usage.model, role).inc()
    AI_TOKENS.labels(usage.provider, usage.model, "prompt").inc(usage.prompt_tokens)
    AI_TOKENS.labels(usage.provider, usage.model, "completion").inc(usage.completion_tokens)
    AI_COST.labels(usage.provider, usage.model).inc(usage.estimated_cost_usd)


def record_scan_outcome(status: str) -> None:
    if _PROM:
        SCAN_OUTCOMES.labels(status).inc()


def metrics_response_body() -> bytes:
    return generate_latest() if _PROM else b""
