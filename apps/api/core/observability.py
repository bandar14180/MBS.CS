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
    # Phase 1.2: orphaned 'running' scans recovered by the reaper. Low-cardinality
    # label only (reason); never scan_id/workspace_id/host.
    SCAN_REAPED = Counter(
        "mbs_scan_reaped_total", "Orphaned running scans recovered by the reaper", ["reason"]
    )
    # Phase 1.3 observability. ALL labels are strictly low-cardinality (tool name,
    # decision action, scan status) -- NEVER scan_id/workspace_id/host/target.
    SCAN_SUCCESS = Counter("mbs_scan_success_total", "Scans that completed successfully")
    SCAN_FAILED = Counter("mbs_scan_failed_total", "Scans that failed")
    SCAN_DURATION = Histogram("mbs_scan_duration_seconds", "End-to-end scan duration", ["status"])
    TOOL_FAILURE = Counter("mbs_tool_failure_total", "Tool executions that failed", ["tool"])
    AI_DECISION = Counter("mbs_ai_decision_total", "Autonomous agent decisions", ["action"])
    # Phase 1.4: API error responses by stable error type (low-cardinality; never a
    # path/scan_id/message).
    API_ERRORS = Counter("mbs_api_errors_total", "API error responses", ["type"])
    # Phase 4.1: reliability-path counters. Low-cardinality labels only.
    SCHEDULE_LAUNCHED = Counter(
        "mbs_schedule_launched_total", "Scheduled scans dispatched by the beat scheduler", ["result"]
    )
    SCAN_RELAYED = Counter(
        "mbs_scan_relayed_total", "Undelivered 'queued' scans re-dispatched by the queued relay"
    )


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


def record_scan_reaped(count: int, reason: str = "timeout") -> None:
    """Count orphaned scans recovered by the reaper (Phase 1.2). No high-cardinality
    labels (no scan_id/workspace_id/host)."""
    if _PROM and count:
        SCAN_REAPED.labels(reason).inc(count)


def record_scan_result(status: str, duration_s: float) -> None:
    """Phase 1.3: record a finished scan -- success/failed counters + duration
    histogram, and wire the (previously dead) outcomes counter. Real lifecycle event."""
    if not _PROM:
        return
    record_scan_outcome(status)  # wires mbs_scan_outcomes_total{status}
    if status in ("completed", "completed_with_errors"):
        SCAN_SUCCESS.inc()
    elif status == "failed":
        SCAN_FAILED.inc()
    SCAN_DURATION.labels(status).observe(max(0.0, duration_s))


def record_tool_failure(tool: str) -> None:
    if _PROM:
        TOOL_FAILURE.labels(tool).inc()


def record_ai_decision(action: str) -> None:
    if _PROM:
        AI_DECISION.labels(action).inc()


def record_api_error(error_type: str) -> None:
    """Phase 1.4: count an API error response by stable error type (validation_error,
    unauthorized, forbidden, not_found, conflict, http_error, internal_error, ...).
    Low-cardinality by construction -- never a path/scan_id/message."""
    if _PROM:
        API_ERRORS.labels(error_type).inc()


def record_schedule_launched(result: str) -> None:
    """Phase 4.1: count a scheduled-scan dispatch outcome (result: launched | failed).
    Low-cardinality label; recorded in the worker/beat process."""
    if _PROM:
        SCHEDULE_LAUNCHED.labels(result).inc()


def record_scan_relayed(count: int) -> None:
    """Phase 4.1: count undelivered 'queued' scans the relay re-dispatched (worker process)."""
    if _PROM and count:
        SCAN_RELAYED.inc(count)


def metrics_response_body() -> bytes:
    return generate_latest() if _PROM else b""
