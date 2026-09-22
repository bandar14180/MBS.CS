import contextvars
import uuid

# Prometheus is an optional-at-import dependency: if it's absent, everything here
# degrades to no-ops so observability can never break the app or unit tests.
try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        Counter,
        # MBS.SC: tunnel/heartbeat/queue-depth are point-in-time STATES, not cumulative
        # counts, so they are Gauges rather than Counters.
        Gauge,
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
    # AI-2.1: provider failovers on an availability failure. Low-cardinality labels ONLY
    # (provider names) -- never a key, endpoint, error body, or tenant id.
    AI_FAILOVER = Counter(
        "mbs_ai_failover_total", "AI provider failovers (availability failure)", ["from_provider", "to_provider"]
    )
    # AI-2.2A: AI calls blocked by the per-workspace daily budget cap. Low-cardinality label ONLY
    # (agent_role) -- NEVER a workspace id, email, key, or amount.
    AI_BUDGET_BLOCKED = Counter(
        "mbs_ai_budget_blocked_total", "AI calls blocked by the daily budget cap", ["agent_role"]
    )
    # AI-2.5: latency of successful AI calls + AI calls that ultimately failed. Low-cardinality
    # labels ONLY (bounded agent_role / provider) -- never model/workspace/scan/host.
    AI_LATENCY = Histogram(
        "mbs_ai_latency_seconds", "AI provider call latency (successful calls)", ["agent_role"]
    )
    AI_ERRORS = Counter("mbs_ai_errors_total", "AI provider calls that ultimately failed", ["provider"])
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
    # ------------------------------------------------------------------------------
    # MBS.SC -- scanner isolation / private scanning (Phase 16).
    #
    # LABEL DISCIPLINE: no workspace_id, no site_id, no worker_id, no CIDR, no hostname.
    # Prometheus labels are effectively public within the deployment and unbounded
    # cardinality is an outage risk -- but the decisive reason is that a tenant's site
    # count, scan timing and internal addressing are customer data. `reason`, `pool_id`
    # and `zone` are bounded, non-identifying vocabularies. The per-tenant detail lives
    # in the structured LOGS, which are access-controlled.
    # ------------------------------------------------------------------------------
    SCANNER_AUTHZ_DENIED = Counter(
        "mbs_scanner_authz_denied_total",
        "Scanner-manager requests refused, by stable reason code",
        ["reason"],
    )
    PRIVATE_SCAN_BLOCKED = Counter(
        "mbs_private_scan_blocked_total",
        "Private scans refused before execution, by reason (site/worker/tunnel/CIDR)",
        ["reason"],
    )
    EGRESS_BLOCKED = Counter(
        "mbs_scanner_egress_blocked_total",
        "Outbound destinations refused by the scanner egress policy",
        ["reason"],
    )
    TUNNEL_STATE = Gauge(
        "mbs_tunnel_up",
        "1 when a private site's tunnel passed its last preflight, 0 when it did not",
        ["pool_id"],
    )
    TUNNEL_HANDSHAKE_AGE = Gauge(
        "mbs_tunnel_handshake_age_seconds",
        "Age of the last observed WireGuard handshake",
        ["pool_id"],
    )
    # DEDICATED VPN EGRESS. Separate series from `mbs_tunnel_up` on purpose: mixing the
    # platform's internet exit into the per-site tunnel gauge would dilute the
    # private-tunnel-down alert with a pool that has no customer tunnel at all, and an
    # operator could not tell which of the two failures they were looking at.
    VPN_EGRESS_STATE = Gauge(
        "mbs_vpn_egress_up",
        "1 when the dedicated VPN egress path passed its last preflight, 0 when it did not",
        ["pool_id"],
    )
    VPN_EGRESS_HANDSHAKE_AGE = Gauge(
        "mbs_vpn_egress_handshake_age_seconds",
        "Age of the last observed VPN egress WireGuard handshake",
        ["pool_id"],
    )
    VPN_EGRESS_EXIT_IP_VERIFIED = Gauge(
        "mbs_vpn_egress_exit_ip_verified",
        "1 when the observed egress exit IP matched the expected VPN exit IP",
        ["pool_id"],
    )
    VPN_EGRESS_BLOCKED = Counter(
        "mbs_vpn_egress_blocked_total",
        "Scans refused because the dedicated VPN egress path could not be verified",
        ["reason"],
    )
    VPN_EGRESS_MIDSCAN_LOSS = Counter(
        "mbs_vpn_egress_midscan_loss_total",
        "Running scans cancelled because VPN egress became unverifiable mid-scan",
        ["reason"],
    )
    WORKER_HEARTBEAT_AGE = Gauge(
        "mbs_scanner_worker_heartbeat_age_seconds",
        "Seconds since a scanner worker last checked in with the manager",
        ["pool_id"],
    )
    SCANNER_QUEUE_DEPTH = Gauge(
        "mbs_scanner_queue_depth",
        "Pending scans on a scanner queue",
        ["zone"],
    )
    WORKER_REVOKED = Counter(
        "mbs_scanner_worker_revoked_total", "Scanner workers revoked by an operator"
    )
    SITE_SUSPENDED = Counter(
        "mbs_private_site_suspended_total", "Private sites moved to a non-scannable state"
    )
    # --- Prompt 33: verification + evidence processing -------------------------------------
    # Two capabilities that fully exist (reports/verification.py, scanner_engine/
    # evidence_store.py + evidence_integrity.py) but emitted NO metric at all, so an operator
    # could not see a verification-mix shift or an evidence-capture outage without reading
    # reports. Deliberately NOT added: discovery/AUL/ASKG/session/TestPlan metrics, whose
    # subsystems do not exist here -- emitting for them would require inventing them.
    #
    # Every label below is a CLOSED vocabulary fixed in code: the verification states and
    # confidence bands from verification.py, and outcome codes chosen here. No workspace, no
    # project, no target, no URL, no finding id, no tenant identifier -- those are unbounded
    # and would both blow up cardinality and leak tenant data through the metrics endpoint.
    VERIFICATION_OUTCOMES = Counter(
        "mbs_verification_outcomes_total",
        "Findings by reported verification state and evidence confidence",
        ["state", "confidence"],
    )
    EVIDENCE_PROCESSED = Counter(
        "mbs_evidence_processed_total",
        "Evidence artifact capture attempts by artifact kind and outcome",
        ["kind", "outcome"],
    )
    EVIDENCE_INTEGRITY = Counter(
        "mbs_evidence_integrity_checks_total",
        "Explicit evidence integrity re-verifications by result",
        ["result"],
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


def record_ai_failover(from_provider: str, to_provider: str) -> None:
    """AI-2.1: count one provider failover. Provider NAMES only -- never keys/endpoints/bodies."""
    if _PROM:
        AI_FAILOVER.labels(from_provider, to_provider).inc()


def record_ai_budget_blocked(agent_role: str) -> None:
    """AI-2.2A: count one AI call blocked by the daily budget cap. Only the low-cardinality
    agent_role label -- never a workspace id or amount."""
    if _PROM:
        AI_BUDGET_BLOCKED.labels(agent_role).inc()


def record_ai_latency(agent_role: str, seconds: float) -> None:
    """AI-2.5: observe the latency of a successful AI call (label: bounded agent_role)."""
    if _PROM:
        AI_LATENCY.labels(agent_role or "unknown").observe(max(0.0, seconds))


# --- MBS.SC recorders. Each takes only bounded, non-identifying labels. -------------

def record_scanner_authz_denied(reason: str) -> None:
    """One refused manager request. `reason` is a stable code (WORKER_REVOKED,
    WORKER_WRONG_SITE, ...) -- never a worker id, workspace or site."""
    if _PROM:
        SCANNER_AUTHZ_DENIED.labels(reason or "unknown").inc()


def record_private_scan_blocked(reason: str) -> None:
    """One private scan refused before execution (SITE_SUSPENDED, TUNNEL_UNHEALTHY,
    ROUTE_MISSING, TARGET_OUTSIDE_AUTHORIZED_CIDRS, ...)."""
    if _PROM:
        PRIVATE_SCAN_BLOCKED.labels(reason or "unknown").inc()


def record_egress_blocked(reason: str) -> None:
    """One destination refused by the egress policy. The DESTINATION is deliberately not a
    label -- it can be a customer's internal hostname."""
    if _PROM:
        EGRESS_BLOCKED.labels(reason or "unknown").inc()


# --- Prompt 33 recorders: verification + evidence ------------------------------------------
#
# Each CLAMPS its labels to a closed vocabulary rather than trusting the caller. That is the
# load-bearing part: `state`/`kind`/`result` are derived from data that originates in scanner
# output, and a caller passing an unexpected value through to `.labels()` would mint a new
# Prometheus time series per distinct value. Clamping to "other" makes an unbounded label
# structurally impossible instead of merely discouraged, and keeps tenant data out of metrics
# by construction -- there is no code path by which a target, URL or id can become a label.

_VERIFICATION_STATES = frozenset({"verified", "partially_verified", "unverified"})
_CONFIDENCE_BANDS = frozenset({"high", "medium", "low"})
_EVIDENCE_KINDS = frozenset({"raw_output", "screenshot", "remediation_proof", "log_excerpt"})
_EVIDENCE_OUTCOMES = frozenset({"stored", "storage_failed", "skipped"})
_INTEGRITY_RESULTS = frozenset({"pass", "integrity_failure", "missing_object", "no_checksum"})


def _bounded(value, allowed: frozenset, default: str = "other") -> str:
    """One label value, clamped to a closed set. Anything unknown collapses to `default`."""
    text = str(value or "").strip().lower()
    return text if text in allowed else default


def record_verification_outcome(state: str, confidence: str) -> None:
    """One finding's reported verification state + evidence confidence.

    Lets an operator watch the MIX (e.g. a sudden collapse of `verified` to `unverified` after
    an evidence-store outage) without reading any report. Counts only -- this NEVER influences
    the state it observes, and carries no finding, target or tenant identity."""
    if _PROM:
        VERIFICATION_OUTCOMES.labels(
            _bounded(state, _VERIFICATION_STATES, "unverified"),
            _bounded(confidence, _CONFIDENCE_BANDS, "medium"),
        ).inc()


def record_evidence_processed(kind: str, outcome: str) -> None:
    """One evidence capture attempt. `outcome=storage_failed` is the signal that the
    `unavailable://` sentinel path was taken -- previously visible only as a log line, though
    it directly suppresses corroboration in the report (see reports/verification.py)."""
    if _PROM:
        EVIDENCE_PROCESSED.labels(
            _bounded(kind, _EVIDENCE_KINDS),
            _bounded(outcome, _EVIDENCE_OUTCOMES),
        ).inc()


def record_evidence_integrity(result: str) -> None:
    """One explicit evidence integrity re-verification (scanner_engine.evidence_integrity).

    `integrity_failure` means stored bytes no longer match their recorded digest -- an alert
    an operator should never have to discover by reading an audit row."""
    if _PROM:
        EVIDENCE_INTEGRITY.labels(_bounded(result, _INTEGRITY_RESULTS)).inc()


def record_tunnel_state(pool_id: str, *, up: bool, handshake_age_s=None) -> None:
    """Tunnel health for one private pool. Keyed by POOL, not by site or workspace: a pool
    maps 1:1 to a site operationally, but the pool id is an infrastructure name rather than
    a tenant identifier."""
    if not _PROM:
        return
    label = pool_id or "unknown"
    TUNNEL_STATE.labels(label).set(1 if up else 0)
    if handshake_age_s is not None:
        TUNNEL_HANDSHAKE_AGE.labels(label).set(float(handshake_age_s))


def record_vpn_egress_state(
    pool_id: str, *, up: bool, handshake_age_s=None, exit_ip_verified=None
) -> None:
    """VPN egress health for one pool. Keyed by POOL, like the tunnel gauge, and for the
    same reason -- a pool id is an infrastructure name, never a tenant identifier.

    `exit_ip_verified` is reported SEPARATELY from `up` because the two fail
    independently and the distinction is the whole point of this feature: a tunnel can be
    perfectly up while traffic bypasses it entirely, and an alert needs to tell those
    apart."""
    if not _PROM:
        return
    label = pool_id or "unknown"
    VPN_EGRESS_STATE.labels(label).set(1 if up else 0)
    if handshake_age_s is not None:
        VPN_EGRESS_HANDSHAKE_AGE.labels(label).set(float(handshake_age_s))
    if exit_ip_verified is not None:
        VPN_EGRESS_EXIT_IP_VERIFIED.labels(label).set(1 if exit_ip_verified else 0)


def record_vpn_egress_blocked(reason: str) -> None:
    """One scan refused because VPN egress could not be verified."""
    if _PROM:
        VPN_EGRESS_BLOCKED.labels(reason or "unknown").inc()


def record_vpn_egress_midscan_loss(reason: str) -> None:
    """One RUNNING scan cancelled because egress became unverifiable mid-flight."""
    if _PROM:
        VPN_EGRESS_MIDSCAN_LOSS.labels(reason or "unknown").inc()


def record_worker_heartbeat_age(pool_id: str, seconds: float) -> None:
    if _PROM:
        WORKER_HEARTBEAT_AGE.labels(pool_id or "unknown").set(max(0.0, float(seconds)))


def record_scanner_queue_depth(zone: str, depth: int) -> None:
    """Queue depth by ZONE (public/private) -- not per site, which would leak how many
    private sites exist and how busy each customer is."""
    if _PROM:
        SCANNER_QUEUE_DEPTH.labels(zone or "unknown").set(max(0, int(depth)))


def record_worker_revoked() -> None:
    if _PROM:
        WORKER_REVOKED.inc()


def record_site_suspended() -> None:
    if _PROM:
        SITE_SUSPENDED.inc()


def record_ai_error(provider: str) -> None:
    """AI-2.5: count one AI call that ultimately failed (label: bounded provider name)."""
    if _PROM:
        AI_ERRORS.labels(provider or "unknown").inc()


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


# --- F4: reliability signals (DLQ depth + backup/retention failures) -----------------------
# These read from a SHARED source (Redis) at scrape time and are exposed on the API /metrics
# endpoint, so they surface across processes WITHOUT the worker prefork/multiprocess machinery.
# Additive: nothing above changes. Registered API-side only (see register_reliability_collector),
# so they appear once, on the mbs-api scrape target.
DLQ_REDIS_KEY = "dlq:scans.run_scan"                          # must match scan_tasks.DLQ_KEY
BACKUP_FAILURES_KEY = "mbs:reliability:backup_failures_total"
RETENTION_FAILURES_KEY = "mbs:reliability:retention_failures_total"
# DR-4: unix timestamp of the last SUCCESSFUL backup set; drives mbs_backup_age_seconds so a
# silently-stalled backup pipeline is alertable even while no explicit failure is recorded.
BACKUP_LAST_SUCCESS_KEY = "mbs:reliability:backup_last_success_ts"
# P1.1: unix timestamp of the last beat-dispatched heartbeat a worker processed; drives
# mbs_beat_age_seconds so a stalled beat scheduler (or a down worker-default) is alertable even
# while no task explicitly fails.
BEAT_LAST_TICK_KEY = "mbs:reliability:beat_last_tick_ts"
# Broker queue-depth backlog: the kombu Redis transport keys each Celery queue's pending-message
# list by the queue NAME, so LLEN(<queue>) is the count of tasks waiting to be picked up. These
# MUST match worker.py (task_default_queue="default" + the scans route). ASSUMPTION: no priority
# queues are configured -- Celery priorities would suffix these keys and change the mapping.
_BROKER_QUEUES = ("scans", "default")


def _reliability_redis():
    """Best-effort Redis client for the reliability signals; None if redis/config is unavailable."""
    try:
        import redis

        from apps.api.core.config import get_settings

        return redis.from_url(get_settings().redis_url)
    except Exception:  # noqa: BLE001
        return None


def _incr_reliability(key: str) -> None:
    client = _reliability_redis()
    if client is None:
        return
    try:
        client.incr(key)
    except Exception:  # noqa: BLE001 -- reliability accounting must never break the caller
        pass


def record_backup_failure() -> None:
    """Count one failed backup run (F4). Best-effort Redis INCR; never raises."""
    _incr_reliability(BACKUP_FAILURES_KEY)


def record_retention_failure() -> None:
    """Count one failed retention purge run (F4). Best-effort Redis INCR; never raises."""
    _incr_reliability(RETENTION_FAILURES_KEY)


def record_backup_success(ts: int | None = None) -> None:
    """DR-4: stamp the time of the last successful backup set. Best-effort Redis SET; never
    raises. Read back at scrape time as mbs_backup_age_seconds."""
    import time as _time

    client = _reliability_redis()
    if client is None:
        return
    try:
        client.set(BACKUP_LAST_SUCCESS_KEY, int(ts if ts is not None else _time.time()))
    except Exception:  # noqa: BLE001 -- reliability accounting must never break the caller
        pass


def record_beat_tick(ts: int | None = None) -> None:
    """P1.1: stamp the time of the last beat heartbeat. Best-effort Redis SET; never raises.
    Read back at scrape time as mbs_beat_age_seconds. Safe when Redis/config is unavailable."""
    import time as _time

    client = _reliability_redis()
    if client is None:
        return
    try:
        client.set(BEAT_LAST_TICK_KEY, int(ts if ts is not None else _time.time()))
    except Exception:  # noqa: BLE001 -- reliability accounting must never break the caller
        pass


# --- Dependency health (A): active liveness of the core backing services ----------------------
# Exposed as mbs_dependency_up{component} on the API /metrics via a scrape-time collector doing
# SHORT-TIMEOUT SYNCHRONOUS probes. The /ready probe already checks MySQL+Redis but is not
# scraped, so a Redis-only outage (whose paths fail open) is otherwise near-silent. Fully
# best-effort: any probe error is reported as down (0) and never breaks a /metrics scrape.
# Low-cardinality label only (component in {mysql, redis}).
_DEP_PROBE_TIMEOUT_S = 1.0


def _probe_mysql() -> bool:
    """Best-effort sync MySQL liveness (SELECT 1) with a short connect timeout. Uses PyMySQL
    directly (a plain sync DB-API driver, not the app's async aiomysql engine) parsed out of the
    app's async DSN. Never raises.

    Phase 0 MySQL cutover: was `_probe_postgres` / psycopg2 against a `+asyncpg`-stripped DSN;
    PyMySQL takes plain connect kwargs rather than a DSN string, so the URL is parsed instead of
    string-replaced."""
    try:
        import pymysql
        from sqlalchemy.engine import make_url

        from apps.api.core.config import get_settings

        url = make_url(get_settings().database_url)
        conn = pymysql.connect(
            host=url.host or "localhost",
            port=url.port or 3306,
            user=url.username,
            password=url.password or "",
            database=url.database,
            connect_timeout=max(1, int(_DEP_PROBE_TIMEOUT_S)),
        )
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchone()
        finally:
            conn.close()
        return True
    except Exception:  # noqa: BLE001 -- a probe failure means "down", never an exception
        return False


def _probe_redis() -> bool:
    """Best-effort sync Redis liveness (PING) with short socket timeouts. Never raises."""
    try:
        import redis

        from apps.api.core.config import get_settings

        client = redis.from_url(
            get_settings().redis_url,
            socket_connect_timeout=_DEP_PROBE_TIMEOUT_S,
            socket_timeout=_DEP_PROBE_TIMEOUT_S,
        )
        try:
            return bool(client.ping())
        finally:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        return False


if _PROM:
    from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

    class ReliabilityCollector:
        """Yields DLQ depth + backup/retention failure counters read from Redis at scrape time.
        Fully best-effort: any Redis error yields nothing and never breaks a /metrics scrape."""

        def collect(self):
            client = _reliability_redis()
            if client is None:
                return
            try:
                depth = int(client.llen(DLQ_REDIS_KEY) or 0)
                queue_depths = {q: int(client.llen(q) or 0) for q in _BROKER_QUEUES}
                backup_failures = int(client.get(BACKUP_FAILURES_KEY) or 0)
                retention_failures = int(client.get(RETENTION_FAILURES_KEY) or 0)
                last_backup_ts = int(client.get(BACKUP_LAST_SUCCESS_KEY) or 0)
                last_beat_ts = int(client.get(BEAT_LAST_TICK_KEY) or 0)
            except Exception:  # noqa: BLE001
                return
            dlq = GaugeMetricFamily("mbs_dlq_depth", "Scan dead-letter queue depth (LLEN)", labels=["queue"])
            dlq.add_metric(["scans.run_scan"], float(depth))
            yield dlq
            # Broker queue backlog: pending tasks per Celery queue (LLEN of the queue's Redis list).
            # A missing/empty queue reads 0. Assumes queue name == list key (no priority queues).
            qd = GaugeMetricFamily(
                "mbs_queue_depth", "Pending tasks in a Celery broker queue (LLEN)", labels=["queue"]
            )
            for q, d in queue_depths.items():
                qd.add_metric([q], float(d))
            yield qd
            cb = CounterMetricFamily("mbs_backup_failures", "Backup runs that failed (reliability signal)")
            cb.add_metric([], float(backup_failures))
            yield cb
            cr = CounterMetricFamily("mbs_retention_failures", "Retention purge runs that failed (reliability signal)")
            cr.add_metric([], float(retention_failures))
            yield cr
            # DR-4: seconds since the last successful backup (only when we have ever recorded one,
            # so a never-backed-up dev/CI target doesn't emit a misleading age).
            if last_backup_ts > 0:
                import time as _time

                age = GaugeMetricFamily("mbs_backup_age_seconds", "Seconds since the last successful backup set")
                age.add_metric([], max(0.0, _time.time() - last_backup_ts))
                yield age
            # P1.1: seconds since the last beat heartbeat (only once beat has ticked at least once,
            # so a never-started scheduler doesn't emit a misleading age).
            if last_beat_ts > 0:
                import time as _time

                bage = GaugeMetricFamily("mbs_beat_age_seconds", "Seconds since the last Celery beat heartbeat")
                bage.add_metric([], max(0.0, _time.time() - last_beat_ts))
                yield bage

    class DependencyHealthCollector:
        """Yields mbs_dependency_up{component} from short-timeout SYNC probes at scrape time.
        Best-effort: a probe error is reported as down (0); the collector itself never raises, so a
        dependency outage can never break the /metrics scrape."""

        def collect(self):
            g = GaugeMetricFamily(
                "mbs_dependency_up", "Core backing-service liveness (1=up, 0=down)", labels=["component"]
            )
            g.add_metric(["mysql"], 1.0 if _probe_mysql() else 0.0)
            g.add_metric(["redis"], 1.0 if _probe_redis() else 0.0)
            yield g


_reliability_registered = False


def register_reliability_collector() -> bool:
    """Register the Redis-backed ReliabilityCollector on the default Prometheus registry.
    Idempotent + best-effort. Call from the API process ONLY (not the worker, whose :9100 also
    serves the default registry) so the signals appear once, on api:8000/metrics. Returns True
    iff a collector was registered by THIS call."""
    global _reliability_registered
    if not _PROM or _reliability_registered:
        return False
    try:
        from prometheus_client import REGISTRY

        REGISTRY.register(ReliabilityCollector())
        _reliability_registered = True
        return True
    except Exception:  # noqa: BLE001 -- never break app startup on a metrics-wiring issue
        return False


_dependency_registered = False


def register_dependency_health_collector() -> bool:
    """Register the DependencyHealthCollector (mbs_dependency_up) on the default registry.
    Idempotent + best-effort. Call from the API process ONLY (mirrors register_reliability_collector)
    so the gauge appears once, on api:8000/metrics. Returns True iff registered by THIS call."""
    global _dependency_registered
    if not _PROM or _dependency_registered:
        return False
    try:
        from prometheus_client import REGISTRY

        REGISTRY.register(DependencyHealthCollector())
        _dependency_registered = True
        return True
    except Exception:  # noqa: BLE001 -- never break app startup on a metrics-wiring issue
        return False
