"""Phase 4.1 -- worker-process Prometheus metrics endpoint.

The Celery worker is where scans actually run, so the scan/tool/AI/reaper/relay counters
(core/observability.py) are incremented there -- but ``/metrics`` is served by the API
process only. This starts a small, BEST-EFFORT HTTP metrics server inside the worker so
those metrics become scrapable, without adding any Prometheus/Grafana infrastructure.

Design notes:
  * Best-effort: any failure to bind/start is logged and swallowed -- worker startup must
    never fail because metrics couldn't start.
  * Config-driven (worker_metrics_enabled / worker_metrics_port) and _PROM-guarded.
  * Prefork aggregation: when ``PROMETHEUS_MULTIPROC_DIR`` is set on the worker container,
    the endpoint serves a MultiProcessCollector registry that aggregates every prefork
    child. Without it, it serves the default (single-process) registry -- see the phase
    report for the recommended one-line worker env to enable full aggregation.
"""
import logging
import os

logger = logging.getLogger("mbs.metrics")


def start_worker_metrics_server() -> bool:
    """Start the worker Prometheus endpoint. Returns True iff a server was started. Never
    raises -- safe to call from a Celery ``worker_ready`` signal handler."""
    from apps.api.core.config import get_settings
    from apps.api.core.observability import _PROM

    settings = get_settings()
    if not settings.worker_metrics_enabled:
        logger.info("worker metrics disabled (worker_metrics_enabled=false)")
        return False
    if not _PROM:
        logger.info("prometheus_client not installed; worker metrics endpoint skipped")
        return False

    try:
        from prometheus_client import CollectorRegistry, start_http_server

        port = int(settings.worker_metrics_port)
        if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
            # Aggregate all prefork children's metric files into one registry.
            from prometheus_client import multiprocess

            registry = CollectorRegistry()
            multiprocess.MultiProcessCollector(registry)
            start_http_server(port, registry=registry)
            logger.info("worker metrics server started on :%d (multiprocess)", port)
        else:
            start_http_server(port)  # default process-local registry
            logger.info("worker metrics server started on :%d (single-process)", port)
        return True
    except Exception:  # noqa: BLE001 -- observability must never break worker startup
        logger.warning(
            "worker metrics server failed to start on :%s (continuing without it)",
            getattr(get_settings(), "worker_metrics_port", "?"),
            exc_info=True,
        )
        return False
