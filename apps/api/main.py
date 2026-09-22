import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy import text
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from apps.api.core.config import configure_networking, get_settings
from apps.api.core.logging import configure_logging
from apps.api.core.stack_mode import assert_stack_mode_configured
from apps.api.core.middleware import (
    ObservabilityMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)
from apps.api.core.observability import (
    CONTENT_TYPE_LATEST,
    get_correlation_id,
    metrics_response_body,
    register_dependency_health_collector,
    register_reliability_collector,
)
from apps.api.modules.api_keys.router import router as api_keys_router
from apps.api.modules.assessment.router import router as risk_assessments_router
from apps.api.modules.assets.router import router as assets_router
from apps.api.modules.assistant.router import ai_router as ai_status_router
from apps.api.modules.assistant.router import router as assistant_router
from apps.api.modules.ai_usage.router import router as ai_usage_router
from apps.api.modules.audit.router import router as audit_router
from apps.api.modules.auth.router import router as auth_router
from apps.api.modules.billing.router import public_router as plans_public_router
from apps.api.modules.billing.router import router as billing_router
from apps.api.modules.notifications.router import router as notifications_router
from apps.api.modules.authorization_scope.router import router as authorization_scope_router
from apps.api.modules.dashboard.router import router as dashboard_router
from apps.api.modules.projects.router import router as projects_router
from apps.api.modules.remediation.router import router as remediation_router
from apps.api.modules.reports.router import router as reports_router
from apps.api.modules.scans.router import capabilities_router as scan_capabilities_router
from apps.api.modules.scans.router import router as scans_router
from apps.api.modules.schedules.router import router as schedules_router
from apps.api.modules.users.router import router as users_router
from apps.api.modules.vulnerabilities.router import router as vulnerabilities_router
from apps.api.modules.workspaces.router import roles_router as roles_router
from apps.api.modules.workspaces.router import router as workspaces_router

logger = logging.getLogger("mbs.app")

# Refuse to run STALE, BAKED-IN IMAGE CODE. A dev stack started from an incomplete compose
# `-f` list loses the apps/api bind mount and silently serves whatever was in the image at
# its last build -- see apps/api/core/stack_mode.py for the full failure mode.
#
# Deliberately at IMPORT time, not inside `lifespan`: uvicorn's --reload supervisor imports
# this module in a child process, and an exception here stops the boot immediately with the
# remedy on stderr, rather than after the app has bound its port and reported itself healthy.
# The guard is a no-op unless the compose sentinel is present, so importing this module from
# tests, scripts or a non-compose runtime is unaffected.
assert_stack_mode_configured()

_ROUTERS = (
    auth_router, users_router, workspaces_router, roles_router, projects_router,
    dashboard_router, authorization_scope_router, scans_router, scan_capabilities_router, schedules_router,
    assets_router, vulnerabilities_router, reports_router, assistant_router,
    ai_status_router, billing_router, plans_public_router, notifications_router,
    audit_router, api_keys_router, ai_usage_router,
    remediation_router, risk_assessments_router,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    # Mirror proxy / custom-CA settings into the process env for all outbound clients.
    configure_networking(settings)
    # Fail fast if production is misconfigured (placeholder secrets, wildcard CORS, ...).
    settings.validate_production()
    # Phase 0 MySQL cutover: workspace isolation moved from Postgres RLS to an
    # app-layer ORM filter (apps/api/core/tenancy.py). Install it FIRST, before the
    # runtime security checks below -- one of those checks (M4.6.1 / F4) verifies the
    # filter is actually installed, so installing it after would make that check
    # always fail. Every router imported at module level above has already pulled in
    # its models transitively, so Base.metadata is fully populated by this point.
    from apps.api.core import tenancy

    tenancy.install()

    # Prompt 34: the audit tables are documented append-only; this installs the ORM-level
    # guard that actually enforces it (UPDATE never, DELETE only via the retention escape
    # hatch). Same phase as tenancy for the same reason -- mappers are fully registered.
    from apps.api.modules.audit import immutability as audit_immutability

    audit_immutability.install()

    # Runtime security checks that need DB context (M4.6.1): refuse to start in
    # production if workspace isolation isn't installed, and warn when derived-scope
    # enforcement is disabled. Dev warns and continues.
    from apps.api.core.db import engine
    from apps.api.core.startup_checks import run_startup_security_checks

    await run_startup_security_checks(
        engine,
        is_production=settings.is_production,
        enforce_derived_scope=settings.scan_enforce_derived_scope,
    )
    # Non-fatal AI configuration report (no paid call at boot).
    logger.info(
        "ai_configuration",
        extra={
            "provider": settings.ai_provider,
            "model": settings.active_ai_model,
            "enabled": settings.ai_enabled,
        },
    )
    if not settings.ai_enabled:
        logger.warning(
            "AI provider '%s' has no API key; AI features will degrade gracefully (503).",
            settings.ai_provider,
        )
    # Cost-safety nudge: a hosted AI provider is billable, so warn when no daily spend cap is
    # enforced. Non-fatal (some deployments intentionally run uncapped); the local provider is free.
    if settings.ai_enabled and settings.ai_provider != "local" and not (
        settings.ai_budget_enforce and settings.ai_daily_budget_usd > 0
    ):
        logger.warning(
            "AI is enabled on billable provider '%s' with NO daily spend cap "
            "(AI_BUDGET_ENFORCE + AI_DAILY_BUDGET_USD). Set a cap to bound cost/abuse.",
            settings.ai_provider,
        )
    # Rate-limit correctness nudge: behind a reverse proxy with TRUSTED_PROXY_COUNT=0 the app
    # cannot see real client IPs, so anonymous requests all share the proxy's IP bucket while
    # X-Forwarded-For is (correctly) ignored. Warn so operators set the real proxy-hop count.
    if settings.rate_limit_enabled and settings.trusted_proxy_count == 0:
        logger.warning(
            "RATE_LIMIT_ENABLED is on but TRUSTED_PROXY_COUNT=0: X-Forwarded-For is ignored and "
            "anonymous requests are bucketed by the direct peer IP. If the app is behind a reverse "
            "proxy, set TRUSTED_PROXY_COUNT to the number of trusted hops (e.g. 1 behind nginx)."
        )
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, lifespan=lifespan)

    # --- Middleware (added innermost-first; TrustedHost ends up outermost) ---
    if settings.security_headers_enabled:
        app.add_middleware(SecurityHeadersMiddleware, enable_hsts=settings.enable_hsts)
    if settings.rate_limit_enabled:
        app.add_middleware(
            RateLimitMiddleware,
            redis_url=settings.redis_url,
            default=settings.rate_limit_default,
            auth=settings.rate_limit_auth,
            ai=settings.rate_limit_ai,
        )
    app.add_middleware(ObservabilityMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=True,
        allow_methods=["*"] if not settings.is_production else ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)

    # Phase 1.4: consistent error contract for every error path (additive; preserves
    # the existing ``detail`` field, adds a stable error code + correlation id).
    from apps.api.core.errors import register_exception_handlers

    register_exception_handlers(app)

    for router in _ROUTERS:
        app.include_router(router, prefix=settings.api_v1_prefix)

    @app.get("/health")
    def health() -> dict:
        """Liveness: the process is up. No dependency checks (never fails on a DB blip).
        Intentionally minimal -- this probe is unauthenticated, so it must not disclose the
        environment name or other deployment metadata to anonymous callers."""
        return {"status": "ok"}

    @app.get("/ready")
    async def ready() -> Response:
        """Readiness: can the app actually serve?

        Three INDEPENDENT checks, reported separately (AUDIT-002 / AUDIT-007):
          * database  -- connectivity (MySQL, not Postgres: the docstring predated the cutover)
          * schema    -- the live alembic_version matches this build's migration head
          * redis     -- broker/cache liveness, deliberately kept apart from schema validation

        503 if any fails. `SELECT 1` alone was NOT readiness: it answers "is a database
        listening", not "is it the schema this code expects" -- a node whose migration step
        was skipped reported ready and then 500ed on the first query touching a missing table.
        """
        checks: dict[str, str] = {}
        ok = True
        try:
            from apps.api.core.db import engine

            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            checks["database"] = "ok"
        except Exception:  # noqa: BLE001
            # Generic status to the client -- never leak raw driver/topology error text on
            # this unauthenticated probe. Full exception + correlation context to the logs.
            checks["database"] = "error"
            ok = False
            logger.warning(
                "ready.check_failed component=database",
                extra={"event": "ready.check_failed", "component": "database",
                       "correlation_id": get_correlation_id()},
                exc_info=True,
            )
        # Schema version -- separate from both connectivity and Redis. Only reported as ok
        # when the DB revision is exactly this build's head; behind/ahead/unknown all mean
        # this node must not receive traffic.
        try:
            from apps.api.core.db import engine as _schema_engine
            from apps.api.core.schema_version import check_schema_version

            schema_status = await check_schema_version(_schema_engine)
            if schema_status.is_healthy:
                checks["schema"] = "ok"
            else:
                # State name only -- never the revision ids or detail text, which would
                # disclose deployment internals on this unauthenticated probe.
                checks["schema"] = schema_status.state.value
                ok = False
                logger.warning(
                    "ready.check_failed component=schema",
                    extra={"event": "ready.check_failed", "component": "schema",
                           "state": schema_status.state.value,
                           "db_revision": schema_status.db_revision,
                           "head_revision": schema_status.head_revision,
                           "correlation_id": get_correlation_id()},
                )
        except Exception:  # noqa: BLE001
            checks["schema"] = "error"
            ok = False
            logger.warning(
                "ready.check_failed component=schema",
                extra={"event": "ready.check_failed", "component": "schema",
                       "correlation_id": get_correlation_id()},
                exc_info=True,
            )

        try:
            import redis.asyncio as aioredis

            client = aioredis.from_url(settings.redis_url)
            await client.ping()
            await client.aclose()
            checks["redis"] = "ok"
        except Exception:  # noqa: BLE001
            checks["redis"] = "error"
            ok = False
            logger.warning(
                "ready.check_failed component=redis",
                extra={"event": "ready.check_failed", "component": "redis",
                       "correlation_id": get_correlation_id()},
                exc_info=True,
            )
        return JSONResponse({"status": "ready" if ok else "not_ready", "checks": checks},
                            status_code=200 if ok else 503)

    @app.get("/metrics")
    def metrics(request: Request) -> Response:
        """Prometheus scrape endpoint. Access is governed by METRICS_MODE
        (secure by default): disabled | token | authenticated | public."""
        mode = settings.metrics_mode
        if mode == "disabled":
            return Response(status_code=404)
        if mode == "authenticated":
            from apps.api.core.security import decode_access_token

            authz = request.headers.get("authorization", "")
            token = authz[7:] if authz[:7].lower() == "bearer " else ""
            try:
                decode_access_token(token)
            except Exception:  # noqa: BLE001
                return Response("Unauthorized", status_code=401)
        elif mode != "public":  # "token" (default) or any unknown value -> fail closed
            import hmac

            supplied = request.headers.get("x-metrics-token", "")
            if not settings.metrics_token or not hmac.compare_digest(supplied, settings.metrics_token):
                return Response("Forbidden", status_code=403)
        return Response(metrics_response_body(), media_type=CONTENT_TYPE_LATEST)

    # F4: expose the Redis-backed reliability signals (DLQ depth + backup/retention failures) on
    # this API process's /metrics only (idempotent; the worker's :9100 must not double-expose them).
    register_reliability_collector()
    # A: expose mbs_dependency_up{component} (Postgres/Redis liveness) on this API process's
    # /metrics only (same rationale -- registered once, best-effort).
    register_dependency_health_collector()

    return app


app = create_app()
