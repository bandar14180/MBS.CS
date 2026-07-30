import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy import text
from starlette.responses import JSONResponse, Response

from apps.api.core.config import configure_networking, get_settings
from apps.api.core.logging import configure_logging
from apps.api.core.middleware import (
    ObservabilityMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)
from apps.api.core.observability import CONTENT_TYPE_LATEST, metrics_response_body
from apps.api.modules.api_keys.router import router as api_keys_router
from apps.api.modules.assets.router import router as assets_router
from apps.api.modules.assistant.router import ai_router as ai_status_router
from apps.api.modules.assistant.router import router as assistant_router
from apps.api.modules.audit.router import router as audit_router
from apps.api.modules.auth.router import router as auth_router
from apps.api.modules.billing.router import public_router as plans_public_router
from apps.api.modules.billing.router import router as billing_router
from apps.api.modules.notifications.router import router as notifications_router
from apps.api.modules.authorization_scope.router import router as authorization_scope_router
from apps.api.modules.dashboard.router import router as dashboard_router
from apps.api.modules.projects.router import router as projects_router
from apps.api.modules.reports.router import router as reports_router
from apps.api.modules.scans.router import router as scans_router
from apps.api.modules.schedules.router import router as schedules_router
from apps.api.modules.users.router import router as users_router
from apps.api.modules.vulnerabilities.router import router as vulnerabilities_router
from apps.api.modules.workspaces.router import roles_router as roles_router
from apps.api.modules.workspaces.router import router as workspaces_router

logger = logging.getLogger("mbs.app")

_ROUTERS = (
    auth_router, users_router, workspaces_router, roles_router, projects_router,
    dashboard_router, authorization_scope_router, scans_router, schedules_router,
    assets_router, vulnerabilities_router, reports_router, assistant_router,
    ai_status_router, billing_router, plans_public_router, notifications_router,
    audit_router, api_keys_router,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    # Mirror proxy / custom-CA settings into the process env for all outbound clients.
    configure_networking(settings)
    # Fail fast if production is misconfigured (placeholder secrets, wildcard CORS, ...).
    settings.validate_production()
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

    for router in _ROUTERS:
        app.include_router(router, prefix=settings.api_v1_prefix)

    @app.get("/health")
    def health() -> dict:
        """Liveness: the process is up. No dependency checks (never fails on a DB blip)."""
        return {"status": "ok", "service": settings.app_name, "environment": settings.environment}

    @app.get("/ready")
    async def ready() -> Response:
        """Readiness: can the app actually serve? Probes Postgres and Redis; 503 if either is down."""
        checks: dict[str, str] = {}
        ok = True
        try:
            from apps.api.core.db import engine

            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            checks["database"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["database"] = f"error: {exc}"[:200]
            ok = False
        try:
            import redis.asyncio as aioredis

            client = aioredis.from_url(settings.redis_url)
            await client.ping()
            await client.aclose()
            checks["redis"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["redis"] = f"error: {exc}"[:200]
            ok = False
        return JSONResponse({"status": "ready" if ok else "not_ready", "checks": checks},
                            status_code=200 if ok else 503)

    @app.get("/metrics")
    def metrics() -> Response:
        """Prometheus scrape endpoint."""
        return Response(metrics_response_body(), media_type=CONTENT_TYPE_LATEST)

    return app


app = create_app()
