import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from apps.api.core.observability import (
    new_correlation_id,
    record_http_metrics,
    set_correlation_id,
)

logger = logging.getLogger("mbs.http")

_PERIODS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}


def _parse_limit(spec: str) -> tuple[int, int]:
    """"300/minute" -> (300, 60). Falls back to a permissive default on garbage."""
    try:
        count, period = spec.split("/")
        return int(count), _PERIODS[period.strip().lower()]
    except Exception:  # noqa: BLE001
        return 1000, 60


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """Binds a correlation id to the request (from X-Request-ID or generated),
    echoes it back, and records request count/latency metrics. Kept separate from
    security so each concern is independently testable."""

    async def dispatch(self, request: Request, call_next):
        correlation_id = request.headers.get("x-request-id") or new_correlation_id()
        set_correlation_id(correlation_id)
        started = time.monotonic()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["X-Request-ID"] = correlation_id
            return response
        finally:
            duration = time.monotonic() - started
            # Use the route template (not the raw path) to keep metric cardinality bounded.
            route = request.scope.get("route")
            path = getattr(route, "path", request.url.path)
            record_http_metrics(request.method, path, status, duration)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds standard hardening headers to every response. HSTS is opt-in (only
    when actually served over HTTPS) to avoid poisoning http:// local dev."""

    def __init__(self, app, *, enable_hsts: bool = False):
        super().__init__(app)
        self._enable_hsts = enable_hsts

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        if self._enable_hsts:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter backed by Redis (reuses REDIS_URL). Path-aware:
    auth and AI endpoints get tighter limits than the global default.

    Uses a per-key Redis sorted set of request timestamps: each request drops
    entries older than the window, records itself, and counts what remains. Unlike
    a fixed window this smooths the boundary burst (a fixed window allows up to 2x
    the limit across an edge). Fail-open -- if Redis is unreachable, requests are
    allowed (availability over enforcement) and a warning is logged, so a Redis
    blip never takes the API down."""

    def __init__(self, app, *, redis_url: str, default: str, auth: str, ai: str):
        super().__init__(app)
        self._redis_url = redis_url
        self._default = _parse_limit(default)
        self._auth = _parse_limit(auth)
        self._ai = _parse_limit(ai)
        self._redis = None

    def _limit_for(self, path: str) -> tuple[str, tuple[int, int]]:
        if "/auth/" in path:
            return "auth", self._auth
        if "/assistant/" in path or "/ai/" in path:
            return "ai", self._ai
        return "default", self._default

    async def _get_redis(self):
        if self._redis is None:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(self._redis_url, encoding="utf-8", decode_responses=True)
        return self._redis

    async def dispatch(self, request: Request, call_next):
        bucket, (limit, window) = self._limit_for(request.url.path)
        ip = _client_ip(request)
        key = f"rl:{bucket}:{ip}"
        now = time.time()
        try:
            client = await self._get_redis()
            async with client.pipeline(transaction=True) as pipe:
                pipe.zremrangebyscore(key, 0, now - window)          # drop entries outside the window
                pipe.zadd(key, {f"{now}:{uuid.uuid4().hex}": now})   # record this request (unique member)
                pipe.zcard(key)                                      # how many remain in the window
                pipe.expire(key, window + 1)                         # let idle keys self-clean
                results = await pipe.execute()
            count = results[2]
            if count > limit:
                # Same unified error envelope as the exception handlers ({detail, error,
                # correlation_id}); correlation_id comes from ObservabilityMiddleware, which
                # wraps this middleware so the id is already bound. Retry-After preserved.
                from apps.api.core.errors import build_error_envelope

                return JSONResponse(
                    build_error_envelope("Rate limit exceeded. Try again later.", "rate_limited"),
                    status_code=429,
                    headers={"Retry-After": str(window)},
                )
        except Exception:  # noqa: BLE001 -- fail open on limiter/redis failure
            logger.warning("rate limiter unavailable; allowing request", exc_info=True)
        return await call_next(request)
