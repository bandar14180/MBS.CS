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
    """Best-effort client IP for rate-limit bucketing.

    X-Forwarded-For is set by the client and MUST NOT be trusted unless the app actually
    sits behind a known number of trusted proxies (TRUSTED_PROXY_COUNT). With N>0 trusted
    proxies we take the client's own hop as the Nth entry FROM THE RIGHT -- the rightmost
    entries are appended by our trusted proxies, the leftmost are attacker-spoofable. With
    the default 0 we ignore XFF entirely and use the direct socket peer, so spoofing the
    header cannot fabricate an unlimited number of distinct rate-limit buckets."""
    from apps.api.core.config import get_settings

    n = get_settings().trusted_proxy_count
    if n > 0:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            parts = [p.strip() for p in fwd.split(",") if p.strip()]
            if len(parts) >= n:
                return parts[-n]
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


# FastAPI's built-in interactive-docs HTML (Swagger UI at /docs, ReDoc at /redoc -- neither
# path is overridden in main.py's `FastAPI(...)` call, so these are the real, fixed URLs) is
# the one part of this app that is actual browser-rendered HTML pulling in external JS/CSS/
# images and running inline bootstrap scripts. Every other route returns JSON, which never
# legitimately needs to load or execute anything -- that's exactly what `default-src 'none'`
# is for, and it must stay the default. Found by actually loading /docs in a browser: the
# strict CSP silently blocked every asset the Swagger UI page needs, rendering a blank page
# with no visible error except in the browser console. /openapi.json is untouched by this
# exception (it's plain JSON, not HTML) and gets the strict policy like any other endpoint.
_DOCS_UI_PATHS = frozenset({"/docs", "/redoc"})


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
        if request.url.path not in _DOCS_UI_PATHS:
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
    the limit across an edge).

    OUTAGE BEHAVIOUR IS BUCKET-DEPENDENT (F-07). It used to be fail-open for
    everything: one `except Exception` around the whole dispatch meant a Redis
    outage silently removed every limit. For ordinary traffic that trade is right --
    availability beats enforcement, and a Redis blip must not take the API down.
    For `/auth/` it is not: the limiter is the ONLY throttle on password and MFA
    guessing (the per-user MFA lockout in modules/auth/mfa_guard.py is Redis-backed
    too and also fails open), so an outage removed EVERY brute-force defence at once
    and turned a cache incident into an open credential-guessing window.

    So the auth bucket now FAILS CLOSED -- 503 with Retry-After while the limiter is
    unavailable -- and every other bucket keeps failing open. Read/scan/report traffic
    is unaffected by a Redis blip; only credential endpoints pause, which is the
    correct direction to fail for an authentication boundary."""

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

    @staticmethod
    def _principal(request: Request) -> str:
        """The rate-limit identity. Prefer the authenticated user (stable, and immune to
        NAT/proxy IP sharing or X-Forwarded-For spoofing); fall back to the client IP for
        anonymous requests. The bearer token is validated by a pure, side-effect-free JWT
        decode -- any invalid/absent token degrades to the IP bucket, never raising."""
        authz = request.headers.get("authorization", "")
        if authz[:7].lower() == "bearer ":
            token = authz[7:].strip()
            try:
                from apps.api.core.security import decode_access_token

                sub = decode_access_token(token).get("sub")
                if sub:
                    return f"user:{sub}"
            except Exception:  # noqa: BLE001 -- unauthenticated/invalid token -> IP bucket
                pass
        return f"ip:{_client_ip(request)}"

    async def _get_redis(self):
        if self._redis is None:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(self._redis_url, encoding="utf-8", decode_responses=True)
        return self._redis

    async def dispatch(self, request: Request, call_next):
        bucket, (limit, window) = self._limit_for(request.url.path)
        key = f"rl:{bucket}:{self._principal(request)}"
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
        except Exception:  # noqa: BLE001 -- limiter/redis failure
            # F-07: fail CLOSED for auth, OPEN for everything else. See the class docstring.
            if bucket == "auth":
                logger.warning(
                    "rate limiter unavailable; REFUSING auth request (fail closed)", exc_info=True
                )
                from apps.api.core.errors import build_error_envelope

                return JSONResponse(
                    build_error_envelope(
                        "Authentication is temporarily unavailable. Try again shortly.",
                        "service_unavailable",
                    ),
                    status_code=503,
                    headers={"Retry-After": str(window)},
                )
            logger.warning("rate limiter unavailable; allowing request", exc_info=True)
        return await call_next(request)
