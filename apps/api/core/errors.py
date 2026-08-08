"""Phase 1.4 -- API error contract.

A single, consistent error envelope for every error path (validation, auth, not-found,
and unhandled internal faults), with:
  * backward compatibility: the existing ``detail`` field is preserved verbatim, so
    clients/tests that read ``response.json()["detail"]`` keep working;
  * a stable ``error`` code for programmatic handling;
  * the request ``correlation_id`` echoed into the body (the ``X-Request-ID`` header is
    set by ObservabilityMiddleware and re-asserted here for error paths);
  * structured error logging (no stack traces or secrets in the response);
  * an ``mbs_api_errors_total{type}`` metric.

Only these handlers are added; no existing route behavior changes.
"""
import logging

from fastapi import FastAPI, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse

from apps.api.core.observability import get_correlation_id, record_api_error

logger = logging.getLogger("mbs.error")

# status code -> stable, low-cardinality error type. Anything unmapped collapses to
# "http_error" (4xx) or "internal_error" (5xx) so the metric label set stays bounded.
_CODE_BY_STATUS = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    422: "validation_error",
    429: "rate_limited",
}


def _error_type(status_code: int) -> str:
    if status_code in _CODE_BY_STATUS:
        return _CODE_BY_STATUS[status_code]
    return "internal_error" if status_code >= 500 else "http_error"


def _envelope(detail, error_type: str) -> dict:
    # ``detail`` first preserves the historical shape; extra keys are purely additive.
    return {"detail": detail, "error": error_type, "correlation_id": get_correlation_id()}


def build_error_envelope(detail, error_type: str) -> dict:
    """Public builder for the standard error envelope, so error paths that do NOT flow
    through the exception handlers (e.g. the rate-limit middleware short-circuit, which runs
    before routing) can emit the identical {detail, error, correlation_id} shape without
    duplicating the contract."""
    return _envelope(detail, error_type)


def _respond(status_code: int, detail, error_type: str, headers=None) -> JSONResponse:
    resp = JSONResponse(_envelope(detail, error_type), status_code=status_code, headers=headers)
    # Guarantee the correlation id is present on error responses even when the
    # unhandled-exception path skipped the middleware's success branch.
    resp.headers["X-Request-ID"] = get_correlation_id()
    return resp


def _log_client_error(request: Request, status_code: int, error_type: str) -> None:
    # 4xx are client faults -- log at INFO/WARNING WITHOUT a traceback (no noise, no leak).
    level = logging.WARNING if status_code in (401, 403) else logging.INFO
    logger.log(
        level,
        "api.error %s %s -> %s",
        request.method,
        request.url.path,
        status_code,
        extra={
            "event": "api.error",
            "error": error_type,
            "status": status_code,
            "method": request.method,
            "path": request.url.path,
            "correlation_id": get_correlation_id(),
        },
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Consistent envelope for HTTPException / StarletteHTTPException (covers 401/403/404/
    409/... raised anywhere). Preserves ``exc.detail`` and any ``exc.headers`` (e.g.
    WWW-Authenticate / Retry-After) so auth and rate-limit semantics are unchanged."""
    error_type = _error_type(exc.status_code)
    record_api_error(error_type)
    _log_client_error(request, exc.status_code, error_type)
    return _respond(exc.status_code, exc.detail, error_type, headers=getattr(exc, "headers", None))


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """422 for request validation errors. Keeps the standard list-of-errors ``detail`` so
    existing clients see the same structure, just wrapped in the shared envelope."""
    record_api_error("validation_error")
    _log_client_error(request, 422, "validation_error")
    # jsonable_encoder mirrors FastAPI's default so ctx objects (e.g. ValueError) serialize.
    return _respond(422, jsonable_encoder(exc.errors()), "validation_error")


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all for uncaught exceptions -> 500. The FULL exception (with traceback) is
    logged server-side ONLY; the response body is a fixed, generic message so no stack
    trace, exception text, or secret can ever leak to the client."""
    record_api_error("internal_error")
    logger.error(
        "api.error %s %s -> 500 (%s)",
        request.method,
        request.url.path,
        type(exc).__name__,
        extra={
            "event": "api.error",
            "error": "internal_error",
            "status": 500,
            "method": request.method,
            "path": request.url.path,
            "correlation_id": get_correlation_id(),
        },
        exc_info=True,
    )
    return _respond(500, "Internal Server Error", "internal_error")


def register_exception_handlers(app: FastAPI) -> None:
    """Wire the handlers. HTTPException (FastAPI) subclasses StarletteHTTPException, so the
    single registration covers both. The bare ``Exception`` registration installs the 500
    handler on Starlette's ServerErrorMiddleware."""
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
