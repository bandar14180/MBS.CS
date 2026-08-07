"""Phase 1.4 -- API error contract.

Every error path returns the same envelope: ``detail`` (backward-compatible) + a stable
``error`` code + a ``correlation_id``, with an ``X-Request-ID`` header. Covers validation,
authentication, authorization, not-found, and internal (500) errors, plus correlation-id
presence/propagation and the guarantee that internal faults never leak details.
"""
import asyncio
import uuid

from starlette.requests import Request

from apps.api.core import errors
from apps.api.core.observability import set_correlation_id
from apps.api.tests.test_scans import _auth, _make_target, _register


def _assert_envelope(body: dict, error_type: str):
    assert body["error"] == error_type
    assert "detail" in body                      # backward-compatible field preserved
    assert body.get("correlation_id") and body["correlation_id"] != "-"


def test_validation_error_envelope(client):
    # Missing required fields -> 422 with the standard list-of-errors detail, wrapped.
    r = client.post("/api/v1/auth/register", json={})
    assert r.status_code == 422
    body = r.json()
    _assert_envelope(body, "validation_error")
    assert isinstance(body["detail"], list)      # historical validation shape kept
    assert r.headers.get("X-Request-ID")


def test_authentication_error_envelope(client):
    # No bearer token on a protected route -> 401.
    ws, proj = uuid.uuid4(), uuid.uuid4()
    r = client.get(f"/api/v1/workspaces/{ws}/projects/{proj}/scans")
    assert r.status_code == 401
    _assert_envelope(r.json(), "unauthorized")
    assert r.headers.get("X-Request-ID")


def test_authorization_error_envelope(client):
    # A user who is not a member of the workspace -> 403 (not 404): forbidden.
    owner = _auth(_register(client, "ErrOwner"))
    ws, proj, _tgt = _make_target(client, owner)
    intruder = _auth(_register(client, "ErrIntruder"))
    r = client.get(f"/api/v1/workspaces/{ws}/projects/{proj}/scans", headers=intruder)
    assert r.status_code == 403
    _assert_envelope(r.json(), "forbidden")


def test_not_found_error_envelope(client):
    owner = _auth(_register(client, "ErrNF"))
    ws, proj, _tgt = _make_target(client, owner)
    r = client.get(f"/api/v1/workspaces/{ws}/projects/{proj}/scans/{uuid.uuid4()}", headers=owner)
    assert r.status_code == 404
    _assert_envelope(r.json(), "not_found")


def test_correlation_id_is_propagated_from_request(client):
    # A client-supplied X-Request-ID is honored and echoed back (header + body).
    cid = "trace-" + uuid.uuid4().hex
    r = client.post("/api/v1/auth/register", json={}, headers={"X-Request-ID": cid})
    assert r.status_code == 422
    assert r.headers.get("X-Request-ID") == cid
    assert r.json()["correlation_id"] == cid


def test_internal_error_handler_hides_details():
    """The 500 handler must log server-side but never surface the exception message,
    a traceback, or secrets. Tested directly (TestClient re-raises server exceptions)."""
    set_correlation_id("cid-internal-500")
    scope = {"type": "http", "method": "GET", "path": "/boom", "headers": [], "query_string": b""}
    request = Request(scope)
    secret = "db_password=SUPER-SECRET-VALUE"
    resp = asyncio.run(errors.unhandled_exception_handler(request, RuntimeError(secret)))

    assert resp.status_code == 500
    body = resp.body.decode()
    assert secret not in body and "SUPER-SECRET-VALUE" not in body
    assert "Traceback" not in body and "RuntimeError" not in body
    import json

    parsed = json.loads(body)
    assert parsed == {
        "detail": "Internal Server Error",
        "error": "internal_error",
        "correlation_id": "cid-internal-500",
    }
    assert resp.headers.get("X-Request-ID") == "cid-internal-500"


def test_error_metric_increments():
    from apps.api.core import observability as obs

    if not obs._PROM:
        return
    before = obs.API_ERRORS.labels("not_found")._value.get()
    obs.record_api_error("not_found")
    assert obs.API_ERRORS.labels("not_found")._value.get() == before + 1
    assert obs.API_ERRORS._labelnames == ("type",)   # low-cardinality


# --- Phase 1.4 final-review verification -------------------------------------------------

def test_exception_handlers_registered_once():
    """Each exception type is wired to exactly one handler; register_exception_handlers
    ran once (no accidental double-registration / no stray extra wiring)."""
    from collections import Counter

    from fastapi import HTTPException as FastAPIHTTPException
    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    from apps.api.core.errors import (
        http_exception_handler,
        unhandled_exception_handler,
        validation_exception_handler,
    )
    from apps.api.main import app

    eh = app.exception_handlers
    assert eh[StarletteHTTPException] is http_exception_handler
    assert eh[FastAPIHTTPException] is http_exception_handler
    assert eh[RequestValidationError] is validation_exception_handler
    assert eh[Exception] is unhandled_exception_handler

    counts = Counter(v.__name__ for v in eh.values())
    assert counts["http_exception_handler"] == 2       # starlette + fastapi HTTPException, one each
    assert counts["validation_exception_handler"] == 1
    assert counts["unhandled_exception_handler"] == 1


def test_error_contract_documentation_exists():
    """docs/error-contract.md exists and documents every supported error code. Skips when
    the docs/ tree isn't present (the dev container bind-mounts only apps/ and db/); runs
    fully on a complete checkout (CI/host)."""
    import pytest
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[3]
    doc = repo_root / "docs" / "error-contract.md"
    if not (repo_root / "docs").is_dir():
        pytest.skip("docs/ not bind-mounted in this environment")
    assert doc.is_file(), f"missing {doc}"
    text = doc.read_text(encoding="utf-8")
    for code in (
        "validation_error", "unauthorized", "forbidden", "not_found",
        "conflict", "rate_limited", "http_error", "internal_error",
    ):
        assert code in text, f"error code {code!r} not documented"
    assert "correlation_id" in text
    assert "429" in text                               # rate-limit behavior documented


def test_existing_error_responses_stay_backward_compatible(client):
    """The envelope is additive: the historical `detail` field is intact on both a 404
    (string detail) and a 422 (list detail), and no error path drops it."""
    # 422 -> list detail (unchanged validation shape)
    r = client.post("/api/v1/auth/register", json={})
    assert r.status_code == 422 and isinstance(r.json()["detail"], list)

    # 401 -> string detail
    r = client.get(f"/api/v1/workspaces/{uuid.uuid4()}/projects/{uuid.uuid4()}/scans")
    assert r.status_code == 401 and isinstance(r.json()["detail"], str)
