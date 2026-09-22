"""F-9-01 -- heartbeat telemetry validation boundary.

THE FINDING THESE PIN
---------------------
`HeartbeatIn.health_state` was `str` (length-capped only) and `handshake_age_s` an unbounded
`int`, so an AUTHENTICATED, ACTIVE worker could post nonsense and have it persisted verbatim.
Confirmed in the Phase 9 adversarial audit against the live stack, then read back from MySQL:

    POST /v1/heartbeat {"health_state":"super-healthy","handshake_age_s":-99999}  -> 200
    SELECT ... -> health_state='super-healthy'  last_handshake_age_s=-99999

WHY IT MATTERED, AND WHY IT WAS ONLY LOW
----------------------------------------
No authorization gate reads either column -- leasing is decided by status + pool/site/
workspace binding + the emergency flag, and private scanning by the live per-job tunnel probe
(`preflight_private_job`). So this was never an authorization bypass.

It WAS a telemetry-integrity defect, and the negative age was the sharper half:
`last_handshake_age_s` is exported as `mbs_tunnel_handshake_age_seconds`, whose alert fires on
`> 600`. A worker reporting a negative age could suppress `MbsTunnelHandshakeStale` for its own
pool indefinitely. `mbs_tunnel_up` was unaffected (it requires exactly 'healthy', so
'super-healthy' correctly projected 0).

REJECT, NEVER COERCE
--------------------
The fix fails the request at the validation boundary with 422. Silently mapping
'super-healthy' -> 'unknown' or -99999 -> 0 was deliberately NOT chosen: it would store a
plausible-looking row and hide the fact that a worker sent malformed or hostile telemetry.

WHAT THESE TESTS ALSO GUARD
---------------------------
That the fix stayed a TELEMETRY fix. `test_health_state_is_not_an_authorization_input` asserts
no authorization gate consults these fields, so a future change cannot quietly promote
self-reported health into a security primitive.
"""
import asyncio
import uuid

import pydantic
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.core.deps import get_db
from apps.api.modules.scanner_workers import service as workers_service
from apps.api.modules.scanner_workers.models import WORKER_HEALTH_STATES, ScannerWorker
from apps.api.scanner_manager.app import HeartbeatIn
from apps.api.scanner_manager.app import app as manager_app

VALID_STATES = ("healthy", "degraded", "unhealthy", "unknown")
INVALID_STATES = ("super-healthy", "admin", "healthy123", "", "HEALTHY", "  healthy  ")


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


# =========================================================================================
# Schema-level: the constraint itself
# =========================================================================================

@pytest.mark.parametrize("state", VALID_STATES)
def test_every_legitimate_health_state_is_accepted(state):
    """The four documented states must all still work -- a fix that rejected a legitimate
    value would break the real worker, which emits 'healthy' and 'unhealthy'."""
    assert HeartbeatIn(health_state=state).health_state == state


@pytest.mark.parametrize("state", INVALID_STATES)
def test_invalid_health_states_are_rejected_not_coerced(state):
    """Rejected, and specifically NOT silently mapped to 'unknown'.

    'HEALTHY' and '  healthy  ' are included deliberately: the metrics projection tolerates
    case/whitespace when READING pre-existing rows, but the write boundary is strict, so a
    worker cannot introduce such a row in the first place.
    """
    with pytest.raises(pydantic.ValidationError):
        HeartbeatIn(health_state=state)


@pytest.mark.parametrize("age", (0, 1, 600, 99999))
def test_non_negative_handshake_ages_are_accepted(age):
    assert HeartbeatIn(handshake_age_s=age).handshake_age_s == age


@pytest.mark.parametrize("age", (-1, -99999))
def test_negative_handshake_ages_are_rejected(age):
    """THE ALERT-SUPPRESSION HALF. A negative age is exported as
    `mbs_tunnel_handshake_age_seconds` and would sit permanently below the `> 600` threshold
    of MbsTunnelHandshakeStale."""
    with pytest.raises(pydantic.ValidationError):
        HeartbeatIn(handshake_age_s=age)


def test_handshake_age_may_still_be_omitted():
    """None is meaningful and must stay allowed: a PUBLIC worker has no tunnel and reports no
    age, and the projection renders a missing age as absent rather than 0."""
    assert HeartbeatIn().handshake_age_s is None
    assert HeartbeatIn(handshake_age_s=None).handshake_age_s is None


def test_the_boundary_and_the_stored_column_share_one_vocabulary():
    """The drift guard, asserted as a test as well as at import: the API must accept exactly
    what the column documents, or one of them is wrong."""
    assert set(HeartbeatIn.model_fields["health_state"].annotation.__args__) == set(
        WORKER_HEALTH_STATES
    )
    assert set(WORKER_HEALTH_STATES) == set(VALID_STATES)


def test_the_openapi_schema_publishes_the_constraints():
    """OpenAPI must document the allowed set and the lower bound, so a client sees the
    contract instead of discovering it through a 422."""
    schema = manager_app.openapi()
    props = schema["components"]["schemas"]["HeartbeatIn"]["properties"]
    assert set(props["health_state"]["enum"]) == set(VALID_STATES)
    age = props["handshake_age_s"]
    # `int | None` renders as anyOf; the integer branch carries the bound.
    branches = age.get("anyOf", [age])
    assert any(b.get("minimum") == 0 for b in branches), age


# =========================================================================================
# HTTP boundary + PERSISTENCE: the values must never reach the database
# =========================================================================================

@pytest.fixture
def env():
    """A live manager TestClient plus one ACTIVE worker with known telemetry.

    Engine-per-loop for the reason `test_scanner_manager_http.manager_env` documents:
    TestClient drives the app on its own loop, and an AsyncEngine binds pooled connections
    to the loop that created them.
    """
    state = {}

    async def seed():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    token = workers_service.generate_worker_token()
                    worker = ScannerWorker(
                        id=uuid.uuid4(),
                        worker_id=f"f901-{uuid.uuid4().hex[:8]}",
                        pool_id="public-default",
                        site_id=None,
                        workspace_id=None,
                        status="active",
                        # KNOWN-GOOD baseline: the persistence assertions below compare
                        # against these, so an accepted-but-invalid write would be visible.
                        health_state="healthy",
                        last_handshake_age_s=42,
                        token_hash=workers_service.hash_worker_token(token),
                    )
                    s.add(worker)
                    await s.commit()
                    state.update(worker_id=worker.worker_id, token=token, row_id=worker.id)
        finally:
            await engine.dispose()

    asyncio.run(seed())

    async def _override_db():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    yield s
        finally:
            await engine.dispose()

    manager_app.dependency_overrides[get_db] = _override_db
    client = TestClient(manager_app)
    try:
        yield client, state
    finally:
        manager_app.dependency_overrides.clear()


def _auth(state):
    return {"X-Worker-Id": state["worker_id"], "Authorization": f"Bearer {state['token']}"}


def _telemetry(row_id):
    async def _go():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    row = await s.scalar(select(ScannerWorker).where(ScannerWorker.id == row_id))
                    await s.refresh(row)
                    return {"health_state": row.health_state,
                            "last_handshake_age_s": row.last_handshake_age_s,
                            "status": row.status}
        finally:
            await engine.dispose()

    return asyncio.run(_go())


def test_the_exact_audit_payload_is_rejected_and_persists_nothing(env):
    """THE REGRESSION TEST FOR F-9-01, with the payload the audit actually sent.

    Asserts BOTH halves: the request fails 422, AND the stored telemetry is byte-for-byte
    what it was before. Checking only the status code would not prove the values never
    reached `record_heartbeat()`.
    """
    client, state = env
    before = _telemetry(state["row_id"])
    assert before == {"health_state": "healthy", "last_handshake_age_s": 42, "status": "active"}

    r = client.post(
        "/v1/heartbeat",
        json={"health_state": "super-healthy", "handshake_age_s": -99999},
        headers=_auth(state),
    )
    assert r.status_code == 422, r.text
    # Both offending fields are named, so an operator reading the rejection knows why.
    body = r.text
    assert "health_state" in body and "handshake_age_s" in body

    assert _telemetry(state["row_id"]) == before, "invalid telemetry reached persistence"


@pytest.mark.parametrize("state_value", INVALID_STATES)
def test_each_invalid_health_state_is_422_and_leaves_the_row_untouched(env, state_value):
    client, state = env
    before = _telemetry(state["row_id"])
    r = client.post("/v1/heartbeat", json={"health_state": state_value}, headers=_auth(state))
    assert r.status_code == 422, f"{state_value!r} was accepted: {r.text}"
    assert _telemetry(state["row_id"]) == before


@pytest.mark.parametrize("age", (-1, -99999))
def test_each_negative_age_is_422_and_leaves_the_row_untouched(env, age):
    client, state = env
    before = _telemetry(state["row_id"])
    r = client.post(
        "/v1/heartbeat",
        json={"health_state": "healthy", "handshake_age_s": age},
        headers=_auth(state),
    )
    assert r.status_code == 422, f"age {age} was accepted: {r.text}"
    assert _telemetry(state["row_id"]) == before


@pytest.mark.parametrize("state_value", VALID_STATES)
def test_a_legitimate_heartbeat_still_succeeds_and_persists(env, state_value):
    """The other direction. A fix that broke real heartbeats would take the fleet down --
    every legitimate value must still be accepted AND stored."""
    client, state = env
    r = client.post(
        "/v1/heartbeat",
        json={"health_state": state_value, "handshake_age_s": 7},
        headers=_auth(state),
    )
    assert r.status_code == 200, r.text
    after = _telemetry(state["row_id"])
    assert after["health_state"] == state_value
    assert after["last_handshake_age_s"] == 7


def test_a_zero_handshake_age_is_accepted_and_stored(env):
    """0 is the value a freshly-completed handshake reports -- the boundary case `ge=0`
    exists to admit, and it must not be confused with 'missing'."""
    client, state = env
    r = client.post(
        "/v1/heartbeat",
        json={"health_state": "healthy", "handshake_age_s": 0},
        headers=_auth(state),
    )
    assert r.status_code == 200, r.text
    assert _telemetry(state["row_id"])["last_handshake_age_s"] == 0


# =========================================================================================
# The fix must NOT have changed authorization
# =========================================================================================

def test_validation_runs_behind_authentication_not_instead_of_it(env):
    """An UNAUTHENTICATED request with an invalid body must still be refused for the
    AUTHENTICATION reason. If validation ran first, an anonymous caller could probe the
    schema, and a 422 would leak that the endpoint exists to someone with no credential.
    """
    client, state = env
    r = client.post("/v1/heartbeat", json={"health_state": "super-healthy"})
    assert r.status_code == 401, r.text
    assert "worker identity required" in r.text


def test_a_bad_credential_with_a_valid_body_is_still_refused(env):
    client, state = env
    r = client.post(
        "/v1/heartbeat",
        json={"health_state": "healthy"},
        headers={"X-Worker-Id": state["worker_id"], "Authorization": "Bearer forged"},
    )
    assert r.status_code == 403
    assert "WORKER_BAD_CREDENTIAL" in r.text


def test_health_state_is_not_an_authorization_input():
    """THE SCOPE GUARD (F-9-01 is a telemetry fix, not an authorization change).

    Constraining the vocabulary must not turn self-reported health into a security
    primitive. Asserted against the real source of every authorization helper: none of them
    may reference these columns, now or after a future edit.
    """
    import inspect

    for fn in (
        workers_service.assert_worker_active,
        workers_service.assert_worker_may_lease,
        workers_service.assert_worker_may_serve_site,
        workers_service.assert_worker_may_take_scan,
        workers_service.assert_worker_in_pool,
    ):
        src = inspect.getsource(fn)
        assert "health_state" not in src, f"{fn.__name__} now reads health_state"
        assert "last_handshake_age_s" not in src, f"{fn.__name__} now reads handshake age"


def test_the_stale_reaper_still_ignores_self_reported_health():
    """P8-F keys on `last_seen_at`, never on what the worker claims about itself -- which is
    why a suspended worker keeps its last self-report. Unchanged by this fix."""
    import inspect

    src = inspect.getsource(workers_service.reap_stale_workers)
    assert "COALESCE(last_seen_at, created_at)" in src
    # The reaper must not WRITE health_state (it is the worker's own last statement).
    update = src[src.index("UPDATE scanner_workers"):src.index("AND COALESCE")]
    assert "health_state" not in update
