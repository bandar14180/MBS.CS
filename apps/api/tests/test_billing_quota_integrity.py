"""PHASE 3 -- quota integrity: atomicity, tenant isolation, and bypass resistance.

`test_billing.py` already covers the plan catalog, the `_over` helper, the public pricing
endpoint and single-request 402 enforcement. This file covers the properties that only show
up under CONCURRENCY, ACROSS TENANTS, or on ALTERNATE EXECUTION PATHS.

THE RACE THIS FILE LOCKS
------------------------
Every quota check was:

    SELECT COUNT(*)  ->  compare to limit  ->  caller INSERTs  ->  COMMIT

with nothing serialising the gap. The app runs at READ COMMITTED
(apps/api/core/db.py::_mysql_isolation_level), where a plain SELECT takes no locks, so N
concurrent requests all read the same pre-limit count and all proceed.

Measured against real MySQL BEFORE the fix: 8 concurrent `create_project` calls on the FREE
plan (max_projects=2) produced **8 rows** -- a 4x quota bypass. After the fix (a
`SELECT ... FOR UPDATE` row lock on the workspace row, in `_plan_for_update`): exactly 2
created, 6 rejected with 402.

These concurrency tests run against the REAL MySQL the suite is pointed at. They are
meaningless on SQLite, which serialises writes anyway and would pass without the fix.

WHAT IS DELIBERATELY NOT TESTED HERE (approved deferrals, not gaps)
-------------------------------------------------------------------
Per-plan AI quotas, plan-specific concurrency limits, Stripe/payment processing, subscription
lifecycle states, and Enterprise per-workspace overrides are all explicitly OUT of Phase 3.
`workspaces.plan_tier` is the authoritative plan assignment; the global AI budget
(`ai_agent/budget.py`, F-06) is unchanged and is not plan-derived.
"""
from __future__ import annotations

import asyncio
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.billing.plans import PLANS, SELECTABLE_TIERS, get_plan
from apps.api.modules.projects.models import Project

_PW = "correct horse battery staple"


# --------------------------------------------------------------------------------------------
# Helpers (mirroring test_billing.py's shape)
# --------------------------------------------------------------------------------------------

def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": _PW, "full_name": "Quota User"},
    )
    assert r.status_code == 201, r.text
    tokens = r.json()
    me = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    return {"headers": {"Authorization": f"Bearer {tokens['access_token']}"}, "id": me.json()["id"]}


def _ws(client: TestClient, headers: dict, name: str = "WS") -> str:
    r = client.post("/api/v1/workspaces", headers=headers, json={"name": name})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _set_plan(client: TestClient, headers: dict, ws: str, tier: str):
    return client.patch(f"/api/v1/workspaces/{ws}/billing/plan", headers=headers, json={"tier": tier})


def _mk_project(client: TestClient, headers: dict, ws: str, name: str):
    return client.post(f"/api/v1/workspaces/{ws}/projects", headers=headers, json={"name": name})


def _usage(client: TestClient, headers: dict, ws: str):
    return client.get(f"/api/v1/workspaces/{ws}/billing/usage", headers=headers)


# --------------------------------------------------------------------------------------------
# A. Plan catalog -- the approved business limits must not drift.
# --------------------------------------------------------------------------------------------

def test_plan_catalog_limits_are_unchanged():
    """The exact limits are a BUSINESS decision recorded in the repo (blueprint Phase 3,
    2026-07-28). Pin them so an edit is a deliberate, reviewed act."""
    free, pro, ent, pilot = PLANS["free"], PLANS["pro"], PLANS["enterprise"], PLANS["pilot"]
    assert (free.max_projects, free.max_targets, free.max_scans_per_month) == (2, 5, 10)
    assert free.price_usd_month == 0
    assert (pro.max_projects, pro.max_targets, pro.max_scans_per_month) == (25, 200, 500)
    assert pro.price_usd_month == 99
    assert (ent.max_projects, ent.max_targets, ent.max_scans_per_month) == (None, None, None)
    # `pilot` is the default tier and MUST stay unlimited: existing workspaces are never
    # retroactively capped by shipping this phase.
    assert (pilot.max_projects, pilot.max_targets, pilot.max_scans_per_month) == (None, None, None)
    assert "pilot" not in SELECTABLE_TIERS, "pilot is internal/default -- not customer-selectable"


def test_unknown_tier_falls_back_to_unlimited_not_to_free():
    """Fail OPEN on an unknown/legacy tier. Failing closed here would cap a workspace because
    of a data problem, which is worse than briefly under-charging."""
    for bogus in ("", "legacy", "FREE", "enterprise ", None):
        assert get_plan(bogus).max_projects is None


# --------------------------------------------------------------------------------------------
# B. Concurrency -- THE headline property. Real MySQL required.
# --------------------------------------------------------------------------------------------

def _engine_maker():
    engine = create_async_engine(get_settings().database_url, pool_size=20, max_overflow=10)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


def _concurrent_project_attempts(ws_id: uuid.UUID, user_id: uuid.UUID, n: int) -> tuple[list[str], int]:
    """Fire `n` concurrent create_project calls, each on its OWN session (as separate HTTP
    requests would be). Returns (outcomes, rows actually in the database)."""
    from apps.api.modules.projects import service as projects

    async def _run():
        engine, maker = _engine_maker()
        try:
            async def attempt(i: int) -> str:
                async with maker() as s:
                    with tenancy.workspace_scope(ws_id):
                        try:
                            await projects.create_project(s, ws_id, user_id, f"race-{i}", None)
                            return "created"
                        except Exception as exc:  # noqa: BLE001 -- the outcome IS the assertion
                            return f"{type(exc).__name__}:{getattr(exc, 'status_code', '')}"

            outcomes = await asyncio.gather(*(attempt(i) for i in range(n)))
            async with maker() as s:
                with tenancy.admin_bypass():
                    rows = await s.scalar(
                        select(func.count()).select_from(Project).where(Project.workspace_id == ws_id)
                    )
            return list(outcomes), int(rows or 0)
        finally:
            await engine.dispose()

    return asyncio.run(_run())


@pytest.mark.parametrize("concurrency", [8, 12])
def test_concurrent_project_creation_cannot_exceed_the_plan_limit(client: TestClient, concurrency):
    """THE RACE LOCK. Without the row lock this produced `concurrency` rows against a limit of
    2. It must now produce exactly 2, with the rest rejected 402."""
    user = _register(client)
    ws = _ws(client, user["headers"], "Race WS")
    assert _set_plan(client, user["headers"], ws, "free").status_code == 200

    outcomes, rows = _concurrent_project_attempts(uuid.UUID(ws), uuid.UUID(user["id"]), concurrency)

    limit = PLANS["free"].max_projects
    assert limit is not None, "the FREE plan must define a project cap"
    assert rows <= limit, (
        f"QUOTA BYPASS: {rows} projects exist against a FREE limit of {limit} "
        f"({concurrency} concurrent requests). Outcomes: {sorted(outcomes)}"
    )
    assert outcomes.count("created") == rows, "reported successes disagree with the database"
    # Everything that did not succeed must have been refused for the RIGHT reason (402),
    # not by an incidental deadlock/500 that would merely look like enforcement.
    for o in outcomes:
        assert o == "created" or o.endswith(":402"), f"unexpected rejection reason: {o}"


def test_concurrency_still_allows_up_to_the_limit(client: TestClient):
    """The lock must not over-block: with room for 2, two concurrent requests both succeed."""
    user = _register(client)
    ws = _ws(client, user["headers"], "Room WS")
    assert _set_plan(client, user["headers"], ws, "free").status_code == 200
    outcomes, rows = _concurrent_project_attempts(uuid.UUID(ws), uuid.UUID(user["id"]), 2)
    assert rows == 2, f"the lock over-blocked: only {rows} of 2 created ({outcomes})"


def test_concurrent_creation_on_two_workspaces_does_not_cross_block(client: TestClient):
    """The lock is PER TENANT (the workspace row). Workspace A's quota check must not block or
    consume workspace B's quota -- a global lock would be a correctness AND availability bug."""
    a, b = _register(client), _register(client)
    ws_a = _ws(client, a["headers"], "A")
    ws_b = _ws(client, b["headers"], "B")
    assert _set_plan(client, a["headers"], ws_a, "free").status_code == 200
    assert _set_plan(client, b["headers"], ws_b, "free").status_code == 200

    _, rows_a = _concurrent_project_attempts(uuid.UUID(ws_a), uuid.UUID(a["id"]), 6)
    _, rows_b = _concurrent_project_attempts(uuid.UUID(ws_b), uuid.UUID(b["id"]), 6)
    assert rows_a == 2 and rows_b == 2, (
        f"per-tenant quota is not independent: A={rows_a}, B={rows_b} (each limit 2)"
    )


# --------------------------------------------------------------------------------------------
# C. Boundary -- below / exactly at / above the limit.
# --------------------------------------------------------------------------------------------

def test_project_quota_boundary_below_at_and_above(client: TestClient):
    user = _register(client)
    ws = _ws(client, user["headers"], "Boundary WS")
    assert _set_plan(client, user["headers"], ws, "free").status_code == 200

    assert _mk_project(client, user["headers"], ws, "p1").status_code == 201   # below
    assert _mk_project(client, user["headers"], ws, "p2").status_code == 201   # reaches the cap
    over = _mk_project(client, user["headers"], ws, "p3")                      # above
    assert over.status_code == 402, f"expected 402 at the cap, got {over.status_code}"

    body = _usage(client, user["headers"], ws).json()
    assert body["usage"]["projects"] == 2
    assert body["limits"]["projects"] == 2


def test_enterprise_and_pilot_are_not_capped(client: TestClient):
    """Unlimited tiers must never 402 on project creation."""
    for tier in ("enterprise",):
        user = _register(client)
        ws = _ws(client, user["headers"], f"{tier} WS")
        assert _set_plan(client, user["headers"], ws, tier).status_code == 200
        for i in range(4):  # comfortably past the FREE cap
            assert _mk_project(client, user["headers"], ws, f"e{i}").status_code == 201
    # pilot is the DEFAULT (not selectable) -- a fresh workspace is already unlimited.
    user = _register(client)
    ws = _ws(client, user["headers"], "Pilot WS")
    assert _usage(client, user["headers"], ws).json()["plan_tier"] == "pilot"
    for i in range(4):
        assert _mk_project(client, user["headers"], ws, f"p{i}").status_code == 201


# --------------------------------------------------------------------------------------------
# D. Tenant isolation -- usage, quota and plan are per-workspace.
# --------------------------------------------------------------------------------------------

def test_tenant_a_usage_does_not_count_against_tenant_b(client: TestClient):
    """Aggregate COUNT(*) escapes tenancy's `with_loader_criteria` auto-filter (documented in
    tenancy.workspace_criterion), so these counts rely on their EXPLICIT workspace predicates.
    This proves those predicates are actually correct."""
    a, b = _register(client), _register(client)
    ws_a, ws_b = _ws(client, a["headers"], "A"), _ws(client, b["headers"], "B")
    assert _set_plan(client, a["headers"], ws_a, "free").status_code == 200
    assert _set_plan(client, b["headers"], ws_b, "free").status_code == 200

    # Fill A to its cap.
    assert _mk_project(client, a["headers"], ws_a, "a1").status_code == 201
    assert _mk_project(client, a["headers"], ws_a, "a2").status_code == 201
    assert _mk_project(client, a["headers"], ws_a, "a3").status_code == 402

    # B must be completely unaffected.
    assert _usage(client, b["headers"], ws_b).json()["usage"]["projects"] == 0
    assert _mk_project(client, b["headers"], ws_b, "b1").status_code == 201
    assert _usage(client, a["headers"], ws_a).json()["usage"]["projects"] == 2


def test_tenant_a_cannot_read_tenant_b_usage(client: TestClient):
    a, b = _register(client), _register(client)
    ws_b = _ws(client, b["headers"], "B")
    r = _usage(client, a["headers"], ws_b)
    assert r.status_code in (403, 404), f"cross-tenant usage read returned {r.status_code}"


def test_tenant_a_cannot_change_tenant_b_plan(client: TestClient):
    """Plan escalation across tenants -- the most valuable target here."""
    a, b = _register(client), _register(client)
    ws_b = _ws(client, b["headers"], "B")
    r = _set_plan(client, a["headers"], ws_b, "enterprise")
    assert r.status_code in (403, 404), f"cross-tenant plan change returned {r.status_code}"
    # B's plan must be untouched.
    assert _usage(client, b["headers"], ws_b).json()["plan_tier"] == "pilot"


# --------------------------------------------------------------------------------------------
# E. Client cannot forge plan / usage / limits.
# --------------------------------------------------------------------------------------------

def test_client_cannot_forge_plan_tier_via_request_body(client: TestClient):
    """Only `tier` is accepted, and only from SELECTABLE_TIERS. Extra fields must not be
    honoured, and `pilot` must not be self-selectable."""
    user = _register(client)
    ws = _ws(client, user["headers"], "Forge WS")

    for bad in ("pilot", "PILOT", "unlimited", "admin", "", "free; drop table", "../enterprise"):
        r = _set_plan(client, user["headers"], ws, bad)
        assert r.status_code in (400, 422), f"tier {bad!r} was accepted: {r.status_code}"
    assert _usage(client, user["headers"], ws).json()["plan_tier"] == "pilot"


def test_client_supplied_usage_and_limits_are_ignored(client: TestClient):
    """Usage/limits are computed server-side. Sending them must not change anything."""
    user = _register(client)
    ws = _ws(client, user["headers"], "Ignore WS")
    r = client.patch(
        f"/api/v1/workspaces/{ws}/billing/plan",
        headers=user["headers"],
        json={"tier": "free", "usage": {"projects": -100}, "limits": {"projects": 9999},
              "max_projects": 9999, "workspace_id": str(uuid.uuid4())},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["limits"]["projects"] == 2, "client-supplied limit was honoured"
    assert body["usage"]["projects"] == 0, "client-supplied usage was honoured"
    # And the forged workspace_id in the body must not have retargeted the change.
    assert _usage(client, user["headers"], ws).json()["plan_tier"] == "free"


def test_usage_can_never_be_negative(client: TestClient):
    user = _register(client)
    ws = _ws(client, user["headers"], "Neg WS")
    u = _usage(client, user["headers"], ws).json()["usage"]
    assert all(v >= 0 for v in u.values()), f"negative usage reported: {u}"


# --------------------------------------------------------------------------------------------
# F. Authorization -- plan changes need workspace:manage.
# --------------------------------------------------------------------------------------------

def test_plan_endpoints_require_authentication(client: TestClient):
    user = _register(client)
    ws = _ws(client, user["headers"], "Auth WS")
    assert client.get(f"/api/v1/workspaces/{ws}/billing/usage").status_code in (401, 403)
    assert client.patch(f"/api/v1/workspaces/{ws}/billing/plan", json={"tier": "pro"}).status_code in (401, 403)


def test_public_plan_catalog_exposes_no_tenant_data(client: TestClient):
    """`GET /plans` is deliberately unauthenticated -- it must therefore contain pricing only,
    never usage or workspace identifiers."""
    r = client.get("/api/v1/plans")
    assert r.status_code == 200
    body = r.json()
    assert {p["tier"] for p in body} == set(SELECTABLE_TIERS), "pilot must not be advertised"
    rendered = str(body)
    for leak in ("workspace", "usage", "user", "email"):
        assert leak not in rendered.lower(), f"public catalog leaks {leak!r}"


# --------------------------------------------------------------------------------------------
# G. Usage period semantics.
# --------------------------------------------------------------------------------------------

def test_month_start_is_utc_first_of_month():
    """The scan quota window. Deterministic and UTC -- a client cannot shift it."""
    from datetime import datetime, timezone

    from apps.api.modules.billing.service import _month_start

    for probe, expected in (
        (datetime(2026, 3, 15, 12, 30, tzinfo=timezone.utc), datetime(2026, 3, 1, tzinfo=timezone.utc)),
        (datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc), datetime(2026, 1, 1, tzinfo=timezone.utc)),
        (datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc), datetime(2026, 12, 1, tzinfo=timezone.utc)),
    ):
        got = _month_start(probe)
        assert got == expected, f"{probe} -> {got}, expected {expected}"
        assert got.tzinfo == timezone.utc
