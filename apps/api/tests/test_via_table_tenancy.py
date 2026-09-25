"""PHASE 14 -- a tenant must not be able to create a CROSS-TENANT RELATIONSHIP.

THE INVARIANT
-------------
VIA tables (`targets`, `vulnerabilities`, `reports`, `tool_runs`, ... -- see
`tenancy._VIA_TABLES`) have no `workspace_id` of their own; they reach the tenant through a
foreign key chain. So the interesting attack is not "read another tenant's row" (the ORM
auto-filter covers that) but "CREATE a row of mine that points at another tenant's parent".

TWO LAYERS, DELIBERATELY DIFFERENT IN STRENGTH
-----------------------------------------------
1. SERVICE LAYER -- the authoritative control, and the only surface a real caller can reach.
   Every write path resolves the parent through the explicit ownership check
   (`projects.service.get_project`) before creating anything. Measured: tenant A posting a
   target under tenant B's project gets 404; addressing B's workspace directly gets 403.

2. ORM `before_flush` GUARD -- a defence-in-depth backstop for code that bypasses the service
   layer. It validates a VIA row's parent WHEN THE PARENT IS ALREADY RESIDENT in the session
   (identity map / pending set) and issues NO queries to do it, so it cannot regress the
   scanner's bulk ingest. When the parent was never loaded -- a caller that fabricated a UUID
   it never read -- the guard stays silent by design and layer 1 is the control.

That division is a deliberate, documented boundary, not an oversight, and these tests assert
BOTH halves of it -- including the residual gap, so it stays visible instead of being
mistaken for full coverage.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from apps.api.core import tenancy
from apps.api.core.config import get_settings

_PW = "correct horse battery staple"


def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": _PW, "full_name": "Tenant"},
    )
    assert r.status_code == 201, r.text
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    me = client.get("/api/v1/users/me", headers=headers)
    return {"headers": headers, "id": me.json()["id"]}


@pytest.fixture
def tenants(client: TestClient):
    a, b = _register(client), _register(client)
    ws_a = client.post("/api/v1/workspaces", headers=a["headers"], json={"name": "A"}).json()["id"]
    ws_b = client.post("/api/v1/workspaces", headers=b["headers"], json={"name": "B"}).json()["id"]
    proj_a = client.post(f"/api/v1/workspaces/{ws_a}/projects", headers=a["headers"],
                         json={"name": "A proj"}).json()["id"]
    proj_b = client.post(f"/api/v1/workspaces/{ws_b}/projects", headers=b["headers"],
                         json={"name": "B proj"}).json()["id"]
    return {"a": a, "b": b, "ws_a": ws_a, "ws_b": ws_b, "proj_a": proj_a, "proj_b": proj_b}


# --------------------------------------------------------------------------------------------
# LAYER 1 -- the service layer. This is what an actual attacker can reach.
# --------------------------------------------------------------------------------------------

def test_cannot_create_target_under_another_tenants_project(tenants, client: TestClient):
    """THE HEADLINE ADVERSARIAL CASE: A creates a child row pointing at B's project."""
    t = tenants
    r = client.post(
        f"/api/v1/workspaces/{t['ws_a']}/projects/{t['proj_b']}/targets",
        headers=t["a"]["headers"], json={"type": "domain", "value": "evil.example"},
    )
    assert r.status_code in (403, 404), (
        f"tenant A created a target under tenant B's project: {r.status_code} {r.text[:200]}"
    )


def test_cannot_create_target_by_addressing_the_other_tenants_workspace(tenants, client: TestClient):
    """Naming B's workspace directly must be refused by the membership check."""
    t = tenants
    r = client.post(
        f"/api/v1/workspaces/{t['ws_b']}/projects/{t['proj_b']}/targets",
        headers=t["a"]["headers"], json={"type": "domain", "value": "evil.example"},
    )
    assert r.status_code in (403, 404), f"non-member wrote into another workspace: {r.status_code}"


def test_cannot_create_scan_against_another_tenants_project(tenants, client: TestClient):
    t = tenants
    r = client.post(
        f"/api/v1/workspaces/{t['ws_a']}/projects/{t['proj_b']}/scans",
        headers=t["a"]["headers"],
        json={"scan_type": "recon", "requested_modules": [], "target_id": str(uuid.uuid4())},
    )
    assert r.status_code != 201, "a scan was created against another tenant's project"


def test_cannot_create_schedule_against_another_tenants_project(tenants, client: TestClient):
    t = tenants
    r = client.post(
        f"/api/v1/workspaces/{t['ws_a']}/projects/{t['proj_b']}/schedules",
        headers=t["a"]["headers"],
        json={"scan_type": "recon", "cron": "0 0 * * *", "target_id": str(uuid.uuid4())},
    )
    assert r.status_code != 201, "a schedule was created against another tenant's project"


def test_own_project_writes_still_work(tenants, client: TestClient):
    """No false positives: the same call against the caller's OWN project must succeed."""
    t = tenants
    r = client.post(
        f"/api/v1/workspaces/{t['ws_a']}/projects/{t['proj_a']}/targets",
        headers=t["a"]["headers"], json={"type": "domain", "value": "own.example"},
    )
    assert r.status_code == 201, f"legitimate target creation broke: {r.status_code} {r.text[:200]}"


# --------------------------------------------------------------------------------------------
# LAYER 2 -- the ORM backstop, exercised by bypassing the service layer entirely.
# --------------------------------------------------------------------------------------------

async def _flush_target(session_maker, *, bind_ws, project_id, added_by, value, preload=None):
    """Insert a Target with `bind_ws` bound. Optionally preload a parent project first.
    Returns the exception type name, or None when the flush was allowed."""
    from apps.api.modules.projects.models import Project, Target

    async with session_maker() as s:
        held = None
        if preload is not None:
            with tenancy.admin_bypass():
                # Strong reference: Session.identity_map is a WeakInstanceDict, so an
                # unreferenced object can be collected before the flush runs.
                held = await s.scalar(select(Project).where(Project.id == uuid.UUID(preload)))
            assert held is not None
        with tenancy.workspace_scope(bind_ws):
            s.add(Target(id=uuid.uuid4(), project_id=uuid.UUID(project_id), type="domain",
                         value=value, criticality="medium", added_by=uuid.UUID(added_by)))
            try:
                await s.flush()
                return None
            except Exception as exc:  # noqa: BLE001 -- the type IS the assertion
                return type(exc).__name__
            finally:
                await s.rollback()


@pytest.fixture
def session_maker():
    engines = []

    def _make():
        eng = create_async_engine(get_settings().database_url)
        engines.append(eng)
        return async_sessionmaker(eng, expire_on_commit=False)

    yield _make
    import asyncio

    for eng in engines:
        asyncio.run(eng.dispose())


def test_orm_guard_refuses_a_loaded_foreign_parent(tenants, session_maker):
    """The backstop fires when the foreign parent IS resident in the session -- the realistic
    mistake: code that legitimately read another tenant's row (admin_bypass, a system task)
    and then writes a child while a different workspace is bound."""
    import asyncio

    t = tenants
    result = asyncio.run(_flush_target(
        session_maker(), bind_ws=t["ws_a"], project_id=t["proj_b"],
        added_by=t["a"]["id"], value="evil.example", preload=t["proj_b"],
    ))
    assert result == "CrossTenantWriteError", (
        f"the ORM guard did not refuse a cross-tenant VIA insert with a loaded parent: {result}"
    )


def test_orm_guard_allows_a_loaded_own_parent(tenants, session_maker):
    """No false positive: the identical write against the caller's own parent must succeed."""
    import asyncio

    t = tenants
    result = asyncio.run(_flush_target(
        session_maker(), bind_ws=t["ws_a"], project_id=t["proj_a"],
        added_by=t["a"]["id"], value="own.example", preload=t["proj_a"],
    ))
    assert result is None, f"a legitimate own-parent insert was refused: {result}"


def test_documented_boundary_unloaded_parent_is_not_caught_by_the_orm_guard(tenants, session_maker):
    """THE HONEST LIMIT, asserted so it cannot be quietly mistaken for full coverage.

    When the parent was never loaded, the guard deliberately issues no query (that would cost
    a SELECT per row on every flush, including the scanner's bulk ingest) and therefore does
    NOT catch a fabricated parent id. The service layer is the control for that case -- see
    the LAYER 1 tests above, which prove a real caller is refused.

    If this test ever FAILS because the insert was refused, the guard grew a lookup: re-check
    the flush cost on bulk ingest, then update this test and the note in tenancy.py.
    """
    import asyncio

    t = tenants
    result = asyncio.run(_flush_target(
        session_maker(), bind_ws=t["ws_a"], project_id=t["proj_b"],
        added_by=t["a"]["id"], value="ghost.example", preload=None,
    ))
    assert result is None, (
        "the ORM guard now catches an unloaded foreign parent -- that is an IMPROVEMENT, but "
        f"it means it started querying ({result}). Verify the bulk-ingest cost, then update "
        "this test and the design note in apps/api/core/tenancy.py."
    )


def test_guard_does_not_query(tenants, session_maker):
    """The backstop must remain I/O-free: no SELECT may be emitted by the parent check."""
    import asyncio

    from sqlalchemy import event as sa_event

    t = tenants
    maker = session_maker()
    emitted: list[str] = []

    async def _run():
        from apps.api.modules.projects.models import Project, Target

        async with maker() as s:
            with tenancy.admin_bypass():
                held = await s.scalar(select(Project).where(Project.id == uuid.UUID(t["proj_b"])))
            assert held is not None

            sync_sess = s.sync_session

            def _before_cursor(conn, cursor, statement, *a):
                emitted.append(statement)

            bind = sync_sess.bind
            sa_event.listen(bind, "before_cursor_execute", _before_cursor)
            try:
                with tenancy.workspace_scope(t["ws_a"]):
                    s.add(Target(id=uuid.uuid4(), project_id=uuid.UUID(t["proj_b"]),
                                 type="domain", value="noio.example", criticality="medium",
                                 added_by=uuid.UUID(t["a"]["id"])))
                    with pytest.raises(tenancy.CrossTenantWriteError):
                        await s.flush()
                    await s.rollback()
            finally:
                sa_event.remove(bind, "before_cursor_execute", _before_cursor)

    asyncio.run(_run())
    selects = [q for q in emitted if q.strip().upper().startswith("SELECT")]
    assert not selects, (
        "the VIA parent check issued SELECT(s) -- it must read only in-memory session state, "
        f"or bulk ingest pays a query per row: {selects[:3]}"
    )
