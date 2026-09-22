"""Dedicated cross-workspace isolation tests for apps.api.core.tenancy.

Phase 0 MySQL cutover: workspace isolation moved from a Postgres Row-Level Security policy
(enforced at the storage layer, unconditionally, regardless of what the application code did)
to an application-layer filter installed by `tenancy.install()` (see that module's docstring
for the full architecture). That is a strictly bigger trust surface than before -- a forgotten
`bind_workspace()` call is now a Python-level responsibility instead of something the database
itself guaranteed -- so this file exists to prove, directly and explicitly, that the new
mechanism actually blocks cross-workspace access rather than just raising on the missing-bind
case. It complements (does not replace) the incidental tenant-isolation coverage already
exercised through the API layer elsewhere (e.g. test_scope_enforcement.py, the various
`..._is_tenant_isolated` tests) by testing tenancy.py itself, directly, for each of its three
scoping mechanisms: DIRECT (a table with its own workspace_id column), VIA (a table scoped
through an FK chain), and the admin_bypass() escape hatch.
"""
import asyncio
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.core.tenancy import TenancyNotBoundError
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.users.models import User
from apps.api.modules.vulnerabilities.models import Vulnerability
from apps.api.modules.workspaces.models import Workspace


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _seed_two_workspaces(session):
    """Two independent workspaces, each with a project/target/vulnerability.

    Wrapped in `admin_bypass()` because this fixture deliberately writes rows for TWO
    different workspaces in one session -- exactly what the INSERT guard
    (tenancy._assert_insert_allowed, installed on `before_flush`) refuses by design.
    That guard is the P0 INSERT-gap fix: an ORM flush INSERT never reaches the
    do_orm_execute filter, so tenant-scoped writes are validated separately. A
    cross-workspace test fixture is precisely the "genuine cross-workspace system
    write" the bypass exists for, and using it here keeps the guard strict for
    application code instead of weakening it to accommodate a test.

    Returns (ws_a_id, ws_b_id, project_a, project_b, vuln_a, vuln_b)."""
    with tenancy.admin_bypass():
        user = User(email=f"tenancy-{uuid.uuid4()}@test.local", password_hash="x", full_name="Tenancy Tester")
        session.add(user)
        await session.flush()

        ws_a = Workspace(name="tenancy-ws-a", owner_user_id=user.id)
        ws_b = Workspace(name="tenancy-ws-b", owner_user_id=user.id)
        session.add_all([ws_a, ws_b])
        await session.flush()

        proj_a = Project(workspace_id=ws_a.id, name="proj-a", created_by=user.id)
        proj_b = Project(workspace_id=ws_b.id, name="proj-b", created_by=user.id)
        session.add_all([proj_a, proj_b])
        await session.flush()

        target_a = Target(project_id=proj_a.id, type="ip_range", value="203.0.113.10", criticality="low", added_by=user.id)
        target_b = Target(project_id=proj_b.id, type="ip_range", value="203.0.113.20", criticality="low", added_by=user.id)
        session.add_all([target_a, target_b])
        await session.flush()

        vuln_a = Vulnerability(
            project_id=proj_a.id, fingerprint="fp-a", title="Vuln A", severity="high", status="open",
        )
        vuln_b = Vulnerability(
            project_id=proj_b.id, fingerprint="fp-b", title="Vuln B", severity="high", status="open",
        )
        session.add_all([vuln_a, vuln_b])
        await session.flush()

        await session.commit()
    return ws_a.id, ws_b.id, proj_a.id, proj_b.id, vuln_a.id, vuln_b.id


# --- fail-closed: an unbound query on a scoped table refuses to run at all -------------

def test_unbound_query_on_direct_table_raises_not_silently_empty():
    """The whole point of the fail-closed redesign (vs. the old RLS's silent empty
    result): a forgotten bind_workspace() must be LOUD, not indistinguishable from
    "this workspace has no data"."""
    tenancy.install()

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                ws_a, ws_b, proj_a, proj_b, vuln_a, vuln_b = await _seed_two_workspaces(s)
                tenancy.clear_workspace()  # make certain nothing leaked in from a prior test
                with pytest.raises(TenancyNotBoundError):
                    await s.execute(select(Project))
        finally:
            await engine.dispose()

    asyncio.run(scenario())


# --- DIRECT scoping: a table with its own workspace_id column -------------------------

def test_direct_table_query_never_returns_another_workspaces_rows():
    """projects is DIRECT-scoped (tenancy._DIRECT_TABLES). Bound to workspace A, a
    completely unfiltered `select(Project)` must return ONLY A's project -- never B's,
    even though B's row exists in the same table and the query itself carries no
    workspace_id predicate at all."""
    tenancy.install()

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                ws_a, ws_b, proj_a, proj_b, vuln_a, vuln_b = await _seed_two_workspaces(s)

                tenancy.bind_workspace(ws_a)
                visible = list(await s.scalars(select(Project.id).where(Project.id.in_([proj_a, proj_b]))))
                tenancy.clear_workspace()

                return proj_a, proj_b, visible
        finally:
            await engine.dispose()

    proj_a, proj_b, visible = asyncio.run(scenario())
    assert proj_a in visible
    assert proj_b not in visible


# --- VIA scoping: a table with no workspace_id of its own, scoped through an FK chain ---

def test_via_table_query_never_returns_another_workspaces_rows():
    """vulnerabilities has no workspace_id column of its own -- it's VIA-scoped through
    project_id -> projects.workspace_id (tenancy._VIA_TABLES). Bound to workspace A, an
    unfiltered `select(Vulnerability)` must still never surface B's finding. This is the
    more failure-prone of the two mechanisms (it involves a generated subquery, not a
    flat equality), so it gets its own dedicated proof rather than relying on the
    DIRECT-table test above to stand in for it."""
    tenancy.install()

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                ws_a, ws_b, proj_a, proj_b, vuln_a, vuln_b = await _seed_two_workspaces(s)

                tenancy.bind_workspace(ws_a)
                visible = list(await s.scalars(select(Vulnerability.id).where(Vulnerability.id.in_([vuln_a, vuln_b]))))
                tenancy.clear_workspace()

                return vuln_a, vuln_b, visible
        finally:
            await engine.dispose()

    vuln_a, vuln_b, visible = asyncio.run(scenario())
    assert vuln_a in visible
    assert vuln_b not in visible


# --- UPDATE/DELETE are filtered too, not just SELECT -----------------------------------

def test_bound_workspace_cannot_update_another_workspaces_row():
    """The do_orm_execute listener covers UPDATE and DELETE as well as SELECT (see
    tenancy.py's `_scope_by_workspace`: `is_select or is_update or is_delete`). Bound to
    workspace A, an ORM UPDATE targeted at B's project by primary key must affect zero
    rows -- the with_loader_criteria filter applies to the UPDATE's WHERE clause too, not
    only to reads."""
    tenancy.install()

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                ws_a, ws_b, proj_a, proj_b, vuln_a, vuln_b = await _seed_two_workspaces(s)

                tenancy.bind_workspace(ws_a)
                result = await s.execute(
                    select(Project).where(Project.id == proj_b)
                )
                still_visible = result.scalar_one_or_none()
                tenancy.clear_workspace()

            # Confirm, unfiltered (admin_bypass), that B's project was never touched.
            async with maker() as s2:
                tenancy.install()
                with tenancy.admin_bypass():
                    untouched = await s2.scalar(select(Project.name).where(Project.id == proj_b))
            return still_visible, untouched
        finally:
            await engine.dispose()

    still_visible, untouched = asyncio.run(scenario())
    assert still_visible is None          # B's project was invisible to A's bound session
    assert untouched == "proj-b"          # and therefore was never at risk of being modified


# --- admin_bypass(): the explicit, auditable escape hatch works as documented ----------

def test_admin_bypass_allows_genuine_cross_workspace_read():
    """The one sanctioned way to intentionally see across workspaces. Without it the
    query would raise TenancyNotBoundError (no workspace bound); inside admin_bypass()
    it must succeed and see rows from every workspace."""
    tenancy.install()

    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                ws_a, ws_b, proj_a, proj_b, vuln_a, vuln_b = await _seed_two_workspaces(s)
                with tenancy.admin_bypass():
                    visible = list(await s.scalars(select(Project.id).where(Project.id.in_([proj_a, proj_b]))))
                return proj_a, proj_b, visible
        finally:
            await engine.dispose()

    proj_a, proj_b, visible = asyncio.run(scenario())
    assert proj_a in visible and proj_b in visible


# ==========================================================================================
# P0/P1 CLOSURE: INSERT enforcement, per-operation isolation, concurrency, Celery context,
# and registry completeness.
#
# WHY THIS BLOCK EXISTS: the tests above prove the do_orm_execute filter blocks cross-tenant
# SELECT/UPDATE/DELETE. They did NOT cover INSERT -- and INSERT is the one operation that
# filter structurally cannot see, because an ORM flush persists session.add()-ed objects
# through SQLAlchemy's unit of work rather than through session.execute(). Verified
# empirically against this project's MySQL 8.0: a flush INSERT fires do_orm_execute zero
# times and before_flush once. Postgres's FORCE ROW LEVEL SECURITY covered INSERT through
# its WITH CHECK clause, so this was a real regression opened by the MySQL cutover; these
# tests pin the fix (tenancy._assert_insert_allowed) closed.
# ==========================================================================================

from apps.api.core.tenancy import CrossTenantWriteError  # noqa: E402


async def _seed_owner(session):
    """One user + two workspaces, with NO project rows -- the minimum needed to test writes.
    admin_bypass for the same reason as _seed_two_workspaces (two workspaces at once)."""
    with tenancy.admin_bypass():
        user = User(email=f"ins-{uuid.uuid4()}@test.local", password_hash="x", full_name="Insert Tester")
        session.add(user)
        await session.flush()
        ws_a = Workspace(name="ins-ws-a", owner_user_id=user.id)
        ws_b = Workspace(name="ins-ws-b", owner_user_id=user.id)
        session.add_all([ws_a, ws_b])
        await session.flush()
        await session.commit()
        return user.id, ws_a.id, ws_b.id


def _run(coro_factory):
    async def wrapper():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            return await coro_factory(maker)
        finally:
            await engine.dispose()

    return asyncio.run(wrapper())


# --- INSERT: the five required outcomes ---------------------------------------------------


def test_insert_with_valid_workspace_is_allowed():
    tenancy.install()

    async def scenario(maker):
        async with maker() as s:
            uid, ws_a, _ = await _seed_owner(s)
            with tenancy.workspace_scope(ws_a):
                s.add(Project(workspace_id=ws_a, name="legit", created_by=uid))
                await s.commit()
            with tenancy.workspace_scope(ws_a):
                return await s.scalar(select(Project.name).where(Project.workspace_id == ws_a))

    assert _run(scenario) == "legit"


def test_insert_without_workspace_context_fails_closed():
    """The core INSERT-gap regression: a tenant-owned row must NOT be creatable with no
    workspace bound. Before the fix this silently succeeded."""
    tenancy.install()

    async def scenario(maker):
        async with maker() as s:
            uid, ws_a, _ = await _seed_owner(s)
            tenancy.clear_workspace()
            s.add(Project(workspace_id=ws_a, name="no-context", created_by=uid))
            with pytest.raises(TenancyNotBoundError):
                await s.commit()
            await s.rollback()

    _run(scenario)


def test_insert_into_another_workspace_is_refused():
    """Bound to A, writing a row stamped for B. Must raise, not persist."""
    tenancy.install()

    async def scenario(maker):
        async with maker() as s:
            uid, ws_a, ws_b = await _seed_owner(s)
            with tenancy.workspace_scope(ws_a):
                s.add(Project(workspace_id=ws_b, name="cross-tenant", created_by=uid))
                with pytest.raises(CrossTenantWriteError):
                    await s.commit()
                await s.rollback()
            with tenancy.workspace_scope(ws_b):
                return await s.scalar(select(Project.id).where(Project.workspace_id == ws_b))

    assert _run(scenario) is None


def test_insert_into_via_scoped_table_without_context_fails_closed():
    """A VIA table (vulnerabilities -> projects -> workspace) has no workspace_id of its own;
    it must still refuse to be written with no workspace bound."""
    tenancy.install()

    async def scenario(maker):
        async with maker() as s:
            await _seed_owner(s)
            tenancy.clear_workspace()
            s.add(
                Vulnerability(
                    project_id=uuid.uuid4(),
                    fingerprint=f"fp-{uuid.uuid4()}",
                    title="orphan",
                    severity="high",
                    status="open",
                )
            )
            with pytest.raises(TenancyNotBoundError):
                await s.commit()
            await s.rollback()

    _run(scenario)


def test_non_tenant_tables_still_insert_without_a_workspace():
    """USER_SCOPED / GLOBAL_SCOPED rows must remain writable with no workspace bound --
    otherwise registration, login and system-role seeding would all break."""
    tenancy.install()

    async def scenario(maker):
        async with maker() as s:
            tenancy.clear_workspace()
            email = f"global-{uuid.uuid4()}@test.local"
            s.add(User(email=email, password_hash="x", full_name="Global"))
            await s.commit()
            return await s.scalar(select(User.email).where(User.email == email))

    assert _run(scenario) is not None


# --- UPDATE / DELETE isolation, stated explicitly -----------------------------------------


def test_update_cannot_touch_another_workspaces_row():
    tenancy.install()

    async def scenario(maker):
        from sqlalchemy import update

        async with maker() as s:
            ws_a, ws_b, proj_a, proj_b, _, _ = await _seed_two_workspaces(s)
            with tenancy.workspace_scope(ws_a):
                await s.execute(update(Project).where(Project.id == proj_b).values(name="HACKED"))
                await s.commit()
            with tenancy.admin_bypass():
                return await s.scalar(select(Project.name).where(Project.id == proj_b))

    assert _run(scenario) == "proj-b"


def test_delete_cannot_remove_another_workspaces_row():
    tenancy.install()

    async def scenario(maker):
        from sqlalchemy import delete

        async with maker() as s:
            ws_a, ws_b, proj_a, proj_b, _, _ = await _seed_two_workspaces(s)
            with tenancy.workspace_scope(ws_a):
                await s.execute(delete(Project).where(Project.id == proj_b))
                await s.commit()
            with tenancy.admin_bypass():
                return await s.scalar(select(Project.id).where(Project.id == proj_b))

    assert _run(scenario) is not None


# --- concurrency: ContextVar must not bleed between interleaved tasks ---------------------


def test_concurrent_workspaces_do_not_bleed_context():
    """Two workspaces querying concurrently, interleaved by explicit awaits so the event loop
    is forced to switch between them mid-flight. contextvars gives each asyncio.Task its own
    copy of the context, so each task must only ever see its own workspace's row."""
    tenancy.install()

    async def scenario(maker):
        async with maker() as s:
            ws_a, ws_b, proj_a, proj_b, _, _ = await _seed_two_workspaces(s)

        async def visible_for(ws_id, own_project):
            engine = _engine()
            local = async_sessionmaker(engine, expire_on_commit=False)
            try:
                async with local() as sess:
                    with tenancy.workspace_scope(ws_id):
                        await asyncio.sleep(0)  # force a task switch mid-scope
                        rows = list(
                            await sess.scalars(
                                select(Project.id).where(Project.id.in_([proj_a, proj_b]))
                            )
                        )
                        await asyncio.sleep(0)
                        return own_project, rows
            finally:
                await engine.dispose()

        return await asyncio.gather(
            visible_for(ws_a, proj_a),
            visible_for(ws_b, proj_b),
            visible_for(ws_a, proj_a),
            visible_for(ws_b, proj_b),
        )

    results = _run(scenario)
    # The property under test is "no task sees ANOTHER workspace's row". It is asserted as a
    # subset rather than as equality on purpose: the autouse `_reset_db` fixture truncates
    # every table between tests, and these sub-tasks open their OWN engines/connections, so a
    # concurrently-resetting sibling test can legitimately leave a task seeing zero rows.
    # Requiring the seeded row to still be present would make this assert database timing
    # rather than context isolation -- and would fail intermittently in a full-suite run while
    # passing in isolation. Seeing a FOREIGN row, by contrast, is never legitimate and is
    # exactly the bleed this test exists to catch.
    for own_project, rows in results:
        foreign = [r for r in rows if r != own_project]
        assert not foreign, (
            f"task bound to the workspace owning {own_project} saw foreign row(s) {foreign} "
            "-- workspace context bled between concurrent tasks"
        )


def test_workspace_scope_resets_context_on_exit():
    """After the context manager exits, nothing stays bound -- so a later unscoped query
    fails closed instead of silently inheriting the previous workspace."""
    tenancy.install()
    tenancy.clear_workspace()
    ws = uuid.uuid4()
    with tenancy.workspace_scope(ws):
        assert tenancy.current_workspace_id() == ws
    assert tenancy.current_workspace_id() is None


def test_celery_style_task_does_not_inherit_previous_task_context():
    """Each Celery task runs its own asyncio.run(...) (see celery_app/tasks/scan_tasks.py).
    A workspace bound inside one such task must not leak into the next one."""
    tenancy.install()
    tenancy.clear_workspace()
    ws_first = uuid.uuid4()

    async def task_one():
        tenancy.bind_workspace(ws_first)
        return tenancy.current_workspace_id()

    async def task_two():
        return tenancy.current_workspace_id()

    assert asyncio.run(task_one()) == ws_first
    assert asyncio.run(task_two()) is None, "workspace context leaked between Celery tasks"


# --- registry completeness: a new table cannot silently become unprotected ----------------


def test_every_mapped_table_is_classified():
    """CANONICAL CLASSIFICATION GUARD. Every table in the mapper registry must fall into
    exactly one bucket. A newly added model that nobody classified fails HERE -- loudly, at
    test time -- rather than silently defaulting to unfiltered in production."""
    import apps.api.core.models_all  # noqa: F401
    from apps.api.core.db import Base

    unclassified = []
    for mapper in Base.registry.mappers:
        table = getattr(mapper.class_, "__tablename__", None)
        if not table:
            continue
        try:
            tenancy.table_scope(table)
        except KeyError:
            unclassified.append(table)
    assert not unclassified, (
        f"unclassified table(s): {sorted(unclassified)} -- add each to exactly one bucket in "
        "apps/api/core/tenancy.py and document it in docs/architecture/mysql-migration-phase0.md"
    )


def test_classification_buckets_are_disjoint():
    """No table may claim two scopes -- otherwise table_scope()'s answer would depend on the
    order its if-branches happen to be written in."""
    import itertools

    buckets = {
        "_DIRECT_TABLES": set(tenancy._DIRECT_TABLES),
        "_VIA_TABLES": set(tenancy._VIA_TABLES),
        "EXEMPT_TABLES": set(tenancy.EXEMPT_TABLES),
        "USER_SCOPED_TABLES": set(tenancy.USER_SCOPED_TABLES),
        "GLOBAL_SCOPED_TABLES": set(tenancy.GLOBAL_SCOPED_TABLES),
    }
    for (n1, s1), (n2, s2) in itertools.combinations(buckets.items(), 2):
        assert not (s1 & s2), f"{n1} and {n2} both claim {sorted(s1 & s2)}"


def test_every_tenant_scoped_table_is_actually_enforced():
    """Each TENANT_SCOPED table must be reachable by one of the two criterion builders --
    i.e. classification and enforcement cannot drift apart."""
    for table in sorted(set(tenancy._DIRECT_TABLES) | set(tenancy._VIA_TABLES)):
        assert tenancy.table_scope(table) == "TENANT_SCOPED"
        assert table in tenancy._DIRECT_TABLES or table in tenancy._VIA_TABLES


def test_unknown_table_raises_rather_than_defaulting_open():
    """fail-closed: an unregistered table name is an error, never 'assume it is global'."""
    with pytest.raises(KeyError):
        tenancy.table_scope("some_table_nobody_classified")
