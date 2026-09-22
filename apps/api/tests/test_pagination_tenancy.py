"""P1-2: a paginated TOTAL may never describe a wider population than its ITEMS.

THE BUG THIS PINS. `paginate()` computed its total as
`select(func.count()).select_from(query.subquery())`. That statement loads no mapped entity,
and SQLAlchemy's `with_loader_criteria` -- the mechanism `core/tenancy.py` uses -- only
attaches to statements that do. So the workspace predicate was silently dropped from the
count while remaining on the items: bound to a workspace owning ONE row, the total came back
as the GLOBAL row count.

Nothing leaked over HTTP at the time, because every call site happened to carry its own
explicit `workspace_id`/`project_id` predicate. That is exactly why this test exists: the
safety net is supposed to hold when a caller forgets, and it did not.

These tests deliberately use queries with NO explicit workspace predicate, so they fail if
the count ever stops being scoped by the tenancy layer itself.
"""
import asyncio
import uuid

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.core.pagination import Pagination, paginate
from apps.api.core.tenancy import TenancyNotBoundError, workspace_criterion
from apps.api.modules.projects.models import Project
from apps.api.modules.users.models import User
from apps.api.modules.vulnerabilities.models import Vulnerability
from apps.api.modules.workspaces.models import Workspace


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _seed(session):
    """Two workspaces, ONE vulnerability each.

    admin_bypass for the same reason test_tenancy_isolation.py uses it: writing rows for two
    workspaces in one session is precisely what the INSERT guard refuses by design, and a
    cross-workspace fixture is the genuine system write the bypass exists for."""
    with tenancy.admin_bypass():
        user = User(email=f"pag-{uuid.uuid4()}@test.local", password_hash="x", full_name="Pag")
        session.add(user)
        await session.flush()

        ws_a = Workspace(name=f"pag-a-{uuid.uuid4().hex[:8]}", owner_user_id=user.id)
        ws_b = Workspace(name=f"pag-b-{uuid.uuid4().hex[:8]}", owner_user_id=user.id)
        session.add_all([ws_a, ws_b])
        await session.flush()

        proj_a = Project(workspace_id=ws_a.id, name="pa", created_by=user.id)
        proj_b = Project(workspace_id=ws_b.id, name="pb", created_by=user.id)
        session.add_all([proj_a, proj_b])
        await session.flush()

        vuln_a = Vulnerability(
            project_id=proj_a.id, fingerprint=f"pa|m|{uuid.uuid4()}", title="A-only",
            severity="high", status="open",
        )
        vuln_b = Vulnerability(
            project_id=proj_b.id, fingerprint=f"pb|m|{uuid.uuid4()}", title="B-only",
            severity="high", status="open",
        )
        session.add_all([vuln_a, vuln_b])
        await session.commit()

    return {"ws_a": ws_a.id, "ws_b": ws_b.id, "va": vuln_a.id, "vb": vuln_b.id}


def _run(scenario):
    # install() explicitly, as test_tenancy_isolation.py does: the ORM filter is registered by
    # the app's startup path, and these tests exercise the tenancy layer directly without
    # constructing the app. Idempotent.
    tenancy.install()

    async def _outer():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                seeded = await _seed(session)
                tenancy.clear_workspace()
                try:
                    return await scenario(session, seeded)
                finally:
                    with tenancy.admin_bypass():
                        await session.execute(
                            delete(Vulnerability).where(
                                Vulnerability.id.in_([seeded["va"], seeded["vb"]])
                            )
                        )
                        await session.commit()
        finally:
            tenancy.clear_workspace()
            await engine.dispose()

    return asyncio.run(_outer())


# =============================================================================================
# THE CORE REQUIREMENT: items and total describe the same workspace
# =============================================================================================

def test_workspace_a_pagination_returns_one_item_and_total_one() -> None:
    """Workspace A owns 1 vulnerability; B owns 1. Bound to A, with a query carrying NO
    explicit workspace predicate, BOTH numbers must be 1."""
    async def scenario(session, seeded):
        with tenancy.workspace_scope(seeded["ws_a"]):
            query = select(Vulnerability).order_by(Vulnerability.id)
            return await paginate(session, query, Pagination(limit=50, offset=0))

    items, total = _run(scenario)
    assert len(items) == 1, f"items leaked another workspace's rows: {[i.title for i in items]}"
    assert total == 1, f"TOTAL leaked a cross-workspace count: {total}"
    assert items[0].title == "A-only"


def test_workspace_b_pagination_returns_one_item_and_total_one() -> None:
    """The mirror image -- proves the scoping follows the bound workspace, rather than one
    workspace happening to own everything."""
    async def scenario(session, seeded):
        with tenancy.workspace_scope(seeded["ws_b"]):
            query = select(Vulnerability).order_by(Vulnerability.id)
            return await paginate(session, query, Pagination(limit=50, offset=0))

    items, total = _run(scenario)
    assert len(items) == 1
    assert total == 1, f"TOTAL leaked a cross-workspace count: {total}"
    assert items[0].title == "B-only"


def test_items_and_total_always_describe_the_same_population() -> None:
    """The invariant in its most general form: with a page big enough to hold everything the
    caller may see, len(items) must EQUAL total. The original bug broke exactly this."""
    async def scenario(session, seeded):
        out = {}
        for label, ws in (("a", seeded["ws_a"]), ("b", seeded["ws_b"])):
            with tenancy.workspace_scope(ws):
                query = select(Vulnerability).order_by(Vulnerability.id)
                items, total = await paginate(session, query, Pagination(limit=200, offset=0))
                out[label] = (len(items), total)
        return out

    result = _run(scenario)
    for label, (n_items, total) in result.items():
        assert n_items == total, f"workspace {label}: items={n_items} but total={total}"


def test_total_is_not_the_global_count() -> None:
    """Explicit regression guard on the exact symptom: the global row count is 2, and neither
    workspace may see it."""
    async def scenario(session, seeded):
        with tenancy.admin_bypass():
            global_count = await session.scalar(
                select(func.count()).select_from(
                    select(Vulnerability)
                    .where(Vulnerability.id.in_([seeded["va"], seeded["vb"]]))
                    .subquery()
                )
            )
        with tenancy.workspace_scope(seeded["ws_a"]):
            _items, total = await paginate(
                session, select(Vulnerability).order_by(Vulnerability.id),
                Pagination(limit=50, offset=0),
            )
        return global_count, total

    global_count, total = _run(scenario)
    assert global_count == 2, "fixture did not create both rows; the test would prove nothing"
    assert total == 1, f"paginate returned the GLOBAL count ({total}) instead of the scoped one"


def test_paging_does_not_inflate_the_total(  ) -> None:
    """A small page must not change the total, and the total must still be workspace-scoped."""
    async def scenario(session, seeded):
        with tenancy.workspace_scope(seeded["ws_a"]):
            return await paginate(
                session, select(Vulnerability).order_by(Vulnerability.id),
                Pagination(limit=1, offset=0),
            )

    items, total = _run(scenario)
    assert len(items) == 1
    assert total == 1


# =============================================================================================
# FAIL CLOSED
# =============================================================================================

def test_unbound_pagination_of_a_tenant_scoped_table_raises() -> None:
    """No workspace context must NOT yield a global total. It must be a loud error -- the same
    fail-closed contract the entity query is already held to."""
    async def scenario(session, seeded):
        tenancy.clear_workspace()
        with pytest.raises(TenancyNotBoundError):
            await paginate(
                session, select(Vulnerability).order_by(Vulnerability.id),
                Pagination(limit=50, offset=0),
            )
        return True

    assert _run(scenario) is True


# =============================================================================================
# THE HELPER THE FIX RELIES ON
# =============================================================================================

def test_workspace_criterion_returns_none_for_non_tenant_tables() -> None:
    # (install() is not required for workspace_criterion itself -- it reads the registry
    # directly -- but calling it keeps these consistent with the rest of the file.)
    """SYSTEM/USER/GLOBAL-scoped tables must be left alone, so their existing counts are
    unchanged and legitimate exempt queries keep working."""
    from apps.api.modules.api_keys.models import ApiKey
    from apps.api.modules.scans.models import Scan
    from apps.api.modules.users.models import User as UserModel
    from apps.api.modules.workspaces.models import Workspace as WorkspaceModel

    tenancy.clear_workspace()
    for model in (Scan, ApiKey, UserModel, WorkspaceModel):
        assert workspace_criterion(model) is None, f"{model.__name__} must not be auto-scoped"


def test_workspace_criterion_returns_none_under_admin_bypass() -> None:
    """A genuine cross-workspace system query must still be able to count everything."""
    with tenancy.admin_bypass():
        assert workspace_criterion(Vulnerability) is None


def test_workspace_criterion_raises_when_unbound_for_a_tenant_table() -> None:
    tenancy.clear_workspace()
    with pytest.raises(TenancyNotBoundError):
        workspace_criterion(Vulnerability)


def test_workspace_criterion_builds_an_expression_for_direct_and_via_tables() -> None:
    """Both scoping mechanisms are covered -- a DIRECT table (own workspace_id) and a VIA
    table (scoped through a FK chain)."""
    from apps.api.modules.projects.models import Project as P

    ws = uuid.uuid4()
    with tenancy.workspace_scope(ws):
        assert workspace_criterion(P) is not None       # DIRECT
        assert workspace_criterion(Vulnerability) is not None  # VIA -> projects
