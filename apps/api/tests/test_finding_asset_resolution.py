"""Fix #1: hierarchical finding-to-asset resolution (`orchestrator._resolve_asset_id`).

WHY THIS FILE EXISTS
--------------------
The resolver used to accept exactly one shape: an `http_service` asset whose `value` was
byte-equal to the finding's `matched_at` (after `rstrip("/")`). A DAST finding is reported
at the URL the payload was delivered to --

    https://reg.ftu.ac.th/registrar/studentset.asp?cmd=1&order=STUDENTNAME&campusid=1'...

-- which equals no stored asset value, because the stored asset is the clean endpoint and
the finding's location differs by the injected bytes. On scan 15488e89 that left 362 of
362 critical+high findings with `asset_id IS NULL` while `https://reg.ftu.ac.th` sat in the
inventory the whole time.

The fix adds two tiers below the original exact match (a `url`-asset exact match, then an
origin fallback). The tests below pin BOTH halves of the contract: that the new tiers
resolve what they should, and -- at least as important -- that they refuse to resolve
anything whose host, port, target or workspace differs, and that the pre-existing tier-1
behaviour is reproduced unchanged.

Every test asserts the RETURNED ASSET ID against a specific seeded row, not merely that a
call did not raise.
"""
import asyncio
import uuid

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.assets.models import Asset
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.orchestrator import _finding_origin, _resolve_asset_id


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


def _run(coro):
    asyncio.run(coro)


async def _seed_target(s, *, workspace_id=None, user_id=None, host="ex.test"):
    """One workspace/project/target/scan chain. Mirrors test_vulnerability_history._seed
    rather than introducing a new factory; `workspace_id`/`user_id` let a caller build a
    SECOND tenant against the same session for the isolation test."""
    if user_id is None:
        user = User(email=f"res-{uuid.uuid4()}@test.local", password_hash="x", full_name="Resolver Tester")
        s.add(user)
        await s.flush()
        user_id = user.id
    if workspace_id is None:
        ws = Workspace(name=f"res-ws-{uuid.uuid4().hex[:8]}", owner_user_id=user_id)
        s.add(ws)
        await s.flush()
        workspace_id = ws.id
    tenancy.bind_workspace(workspace_id)
    project = Project(workspace_id=workspace_id, name=f"res-{uuid.uuid4().hex[:8]}", created_by=user_id)
    s.add(project)
    await s.flush()
    target = Target(
        project_id=project.id, type="domain", value=host, criticality="low", added_by=user_id
    )
    s.add(target)
    await s.flush()
    scan = Scan(
        workspace_id=workspace_id, project_id=project.id, target_id=target.id,
        initiated_by=user_id, scan_type="web", status="running", config={},
        execution_token=uuid.uuid4(),
    )
    s.add(scan)
    await s.flush()
    return project, target, scan, workspace_id, user_id


async def _asset(s, project, target, asset_type, value):
    a = Asset(project_id=project.id, target_id=target.id, asset_type=asset_type, value=value)
    s.add(a)
    await s.flush()
    return a


# --- 1: the pre-existing exact http_service match, unchanged ----------------------------------

def test_exact_http_service_match_still_resolves():
    """Tier 1 is the original implementation's only behaviour. It must be reproduced
    byte-for-byte, because every one of the 235 already-linked findings on scan 15488e89
    was produced by it."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    svc = await _asset(s, project, target, "http_service", "https://ex.test")
                    assert await _resolve_asset_id(s, scan, "https://ex.test") == svc.id
                    # The original `.rstrip("/")` is preserved, so the trailing-slash form
                    # of the same location still lands on the same row.
                    assert await _resolve_asset_id(s, scan, "https://ex.test/") == svc.id
        finally:
            await engine.dispose()
    _run(scenario())


def test_http_service_wins_over_url_asset_with_the_same_value():
    """When a target stores one value under BOTH types, tier 1 must win -- otherwise the
    fix would silently REASSIGN findings that already resolve correctly today."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    url_asset = await _asset(s, project, target, "url", "https://ex.test/app")
                    svc = await _asset(s, project, target, "http_service", "https://ex.test/app")
                    got = await _resolve_asset_id(s, scan, "https://ex.test/app")
                    assert got == svc.id
                    assert got != url_asset.id
        finally:
            await engine.dispose()
    _run(scenario())


# --- 2: exact url-asset match ------------------------------------------------------------------

def test_exact_url_asset_match_resolves():
    """Tier 2. katana/ffuf/arjun record deep endpoints as `url`, which tier 1 could never
    see -- the old resolver filtered on `asset_type == "http_service"` alone."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    deep = await _asset(s, project, target, "url", "https://ex.test/registrar/home.asp")
                    assert await _resolve_asset_id(
                        s, scan, "https://ex.test/registrar/home.asp"
                    ) == deep.id
        finally:
            await engine.dispose()
    _run(scenario())


# --- 3: deep URL -> origin ---------------------------------------------------------------------

def test_deep_url_resolves_to_origin_asset():
    """Tier 3, the core of Fix #1: a deep path that matches no asset exactly still resolves
    to the asset representing its origin."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    origin = await _asset(s, project, target, "http_service", "https://ex.test")
                    assert await _resolve_asset_id(
                        s, scan, "https://ex.test/registrar/studentByProgramShow_RTF.asp"
                    ) == origin.id
        finally:
            await engine.dispose()
    _run(scenario())


def test_query_string_url_resolves_to_origin():
    """A parameterised endpoint -- the shape carrying the real DAST findings."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    origin = await _asset(s, project, target, "http_service", "https://ex.test")
                    assert await _resolve_asset_id(
                        s, scan,
                        "https://ex.test/registrar/studentset.asp?cmd=1&order=STUDENTNAME"
                        "&campusid=1&groupyear=69&studentgroup=12402",
                    ) == origin.id
        finally:
            await engine.dispose()
    _run(scenario())


def test_injected_and_encoded_payload_url_resolves_to_origin():
    """The literal shapes from scan 15488e89: a quote-injected SQLi location, a `|dir`
    command-injection location, and a percent-encoded one. The payload lives in the query,
    so it must not influence WHICH asset is chosen -- only the origin does."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    origin = await _asset(s, project, target, "http_service", "https://ex.test")
                    for loc in (
                        "https://ex.test/registrar/studentset.asp?cmd=1&campusid=1'&groupyear=69",
                        "https://ex.test/registrar/studentset.asp?cmd=1&order=|dir&campusid=1",
                        "https://ex.test/registrar/News.asp?webmsgid=%27%20OR%201%3D1--",
                        "https://ex.test/a?x=<script>alert(1)</script>",
                    ):
                        assert await _resolve_asset_id(s, scan, loc) == origin.id, loc
        finally:
            await engine.dispose()
    _run(scenario())


def test_trailing_slash_forms_normalize_to_one_origin():
    """`https://ex.test`, `https://ex.test/` and a deep path under it are one origin."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    # Stored WITH a trailing slash; findings arrive without one and vice versa.
                    origin = await _asset(s, project, target, "http_service", "https://ex.test/")
                    assert await _resolve_asset_id(s, scan, "https://ex.test/deep/path") == origin.id
                    # Exact tier still handles the bare form via the preserved rstrip("/").
                    assert await _resolve_asset_id(s, scan, "https://ex.test") == origin.id
        finally:
            await engine.dispose()
    _run(scenario())


# --- 4: explicit ports -------------------------------------------------------------------------

def test_explicit_non_default_port_resolves_to_its_own_origin():
    """An explicit non-default port is part of the origin and must resolve to the asset
    carrying that port -- not to the :443 asset on the same hostname."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    default = await _asset(s, project, target, "http_service", "https://ex.test")
                    alt = await _asset(s, project, target, "http_service", "https://ex.test:8443")
                    assert await _resolve_asset_id(s, scan, "https://ex.test:8443/admin/x") == alt.id
                    assert await _resolve_asset_id(s, scan, "https://ex.test/admin/x") == default.id
                    # :443 is the default for https and folds onto the portless asset.
                    assert await _resolve_asset_id(s, scan, "https://ex.test:443/admin/x") == default.id
        finally:
            await engine.dispose()
    _run(scenario())


def test_wrong_port_does_not_match():
    """Only the :8443 asset exists; a finding on :9000 must NOT borrow it."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    await _asset(s, project, target, "http_service", "https://ex.test:8443")
                    assert await _resolve_asset_id(s, scan, "https://ex.test:9000/x") is None
        finally:
            await engine.dispose()
    _run(scenario())


def test_scheme_must_match():
    """http and https are different origins even on one hostname."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    await _asset(s, project, target, "http_service", "https://ex.test")
                    assert await _resolve_asset_id(s, scan, "http://ex.test/x") is None
        finally:
            await engine.dispose()
    _run(scenario())


# --- 5: wrong host / sibling hostnames ---------------------------------------------------------

def test_wrong_hostname_does_not_match():
    """Never a hostname-only or suffix match. `www.reg` and `reg` are real sibling hosts in
    the inventory this fix was written against, and they are NOT interchangeable."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    reg = await _asset(s, project, target, "http_service", "https://reg.ex.test")
                    assert await _resolve_asset_id(s, scan, "https://other.ex.test/x") is None
                    assert await _resolve_asset_id(s, scan, "https://www.reg.ex.test/x") is None
                    assert await _resolve_asset_id(s, scan, "https://ex.test/x") is None
                    # ...while the correct host still resolves.
                    assert await _resolve_asset_id(s, scan, "https://reg.ex.test/x") == reg.id
        finally:
            await engine.dispose()
    _run(scenario())


# --- 6: cross-target and cross-tenant ----------------------------------------------------------

def test_asset_of_a_different_target_does_not_match():
    """Two targets in ONE project/workspace: the origin lives only on target B, so a scan
    of target A must not attribute to it. Tenancy alone would not catch this -- the
    target_id predicate is what does."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target_a, scan_a, wsid, uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    target_b = Target(
                        project_id=project.id, type="domain", value="b.test",
                        criticality="low", added_by=uid,
                    )
                    s.add(target_b)
                    await s.flush()
                    b_asset = Asset(
                        project_id=project.id, target_id=target_b.id,
                        asset_type="http_service", value="https://shared.test",
                    )
                    s.add(b_asset)
                    await s.flush()
                    # Same origin string, different target -> no attribution.
                    assert await _resolve_asset_id(s, scan_a, "https://shared.test/deep") is None
                    assert await _resolve_asset_id(s, scan_a, "https://shared.test") is None
        finally:
            await engine.dispose()
    _run(scenario())


def test_asset_of_a_different_workspace_does_not_match():
    """Cross-tenant: the only asset for this origin belongs to another workspace. The
    tenancy auto-filter on `select(Asset)` must keep it invisible in both tiers."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                # Tenant B owns an asset at the origin.
                project_b, target_b, _scan_b, ws_b, _uid_b = await _seed_target(s, host="t.test")
                with tenancy.workspace_scope(ws_b):
                    await _asset(s, project_b, target_b, "http_service", "https://tenant.test")
                # Tenant A scans, and must see nothing of B's.
                project_a, target_a, scan_a, ws_a, _uid_a = await _seed_target(s, host="t.test")
                with tenancy.workspace_scope(ws_a):
                    assert await _resolve_asset_id(s, scan_a, "https://tenant.test/deep") is None
                    assert await _resolve_asset_id(s, scan_a, "https://tenant.test") is None
        finally:
            await engine.dispose()
    _run(scenario())


# --- 7: ambiguity fails closed -----------------------------------------------------------------

def test_ambiguous_origin_returns_none():
    """Two assets of one type that BOTH merely live under an origin, neither of which is
    the origin itself, are a genuine tie -- a coin flip between two deep pages. Tier 3
    returns None; an unlinked finding beats a misattributed one.

    This is the real `https://www.google.com` case on the audited target: two deep
    `/accounts/...` and `/a/...` pages, no bare-origin row."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    await _asset(s, project, target, "http_service", "https://ex.test/accounts/a")
                    await _asset(s, project, target, "http_service", "https://ex.test/a/b")
                    assert await _resolve_asset_id(s, scan, "https://ex.test/deep/path") is None
        finally:
            await engine.dispose()
    _run(scenario())


def test_asset_that_is_the_origin_outranks_one_merely_under_it():
    """THE case that decides whether this fix works at all. On the audited target both
    `https://reg.ftu.ac.th` and `https://reg.ftu.ac.th/registrar/home.asp` are
    http_service rows. They are NOT interchangeable: the first IS the origin, the second
    is one page beneath it. Ranking the origin row above the deep row is what lets the 274
    critical/high findings on that host resolve; treating it as a tie leaves every one of
    them unattributed."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    deep = await _asset(
                        s, project, target, "http_service", "https://ex.test/registrar/home.asp"
                    )
                    origin = await _asset(s, project, target, "http_service", "https://ex.test")
                    got = await _resolve_asset_id(
                        s, scan, "https://ex.test/registrar/studentset.asp?cmd=1&campusid=1'"
                    )
                    assert got == origin.id
                    assert got != deep.id
                    # The deep row is still reachable by its own exact value (tier 1).
                    assert await _resolve_asset_id(
                        s, scan, "https://ex.test/registrar/home.asp"
                    ) == deep.id
        finally:
            await engine.dispose()
    _run(scenario())


def test_two_spellings_of_one_origin_are_not_a_tie():
    """`https://ex.test` and `https://ex.test/` are the same location written two ways --
    both exist as http_service rows on the real target. That must resolve, not fail closed
    as a false conflict; whichever row is chosen denotes the identical origin."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    bare = await _asset(s, project, target, "http_service", "https://ex.test")
                    slashed = await _asset(s, project, target, "http_service", "https://ex.test/")
                    got = await _resolve_asset_id(s, scan, "https://ex.test/deep/path")
                    assert got in {bare.id, slashed.id}
        finally:
            await engine.dispose()
    _run(scenario())


def test_preferred_type_is_not_made_ambiguous_by_a_lower_type():
    """A `url` asset sharing an origin with a single `http_service` asset is NOT a tie --
    the preferred type resolves. Ambiguity only applies WITHIN one type, otherwise the 701
    url assets on the real target would poison nearly every origin."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    svc = await _asset(s, project, target, "http_service", "https://ex.test")
                    await _asset(s, project, target, "url", "https://ex.test/a")
                    await _asset(s, project, target, "url", "https://ex.test/b")
                    assert await _resolve_asset_id(s, scan, "https://ex.test/deep") == svc.id
        finally:
            await engine.dispose()
    _run(scenario())


def test_url_assets_alone_resolve_an_origin_when_unambiguous():
    """With no http_service asset, a single url asset's origin still serves the fallback."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    only = await _asset(s, project, target, "url", "https://ex.test/a")
                    assert await _resolve_asset_id(s, scan, "https://ex.test/zzz") == only.id
        finally:
            await engine.dispose()
    _run(scenario())


# --- 8: non-URL and empty locations ------------------------------------------------------------

def test_non_url_locations_return_none():
    """A bare host:port (nmap/naabu), a source location (Semgrep readiness), a non-http
    scheme and an empty value have no http(s) origin and must not resolve."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                project, target, scan, wsid, _uid = await _seed_target(s)
                with tenancy.workspace_scope(wsid):
                    await _asset(s, project, target, "http_service", "https://ex.test")
                    for loc in (None, "", "ex.test:443", "src/Auth/Login.java:42", "ftp://ex.test/x"):
                        assert await _resolve_asset_id(s, scan, loc) is None, loc
        finally:
            await engine.dispose()
    _run(scenario())


# --- 9: the origin helper in isolation ---------------------------------------------------------

def test_finding_origin_keeps_scheme_host_and_explicit_port():
    """Pure-function pin on the comparison key: scheme, host and an explicit non-default
    port are all preserved; a default port folds; path/query/fragment/userinfo are dropped."""
    assert _finding_origin("https://H.ex.test/a/b?c=1#f") == "https://h.ex.test"
    assert _finding_origin("https://h.ex.test:443/a") == "https://h.ex.test"
    assert _finding_origin("http://h.ex.test:80/a") == "http://h.ex.test"
    assert _finding_origin("https://h.ex.test:8443/a") == "https://h.ex.test:8443"
    assert _finding_origin("http://h.ex.test/a") == "http://h.ex.test"
    assert _finding_origin("https://user:pw@h.ex.test/a") == "https://h.ex.test"
    assert _finding_origin("https://[::1]:8443/a") == "https://[::1]:8443"
    # Distinctness is the safety property: none of these collapse into another.
    distinct = {
        _finding_origin(u)
        for u in (
            "https://h.ex.test/a", "http://h.ex.test/a", "https://h.ex.test:8443/a",
            "https://www.h.ex.test/a", "https://other.ex.test/a",
        )
    }
    assert len(distinct) == 5
    for bad in (None, "", "ex.test:443", "src/A.java:1", "ftp://h/x", "not a url"):
        assert _finding_origin(bad or "") is None, bad
