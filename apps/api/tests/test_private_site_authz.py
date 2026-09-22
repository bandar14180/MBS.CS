"""MBS.SC -- private-site authorization and per-scan network policy.

These tests prove the property the old design could not even express: that private
network access is decided PER TENANT, from persisted state, rather than by a global
configuration flag.

The single most important test here is
`test_global_flag_alone_does_not_authorize_any_tenant`: it turns the global on-prem
settings fully on -- the exact configuration that previously granted every workspace
access to every listed CIDR -- and asserts that nothing is thereby authorized.
"""
import asyncio
import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.private_sites import service as sites_service
from apps.api.modules.private_sites.models import PrivateSite
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine import net_policy
from apps.api.scanner_engine.net_guard import TargetNotAllowed, assert_ip_allowed, is_ip_allowed


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


@pytest.fixture
def private_scanning_enabled(monkeypatch):
    """The MOST PERMISSIVE global configuration this platform allows.

    Every test that uses this fixture runs with the outer safety boundary wide open for
    both 10/8 and 192.168/16 -- i.e. the deployment-wide setting that used to be the
    entire authorization decision. Anything still blocked in these tests is blocked by
    PER-TENANT authorization, which is exactly what we are proving.
    """
    s = get_settings()
    monkeypatch.setattr(s, "scan_allow_private_targets", True)
    monkeypatch.setattr(s, "scan_allowed_cidrs", ["10.0.0.0/8", "192.168.0.0/16"])
    return s


async def _new_workspace(session, label="mbs-sc"):
    """One user + one workspace. Workspace.owner_user_id is NOT NULL, so a real user row
    must exist first (same shape as test_tenancy_isolation's _seed_owner)."""
    user = User(email=f"{label}-{uuid.uuid4()}@test.local", password_hash="x", full_name="MBS.SC Test")
    session.add(user)
    await session.flush()
    ws = Workspace(name=f"{label}-{uuid.uuid4().hex[:8]}", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    return ws.id


async def _seed_two_tenants_with_sites(session):
    """Two workspaces, each with an ACTIVE private site whose CIDRs OVERLAP exactly.

    Both sites authorize 10.0.0.0/16 -- the realistic case, since RFC1918 space is not
    globally unique and two customers routinely use the same ranges. Isolation therefore
    cannot come from the addresses themselves; it must come from the site binding.
    """
    with tenancy.admin_bypass():
        ws_a = await _new_workspace(session, "ws-a")
        ws_b = await _new_workspace(session, "ws-b")
        site_a = PrivateSite(
            id=uuid.uuid4(), workspace_id=ws_a, name="hq",
            authorized_cidrs=["10.0.0.0/16"], dns_servers=["10.0.0.53"],
            dns_search_domains=[], status="active", scanner_pool_id="private-a",
        )
        site_b = PrivateSite(
            id=uuid.uuid4(), workspace_id=ws_b, name="hq",
            authorized_cidrs=["10.0.0.0/16"], dns_servers=["10.0.0.53"],
            dns_search_domains=[], status="active", scanner_pool_id="private-b",
        )
        session.add_all([site_a, site_b])
        await session.flush()
        return ws_a, ws_b, site_a, site_b


# --------------------------------------------------------------------------------------
# THE CORE PROPERTY: global configuration is a ceiling, not a grant.
# --------------------------------------------------------------------------------------

def test_global_flag_alone_does_not_authorize_any_tenant(private_scanning_enabled):
    """BEFORE: `scan_allow_private_targets=true` + a CIDR list authorized EVERY tenant.
    AFTER: with no per-scan policy bound, the same configuration authorizes nothing."""
    for addr in ("10.0.0.5", "10.99.1.1", "192.168.1.10"):
        assert is_ip_allowed(addr) is False, f"{addr} was authorized by global config alone"


def test_public_targets_are_unaffected_by_the_policy(private_scanning_enabled):
    """Existing public scanning must not change. A public address is allowed with no
    policy bound, with a public policy, and with a private policy alike."""
    policies = [
        None,
        net_policy.build_public_policy(workspace_id=uuid.uuid4()),
        net_policy.build_private_policy(
            workspace_id=uuid.uuid4(), scan_id=None, site_id=uuid.uuid4(),
            authorized_cidrs=["10.0.0.0/16"],
        ),
    ]
    for policy in policies:
        assert is_ip_allowed("93.184.216.34", policy=policy) is True


def test_public_policy_never_reaches_private_space(private_scanning_enabled):
    """A workspace that owns a private site still cannot reach it from a PUBLIC scan."""
    policy = net_policy.build_public_policy(workspace_id=uuid.uuid4())
    assert is_ip_allowed("10.0.0.5", policy=policy) is False


def test_unbound_context_is_fail_closed(private_scanning_enabled):
    """Forgetting to bind a policy must LOSE access, never gain it."""
    assert net_policy.current() is None
    assert net_policy.current_or_public().is_private is False
    assert is_ip_allowed("10.0.0.5") is False


# --------------------------------------------------------------------------------------
# CROSS-TENANT ISOLATION (Property C)
# --------------------------------------------------------------------------------------

def test_tenant_cannot_load_another_tenants_site():
    """Tenant A asking for tenant B's site id is refused, and the error does not
    disclose who actually owns it."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as session:
                ws_a, ws_b, site_a, site_b = await _seed_two_tenants_with_sites(session)
                with tenancy.workspace_scope(ws_a):
                    # A can load its own site.
                    got = await sites_service.get_site_for_workspace(session, site_a.id, ws_a)
                    assert got.id == site_a.id
                    # A cannot load B's.
                    with pytest.raises(sites_service.PrivateSiteNotAuthorized) as exc:
                        await sites_service.get_site_for_workspace(session, site_b.id, ws_a)
                assert exc.value.reason == sites_service.REASON_SITE_WRONG_WORKSPACE
                assert str(ws_b) not in exc.value.message, "error message leaked the owning workspace"
        finally:
            await engine.dispose()

    asyncio.run(scenario())

def test_overlapping_rfc1918_ranges_stay_isolated(private_scanning_enabled):
    """Both tenants authorize 10.0.0.0/16. Each policy admits the address only under its
    OWN site -- the addresses are identical, so only the binding separates them."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as session:
                ws_a, ws_b, site_a, site_b = await _seed_two_tenants_with_sites(session)
                with tenancy.workspace_scope(ws_a):
                    policy_a = await sites_service.build_scan_network_policy(
                        session, workspace_id=ws_a, scan_id=None,
                        network_zone="private", site_id=site_a.id,
                    )
                with tenancy.workspace_scope(ws_b):
                    policy_b = await sites_service.build_scan_network_policy(
                        session, workspace_id=ws_b, scan_id=None,
                        network_zone="private", site_id=site_b.id,
                    )
                # Each policy is scoped to its own workspace and site...
                assert policy_a.workspace_id == ws_a and policy_a.site_id == site_a.id
                assert policy_b.workspace_id == ws_b and policy_b.site_id == site_b.id
                assert policy_a.site_id != policy_b.site_id
                # ...and A can never obtain a policy naming B's site.
                with tenancy.workspace_scope(ws_a):
                    with pytest.raises(sites_service.PrivateSiteNotAuthorized):
                        await sites_service.build_scan_network_policy(
                            session, workspace_id=ws_a, scan_id=None,
                            network_zone="private", site_id=site_b.id,
                        )
        finally:
            await engine.dispose()

    asyncio.run(scenario())

def test_cross_tenant_cidr_is_blocked(private_scanning_enabled):
    """Tenant A authorized for 10.0.0.0/16 cannot reach tenant B's 10.50.0.0/16."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as session:
                with tenancy.admin_bypass():
                    ws_a = await _new_workspace(session)
                    site_a = PrivateSite(
                        id=uuid.uuid4(), workspace_id=ws_a, name="dc1",
                        authorized_cidrs=["10.0.0.0/16"], dns_servers=[], dns_search_domains=[],
                        status="active",
                    )
                    session.add(site_a)
                    await session.flush()
                with tenancy.workspace_scope(ws_a):
                    policy = await sites_service.build_scan_network_policy(
                        session, workspace_id=ws_a, scan_id=None,
                        network_zone="private", site_id=site_a.id,
                    )
                with net_policy.bind(policy):
                    assert is_ip_allowed("10.0.5.5") is True        # inside its own site
                    assert is_ip_allowed("10.50.0.5") is False      # another tenant's range
                    # The refusal is an AUTHORIZATION message, not a generic SSRF one --
                    # 10.50.0.5 clears the global boundary but not this scan's.
                    with pytest.raises(TargetNotAllowed, match="not authorized for this scan"):
                        assert_ip_allowed("10.50.0.5")
        finally:
            await engine.dispose()


    # --------------------------------------------------------------------------------------
    # SITE LIFECYCLE (Phases 11/13)
    # --------------------------------------------------------------------------------------

    asyncio.run(scenario())

@pytest.mark.parametrize("status", ["pending", "key_exchanged", "verified", "suspended", "revoked"])
def test_only_active_sites_are_scannable(status, private_scanning_enabled):
    """ACTIVE is the only scannable state; every other lifecycle state refuses."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as session:
                with tenancy.admin_bypass():
                    ws = await _new_workspace(session)
                    site = PrivateSite(
                        id=uuid.uuid4(), workspace_id=ws, name=f"s-{status}",
                        authorized_cidrs=["10.0.0.0/16"], dns_servers=[], dns_search_domains=[],
                        status=status,
                    )
                    session.add(site)
                    await session.flush()
                with tenancy.workspace_scope(ws):
                    with pytest.raises(sites_service.PrivateSiteNotAuthorized) as exc:
                        await sites_service.build_scan_network_policy(
                            session, workspace_id=ws, scan_id=None,
                            network_zone="private", site_id=site.id,
                        )
                assert exc.value.reason in {
                    sites_service.REASON_SITE_SUSPENDED,
                    sites_service.REASON_SITE_REVOKED,
                    sites_service.REASON_SITE_NOT_ACTIVE,
                }
        finally:
            await engine.dispose()

    asyncio.run(scenario())

def test_site_with_no_authorized_cidrs_refuses(private_scanning_enabled):
    """An empty CIDR list must REFUSE, not be read as 'unrestricted'."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as session:
                with tenancy.admin_bypass():
                    ws = await _new_workspace(session)
                    site = PrivateSite(
                        id=uuid.uuid4(), workspace_id=ws, name="empty",
                        authorized_cidrs=[], dns_servers=[], dns_search_domains=[], status="active",
                    )
                    session.add(site)
                    await session.flush()
                with tenancy.workspace_scope(ws):
                    with pytest.raises(sites_service.PrivateSiteNotAuthorized) as exc:
                        await sites_service.build_scan_network_policy(
                            session, workspace_id=ws, scan_id=None,
                            network_zone="private", site_id=site.id,
                        )
                assert exc.value.reason == sites_service.REASON_NO_AUTHORIZED_CIDRS
        finally:
            await engine.dispose()

    asyncio.run(scenario())

def test_private_target_without_a_site_refuses():
    """network_zone=private with site_id=None cannot be authorized against anything."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as session:
                with pytest.raises(sites_service.PrivateSiteNotAuthorized) as exc:
                    await sites_service.build_scan_network_policy(
                        session, workspace_id=uuid.uuid4(), scan_id=None,
                        network_zone="private", site_id=None,
                    )
                assert exc.value.reason == sites_service.REASON_TARGET_MISSING_SITE
        finally:
            await engine.dispose()


    # --------------------------------------------------------------------------------------
    # ADDRESS-LEVEL EDGE CASES preserved from net_guard, now under a private policy
    # --------------------------------------------------------------------------------------

    asyncio.run(scenario())

def test_ipv4_mapped_ipv6_cannot_smuggle_an_unauthorized_address(private_scanning_enabled):
    """::ffff:10.50.0.5 must be normalized and judged as 10.50.0.5."""
    policy = net_policy.build_private_policy(
        workspace_id=uuid.uuid4(), scan_id=None, site_id=uuid.uuid4(),
        authorized_cidrs=["10.0.0.0/16"],
    )
    with net_policy.bind(policy):
        assert is_ip_allowed("::ffff:10.0.0.5") is True
        assert is_ip_allowed("::ffff:10.50.0.5") is False


def test_metadata_needs_explicit_host_and_scan_authorization(monkeypatch):
    """A cloud metadata IP requires BOTH an explicit /32 globally AND scan authorization."""
    s = get_settings()
    monkeypatch.setattr(s, "scan_allow_private_targets", True)
    monkeypatch.setattr(s, "scan_allowed_cidrs", ["169.254.169.254/32"])
    # Authorized for a broad range that CONTAINS the metadata IP, but the global side
    # still demands an explicit single-host entry -- which it has here -- so this is the
    # one combination that permits it.
    permitted = net_policy.build_private_policy(
        workspace_id=uuid.uuid4(), scan_id=None, site_id=uuid.uuid4(),
        authorized_cidrs=["169.254.169.254/32"],
    )
    with net_policy.bind(permitted):
        assert is_ip_allowed("169.254.169.254") is True
    # A site authorizing only RFC1918 space cannot reach metadata.
    other = net_policy.build_private_policy(
        workspace_id=uuid.uuid4(), scan_id=None, site_id=uuid.uuid4(),
        authorized_cidrs=["10.0.0.0/8"],
    )
    with net_policy.bind(other):
        assert is_ip_allowed("169.254.169.254") is False


def test_cgnat_range_still_requires_authorization(private_scanning_enabled):
    """RFC6598 (100.64/10) handling is preserved and now also policy-gated."""
    policy = net_policy.build_private_policy(
        workspace_id=uuid.uuid4(), scan_id=None, site_id=uuid.uuid4(),
        authorized_cidrs=["10.0.0.0/16"],
    )
    with net_policy.bind(policy):
        assert is_ip_allowed("100.64.0.1") is False


def test_loopback_and_link_local_never_become_reachable(private_scanning_enabled):
    """Even a site that tries to authorize them is bounded by the global allowlist,
    which does not contain them."""
    policy = net_policy.build_private_policy(
        workspace_id=uuid.uuid4(), scan_id=None, site_id=uuid.uuid4(),
        authorized_cidrs=["127.0.0.0/8", "169.254.0.0/16", "10.0.0.0/16"],
    )
    with net_policy.bind(policy):
        assert is_ip_allowed("127.0.0.1") is False
        assert is_ip_allowed("169.254.1.1") is False
        assert is_ip_allowed("10.0.0.1") is True  # the one range both keys agree on


def test_cidr_target_must_be_fully_contained(private_scanning_enabled):
    """A /8 whose edges happen to sit inside an authorized /16 must NOT be accepted --
    tools expand a CIDR, so partial overlap would scan unauthorized addresses."""
    from apps.api.scanner_engine.net_guard import resolve_and_validate

    policy = net_policy.build_private_policy(
        workspace_id=uuid.uuid4(), scan_id=None, site_id=uuid.uuid4(),
        authorized_cidrs=["10.0.0.0/16"],
    )
    with net_policy.bind(policy):
        assert resolve_and_validate("10.0.0.0/24") == "10.0.0.0/24"   # inside
        with pytest.raises(TargetNotAllowed):
            resolve_and_validate("10.0.0.0/8")                        # straddles


# --------------------------------------------------------------------------------------
# CONCURRENCY (Property C under concurrent scans)
# --------------------------------------------------------------------------------------

def test_concurrent_scans_do_not_share_policy(private_scanning_enabled):
    """Two scans running concurrently in one process must not observe each other's
    policy. Each asyncio task gets its own contextvar copy."""
    async def scenario():
        import asyncio

        policy_a = net_policy.build_private_policy(
            workspace_id=uuid.uuid4(), scan_id=None, site_id=uuid.uuid4(),
            authorized_cidrs=["10.1.0.0/16"],
        )
        policy_b = net_policy.build_private_policy(
            workspace_id=uuid.uuid4(), scan_id=None, site_id=uuid.uuid4(),
            authorized_cidrs=["10.2.0.0/16"],
        )
        observed = {}

        async def scan(name, policy, own_ip, other_ip):
            with net_policy.bind(policy):
                await asyncio.sleep(0)  # force interleaving
                observed[name] = (is_ip_allowed(own_ip), is_ip_allowed(other_ip))
                await asyncio.sleep(0)
                # still ours after the other task ran
                assert net_policy.current().site_id == policy.site_id

        await asyncio.gather(
            scan("a", policy_a, "10.1.0.5", "10.2.0.5"),
            scan("b", policy_b, "10.2.0.5", "10.1.0.5"),
        )
        assert observed["a"] == (True, False)
        assert observed["b"] == (True, False)
        # And the ambient context is clean afterwards.
        assert net_policy.current() is None

    asyncio.run(scenario())
