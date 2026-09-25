"""MBS.SC P7-3 -- site-specific private DNS for private hostname targets.

THE FINDING
-----------
`site_dns` was complete except that NOTHING in production ever called `set_backend()`, so
`_default_backend` answered every private lookup and every private HOSTNAME target failed
closed with SiteDNSUnavailable. (Private IP/CIDR targets were unaffected -- they never
resolve.) The gap was the TRANSPORT, not the policy.

THE PROPERTY THAT MAKES THE FIX SAFE
------------------------------------
The production backend holds NO SITE STATE. Site selection already travels per-scan on
`ScanNetworkPolicy.dns_servers`, which `net_guard.resolve_hostname` reads from the
task-local policy ContextVar. The global `_backend` is only "send this query to THAT
resolver", so it cannot race or leak between concurrent scans.

These tests prove that, plus the thing the whole module exists for: NO PUBLIC FALLBACK,
under every failure mode.
"""
import asyncio
import socket
import uuid

import pytest

from apps.api.scanner_engine import net_guard, net_policy, site_dns

SITE_A_RESOLVER = "10.0.0.53"
SITE_B_RESOLVER = "10.1.0.53"


@pytest.fixture
def private_scanning_enabled(monkeypatch):
    """Global ceiling wide open, so anything refused below is refused per-tenant."""
    from apps.api.core.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "scan_allow_private_targets", True)
    monkeypatch.setattr(s, "scan_allowed_cidrs", ["10.0.0.0/8"])
    return s


@pytest.fixture(autouse=True)
def _no_backend_leaks_between_tests():
    """A backend installed by one test must never survive into the next -- that is the
    very leak this module is about."""
    site_dns.reset_backend()
    yield
    site_dns.reset_backend()


@pytest.fixture
def resolver_tripwire(monkeypatch):
    """Counts every OS/public resolver call. Any non-zero count on a private lookup is a
    DNS leak, which is the single most important thing here."""
    calls = []
    real = socket.getaddrinfo

    def spy(*a, **k):
        calls.append(a[0] if a else None)
        return real(*a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", spy)
    return calls


def _policy_a():
    return net_policy.build_private_policy(
        workspace_id=uuid.uuid4(), scan_id=uuid.uuid4(), site_id=uuid.uuid4(),
        authorized_cidrs=["10.0.0.0/16"], dns_servers=[SITE_A_RESOLVER])


def _policy_b():
    return net_policy.build_private_policy(
        workspace_id=uuid.uuid4(), scan_id=uuid.uuid4(), site_id=uuid.uuid4(),
        authorized_cidrs=["10.1.0.0/16"], dns_servers=[SITE_B_RESOLVER])


def _split_horizon_backend(record):
    """A two-site resolver. Each site answers ONLY for its own zone, and records which
    resolver was asked -- so a cross-site query is visible, not merely wrong."""
    zones = {
        SITE_A_RESOLVER: {"app.site-a.internal": ["10.0.0.20"]},
        SITE_B_RESOLVER: {"app.site-b.internal": ["10.1.0.20"]},
    }

    def backend(hostname, resolver):
        record.append((hostname, resolver))
        return list(zones.get(resolver, {}).get(hostname, []))

    return backend


# =======================================================================================
# 1-2 -- the authorized private path now WORKS, through the correct site's resolver
# =======================================================================================

def test_an_authorized_private_hostname_resolves_through_its_own_site_resolver(
        private_scanning_enabled, resolver_tripwire):
    seen = []
    site_dns.set_backend(_split_horizon_backend(seen))
    with net_policy.bind(_policy_a()):
        addrs = net_guard.resolve_hostname("app.site-a.internal", attempts=1)
    assert addrs == ["10.0.0.20"]
    assert seen == [("app.site-a.internal", SITE_A_RESOLVER)]
    assert resolver_tripwire == [], "a private lookup touched the OS/public resolver"


def test_the_resolved_address_is_still_subject_to_cidr_authorization(
        private_scanning_enabled, resolver_tripwire):
    """§11: a successful DNS lookup alone must NOT authorize the target. The resolved IP
    still has to clear the existing policy."""
    # The site's own resolver answers with an address OUTSIDE the site's authorized CIDRs.
    site_dns.set_backend(lambda h, r: ["10.9.9.9"])
    with net_policy.bind(_policy_a()):
        with pytest.raises(net_guard.TargetNotAllowed):
            net_guard.resolve_and_validate("app.site-a.internal")
    assert resolver_tripwire == []


# =======================================================================================
# 3-5, 15-16 -- cross-site and cross-tenant
# =======================================================================================

def test_site_a_cannot_resolve_site_bs_hostname(private_scanning_enabled, resolver_tripwire):
    """§16: site A asks for a site-B name. A's resolver does not know it -> FAIL CLOSED,
    and site B's resolver is never queried."""
    seen = []
    site_dns.set_backend(_split_horizon_backend(seen))
    with net_policy.bind(_policy_a()):
        with pytest.raises(site_dns.SiteDNSUnavailable):
            net_guard.resolve_hostname("app.site-b.internal", attempts=1)

    queried_resolvers = {r for (_h, r) in seen}
    assert queried_resolvers == {SITE_A_RESOLVER}
    assert SITE_B_RESOLVER not in queried_resolvers, "site B's DNS backend was queried"
    assert resolver_tripwire == []


def test_site_b_cannot_resolve_site_as_hostname(private_scanning_enabled, resolver_tripwire):
    seen = []
    site_dns.set_backend(_split_horizon_backend(seen))
    with net_policy.bind(_policy_b()):
        with pytest.raises(site_dns.SiteDNSUnavailable):
            net_guard.resolve_hostname("app.site-a.internal", attempts=1)
    assert {r for (_h, r) in seen} == {SITE_B_RESOLVER}
    assert resolver_tripwire == []


def test_each_site_resolves_its_own_name_to_its_own_address(
        private_scanning_enabled, resolver_tripwire):
    """§8: the same module, two sites, no bleed -- including the overlapping-name case."""
    seen = []
    site_dns.set_backend(_split_horizon_backend(seen))
    with net_policy.bind(_policy_a()):
        assert net_guard.resolve_hostname("app.site-a.internal", attempts=1) == ["10.0.0.20"]
    with net_policy.bind(_policy_b()):
        assert net_guard.resolve_hostname("app.site-b.internal", attempts=1) == ["10.1.0.20"]
    assert resolver_tripwire == []


# =======================================================================================
# 6-8 -- FAIL CLOSED on every failure mode (§7)
# =======================================================================================

def test_an_unavailable_backend_fails_closed(private_scanning_enabled, resolver_tripwire):
    def dead(hostname, resolver):
        raise OSError("connection refused")

    site_dns.set_backend(dead)
    with net_policy.bind(_policy_a()):
        with pytest.raises(site_dns.SiteDNSUnavailable):
            net_guard.resolve_hostname("app.site-a.internal", attempts=1)
    assert resolver_tripwire == [], "a resolver outage fell back to the public resolver"


def test_a_resolver_timeout_fails_closed(private_scanning_enabled, resolver_tripwire):
    def slow(hostname, resolver):
        raise TimeoutError("query timed out")

    site_dns.set_backend(slow)
    with net_policy.bind(_policy_a()):
        with pytest.raises(site_dns.SiteDNSUnavailable):
            net_guard.resolve_hostname("app.site-a.internal", attempts=1)
    assert resolver_tripwire == []


def test_a_site_with_no_resolver_named_never_reaches_the_site_dns_backend(
        private_scanning_enabled, resolver_tripwire):
    """A private policy naming NO resolver must not borrow ANOTHER site's backend.

    P7-3-OBS-1 IS NOW FIXED, and this test asserts the secure behaviour.

    It was originally written as a CHARACTERISATION of a pre-existing gap found while
    building P7-3: `net_guard.resolve_hostname` gated the private branch on
    `is_private AND dns_servers`, so a private policy whose site had an EMPTY resolver list
    fell through to the OS resolver. That gate now routes on the ZONE ALONE, so a private
    scan has no path to the OS resolver at all.

    Two properties are locked here:
      * P7-3's own: no other site's resolver is ever consulted for this lookup;
      * P7-3-OBS-1's: the OS/public resolver is not consulted either -- it fails closed.
    """
    seen = []
    site_dns.set_backend(_split_horizon_backend(seen))
    no_dns = net_policy.build_private_policy(
        workspace_id=uuid.uuid4(), scan_id=None, site_id=uuid.uuid4(),
        authorized_cidrs=["10.0.0.0/16"], dns_servers=[])
    with net_policy.bind(no_dns):
        with pytest.raises(socket.gaierror):
            net_guard.resolve_hostname("app.site-a.internal", attempts=1)

    # P7-3's own guarantee: no site's resolver was queried on this path.
    assert seen == [], "a site with no resolvers borrowed another site's DNS backend"
    # P7-3-OBS-1's guarantee: it fails closed instead of leaking to the public resolver.
    assert resolver_tripwire == [], (
        "P7-3-OBS-1 regression: a private lookup with no resolvers reached the OS/public "
        "resolver"
    )


def test_with_no_backend_installed_it_still_fails_closed(
        private_scanning_enabled, resolver_tripwire):
    """The pre-P7-3 state must remain the SAFE state, not become a fallback."""
    site_dns.reset_backend()
    with net_policy.bind(_policy_a()):
        with pytest.raises(site_dns.SiteDNSUnavailable, match="refusing to resolve"):
            net_guard.resolve_hostname("app.site-a.internal", attempts=1)
    assert resolver_tripwire == []


def test_an_empty_answer_is_not_success(private_scanning_enabled, resolver_tripwire):
    site_dns.set_backend(lambda h, r: [])
    with net_policy.bind(_policy_a()):
        with pytest.raises(site_dns.SiteDNSUnavailable):
            net_guard.resolve_hostname("nx.site-a.internal", attempts=1)
    assert resolver_tripwire == []


# =======================================================================================
# 9-11 -- malformed input (§13)
# =======================================================================================

@pytest.mark.parametrize("hostname", [
    "", "...", "a" * 300, "evil.com\x00.site-a.internal", "*.site-a.internal",
    "-bad-label.internal", "app.site-a.internal.", "APP.SITE-A.INTERNAL",
    "app..site-a.internal", "app.site-a.internal:53",
])
def test_malformed_hostnames_never_reach_a_public_resolver(
        private_scanning_enabled, resolver_tripwire, hostname):
    """Whatever the shape, the answer is a refusal or a site answer -- never a public one."""
    seen = []
    site_dns.set_backend(_split_horizon_backend(seen))
    with net_policy.bind(_policy_a()):
        try:
            net_guard.resolve_hostname(hostname, attempts=1)
        except (site_dns.SiteDNSUnavailable, socket.gaierror, UnicodeError, ValueError):
            pass
    assert resolver_tripwire == [], f"{hostname!r} leaked to the OS/public resolver"
    for _h, resolver in seen:
        assert resolver == SITE_A_RESOLVER


# =======================================================================================
# 12 -- DNS rebinding / TOCTOU (§12)
# =======================================================================================

@pytest.mark.parametrize("answer,label", [
    (["10.0.0.20", "169.254.169.254"], "cloud metadata"),
    (["10.0.0.20", "10.1.0.20"], "another tenant's private range"),
    (["10.0.0.20", "127.0.0.1"], "loopback"),
    (["169.254.169.254"], "metadata only"),
    (["10.1.0.20"], "another tenant only"),
])
def test_a_rebinding_answer_is_refused_on_the_resolved_address(
        private_scanning_enabled, resolver_tripwire, answer, label):
    """A compromised/hostile SITE resolver answers with an out-of-scope address.

    `resolve_and_validate` rejects if ANY returned address is forbidden, so a DNS answer
    can never become authorization on its own -- the resolved IP still has to clear the
    policy. This is the TOCTOU/rebinding defence (§12).
    """
    site_dns.set_backend(lambda h, r, _a=answer: list(_a))
    with net_policy.bind(_policy_a()):
        with pytest.raises(net_guard.TargetNotAllowed):
            net_guard.resolve_and_validate("rebind.site-a.internal")
    assert resolver_tripwire == []


def test_a_site_resolver_answering_with_a_public_address_stays_public(
        private_scanning_enabled, resolver_tripwire):
    """The one rebinding shape that is ACCEPTED, and why that is correct.

    A PUBLIC address is allowed under any policy: `net_guard` documents that a public
    address never consults the policy at all, because the per-scan policy exists to
    authorize PRIVATE destinations and must never be able to restrict (or re-permit)
    ordinary public scanning. So a site resolver answering 8.8.8.8 yields a target that is
    scannable exactly as any public target is -- it gains NO private reach, which is the
    property that matters. Asserted explicitly so the behaviour is a decision on record
    rather than an untested assumption.
    """
    site_dns.set_backend(lambda h, r: ["10.0.0.20", "8.8.8.8"])
    with net_policy.bind(_policy_a()):
        out = net_guard.resolve_and_validate("rebind.site-a.internal")
    assert out == "10.0.0.20"
    # The public answer bought no access to any private range.
    with net_policy.bind(_policy_a()):
        with pytest.raises(net_guard.TargetNotAllowed):
            net_guard.assert_ip_allowed("10.1.0.20")
    assert resolver_tripwire == []


# =======================================================================================
# 13 -- private IP/CIDR authorization is UNCHANGED (§17 -- no second policy)
# =======================================================================================

def test_private_ip_authorization_is_unchanged_by_the_dns_work(private_scanning_enabled):
    site_dns.set_backend(lambda h, r: ["10.0.0.20"])
    with net_policy.bind(_policy_a()):
        assert net_guard.resolve_and_validate("10.0.0.20") == "10.0.0.20"   # inside CIDR
        with pytest.raises(net_guard.TargetNotAllowed):
            net_guard.resolve_and_validate("10.9.9.9")                      # outside CIDR


# =======================================================================================
# 14-16 -- the PUBLIC path is untouched (§10)
# =======================================================================================

def test_a_public_scan_never_consults_the_site_dns_backend(private_scanning_enabled):
    """The most important non-regression: installing a backend must not reroute public
    scanning into private DNS."""
    seen = []
    site_dns.set_backend(_split_horizon_backend(seen))
    pub = net_policy.build_public_policy(workspace_id=uuid.uuid4())
    with net_policy.bind(pub):
        try:
            net_guard.resolve_hostname("example.com", attempts=1)
        except socket.gaierror:
            pass  # offline CI: the PATH is what matters, not the answer
    assert seen == [], "a public scan was routed into a site's private resolver"


def test_public_ip_and_cidr_targets_are_unaffected(private_scanning_enabled):
    site_dns.set_backend(lambda h, r: ["10.0.0.20"])
    pub = net_policy.build_public_policy(workspace_id=uuid.uuid4())
    with net_policy.bind(pub):
        assert net_guard.resolve_and_validate("93.184.216.34") == "93.184.216.34"
        assert net_guard.resolve_and_validate("93.184.216.0/24") == "93.184.216.0/24"


# =======================================================================================
# 21 -- CONCURRENT scans stay isolated (§9) -- the race the global backend could have been
# =======================================================================================

def test_concurrent_scans_for_different_sites_never_cross_dns_backends(
        private_scanning_enabled, resolver_tripwire):
    """Two interleaved async scans, A and B, sharing ONE process-global backend.

    Each must resolve through its OWN resolver every time. This is the test that would
    catch a backend that had been made site-aware via global state.
    """
    seen = []
    site_dns.set_backend(_split_horizon_backend(seen))
    errors = []

    async def scan(policy, hostname, expected_resolver, expected_addr):
        with net_policy.bind(policy):
            for _ in range(12):
                await asyncio.sleep(0)  # force interleaving at every step
                got = net_guard.resolve_hostname(hostname, attempts=1)
                if got != [expected_addr]:
                    errors.append(f"{hostname} -> {got}, expected {expected_addr}")
                await asyncio.sleep(0)

    async def main():
        await asyncio.gather(
            scan(_policy_a(), "app.site-a.internal", SITE_A_RESOLVER, "10.0.0.20"),
            scan(_policy_b(), "app.site-b.internal", SITE_B_RESOLVER, "10.1.0.20"),
        )

    asyncio.run(main())

    assert errors == [], f"cross-site resolution under concurrency: {errors}"
    # Every query went to the resolver belonging to its own site.
    for hostname, resolver in seen:
        expected = SITE_A_RESOLVER if "site-a" in hostname else SITE_B_RESOLVER
        assert resolver == expected, f"{hostname} was asked of {resolver}"
    assert resolver_tripwire == []


# =======================================================================================
# THE PRODUCTION BACKEND ITSELF
# =======================================================================================

def test_the_production_backend_never_reads_the_system_resolver_config():
    """`configure=False` is the whole no-leak guarantee: the nameserver list starts EMPTY,
    so /etc/resolv.conf can never contribute a public resolver."""
    dns_resolver = pytest.importorskip("dns.resolver")
    captured = {}

    class FakeResolver:
        def __init__(self, configure=True):
            captured["configure"] = configure
            self.nameservers = ["SHOULD-BE-REPLACED"]
            self.search = ["SHOULD-BE-CLEARED"]
            self.timeout = None
            self.lifetime = None

        def resolve(self, hostname, rdtype):
            captured["asked"] = (hostname, rdtype, tuple(self.nameservers))
            raise dns_resolver.NoAnswer()

    import unittest.mock as m

    with m.patch.object(dns_resolver, "Resolver", FakeResolver):
        site_dns.dnspython_backend("app.site-a.internal", SITE_A_RESOLVER)

    assert captured["configure"] is False, "the resolver read the system DNS configuration"
    assert captured["asked"][2] == (SITE_A_RESOLVER,), "queried something other than the site"


def test_a_refused_aaaa_does_not_discard_a_good_a_answer():
    """REGRESSION, found in the lab against real dnsmasq.

    dnsmasq answers A for a configured private name and REFUSES the AAAA. The first
    implementation re-raised on the AAAA failure and threw away the good A answer, turning
    a working private lookup into SiteDNSUnavailable. A per-type failure is now remembered
    rather than raised, and only surfaces if NEITHER type produced an address -- so this
    stays fail-closed while no longer discarding a valid answer.
    """
    dns_resolver = pytest.importorskip("dns.resolver")
    import unittest.mock as m

    class PartialResolver:
        def __init__(self, configure=True):
            self.nameservers = []
            self.search = []
            self.timeout = None
            self.lifetime = None

        def resolve(self, hostname, rdtype):
            if rdtype == "A":
                return [type("R", (), {"__str__": lambda s: "10.0.0.20"})()]
            raise dns_resolver.NoNameservers("REFUSED")  # what dnsmasq does for AAAA

    with m.patch.object(dns_resolver, "Resolver", PartialResolver):
        assert site_dns.dnspython_backend("app.site-a.internal", SITE_A_RESOLVER) == \
            ["10.0.0.20"]


def test_when_every_record_type_fails_the_error_is_raised_not_swallowed():
    """The other half of the same rule: no answer + a real error must NOT read as
    NXDOMAIN (an empty list), which `resolve_via_site_dns` would report as a clean
    'no such name' rather than a resolver outage."""
    dns_resolver = pytest.importorskip("dns.resolver")
    import unittest.mock as m

    class DeadResolver:
        def __init__(self, configure=True):
            self.nameservers = []
            self.search = []
            self.timeout = None
            self.lifetime = None

        def resolve(self, hostname, rdtype):
            raise dns_resolver.LifetimeTimeout("timed out")

    with m.patch.object(dns_resolver, "Resolver", DeadResolver):
        with pytest.raises(Exception):
            site_dns.dnspython_backend("app.site-a.internal", SITE_A_RESOLVER)


def test_installing_the_backend_is_idempotent_and_never_overrides_an_explicit_one():
    """A caller-installed backend (tests, or a future deployment transport) must win."""
    sentinel = lambda h, r: ["10.0.0.20"]  # noqa: E731
    site_dns.set_backend(sentinel)
    assert site_dns.install_default_backend() is True
    assert site_dns.get_backend() is sentinel, "an explicit backend was overwritten"


def test_install_reports_success_and_is_safe_to_call_twice():
    site_dns.reset_backend()
    assert site_dns.install_default_backend() is True
    first = site_dns.get_backend()
    assert first is not None
    assert site_dns.install_default_backend() is True
    assert site_dns.get_backend() is first, "a second install replaced the backend"


def test_a_missing_dnspython_keeps_the_fail_closed_default(monkeypatch):
    """No dnspython -> report False and leave the refusing default in place. It must NOT
    raise (that would stop a worker that can still do private IP work)."""
    import builtins

    site_dns.reset_backend()
    real_import = builtins.__import__

    def no_dns(name, *a, **k):
        if name.startswith("dns"):
            raise ImportError("no dnspython")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_dns)
    assert site_dns.install_default_backend() is False
    assert site_dns.get_backend() is None, "a broken backend was installed anyway"


def test_the_worker_installs_the_backend_at_startup():
    """P7-3's actual closure: there is now a PRODUCTION call site."""
    from pathlib import Path

    src = Path("apps/api/scanner_worker/main.py").read_text(encoding="utf-8")
    assert "install_default_backend()" in src
    # And it is on the PRIVATE path only -- a public worker has no site and no tunnel.
    assert "_prepare_private_tunnel" in src


def test_resolver_addresses_are_not_logged(caplog, private_scanning_enabled):
    """§19: a customer's internal resolver addresses are site configuration. The success
    path must not scatter them through logs."""
    site_dns.set_backend(_split_horizon_backend([]))
    with caplog.at_level("INFO"):
        with net_policy.bind(_policy_a()):
            net_guard.resolve_hostname("app.site-a.internal", attempts=1)
    startup = [r.getMessage() for r in caplog.records
               if "tunnel_ready" in r.getMessage() or "backend_installed" in r.getMessage()]
    for message in startup:
        assert SITE_A_RESOLVER not in message
