"""MBS.SC P7-3-OBS-1 -- a private scan with NO resolvers must fail closed, not go public.

THE FINDING
-----------
`net_guard.resolve_hostname` gated the private-DNS branch on:

    if effective.is_private and effective.dns_servers:      # <- required NON-EMPTY

so a private scan whose site had an EMPTY resolver list fell through to
`socket.getaddrinfo` and sent the customer's internal hostname to the public resolver --
disclosing internal naming and inviting an attacker-influenced answer. This is the exact
leak `site_dns` exists to prevent, reached by a configuration shape rather than by a bug in
`site_dns` itself.

It was REACHABLE: `private_sites` never required `dns_servers` to be non-empty (unlike
`authorized_networks()`, which refuses an empty CIDR set), and `build_private_policy` strips
blank/whitespace entries -- so `[]`, `None`, `[""]` and `["  "]` all landed there.

THE FIX
-------
Route on the ZONE ALONE. Once a scan is private, `resolve_hostname` has no path to the OS
resolver at all, so missing configuration means NO ANSWER rather than A PUBLIC ANSWER.
`resolve_via_site_dns` already refuses an empty resolver list with the EXISTING
`SiteDNSUnavailable` -- no parallel error model was introduced.
"""
import asyncio
import socket
import uuid

import pytest

from apps.api.scanner_engine import net_guard, net_policy, site_dns

RESOLVER_A = "10.0.0.53"
RESOLVER_B = "10.1.0.53"


@pytest.fixture
def private_scanning_enabled(monkeypatch):
    from apps.api.core.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "scan_allow_private_targets", True)
    monkeypatch.setattr(s, "scan_allowed_cidrs", ["10.0.0.0/8"])
    return s


@pytest.fixture(autouse=True)
def _clean_backend():
    site_dns.reset_backend()
    yield
    site_dns.reset_backend()


@pytest.fixture
def tripwire(monkeypatch):
    """Counts OS/public resolver calls. Non-zero on a private lookup == DNS leak."""
    calls = []
    real = socket.getaddrinfo

    def spy(*a, **k):
        calls.append(a[0] if a else None)
        return real(*a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", spy)
    return calls


def _private(dns_servers, cidrs=("10.0.0.0/16",)):
    return net_policy.build_private_policy(
        workspace_id=uuid.uuid4(), scan_id=uuid.uuid4(), site_id=uuid.uuid4(),
        authorized_cidrs=list(cidrs), dns_servers=dns_servers)


# =======================================================================================
# 1 -- the working private path is UNCHANGED (P7-3 must stay green)
# =======================================================================================

def test_a_private_site_with_a_valid_resolver_still_uses_private_dns(
        private_scanning_enabled, tripwire):
    seen = []
    site_dns.set_backend(lambda h, r: (seen.append((h, r)), ["10.0.0.20"])[1])
    with net_policy.bind(_private([RESOLVER_A])):
        assert net_guard.resolve_hostname("app.internal", attempts=1) == ["10.0.0.20"]
    assert seen == [("app.internal", RESOLVER_A)]
    assert tripwire == []


# =======================================================================================
# 2-5 -- THE FINDING: empty/missing resolvers must FAIL CLOSED with zero OS calls
# =======================================================================================

@pytest.mark.parametrize("dns_servers,label", [
    ([], "empty list -- the site simply has none"),
    (None, "None -- column default / absent"),
    ([""], "a single blank entry (sanitised to empty)"),
    (["   "], "whitespace only (sanitised to empty)"),
    (["", "  ", ""], "several blanks (sanitised to empty)"),
])
def test_a_private_scan_without_resolvers_fails_closed(
        private_scanning_enabled, tripwire, dns_servers, label):
    """The core regression. Every shape that yields an empty resolver tuple must refuse.

    A WORKING private backend is installed, to prove the refusal comes from the missing
    SITE configuration and not from a missing transport.
    """
    site_dns.set_backend(lambda h, r: ["10.0.0.20"])
    policy = _private(dns_servers)
    assert policy.is_private is True
    assert policy.dns_servers == (), f"fixture wrong for: {label}"

    with net_policy.bind(policy):
        with pytest.raises(site_dns.SiteDNSUnavailable, match="refusing public fallback"):
            net_guard.resolve_hostname("secret.internal", attempts=1)

    assert tripwire == [], f"OS/public resolver was called for: {label}"


def test_the_failure_reuses_the_existing_error_model(private_scanning_enabled, tripwire):
    """No parallel error type: SiteDNSUnavailable subclasses socket.gaierror, so every
    existing caller keeps treating this as 'unresolvable, fail this target cleanly'."""
    site_dns.set_backend(lambda h, r: ["10.0.0.20"])
    with net_policy.bind(_private([])):
        with pytest.raises(socket.gaierror):          # the BROAD existing contract
            net_guard.resolve_hostname("secret.internal", attempts=1)
    assert issubclass(site_dns.SiteDNSUnavailable, socket.gaierror)
    assert tripwire == []


def test_no_backend_and_no_resolvers_still_fails_closed(private_scanning_enabled, tripwire):
    """Both halves missing is still a refusal, never a fall-through."""
    site_dns.reset_backend()
    with net_policy.bind(_private([])):
        with pytest.raises(site_dns.SiteDNSUnavailable):
            net_guard.resolve_hostname("secret.internal", attempts=1)
    assert tripwire == []


# =======================================================================================
# 6 -- the scanner never executes against such a target
# =======================================================================================

def test_the_scanner_never_gets_an_address_for_an_unresolvable_private_target(
        private_scanning_enabled, tripwire):
    """`resolve_and_validate` is what every tool runner calls to turn a target into an
    address. It must raise, so no tool is ever handed a public address for a private
    engagement."""
    site_dns.set_backend(lambda h, r: ["10.0.0.20"])
    with net_policy.bind(_private([])):
        with pytest.raises(socket.gaierror):
            net_guard.resolve_and_validate("secret.internal")
    assert tripwire == []


def test_a_private_bare_ip_target_is_unaffected(private_scanning_enabled, tripwire):
    """Only HOSTNAME resolution changes. A private IP/CIDR target never resolves, so a
    site without DNS can still be scanned by address -- the fix must not break that."""
    with net_policy.bind(_private([])):
        assert net_guard.resolve_and_validate("10.0.0.20") == "10.0.0.20"
        with pytest.raises(net_guard.TargetNotAllowed):
            net_guard.resolve_and_validate("10.9.9.9")      # outside the site's CIDRs
    assert tripwire == []


# =======================================================================================
# 7 -- PUBLIC behaviour is untouched
# =======================================================================================

def test_public_hostname_resolution_is_unchanged(private_scanning_enabled, tripwire):
    """The fix must not block public scanning: a public policy still uses the OS resolver."""
    site_dns.set_backend(lambda h, r: ["10.0.0.20"])
    with net_policy.bind(net_policy.build_public_policy(workspace_id=uuid.uuid4())):
        try:
            net_guard.resolve_hostname("example.com", attempts=1)
        except socket.gaierror:
            pass  # offline CI: the PATH is what matters
    assert tripwire == ["example.com"], "the public path stopped using the OS resolver"


def test_an_unbound_context_still_resolves_publicly(private_scanning_enabled, tripwire):
    """No policy bound == PUBLIC_ONLY, which is not private, so the OS resolver is correct."""
    site_dns.set_backend(lambda h, r: ["10.0.0.20"])
    try:
        net_guard.resolve_hostname("example.com", attempts=1)
    except socket.gaierror:
        pass
    assert tripwire == ["example.com"]


def test_a_public_scan_never_consults_the_site_backend(private_scanning_enabled):
    seen = []
    site_dns.set_backend(lambda h, r: (seen.append((h, r)), ["10.0.0.20"])[1])
    with net_policy.bind(net_policy.build_public_policy(workspace_id=uuid.uuid4())):
        try:
            net_guard.resolve_hostname("example.com", attempts=1)
        except socket.gaierror:
            pass
    assert seen == []


# =======================================================================================
# 8 -- site A's configuration cannot affect site B
# =======================================================================================

def test_site_a_resolvers_do_not_rescue_site_b_without_any(
        private_scanning_enabled, tripwire):
    """The dangerous shape: A is configured, B is not. B must refuse -- it must NOT
    inherit A's resolver, and it must NOT go public."""
    seen = []
    site_dns.set_backend(lambda h, r: (seen.append((h, r)), ["10.0.0.20"])[1])

    with net_policy.bind(_private([RESOLVER_A])):
        assert net_guard.resolve_hostname("a.internal", attempts=1) == ["10.0.0.20"]

    seen.clear()
    with net_policy.bind(_private([], cidrs=("10.1.0.0/16",))):
        with pytest.raises(site_dns.SiteDNSUnavailable):
            net_guard.resolve_hostname("b.internal", attempts=1)

    assert seen == [], "site B borrowed another site's resolver"
    assert tripwire == []


# =======================================================================================
# 9-10 -- a failed private lookup must not POISON the next lookup
# =======================================================================================

def test_a_failed_private_lookup_does_not_poison_the_next_public_lookup(
        private_scanning_enabled, tripwire):
    site_dns.set_backend(lambda h, r: ["10.0.0.20"])
    with net_policy.bind(_private([])):
        with pytest.raises(site_dns.SiteDNSUnavailable):
            net_guard.resolve_hostname("secret.internal", attempts=1)
    assert tripwire == []

    with net_policy.bind(net_policy.build_public_policy(workspace_id=uuid.uuid4())):
        try:
            net_guard.resolve_hostname("example.com", attempts=1)
        except socket.gaierror:
            pass
    assert tripwire == ["example.com"], "the public path was broken by a prior failure"


def test_a_failed_private_lookup_does_not_poison_the_next_valid_private_lookup(
        private_scanning_enabled, tripwire):
    seen = []
    site_dns.set_backend(lambda h, r: (seen.append((h, r)), ["10.0.0.20"])[1])

    with net_policy.bind(_private([])):
        with pytest.raises(site_dns.SiteDNSUnavailable):
            net_guard.resolve_hostname("secret.internal", attempts=1)

    with net_policy.bind(_private([RESOLVER_A])):
        assert net_guard.resolve_hostname("app.internal", attempts=1) == ["10.0.0.20"]
    assert seen == [("app.internal", RESOLVER_A)]
    assert tripwire == []


# =======================================================================================
# 11 -- concurrency: a resolver-less scan cannot borrow a concurrent scan's resolver
# =======================================================================================

def test_concurrent_scans_one_with_dns_one_without_stay_isolated(
        private_scanning_enabled, tripwire):
    """Interleaved: scan A has a resolver, scan B has none. A must keep succeeding and B
    must keep refusing -- neither may drift into the other's outcome, and B must never
    borrow A's resolver or fall through to the OS one."""
    seen = []
    site_dns.set_backend(lambda h, r: (seen.append((h, r)), ["10.0.0.20"])[1])
    errors = []

    async def with_dns():
        with net_policy.bind(_private([RESOLVER_A])):
            for _ in range(12):
                await asyncio.sleep(0)
                if net_guard.resolve_hostname("a.internal", attempts=1) != ["10.0.0.20"]:
                    errors.append("A failed to resolve")

    async def without_dns():
        with net_policy.bind(_private([], cidrs=("10.1.0.0/16",))):
            for _ in range(12):
                await asyncio.sleep(0)
                try:
                    net_guard.resolve_hostname("b.internal", attempts=1)
                    errors.append("B RESOLVED with no resolver -- leak")
                except site_dns.SiteDNSUnavailable:
                    pass

    async def main():
        await asyncio.gather(with_dns(), without_dns())

    asyncio.run(main())

    assert errors == [], f"concurrent isolation broke: {errors}"
    assert all(r == RESOLVER_A for _h, r in seen)
    assert all(h == "a.internal" for h, _r in seen), "B's name reached a resolver"
    assert tripwire == []


# =======================================================================================
# 12 -- malformed hostnames stay protected under the EMPTY-resolver shape too
# =======================================================================================

@pytest.mark.parametrize("hostname", [
    "", "...", "a" * 300, "evil.com\x00.internal", "*.internal", "localhost",
    "app.internal.", "APP.INTERNAL", "10.0.0.20.nip.io",
])
def test_malformed_hostnames_with_no_resolver_never_reach_the_os_resolver(
        private_scanning_enabled, tripwire, hostname):
    site_dns.set_backend(lambda h, r: ["10.0.0.20"])
    with net_policy.bind(_private([])):
        with pytest.raises((site_dns.SiteDNSUnavailable, socket.gaierror,
                            UnicodeError, ValueError)):
            net_guard.resolve_hostname(hostname, attempts=1)
    assert tripwire == [], f"{hostname!r} leaked to the OS/public resolver"
