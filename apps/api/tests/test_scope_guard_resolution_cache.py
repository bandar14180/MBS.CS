"""Per-scan memoization of derived-scope hostname resolution.

THE REGRESSION. `scope_guard.host_in_scope` consults every entry of
`extra_authorized_hosts` for every out-of-scope finding, and each consultation was a live,
BLOCKING `socket.getaddrinfo`. `net_guard.resolve_hostname` retries a failure 3x with a
0.2s + 0.4s backoff before raising, so a permanently dead authorized host cost a full
retry sequence PER FINDING. On a real 13h20m scan of a target with 54 authorized hostnames
(27 of them unresolvable) that produced 115,791 `net_guard.resolve_failed` log lines and
consumed ~12h05m -- against ~1h14m of actual tool execution.

WHAT THESE TESTS PIN. Both halves, and they are equally important:

  * PERFORMANCE -- a hostname is resolved at most ONCE per cache scope, whether it
    resolves or not. The failure case is the one that mattered.
  * SECURITY -- the scope verdict is unchanged, host for host. The cache is only allowed
    to be a speed-up; a cached failure must stay a failure (fail closed), an out-of-scope
    host must stay out, and the cache must not outlive its scope.

The counting fixture patches `socket.getaddrinfo` (not `net_guard.resolve_hostname`)
deliberately: it keeps the real retry/backoff logic in the path, so a regression that
re-introduced per-finding resolution would be caught by the call COUNT even if the verdict
still happened to be right.
"""
import socket
from dataclasses import dataclass, field

import pytest

from apps.api.scanner_engine import net_guard, scope_guard

DOMAIN = "example.com"
APEX_IP = "203.0.113.1"
WWW_IP = "203.0.113.9"


@dataclass
class _F:
    asset_type: str
    value: str
    metadata: dict = field(default_factory=dict)


@pytest.fixture
def dns(monkeypatch):
    """A counting, zone-driven stand-in for the OS resolver.

    Patches `socket.getaddrinfo`, so `net_guard.resolve_hostname`'s real 3-attempt retry
    and its backoff sleeps still run -- the sleep is neutralized (not shortened) so the
    test stays fast without removing the retry itself from the code path under test.
    """

    class _DNS:
        def __init__(self):
            self.zone = {DOMAIN: [APEX_IP], f"www.{DOMAIN}": [WWW_IP]}
            self.calls: list[str] = []
            self.slept: float = 0.0

        def count(self, host: str) -> int:
            return self.calls.count(host)

    d = _DNS()

    def _getaddrinfo(host, port, *a, **kw):
        d.calls.append(host)
        if host in d.zone:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in d.zone[host]]
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    def _sleep(seconds):
        d.slept += seconds

    monkeypatch.setattr(net_guard.socket, "getaddrinfo", _getaddrinfo)
    monkeypatch.setattr(net_guard.time, "sleep", _sleep)
    return d


# ---------------------------------------------------------------------------
# 1-3. Authorization semantics are unchanged INSIDE a cache scope.
# ---------------------------------------------------------------------------

def test_in_scope_hostname_still_passes(dns):
    """(1) A host under the authorized domain is still in scope, cache or no cache."""
    with scope_guard.resolution_cache_scope():
        assert scope_guard.host_in_scope("domain", DOMAIN, f"api.{DOMAIN}") is True
        assert scope_guard.host_in_scope("domain", DOMAIN, DOMAIN) is True
        assert scope_guard.host_in_scope("domain", DOMAIN, f"a.b.{DOMAIN}") is True


def test_out_of_scope_hostname_still_rejected(dns):
    """(2) An unrelated host is still refused -- including the suffix-confusion shapes."""
    with scope_guard.resolution_cache_scope():
        for hostile in ("evil.com", f"{DOMAIN}.evil.com", "notexample.com", "evilexample.com"):
            assert scope_guard.host_in_scope("domain", DOMAIN, hostile) is False, hostile
        # Fail closed on an indeterminable host.
        assert scope_guard.host_in_scope("domain", DOMAIN, None) is False
        assert scope_guard.host_in_scope("domain", DOMAIN, "") is False


def test_unresolvable_hostname_remains_fail_closed(dns):
    """(3) THE CORE SECURITY ASSERTION. A cached FAILURE is still a failure.

    Both resolution-dependent paths are checked, because both feed the cache:
      * domain target + IP finding  -> _hostname_resolves_to
      * ip_range target + hostname  -> _ip_host_in_range
    A cached failure must never read back as an empty success that authorizes something.
    """
    with scope_guard.resolution_cache_scope():
        # The authorized NAME is dead -> an IP cannot be confirmed as its address.
        assert scope_guard.host_in_scope("domain", "dead.invalid", "203.0.113.77") is False
        # Re-asking inside the same scope (now served from the cache) is STILL False.
        assert scope_guard.host_in_scope("domain", "dead.invalid", "203.0.113.77") is False
        # ip_range + unresolvable hostname -> out of scope.
        assert scope_guard.host_in_scope("ip_range", "10.0.0.0/24", "dead.invalid") is False
        assert scope_guard.host_in_scope("ip_range", "10.0.0.0/24", "dead.invalid") is False


# ---------------------------------------------------------------------------
# 4-6. The memoization itself.
# ---------------------------------------------------------------------------

def test_successful_resolution_happens_once_per_scope(dns):
    """(4) A hostname that RESOLVES is looked up once, however many checks ask for it."""
    with scope_guard.resolution_cache_scope():
        for _ in range(25):
            assert scope_guard.host_in_scope("domain", DOMAIN, APEX_IP) is True
    assert dns.count(DOMAIN) == 1, f"resolved {dns.count(DOMAIN)}x, expected 1"


def test_failed_resolution_happens_once_per_scope(dns):
    """(5) THE REGRESSION ITSELF. A DEAD hostname is looked up ONE retry sequence per
    scope -- not one per check. Pre-fix this was 25 x 3 = 75 getaddrinfo calls and
    25 x 0.6s = 15s of pure sleep; the scan that triggered this did it ~115,791 times."""
    with scope_guard.resolution_cache_scope():
        for _ in range(25):
            assert scope_guard.host_in_scope("ip_range", "10.0.0.0/24", "dead.invalid") is False
    # Exactly ONE retry sequence: `attempts=3` on the single cached lookup.
    assert dns.count("dead.invalid") == 3, (
        f"dead host resolved {dns.count('dead.invalid')}x, expected 3 (one 3-attempt "
        "sequence). A failure is not being cached."
    )
    # And therefore only ONE backoff sequence's worth of sleeping (0.2 + 0.4).
    assert dns.slept == pytest.approx(0.6), dns.slept


def test_repeated_scope_checks_reuse_cached_result(dns):
    """(6) Cache hits are counted, and the reused answer is the same answer."""
    with scope_guard.resolution_cache_scope() as cache:
        first = scope_guard.host_in_scope("domain", DOMAIN, APEX_IP)
        assert cache.hits == 0          # first lookup is a miss
        assert len(cache.entries) == 1
        for _ in range(9):
            assert scope_guard.host_in_scope("domain", DOMAIN, APEX_IP) is first
        assert cache.hits == 9          # nine reuses, no new lookups
        assert len(cache.entries) == 1
    assert dns.count(DOMAIN) == 1


def test_cache_records_both_successes_and_failures(dns):
    """Both outcomes are STORED -- the failure as an empty tuple, which is what makes the
    fail-closed reading (`ip in ()` -> False) identical to the raised-error path."""
    with scope_guard.resolution_cache_scope() as cache:
        scope_guard.host_in_scope("domain", DOMAIN, APEX_IP)                   # resolves
        scope_guard.host_in_scope("ip_range", "10.0.0.0/24", "dead.invalid")   # does not
        assert cache.entries[DOMAIN] == (APEX_IP,)
        assert cache.entries["dead.invalid"] == ()      # cached FAILURE, not absent
        assert cache.resolved_count == 1
        assert cache.unresolvable_count == 1


# ---------------------------------------------------------------------------
# 7. Equivalence, lifetime and isolation.
# ---------------------------------------------------------------------------

def test_verdicts_identical_with_and_without_cache(dns):
    """(7) DIFFERENTIAL: for a mixed population and every scannable target type, the
    partition is byte-for-byte the same cached and uncached. This is the assertion that
    would fail if the cache ever changed a security decision rather than just its cost."""
    dns.zone[f"mail.{DOMAIN}"] = [WWW_IP, "203.0.113.20"]
    authorized = frozenset({
        DOMAIN, f"www.{DOMAIN}", f"mail.{DOMAIN}", "dead1.invalid", "dead2.invalid",
    })
    findings = [
        _F("subdomain", f"www.{DOMAIN}"),
        _F("subdomain", "evil.attacker.com"),
        _F("subdomain", f"{DOMAIN}.evil.com"),
        _F("port", f"{WWW_IP}:80", {"ip": WWW_IP}),
        _F("port", "203.0.113.20:443", {"ip": "203.0.113.20"}),
        _F("port", "198.51.100.7:80", {"ip": "198.51.100.7"}),
        _F("port", f"{APEX_IP}:22", {"ip": APEX_IP}),
        _F("weird", ""),
    ]
    for target_type, target_value in (
        ("domain", DOMAIN), ("ip_range", "203.0.113.0/24"), ("ip_range", "10.0.0.0/24"),
    ):
        uncached = scope_guard.partition_in_scope(
            target_type, target_value, findings, extra_authorized_hosts=authorized
        )
        with scope_guard.resolution_cache_scope():
            cached = scope_guard.partition_in_scope(
                target_type, target_value, findings, extra_authorized_hosts=authorized
            )
        assert [f.value for f in cached[0]] == [f.value for f in uncached[0]], target_value
        assert [f.value for f in cached[1]] == [f.value for f in uncached[1]], target_value


def test_cache_does_not_outlive_its_scope(dns):
    """A scope's answers must not leak into the next scan: a stale address for an
    authorized host would be a scope decision made on data that scan never verified."""
    with scope_guard.resolution_cache_scope():
        assert scope_guard.host_in_scope("domain", DOMAIN, APEX_IP) is True
    assert dns.count(DOMAIN) == 1
    # A SECOND scope re-resolves from scratch.
    with scope_guard.resolution_cache_scope():
        assert scope_guard.host_in_scope("domain", DOMAIN, APEX_IP) is True
    assert dns.count(DOMAIN) == 2
    # And the contextvar is released, so an unscoped check resolves live too.
    assert scope_guard._resolution_cache.get() is None
    assert scope_guard.host_in_scope("domain", DOMAIN, APEX_IP) is True
    assert dns.count(DOMAIN) == 3


def test_no_cache_scope_behaves_exactly_as_before(dns):
    """With no scope open, every check resolves live -- the pre-fix behaviour. Forgetting
    to open a scope loses the optimization; it never reuses a stale answer."""
    for _ in range(3):
        assert scope_guard.host_in_scope("domain", DOMAIN, APEX_IP) is True
    assert dns.count(DOMAIN) == 3


def test_second_scan_sees_dns_changes(dns):
    """The cache is per-scan, so a rebinding/DNS change IS observed by the next scan --
    the memoization narrows nothing about how fresh the next scan's view is."""
    with scope_guard.resolution_cache_scope():
        assert scope_guard.host_in_scope("domain", DOMAIN, APEX_IP) is True
    dns.zone[DOMAIN] = ["198.51.100.200"]          # address changes between scans
    with scope_guard.resolution_cache_scope():
        assert scope_guard.host_in_scope("domain", DOMAIN, APEX_IP) is False   # now refused
        assert scope_guard.host_in_scope("domain", DOMAIN, "198.51.100.200") is True


def test_excludes_still_win_inside_a_cache_scope(dns, monkeypatch):
    """The narrowing-only deny-list (M4.6.4/F1) is evaluated BEFORE any resolution, so
    caching cannot resurrect an excluded host."""
    from apps.api.core.config import get_settings

    monkeypatch.setattr(get_settings(), "scan_derived_scope_excludes", [f"cdn.{DOMAIN}"])
    with scope_guard.resolution_cache_scope():
        assert scope_guard.host_in_scope("domain", DOMAIN, f"cdn.{DOMAIN}") is False
        assert scope_guard.host_in_scope("domain", DOMAIN, f"assets.cdn.{DOMAIN}") is False
        assert scope_guard.host_in_scope("domain", DOMAIN, f"api.{DOMAIN}") is True


def test_net_guard_resolver_itself_is_not_cached(dns):
    """THE BOUNDARY OF THIS CHANGE. The memoization lives in `scope_guard`, NOT in
    `net_guard.resolve_hostname`. That matters because `resolve_hostname` is also the
    resolver behind `net_guard.resolve_and_validate` -- the path that resolves a host
    immediately before handing an address to a tool, whose re-resolution IS the
    DNS-rebinding defense. Calling it directly must still hit the network every time,
    even from inside an open scope cache.

    (Asserted on `resolve_hostname` rather than `resolve_and_validate` because the
    latter's SSRF gate refuses the documentation ranges used here -- `is_private` is True
    for 203.0.113.0/24 in this Python. The resolver is the shared component, and it is
    what a cache in the wrong place would have poisoned.)
    """
    with scope_guard.resolution_cache_scope():
        # The scope gate populates the cache for DOMAIN ...
        assert scope_guard.host_in_scope("domain", DOMAIN, APEX_IP) is True
        assert dns.count(DOMAIN) == 1
        # ... and net_guard's own resolver still ignores it completely.
        for _ in range(3):
            assert net_guard.resolve_hostname(DOMAIN) == [APEX_IP]
    assert dns.count(DOMAIN) == 4, (
        "net_guard.resolve_hostname was memoized -- the DNS-rebinding defense in "
        "resolve_and_validate depends on this resolving live on every call"
    )


def test_pathological_fanout_is_bounded_by_distinct_hosts(dns):
    """END-TO-END SHAPE of the original incident, scaled down: many findings x many
    authorized hosts, half of them dead. Resolution count must scale with DISTINCT HOSTS,
    not with findings x hosts."""
    n_live, n_dead, n_findings = 8, 8, 40
    for i in range(n_live):
        dns.zone[f"live{i}.{DOMAIN}"] = [f"203.0.113.{100 + i}"]
    authorized = frozenset(
        [f"live{i}.{DOMAIN}" for i in range(n_live)]
        + [f"dead{i}.{DOMAIN}" for i in range(n_dead)]
    )
    # IP findings matching NO authorized host -> worst case, every host consulted.
    findings = [
        _F("port", f"198.51.100.{i}:80", {"ip": f"198.51.100.{i}"}) for i in range(n_findings)
    ]
    with scope_guard.resolution_cache_scope() as cache:
        in_scope, out = scope_guard.partition_in_scope(
            "domain", DOMAIN, findings, extra_authorized_hosts=authorized
        )
    assert in_scope == [] and len(out) == n_findings      # verdict: all out of scope
    # One sequence per distinct host: live resolve in 1 call, dead take 3 (attempts=3),
    # plus the apex. Uncached this was n_findings x (n_live + n_dead + 1) sequences.
    expected = n_live + (n_dead * 3) + 1
    assert len(dns.calls) == expected, f"{len(dns.calls)} lookups, expected {expected}"
    assert cache.unresolvable_count == n_dead
    naive = n_findings * (n_live + n_dead * 3 + 1)
    assert len(dns.calls) < naive / 20                    # >20x fewer lookups
