"""Authorization-scope enforcement for DISCOVERED (derived) hosts (M4.5 / G9).

`net_guard` enforces ADDRESS safety (SSRF: no private/reserved/metadata addresses).
This module is a SEPARATE, complementary control that enforces AUTHORIZATION SCOPE: a
host discovered during a scan (a subfinder subdomain, a crawled URL's host, ...) may
be ACTIVELY probed only if it falls within the target's authorized scope, derived
deterministically from the target that the operator authorized:

  * domain   -> the domain itself and its subdomains  (host == d OR host endswith "."+d)
  * ip_range -> the target IP / CIDR                  (host's IP must be within it)

FAIL CLOSED for active probing: a finding whose host cannot be determined, cannot be
resolved (ip_range), or falls outside the target scope is NOT eligible for active
probing. Such findings are still stored as observations elsewhere (asset ingest); this
module only decides what may be actively TOUCHED.

This module NEVER expands scope and NEVER changes net_guard/SSRF behavior -- it only
reuses net_guard's host parser / resolver. It can only NARROW what gets probed.

PER-SCAN RESOLUTION MEMOIZATION
-------------------------------
The scope decision above needs a hostname's addresses, and it needs them once per
(finding x authorized host) pair. Resolving live at each of those pairs made the gate an
O(findings x authorized-hosts) blocking DNS loop -- see `resolution_cache_scope`, which
memoizes BOTH successful and failed lookups for the duration of one scan. It is a pure
performance boundary: the verdict for any given (host, target) pair is identical with and
without the cache, a cached failure stays a failure, and the DNS-rebinding defense (which
lives in `net_guard.resolve_and_validate`, immediately before a tool is handed an address)
is untouched and still re-resolves on every call.
"""
import contextlib
import contextvars
import ipaddress
import logging
from typing import Iterator

from apps.api.core.config import get_settings
from apps.api.scanner_engine import net_guard

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PER-SCAN RESOLUTION CACHE (performance only -- see the module docstring)
# ---------------------------------------------------------------------------
# A sentinel distinguishing "resolved to nothing / failed" from "not yet looked up".
# A FAILURE IS CACHED AS A FAILURE, never as an empty success: every consumer below
# treats an empty address list exactly as it treats a raised resolver error -- as
# "cannot confirm membership" -> out of scope. That equivalence is what makes caching
# the negative result security-neutral.
_UNRESOLVED: tuple = ()

# ContextVar, not a module global, and deliberately mirroring `net_policy._current`:
# resolution results are only comparable WITHIN one scan's policy (a private scan
# resolves through the customer's own site resolvers via site_dns, a public scan
# through the OS resolver, so the same name can legitimately have different answers
# in two concurrently-running scans). Each asyncio task and each thread gets its own
# copy of the context, so two scans in one worker process cannot read each other's
# cached answers -- the same property that keeps their policies isolated.
#
# Unbound default is None, meaning NO CACHING AT ALL: every lookup goes live, exactly
# as before this change. Forgetting to open a scope means losing the optimization,
# never reusing a stale answer.
_resolution_cache: contextvars.ContextVar = contextvars.ContextVar(
    "mbs_scope_guard_resolution_cache", default=None
)


class _ResolutionCache:
    """One scan's memoized derived-scope resolutions, plus counters for the log line.

    `entries` maps hostname -> tuple of addresses, where the EMPTY tuple (`_UNRESOLVED`)
    is a cached FAILURE. Membership is tested with a `KeyError` lookup rather than
    `.get() is not None`, so a cached failure is a genuine hit and never re-resolves.
    """

    __slots__ = ("entries", "hits")

    def __init__(self) -> None:
        self.entries: dict[str, tuple] = {}
        self.hits: int = 0

    @property
    def resolved_count(self) -> int:
        return sum(1 for v in self.entries.values() if v)

    @property
    def unresolvable_count(self) -> int:
        return sum(1 for v in self.entries.values() if not v)


@contextlib.contextmanager
def resolution_cache_scope() -> "Iterator[_ResolutionCache]":
    """Memoize derived-scope hostname resolution for the duration of ONE scan.

    WHY (the ftu.ac.th regression). `host_in_scope` consults every entry of
    `extra_authorized_hosts` for every out-of-scope finding, and each consultation was a
    live, BLOCKING `socket.getaddrinfo` -- including for permanently dead names, which
    `net_guard.resolve_hostname` retries 3x with a 0.2s + 0.4s backoff before raising.
    On a real scan (54 authorized hosts, 27 of them unresolvable) that was an uncached
    O(findings x authorized-hosts) DNS loop: 115,791 `net_guard.resolve_failed` lines and
    ~12h05m of a 13h20m runtime, against ~1h14m of actual tool execution.

    WHAT IT DOES NOT CHANGE. This caches ONLY the two `scope_guard` lookups, which decide
    "may this discovered host be actively probed". It does NOT touch
    `net_guard.resolve_and_validate` -- the path that resolves a host immediately before
    handing an address to a tool, whose re-resolution IS the DNS-rebinding defense. That
    path still resolves live, every time, per call. Caching here cannot affect which
    address any tool is actually given.

    Fail-closed semantics are preserved exactly: a failed lookup is cached AS A FAILURE
    (`_UNRESOLVED`) and every reader turns it into "out of scope", identically to the
    raised-exception path it replaces. The cache can therefore only ever reproduce the
    verdict the live lookup already returned in this scan -- it never converts a failure
    into a success, and never widens scope.
    """
    cache = _ResolutionCache()
    token = _resolution_cache.set(cache)
    try:
        yield cache
    finally:
        _resolution_cache.reset(token)
        logger.info(
            "scope_guard.resolution_cache_closed distinct_hosts=%d resolved=%d "
            "unresolvable=%d reused=%d",
            len(cache.entries), cache.resolved_count, cache.unresolvable_count, cache.hits,
            extra={"event": "scope_guard.resolution_cache_closed",
                   "distinct_hosts": len(cache.entries),
                   "resolved": cache.resolved_count,
                   "unresolvable": cache.unresolvable_count,
                   "reused": cache.hits},
        )


def _resolve_cached(hostname: str) -> tuple:
    """`net_guard.resolve_hostname` memoized for this scan. Returns a tuple of
    addresses, or `_UNRESOLVED` (empty) when the name does not resolve.

    A resolver error is NOT propagated: it is recorded as `_UNRESOLVED` and every caller
    below already treats "no addresses" as fail-closed, which is what the previous
    `except Exception -> return False` did at each call site. Both outcomes are stored, so
    a dead host costs exactly one retry sequence per scan instead of one per finding.
    """
    cache = _resolution_cache.get()
    if cache is None:
        # No scope open -> behave exactly as before: resolve live, let errors propagate
        # to the caller's own existing try/except.
        return tuple(net_guard.resolve_hostname(hostname))
    try:
        result = cache.entries[hostname]
    except KeyError:
        pass
    else:
        cache.hits += 1
        return result
    try:
        result = tuple(net_guard.resolve_hostname(hostname) or ())
    except Exception as exc:  # noqa: BLE001 -- a failure is a CACHED failure, see above
        logger.debug(
            "scope_guard.resolution_cached_failure host=%s error=%s", hostname, exc,
        )
        result = _UNRESOLVED
    cache.entries[hostname] = result
    return result


def _norm(host: str | None) -> str:
    return (str(host).strip().lower().rstrip(".")) if host else ""


def _host_excluded(host: str) -> bool:
    """True if `host` is on the operator's explicit derived-scope exclude list
    (M4.6.4 / F1): an exact host or a parent suffix. A pure deny-list that only
    NARROWS -- it can never authorize a host the name/CIDR check would reject."""
    for entry in get_settings().scan_derived_scope_excludes:
        e = _norm(entry)
        if e and (host == e or host.endswith("." + e)):
            return True
    return False


def _target_domain(target_value: str) -> str:
    # Strip any scheme/port/path from the target, lower-case, drop a trailing dot.
    return _norm(net_guard._host_from_value(target_value))


def _ip_host_in_range(target_value: str, host: str) -> bool:
    """True iff `host` (a bare IP, or a hostname whose EVERY resolved address) lies
    within the target IP/CIDR. Unresolvable / partial -> False (fail closed)."""
    try:
        net = ipaddress.ip_network(target_value.strip(), strict=False)
    except ValueError:
        return False
    try:
        return ipaddress.ip_address(host) in net
    except ValueError:
        pass  # not a bare IP -> a hostname; resolve it
    # Memoized per scan (see resolution_cache_scope). `_resolve_cached` already folds a
    # resolver error into an EMPTY result, and an empty result is refused two lines below
    # -- the same fail-closed verdict the bare `except -> return False` produced. The
    # try/except is kept for the no-cache-scope path, where errors still propagate here.
    try:
        addrs = _resolve_cached(host)
    except Exception:  # noqa: BLE001 -- unresolvable => out of scope for probing
        return False
    if not addrs:
        return False
    try:
        return all(ipaddress.ip_address(a) in net for a in addrs)
    except ValueError:
        return False


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _hostname_resolves_to(hostname: str, ip_value: str) -> bool:
    """True iff `ip_value` (a bare IP) is one of `hostname`'s currently-resolved addresses.
    Non-IP input / unresolvable hostname -> False (fail closed)."""
    if not _is_ip(ip_value):
        return False
    # Memoized per scan (see resolution_cache_scope). THIS is the hot site behind the
    # ftu.ac.th regression: it is called once per (finding x authorized host), and a dead
    # authorized host cost a full 3-attempt retry sequence every single time. A cached
    # failure is the empty tuple, and `in ()` is False -- byte-for-byte the fail-closed
    # verdict the exception path gave.
    try:
        addrs = _resolve_cached(hostname)
    except Exception:  # noqa: BLE001 -- unresolvable => cannot confirm membership, fail closed
        return False
    return ip_value in addrs


def host_in_scope(
    target_type: str,
    target_value: str,
    host: str | None,
    *,
    extra_authorized_hosts: "frozenset[str] | set[str] | None" = None,
) -> bool:
    """Whether a discovered `host` is within the authorized scope of the target.
    FAIL CLOSED: an empty/undeterminable host is never in scope.

    `extra_authorized_hosts`: additional NAMED hosts (e.g. subdomains already confirmed
    in-scope earlier in the same scan, via subfinder) whose OWN resolved addresses also
    count as in-scope for a domain-type target -- see `derived_scope_roots`, which is what
    actually populates this from sibling findings. Defaults to none (the target domain
    itself, alone)."""
    host = _norm(host)
    if not host:
        return False
    # M4.6.4 (F1): an explicit exclude always wins (narrowing-only) -- applies to every
    # target type, before the name/CIDR authorization check.
    if _host_excluded(host):
        return False
    if target_type == "domain":
        d = _target_domain(target_value)
        if not d:
            return False
        if host == d or host.endswith("." + d):
            return True
        # Every active tool runner resolves a hostname to a validated IP before invoking the
        # underlying binary (SSRF / DNS-rebinding defense -- net_guard.resolve_scan_host /
        # tool_runners._net.resolve_scan_host), so a naabu/nmap-produced finding's host is
        # always a bare IP, never the original hostname. Matching by hostname suffix alone
        # would then reject every one of THOSE tools' own findings for every domain-type
        # target -- silently starving nmap of every host naabu just found. Recognize an IP
        # as in-scope when it is one of the authorized domain's own currently-resolved
        # addresses, OR one of an already-authorized SUBDOMAIN's (a subdomain commonly
        # resolves to a different address than the apex -- e.g. a CDN/host split between
        # apex and www -- so the apex alone is not enough).
        if _hostname_resolves_to(d, host):
            return True
        for named in extra_authorized_hosts or ():
            if _hostname_resolves_to(named, host):
                return True
        return False
    if target_type == "ip_range":
        return _ip_host_in_range(target_value, host)
    # Only domain / ip_range are scannable target types; anything else is out of scope.
    return False


def derived_scope_roots(target_type: str, target_value: str, findings) -> frozenset[str]:
    """NAMED (non-IP) hosts within `findings` that already pass the plain name-based scope
    check -- e.g. a subfinder-discovered subdomain. Used as additional resolution roots so an
    IP-only finding (naabu/nmap; every active tool resolves before invoking its binary) can be
    recognized as in-scope when it is one of THESE hosts' own resolved addresses, not just the
    target's. Domain-type targets only -- ip_range hosts are already matched directly by
    address, with no name-based root to derive from."""
    if target_type != "domain":
        return frozenset()
    roots: set[str] = set()
    for f in findings:
        h = _norm(extract_host(f))
        if h and not _is_ip(h) and host_in_scope(target_type, target_value, h):
            roots.add(h)
    return frozenset(roots)


def extract_host(finding) -> str | None:
    """Best-effort host of a discovered asset: prefer the explicit metadata host/ip
    (set by the tool runners), else parse it out of the value. None if indeterminable."""
    metadata = getattr(finding, "metadata", None) or {}
    host = metadata.get("host") or metadata.get("ip")
    if host:
        return str(host)
    value = getattr(finding, "value", None)
    if not value:
        return None
    parsed = net_guard._host_from_value(str(value))
    return parsed or None


def finding_in_scope(
    target_type: str,
    target_value: str,
    finding,
    *,
    extra_authorized_hosts: "frozenset[str] | set[str] | None" = None,
) -> bool:
    """Whether a discovered asset may be actively probed. Fail closed: no
    determinable host => not in scope. See host_in_scope for extra_authorized_hosts."""
    return host_in_scope(
        target_type, target_value, extract_host(finding), extra_authorized_hosts=extra_authorized_hosts
    )


def partition_in_scope(
    target_type: str,
    target_value: str,
    findings,
    *,
    extra_authorized_hosts: "frozenset[str] | set[str] | None" = None,
):
    """Split findings into (in_scope, out_of_scope) for active probing. Preserves order.

    `extra_authorized_hosts`: forwarded to finding_in_scope/host_in_scope. When omitted,
    computed from `findings` itself via derived_scope_roots -- the common case, and what lets
    an IP-only naabu/nmap finding pass once the hostname behind it was already authorized
    earlier in the same batch. Pass it explicitly only when a caller wants to reuse a set
    already computed elsewhere (avoids redundant DNS resolution)."""
    if extra_authorized_hosts is None:
        extra_authorized_hosts = derived_scope_roots(target_type, target_value, findings)
    in_scope: list = []
    out_of_scope: list = []
    for f in findings:
        ok = finding_in_scope(target_type, target_value, f, extra_authorized_hosts=extra_authorized_hosts)
        (in_scope if ok else out_of_scope).append(f)
    return in_scope, out_of_scope
