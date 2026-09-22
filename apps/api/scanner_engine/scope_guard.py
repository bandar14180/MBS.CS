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
"""
import ipaddress

from apps.api.core.config import get_settings
from apps.api.scanner_engine import net_guard


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
    try:
        addrs = net_guard.resolve_hostname(host)
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
    try:
        addrs = net_guard.resolve_hostname(hostname)
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
