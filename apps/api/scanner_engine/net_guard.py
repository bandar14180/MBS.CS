"""SSRF / internal-target protection for the scan engine.

A hosted, multi-tenant pentest platform must not let a tenant point the scanner at
internal infrastructure (loopback, RFC1918, CGNAT/RFC6598, link-local, ULA, reserved, multicast)
or a cloud metadata endpoint. Authorization-scope verification is self-service and
is NOT sufficient on its own, so this guard enforces address safety independently,
at two layers (defense in depth):

  1. Target creation -- reject obviously-forbidden literals / hostnames.
  2. Every DNS resolution at scan time -- resolve ALL A/AAAA records and reject if
     *any* is forbidden, then hand a validated address to the tool. Re-resolving
     at scan time (not trusting creation-time DNS) is what defends DNS rebinding.

Default policy: only public addresses are scannable. `scan_allow_private_targets`
+ `scan_allowed_cidrs` narrowly re-enable specific internal ranges for on-prem use;
cloud metadata stays blocked unless listed as an explicit host. There is no blanket
"disable SSRF protection" switch, and TLS verification is never touched here.

MBS.SC -- PER-SCAN TENANT AUTHORIZATION (two-key rule)
------------------------------------------------------
Everything above describes ADDRESS SAFETY and is unchanged. What it could not express is
WHOSE internal network an address belongs to: `scan_allow_private_targets` and
`scan_allowed_cidrs` are process-wide, so enabling them for one on-prem customer enabled
them for every tenant in the deployment. `is_ip_allowed(ip)` had no workspace parameter,
so cross-tenant private access was not merely possible, it was unrepresentable.

A non-public address is therefore now permitted only when BOTH keys turn:

  KEY 1 (unchanged, global)  settings.scan_allow_private_targets and the address falls in
                             settings.scan_allowed_cidrs  -- the OUTER safety boundary.
  KEY 2 (new, per-scan)      the ScanNetworkPolicy bound for THIS scan authorizes it, from
                             persisted workspace -> private site -> CIDR authorization.

Global configuration is now a CEILING, never a grant: with the flag on and no policy
bound, every private address is still refused. When no policy is bound at all the
effective policy is PUBLIC_ONLY, so forgetting to bind one loses access instead of
gaining it. Public-address behaviour is byte-for-byte unchanged -- a public IP never
consults the policy at all, so existing public scanning is unaffected.
"""
import ipaddress
import logging
import socket
import time

from apps.api.core.config import get_settings
from apps.api.scanner_engine import net_policy as _net_policy

logger = logging.getLogger(__name__)

# Cloud metadata service addresses (AWS/GCP/Azure/OpenStack share 169.254.169.254;
# Alibaba uses 100.100.100.200; AWS IMDS also has an IPv6 form). Blocked unless
# listed as an explicit /32 or /128 host in scan_allowed_cidrs.
_METADATA_IPS = frozenset(
    {"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}
)

# AUDIT-006 -- ranges that are NOT public but that Python's `ipaddress` module does not flag
# through any of is_private / is_reserved / is_link_local. Without these, the property-based
# check below returns "public" for them and the scanner would happily target them.
#
# 100.64.0.0/10 (RFC 6598, "Shared Address Space" / CGNAT) is the important one: carriers and,
# far more relevant here, container and cloud fabrics route real internal hosts in it --
# Tailscale hands out 100.64/10 addresses, and Alibaba's metadata endpoint 100.100.100.200
# lives inside it. `ipaddress.ip_address("100.64.0.1").is_private` is False (verified against
# CPython 3.12), so this range was reachable while every RFC1918 address was correctly denied.
#
# Listed explicitly rather than relying on library classification, so a future Python release
# changing its `is_private` semantics cannot silently reopen the hole in either direction.
_EXTRA_FORBIDDEN_NETS = (
    ipaddress.ip_network("100.64.0.0/10"),      # RFC 6598 CGNAT / shared address space
)


class TargetNotAllowed(ValueError):
    """Raised when a target address/host is forbidden by the SSRF policy."""


def _to_ip(value: str) -> ipaddress._BaseAddress | None:
    """Parse an IP, normalizing an IPv4-mapped IPv6 address (::ffff:10.0.0.1) to
    its embedded IPv4 so mapped forms can't smuggle a private address past checks.
    Returns None if `value` is not a bare IP."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return mapped if mapped is not None else ip


def _allowed_networks() -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for entry in get_settings().scan_allowed_cidrs:
        entry = str(entry).strip()
        if not entry:
            continue
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    return nets


def _explicitly_allowed_host(ip: ipaddress._BaseAddress) -> bool:
    """True only if `ip` is listed as an exact single-host CIDR (/32 or /128) in
    scan_allowed_cidrs -- the 'explicit, separately named' allowance required to
    ever reach a metadata endpoint."""
    for net in _allowed_networks():
        if net.num_addresses == 1 and ip == net.network_address:
            return True
    return False


def _in_allowed_cidrs(ip: ipaddress._BaseAddress) -> bool:
    return any(ip in net for net in _allowed_networks())


def is_ip_allowed(ip_value: str, *, policy=None) -> bool:
    """Whether a single resolved IP may be scanned.

    `policy` is the per-scan ScanNetworkPolicy (MBS.SC). When omitted it is taken from
    the ambient scan context, and when nothing is bound there it defaults to PUBLIC_ONLY
    -- so an unbound caller can reach public addresses and nothing else.
    """
    ip = _to_ip(ip_value)
    if ip is None:
        return False
    settings = get_settings()
    effective = policy if policy is not None else _net_policy.current_or_public()

    # Cloud metadata: blocked unless explicitly allowlisted as a single host AND the
    # scan's own policy authorizes it. Metadata endpoints are the highest-value SSRF
    # target in a cloud deployment, so they require both keys exactly like any other
    # non-public address -- a global allowlist entry alone no longer reaches them.
    if str(ip) in _METADATA_IPS:
        return (
            settings.scan_allow_private_targets
            and _explicitly_allowed_host(ip)
            and effective.allows_private_ip(ip)
        )

    forbidden = (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        # AUDIT-006: ranges the stdlib does not classify as private. `ip` is already
        # normalized by _to_ip(), so an IPv4-mapped ::ffff:100.64.0.1 is matched here too.
        or any(ip.version == net.version and ip in net for net in _EXTRA_FORBIDDEN_NETS)
    )
    if not forbidden:
        # PUBLIC ADDRESS: unchanged behaviour, and deliberately policy-independent. The
        # per-scan policy exists to authorize PRIVATE destinations; it must never be able
        # to restrict or re-permit ordinary public scanning, which is what keeps every
        # existing public engagement working exactly as before.
        return True

    # NON-PUBLIC ADDRESS -- both keys must turn (see the module docstring).
    #   Key 1: the global outer boundary (unchanged semantics).
    #   Key 2: THIS scan's persisted tenant authorization.
    # Evaluating key 2 second means a deployment that never enables private scanning
    # behaves precisely as it did before this change.
    if not (settings.scan_allow_private_targets and _in_allowed_cidrs(ip)):
        return False
    return effective.allows_private_ip(ip)


def assert_ip_allowed(ip_value: str, *, policy=None) -> None:
    """Raise TargetNotAllowed unless `ip_value` passes both the SSRF and per-scan checks.

    The message distinguishes the two denial reasons so an operator can tell "this address
    is unsafe for anyone" from "this tenant is not authorized for this internal range"
    without having to reproduce the decision -- while still naming no other tenant's
    configuration.
    """
    if is_ip_allowed(ip_value, policy=policy):
        return
    effective = policy if policy is not None else _net_policy.current_or_public()
    ip = _to_ip(ip_value)
    settings = get_settings()
    globally_permitted = (
        ip is not None
        and settings.scan_allow_private_targets
        and (_in_allowed_cidrs(ip) or _explicitly_allowed_host(ip))
    )
    if globally_permitted:
        # The address clears the outer safety boundary, so the refusal is an
        # AUTHORIZATION decision about this scan specifically.
        raise TargetNotAllowed(
            f"Address {ip_value} is not authorized for this scan: it is not within the "
            f"authorized CIDRs of the scan's private site ({effective.describe()})."
        )
    raise TargetNotAllowed(
        f"Address {ip_value} is not permitted: it is a private/reserved/metadata "
        f"address blocked by SSRF policy."
    )


def _host_from_value(value: str) -> str:
    """Extract a bare host from a target value that may carry a scheme, port,
    path, or userinfo (e.g. https://user@host:8443/x -> host)."""
    v = value.strip()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0]          # drop path
    if "@" in v:
        v = v.rsplit("@", 1)[1]     # drop userinfo
    # strip :port (but keep bracketed IPv6 like [::1]:80 -> ::1)
    if v.startswith("[") and "]" in v:
        return v[1 : v.index("]")]
    if v.count(":") == 1:           # host:port (a single colon => not bare IPv6)
        v = v.split(":", 1)[0]
    return v


def _assert_network_within_policy(net, *, policy=None) -> None:
    """For a CIDR target, require the WHOLE range to be authorized -- not just its edges.

    `assert_ip_allowed` on the network and broadcast addresses is necessary but not
    sufficient for a private range: 10.0.0.0/8 and 10.0.255.255 both sit inside an
    authorized 10.0.0.0/16, so edge checks alone would hand nmap an entire /8 while only
    a /16 was authorized. A public range is unaffected (there is no private authorization
    to contain it), which keeps public CIDR scanning exactly as it was.
    """
    effective = policy if policy is not None else _net_policy.current_or_public()
    edge = _to_ip(str(net.network_address))
    if edge is None:
        return
    is_private_range = (
        edge.is_private
        or edge.is_loopback
        or edge.is_link_local
        or edge.is_reserved
        or any(edge.version == n.version and edge in n for n in _EXTRA_FORBIDDEN_NETS)
    )
    if not is_private_range:
        return
    if any(
        net.version == authorized.version and net.subnet_of(authorized)
        for authorized in effective.authorized_cidrs
    ):
        return
    raise TargetNotAllowed(
        f"Range {net} is not fully contained in the authorized CIDRs for this scan "
        f"({effective.describe()}). A private range must be a subnet of an authorized "
        f"CIDR -- partial overlap is refused."
    )


def resolve_hostname(
    host: str, *, attempts: int = 3, retry_backoff_seconds: float = 0.2, policy=None
) -> list[str]:
    """Resolve a hostname to ALL of its distinct A/AAAA addresses.

    MBS.SC Phase 9: when the scan's policy names site-specific resolvers, the lookup goes
    to THOSE resolvers and must not silently fall back to the public/OS resolver -- a
    private hostname leaking to 8.8.8.8 both discloses the customer's internal naming and
    can return an attacker-influenced public answer. `_resolve_via_site_dns` therefore
    raises rather than falling back. A public scan keeps using the OS resolver exactly as
    before.

    Retries a transient resolver failure (a container's embedded DNS occasionally
    blips on a single lookup -- observed directly against Docker Desktop's
    127.0.0.11 resolver) up to `attempts` times with a short linear backoff before
    giving up. A single flaky lookup must not fail an otherwise-live, scannable
    target -- this is the ONLY retry; a genuinely unresolvable host still raises
    (just after `attempts` tries instead of one)."""
    effective = policy if policy is not None else _net_policy.current_or_public()
    if effective.is_private:
        # Split-horizon: this name must be resolved by the customer's own resolver,
        # through the tunnel. No public fallback -- see site_dns.resolve_via_site_dns.
        #
        # P7-3-OBS-1: the branch is taken on the ZONE ALONE. It previously also required
        # `and effective.dns_servers`, so a private scan whose site had an EMPTY resolver
        # list fell through to `socket.getaddrinfo` below and sent the customer's internal
        # hostname to the public resolver -- the exact leak this module exists to prevent.
        # `private_sites` never required `dns_servers` to be non-empty (unlike
        # `authorized_networks()`, which refuses an empty CIDR set), and
        # `build_private_policy` strips blank/whitespace entries, so `[]`, `None`, `[""]`
        # and `["  "]` all reached that fall-through.
        #
        # Missing configuration must mean NO ANSWER, never A PUBLIC ANSWER. Routing on the
        # zone makes that structural: once a scan is private, this function has no path to
        # the OS resolver at all. `resolve_via_site_dns` already refuses an empty resolver
        # list with SiteDNSUnavailable ("refusing public fallback"), which is the correct,
        # EXISTING failure semantics -- a gaierror subclass, so callers that already treat
        # an unresolvable host as "fail this target cleanly" are unaffected.
        from apps.api.scanner_engine import site_dns

        return site_dns.resolve_via_site_dns(
            host, resolvers=effective.dns_servers, attempts=attempts,
            retry_backoff_seconds=retry_backoff_seconds,
        )
    last_exc: socket.gaierror | None = None
    for attempt in range(attempts):
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            last_exc = exc
            logger.warning(
                "net_guard.resolve_failed host=%s attempt=%d/%d error=%s",
                host, attempt + 1, attempts, exc,
            )
            if attempt < attempts - 1:
                time.sleep(retry_backoff_seconds * (attempt + 1))
            continue
        seen: set[str] = set()
        out: list[str] = []
        for info in infos:
            addr = info[4][0]
            if addr not in seen:
                seen.add(addr)
                out.append(addr)
        return out
    raise last_exc


def validate_target_value(target_type: str, value: str, *, policy=None) -> None:
    """Creation-time check. Rejects a literal/hostname target that is (or resolves
    to) a forbidden address. Best-effort for hostnames -- if DNS can't resolve at
    creation, we allow creation and rely on the authoritative scan-time check
    (resolve_and_validate). Only network-scannable types are checked here."""
    if target_type not in ("domain", "ip_range"):
        return
    host = _host_from_value(value)
    # Bare IP or CIDR: validate directly.
    try:
        net = ipaddress.ip_network(host, strict=False)
        for ip in (net.network_address, net.broadcast_address):
            assert_ip_allowed(str(ip), policy=policy)
        return
    except TargetNotAllowed:
        raise
    except ValueError:
        pass  # not an IP/CIDR -> a hostname
    if host.lower() in ("localhost", "localhost.localdomain"):
        raise TargetNotAllowed("localhost targets are not permitted.")
    try:
        addrs = resolve_hostname(host)
    except socket.gaierror:
        return  # unresolvable now; scan-time check enforces
    for addr in addrs:
        assert_ip_allowed(addr, policy=policy)


def resolve_and_validate(host: str, *, policy=None) -> str:
    """Scan-time resolver + SSRF gate (replaces the old resolve_scan_host).

    - Bare IP or CIDR: validate and return it UNCHANGED, so tools that expand a
      CIDR (nmap/naabu) still scan the whole range.
    - Hostname: resolve every A/AAAA address, reject if ANY is forbidden (DNS
      rebinding defense), and return a single validated address for the tool.
    Raises TargetNotAllowed on a forbidden address; socket.gaierror if unresolvable.
    """
    try:
        net = ipaddress.ip_network(host, strict=False)
    except ValueError:
        net = None
    if net is not None:
        # A CIDR target is expanded by the tool itself, so BOTH edges must clear the
        # policy -- otherwise a /8 whose network address happens to sit inside an
        # authorized /16 would smuggle the whole range past the check.
        assert_ip_allowed(str(net.network_address), policy=policy)
        assert_ip_allowed(str(net.broadcast_address), policy=policy)
        _assert_network_within_policy(net, policy=policy)
        return host  # unchanged (IP or CIDR)

    # Not a bare IP/CIDR -> treat as a hostname, but normalize it first. A `domain` target's
    # stored value can carry a scheme/port/path/userinfo (e.g. a user entered
    # "https://example.com" at target creation, which creation-time validation accepts --
    # validate_target_value is best-effort for hostnames and doesn't reject on this). Every
    # runner (httpx/naabu/nmap/...) hands its target value straight through to this function,
    # so `socket.getaddrinfo` would otherwise be asked to resolve the LITERAL string
    # "https://example.com" -- which always fails with "Name or service not known", not because
    # the host is unreachable but because it was never a valid hostname to begin with. The
    # orchestrator's own pre-flight SSRF check already normalizes via `_host_from_value` before
    # calling this function; folding it in HERE closes the same gap for every other caller
    # (every tool runner's `resolve_scan_host`) instead of requiring each one to remember it.
    normalized = _host_from_value(host)
    addrs = resolve_hostname(normalized, policy=policy)
    if not addrs:
        raise socket.gaierror(f"could not resolve {normalized}")
    for addr in addrs:
        assert_ip_allowed(addr, policy=policy)
    return addrs[0]
