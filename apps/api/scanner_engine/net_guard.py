"""SSRF / internal-target protection for the scan engine.

A hosted, multi-tenant pentest platform must not let a tenant point the scanner at
internal infrastructure (loopback, RFC1918, link-local, ULA, reserved, multicast)
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
"""
import ipaddress
import socket

from apps.api.core.config import get_settings

# Cloud metadata service addresses (AWS/GCP/Azure/OpenStack share 169.254.169.254;
# Alibaba uses 100.100.100.200; AWS IMDS also has an IPv6 form). Blocked unless
# listed as an explicit /32 or /128 host in scan_allowed_cidrs.
_METADATA_IPS = frozenset(
    {"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}
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


def is_ip_allowed(ip_value: str) -> bool:
    """Whether a single resolved IP may be scanned under the current policy."""
    ip = _to_ip(ip_value)
    if ip is None:
        return False
    settings = get_settings()

    # Cloud metadata: blocked unless explicitly allowlisted as a single host.
    if str(ip) in _METADATA_IPS:
        return settings.scan_allow_private_targets and _explicitly_allowed_host(ip)

    forbidden = (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )
    if not forbidden:
        return True
    # A non-public address is scannable only for an explicit on-prem allowlist.
    return settings.scan_allow_private_targets and _in_allowed_cidrs(ip)


def assert_ip_allowed(ip_value: str) -> None:
    if not is_ip_allowed(ip_value):
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


def resolve_hostname(host: str) -> list[str]:
    """Resolve a hostname to ALL of its distinct A/AAAA addresses via the OS
    resolver. Raises socket.gaierror if it does not resolve."""
    infos = socket.getaddrinfo(host, None)
    seen: set[str] = set()
    out: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.add(addr)
            out.append(addr)
    return out


def validate_target_value(target_type: str, value: str) -> None:
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
            assert_ip_allowed(str(ip))
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
        assert_ip_allowed(addr)


def resolve_and_validate(host: str) -> str:
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
        assert_ip_allowed(str(net.network_address))
        assert_ip_allowed(str(net.broadcast_address))
        return host  # unchanged (IP or CIDR)

    addrs = resolve_hostname(host)
    if not addrs:
        raise socket.gaierror(f"could not resolve {host}")
    for addr in addrs:
        assert_ip_allowed(addr)
    return addrs[0]
