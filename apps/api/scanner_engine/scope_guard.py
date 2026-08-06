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

from apps.api.scanner_engine import net_guard


def _norm(host: str | None) -> str:
    return (str(host).strip().lower().rstrip(".")) if host else ""


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


def host_in_scope(target_type: str, target_value: str, host: str | None) -> bool:
    """Whether a discovered `host` is within the authorized scope of the target.
    FAIL CLOSED: an empty/undeterminable host is never in scope."""
    host = _norm(host)
    if not host:
        return False
    if target_type == "domain":
        d = _target_domain(target_value)
        return bool(d) and (host == d or host.endswith("." + d))
    if target_type == "ip_range":
        return _ip_host_in_range(target_value, host)
    # Only domain / ip_range are scannable target types; anything else is out of scope.
    return False


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


def finding_in_scope(target_type: str, target_value: str, finding) -> bool:
    """Whether a discovered asset may be actively probed. Fail closed: no
    determinable host => not in scope."""
    return host_in_scope(target_type, target_value, extract_host(finding))


def partition_in_scope(target_type: str, target_value: str, findings):
    """Split findings into (in_scope, out_of_scope) for active probing. Preserves order."""
    in_scope, out_of_scope = [], []
    for f in findings:
        (in_scope if finding_in_scope(target_type, target_value, f) else out_of_scope).append(f)
    return in_scope, out_of_scope
