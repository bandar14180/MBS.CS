from apps.api.scanner_engine.net_guard import resolve_and_validate


def resolve_scan_host(target_value: str) -> str:
    """Resolve a hostname to an IP via the OS resolver, enforcing the SSRF policy.

    ProjectDiscovery tools (naabu/httpx/...) use their own bundled DNS resolvers,
    which bypass the OS resolver -- so Docker-internal names and split-horizon DNS
    fail. We resolve here, validate EVERY resolved address against the SSRF guard
    (net_guard), and hand the tool a single validated IP. IPs/CIDRs are validated
    too. Raises net_guard.TargetNotAllowed if any resolved address is forbidden
    (loopback/RFC1918/link-local/reserved/metadata) -- this is the scan-time,
    DNS-rebinding-resistant check that backs up creation-time validation.
    """
    return resolve_and_validate(target_value)
