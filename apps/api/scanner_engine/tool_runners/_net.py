import ipaddress
import socket


def resolve_scan_host(target_value: str) -> str:
    """Resolve a hostname to an IP via the OS resolver.

    ProjectDiscovery tools (naabu/httpx/...) use their own bundled DNS
    resolvers, which bypass the OS resolver -- so Docker-internal names, and
    any split-horizon/internal DNS, fail. We resolve here and hand the tool an
    IP. IPs and CIDR ranges pass through untouched.
    """
    try:
        ipaddress.ip_network(target_value, strict=False)
        return target_value  # already an IP or CIDR
    except ValueError:
        pass
    # getaddrinfo uses the OS resolver; take the first A/AAAA record.
    infos = socket.getaddrinfo(target_value, None)
    return infos[0][4][0]
