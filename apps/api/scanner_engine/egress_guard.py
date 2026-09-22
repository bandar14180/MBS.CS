"""Deny-by-default egress policy for the scanner execution plane -- MBS.SC Phase 8.

WHAT THIS IS, AND WHAT IT IS NOT
--------------------------------
This module answers ONE question: given the scan currently executing, is destination D
permitted? It is the authoritative, testable statement of the egress rule, and it is used
by everything in this codebase that opens a connection on the scanner's behalf.

It is NOT the only enforcement, and must not be treated as such. External tool binaries
(nuclei, katana, ffuf, curl inside a template) do their own socket work in another process
and follow their own redirects; no Python check can intercept those. That is precisely why
the compose-level network segmentation exists (the scanner is on no network that carries a
control-plane service) and why the private worker carries an iptables/WireGuard egress
policy. Defense in depth, in this order:

    1. Docker network isolation   -- the scanner has NO ROUTE to mysql/redis/minio/api.
    2. Host/namespace firewall    -- deny-by-default on the private worker.
    3. THIS module                -- in-process refusal, with the tenant's own CIDR set.
    4. net_guard                  -- address safety (SSRF) at every resolution.

Layer 1 is what makes a compromised scanner unable to reach the control plane even if it
never calls a single function here. Layers 3 and 4 stop the SCANNER'S OWN honest code
paths from being tricked into it (a redirect, a rebinding DNS answer, a crafted finding).

THE PERMITTED SET
-----------------
Exactly five kinds of destination, and nothing else:

    1. an authorized public scan target
    2. an address inside the scan's authorized private CIDRs
    3. the site's own DNS resolvers
    4. the scanner-manager endpoint
    5. the site's WireGuard endpoint

Everything else is denied, including -- deliberately -- every control-plane host.
"""
from __future__ import annotations

import logging
from urllib.parse import urlparse

from apps.api.core.observability import record_egress_blocked
from apps.api.scanner_engine import net_guard, net_policy

logger = logging.getLogger(__name__)


class EgressDenied(PermissionError):
    """A destination is outside the permitted egress set."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


REASON_CONTROL_PLANE = "EGRESS_CONTROL_PLANE_DENIED"
REASON_NOT_AUTHORIZED = "EGRESS_NOT_AUTHORIZED"
REASON_UNRESOLVABLE = "EGRESS_UNRESOLVABLE"

# Control-plane service names. A scanner has no legitimate reason to resolve or connect to
# any of these, so they are refused BY NAME as well as by address -- the name check catches
# an attempt before a resolver is even consulted, and survives the services' addresses
# changing. This is belt-and-braces on top of the network segmentation that already makes
# them unroutable from the execution plane.
CONTROL_PLANE_HOSTNAMES = frozenset({
    "mysql", "redis", "minio", "api", "web", "nginx", "ollama",
    "prometheus", "alertmanager", "grafana", "beat", "worker-default",
    "postgres",  # legacy name; kept so a stale config cannot quietly reach a live host
})


def _is_control_plane_host(host: str) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return False
    if h in CONTROL_PLANE_HOSTNAMES:
        return True
    # Compose/Kubernetes qualified forms: `mysql.mbs-core`, `api.default.svc.cluster.local`.
    first = h.split(".", 1)[0]
    return first in CONTROL_PLANE_HOSTNAMES


def assert_destination_allowed(
    destination: str,
    *,
    policy=None,
    manager_host: str | None = None,
    purpose: str = "scan",
) -> None:
    """Refuse `destination` unless it is in the permitted egress set.

    `destination` may be a URL, a host:port, a bare hostname or a bare IP.
    """
    effective = policy if policy is not None else net_policy.current_or_public()
    host = _extract_host(destination)
    if not host:
        raise EgressDenied(REASON_NOT_AUTHORIZED, f"cannot determine a host from {destination!r}")

    # The manager is reachable BY DESIGN -- it is the one control-plane endpoint the
    # execution plane may speak to, and it is on the dispatch network for that purpose.
    if manager_host and host.lower() == manager_host.strip().lower():
        return

    # A control-plane hostname is refused outright, before any resolution.
    if _is_control_plane_host(host):
        logger.warning(
            "egress.control_plane_denied host=%s purpose=%s", host, purpose,
            extra={"event": "egress.blocked", "reason": REASON_CONTROL_PLANE, "purpose": purpose},
        )
        record_egress_blocked(REASON_CONTROL_PLANE)
        raise EgressDenied(
            REASON_CONTROL_PLANE,
            f"{host!r} is a control-plane service; the scanner execution plane may not "
            f"connect to it.",
        )

    # Site DNS resolvers and the WireGuard endpoint are permitted for a private scan.
    if effective.is_private:
        if host in set(effective.dns_servers or ()):
            return

    # Everything else must satisfy the ordinary address policy: public targets pass, and a
    # private address passes only if this scan's site authorizes it.
    try:
        net_guard.resolve_and_validate(host, policy=effective)
    except net_guard.TargetNotAllowed as exc:
        logger.warning(
            "egress.denied host=%s purpose=%s reason=%s", host, purpose, exc,
            extra={"event": "egress.blocked", "reason": REASON_NOT_AUTHORIZED,
                   "purpose": purpose},
        )
        record_egress_blocked(REASON_NOT_AUTHORIZED)
        raise EgressDenied(REASON_NOT_AUTHORIZED, str(exc)) from exc
    except OSError as exc:
        # Unresolvable is a DENIAL, not a pass: we cannot prove it is permitted.
        record_egress_blocked(REASON_UNRESOLVABLE)
        raise EgressDenied(
            REASON_UNRESOLVABLE, f"could not resolve {host!r} to verify egress policy: {exc}"
        ) from exc


def is_destination_allowed(destination: str, *, policy=None, manager_host: str | None = None) -> bool:
    try:
        assert_destination_allowed(destination, policy=policy, manager_host=manager_host)
        return True
    except EgressDenied:
        return False


def _extract_host(value: str) -> str:
    """Host from a URL / host:port / bare host or IP. Reuses net_guard's parser so the two
    layers can never disagree about what 'the host' of a value is."""
    v = (value or "").strip()
    if not v:
        return ""
    if "://" in v:
        parsed = urlparse(v)
        return (parsed.hostname or "").strip()
    return net_guard._host_from_value(v)


def assert_redirect_allowed(
    original_url: str, redirect_url: str, *, policy=None, manager_host: str | None = None
) -> None:
    """A redirect is a FRESH destination and gets a fresh decision.

    This is the classic escalation: an authorized public target answers 302 to
    http://10.0.0.5/ or to http://169.254.169.254/latest/meta-data/, and a client that
    follows redirects blindly turns an authorized external scan into an internal one. The
    check is identical to the initial one -- being reached via a redirect confers no
    authority whatsoever.
    """
    try:
        assert_destination_allowed(
            redirect_url, policy=policy, manager_host=manager_host, purpose="redirect"
        )
    except EgressDenied as exc:
        logger.warning(
            "egress.redirect_blocked from=%s to=%s reason=%s",
            original_url, redirect_url, exc.reason,
            extra={"event": "egress.redirect_blocked", "reason": exc.reason},
        )
        raise
