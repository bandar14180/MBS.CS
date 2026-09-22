"""Dedicated VPN egress for PUBLIC scanner traffic -- a separate tunnel, separate code.

WHY THIS IS NOT `scanner_engine/wireguard.py`
---------------------------------------------
The two tunnels are opposites, and that is the whole reason they do not share a module.

    scanner_engine/wireguard.py   PRIVATE SITE tunnel.  SPLIT tunnel.  AllowedIPs is
                                  EXACTLY the customer's authorized CIDRs, and
                                  `build_allowed_ips` REFUSES 0.0.0.0/0 outright, because a
                                  default route there would send every other tenant's scan
                                  traffic -- and the worker's own manager connection --
                                  into one customer's network.

    THIS MODULE                   PLATFORM VPN EGRESS.  FULL tunnel.  AllowedIPs IS
                                  0.0.0.0/0, because the entire point is that public
                                  target traffic leaves from the VPN provider's exit IP
                                  rather than the platform's own address.

Sharing one code path and distinguishing the cases with a flag was considered and
rejected: the flag would have to be threaded through `build_allowed_ips`, and one bad call
site would then re-open the private path to a default route -- the exact failure the
private module refuses by construction. Keeping the codepaths disjoint means the private
refusal can stay unconditional, with no parameter that could ever disable it.

WHAT MAKES A FULL TUNNEL SAFE HERE, WHEN IT IS UNSAFE THERE
------------------------------------------------------------
Three things, and all three are structural rather than advisory:

  1. THE DEFAULT ROUTE IS NOT IN THE MAIN TABLE. It is installed in a dedicated routing
     table (see `egress_setup.py`) selected by an `ip rule`. The main table is untouched,
     so the manager connection on mbs-dispatch keeps its ordinary path. A full tunnel that
     replaced the main table's default route would break the control channel and send
     authenticated worker traffic to the VPN provider.
  2. THE WORKER HOLDS NO SITE STATE. A VPN-egress worker has no `site_id`, no site secret,
     and is on no `mbs-site-*` network. It cannot reach a private range at all, so the
     full tunnel cannot become a path into a customer network.
  3. THE POLICY LAYER IS UNCHANGED. `net_policy` still binds PUBLIC-ONLY for these scans,
     so `net_guard`/`egress_guard` refuse every private destination exactly as before. The
     VPN changes WHICH PUBLIC IP the traffic leaves from; it does not widen what may be
     reached.

EXIT-IP VERIFICATION IS PART OF HEALTH, NOT A NICETY
-----------------------------------------------------
Interface-up plus a fresh handshake proves the TUNNEL is alive. It does NOT prove traffic
is USING it: a missing `ip rule`, a routing table that was flushed, or a policy rule that
never matched all leave a perfectly healthy-looking tunnel beside traffic still going out
the host's own address. Since the entire feature is "scans leave from the VPN exit IP",
health here means the OBSERVED egress address is the VPN's -- see `assert_egress_healthy`,
which refuses on a missing, stale or unexpected exit IP.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# The FULL tunnel this module exists to build. Stated as a constant so the contrast with
# `wireguard._DEFAULT_ROUTES` (which refuses exactly these) is explicit and greppable.
FULL_TUNNEL_ALLOWED_IPS = ("0.0.0.0/0",)

# The dedicated interface name. Deliberately NOT `wg0`: a private site worker's interface
# is `wg0`, and identical names across the two roles would make logs, probes and operator
# commands ambiguous at exactly the moment clarity matters.
DEFAULT_EGRESS_INTERFACE = "wg-egress"

# The dedicated routing table for the tunnel default route. The main table (254) is never
# touched, which is what keeps the manager/dispatch path on its ordinary route.
DEFAULT_EGRESS_TABLE = 51820
# The fwmark used to steer scan traffic into that table.
DEFAULT_EGRESS_FWMARK = 0x51820

# Same rekey reasoning as the private tunnel: WireGuard rekeys ~every 120s while carrying
# traffic, so ~3 minutes of silence is a real signal rather than a timing artifact.
DEFAULT_MAX_HANDSHAKE_AGE_S = 180

# How old an exit-IP observation may be before it is no longer evidence of anything. The
# check is cheap but not free (it is one HTTPS request), so it is cached for this long and
# re-verified after. Deliberately much shorter than a long scan: a tunnel that fails
# mid-scan must be caught while the scan is still running.
DEFAULT_MAX_EXIT_IP_AGE_S = 120


class VpnEgressConfigError(ValueError):
    """The requested egress configuration is unsafe or incomplete."""


class EgressUnhealthy(RuntimeError):
    """Preflight failed; scans that require VPN egress must not run. `reason` is stable."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


# Refusal vocabulary. Distinct from the private tunnel's codes on purpose: an operator
# reading a log must be able to tell which of the two tunnels failed without cross
# referencing anything.
REASON_EGRESS_DOWN = "VPN_EGRESS_DOWN"
REASON_EGRESS_NO_HANDSHAKE = "VPN_EGRESS_NO_HANDSHAKE"
REASON_EGRESS_HANDSHAKE_STALE = "VPN_EGRESS_HANDSHAKE_STALE"
REASON_EGRESS_ROUTE_MISSING = "VPN_EGRESS_ROUTE_MISSING"
REASON_EGRESS_RULE_MISSING = "VPN_EGRESS_RULE_MISSING"
REASON_EGRESS_EXIT_IP_UNKNOWN = "VPN_EGRESS_EXIT_IP_UNKNOWN"
REASON_EGRESS_EXIT_IP_MISMATCH = "VPN_EGRESS_EXIT_IP_MISMATCH"
REASON_EGRESS_EXIT_IP_STALE = "VPN_EGRESS_EXIT_IP_STALE"
REASON_EGRESS_LEAK = "VPN_EGRESS_LEAK"
REASON_EGRESS_NOT_CONFIGURED = "VPN_EGRESS_NOT_CONFIGURED"
REASON_EGRESS_KILLSWITCH_MISSING = "VPN_EGRESS_KILLSWITCH_MISSING"


def assert_not_platform_address(value: str, *, what: str) -> None:
    """Refuse a VPN endpoint that points anywhere inside the platform or a private range.

    A VPN endpoint is one of the very few destinations the kill-switch firewall lets out
    directly, so a misconfigured (or malicious) endpoint value is a hole punched straight
    through the egress policy. A loopback/link-local/private endpoint would additionally
    mean the "VPN" terminates somewhere inside our own deployment, which is not an egress
    path at all.
    """
    host = (value or "").strip()
    if not host:
        raise VpnEgressConfigError(f"{what} is empty")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # A hostname. It is resolved at bring-up time; the address check below then runs
        # against what it actually resolved to, which is the value that matters.
        return
    if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved or ip.is_multicast:
        raise VpnEgressConfigError(
            f"{what} {host!r} is a non-public address. The VPN endpoint is permitted "
            f"through the egress kill-switch by definition, so it must be a genuine "
            f"external provider address -- never a platform-internal one."
        )


@dataclass(frozen=True)
class EgressConfig:
    """A rendered VPN egress configuration, WITHOUT any private key.

    Mirrors `wireguard.TunnelConfig`'s discipline for the same reason: safe to log, safe to
    return, safe to assert on -- which only holds while the private key is not a field.
    """

    interface: str = DEFAULT_EGRESS_INTERFACE
    interface_address: str | None = None
    peer_public_key: str | None = None
    endpoint: str | None = None
    # ALWAYS the full tunnel. Not a parameter: a "partial" VPN egress would silently send
    # some target traffic out the platform's own address, which is the failure this
    # feature exists to prevent.
    allowed_ips: tuple = FULL_TUNNEL_ALLOWED_IPS
    table: int = DEFAULT_EGRESS_TABLE
    fwmark: int = DEFAULT_EGRESS_FWMARK
    mtu: int | None = None
    persistent_keepalive: int | None = 25
    dns_servers: tuple = field(default_factory=tuple)
    # The exit IP this tunnel is EXPECTED to present, when the operator has pinned one.
    # Empty means "any address that is not ours", which is weaker but still catches the
    # common failure of traffic never entering the tunnel at all.
    expected_exit_ip: str | None = None

    @property
    def is_full_tunnel(self) -> bool:
        return any(str(a).endswith("/0") for a in self.allowed_ips)


def describe_config(
    *,
    interface: str = DEFAULT_EGRESS_INTERFACE,
    interface_address: str | None,
    peer_public_key: str | None,
    endpoint_host: str | None,
    endpoint_port: int | None,
    table: int = DEFAULT_EGRESS_TABLE,
    fwmark: int = DEFAULT_EGRESS_FWMARK,
    mtu: int | None = None,
    persistent_keepalive: int | None = 25,
    dns_servers=(),
    expected_exit_ip: str | None = None,
) -> EgressConfig:
    """Build the (key-free) description of the platform VPN egress tunnel."""
    if not peer_public_key:
        raise VpnEgressConfigError(
            "a VPN egress peer public key is required; without it the tunnel would have no "
            "authenticated peer and could not be brought up."
        )
    if not endpoint_host or not endpoint_port:
        raise VpnEgressConfigError(
            "a VPN egress endpoint host and port are required; the kill-switch firewall "
            "allows exactly this one destination out directly, so it cannot be inferred."
        )
    assert_not_platform_address(endpoint_host, what="the VPN egress endpoint host")
    if not interface_address:
        raise VpnEgressConfigError(
            "a VPN egress interface address is required (the address the provider assigned "
            "this peer)."
        )
    if expected_exit_ip:
        assert_not_platform_address(expected_exit_ip, what="the expected VPN exit IP")
    return EgressConfig(
        interface=(interface or DEFAULT_EGRESS_INTERFACE).strip(),
        interface_address=interface_address,
        peer_public_key=peer_public_key,
        endpoint=f"{endpoint_host}:{int(endpoint_port)}",
        table=int(table),
        fwmark=int(fwmark),
        mtu=int(mtu) if mtu else None,
        persistent_keepalive=int(persistent_keepalive) if persistent_keepalive else None,
        dns_servers=tuple(str(d).strip() for d in (dns_servers or ()) if str(d).strip()),
        expected_exit_ip=(expected_exit_ip or None),
    )


def render_egress_config(config: EgressConfig, *, private_key: str) -> str:
    """Render the egress wg config. The caller must treat the result as SECRET.

    `Table = off` for the same reason the private path uses it, arrived at from the
    opposite direction: wg-quick would install this tunnel's 0.0.0.0/0 into the MAIN table
    and capture the manager connection. Routes are installed explicitly into the dedicated
    table by `egress_setup.py`, so the full tunnel is scoped by construction.
    """
    if not private_key:
        raise VpnEgressConfigError("a private key is required to render the egress config")
    lines = ["[Interface]", f"PrivateKey = {private_key}"]
    if config.interface_address:
        lines.append(f"Address = {config.interface_address}")
    lines.append(f"FwMark = {config.fwmark}")
    # NOT set: DNS=. Same reasoning as the private path -- wg-quick's DNS handling rewrites
    # the whole namespace resolver. Egress DNS is handled by the resolver configuration on
    # the egress worker itself, which is forced through the tunnel by the firewall.
    lines.append("Table = off")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {config.peer_public_key}")
    lines.append(f"AllowedIPs = {', '.join(config.allowed_ips)}")
    if config.endpoint:
        lines.append(f"Endpoint = {config.endpoint}")
    if config.persistent_keepalive:
        lines.append(f"PersistentKeepalive = {int(config.persistent_keepalive)}")
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class EgressStatus:
    """An observation of the live egress path, supplied by a probe.

    `observed_exit_ip` is the load-bearing field and the reason this type is not
    `wireguard.TunnelStatus`: the private tunnel's health is about REACHING a network,
    while this one's is about LEAVING FROM a specific address.
    """

    interface_up: bool = False
    last_handshake_age_s: int | None = None
    # Whether the dedicated table carries a default route over the interface.
    default_route_in_table: bool = False
    # Whether the `ip rule` that steers marked traffic into that table exists.
    policy_rule_present: bool = False
    # Whether the main table's default route still points somewhere OTHER than the tunnel.
    # True is the CORRECT state: the control-plane path must remain on its ordinary route.
    main_table_untouched: bool = True
    observed_exit_ip: str | None = None
    exit_ip_age_s: int | None = None
    killswitch_active: bool = False
    mtu: int | None = None
    detail: str | None = None


class EgressProbe:
    """Interface for observing the egress path. Injectable so preflight is testable."""

    def status(self) -> EgressStatus:  # pragma: no cover - interface
        raise NotImplementedError


class StaticEgressProbe(EgressProbe):
    """Returns a fixed status. Tests and the local/dev profile."""

    def __init__(self, status: EgressStatus) -> None:
        self._status = status

    def status(self) -> EgressStatus:
        return self._status


def assert_egress_healthy(
    status: EgressStatus,
    *,
    expected_exit_ip: str | None = None,
    forbidden_exit_ips=(),
    max_handshake_age_s: int = DEFAULT_MAX_HANDSHAKE_AGE_S,
    max_exit_ip_age_s: int = DEFAULT_MAX_EXIT_IP_AGE_S,
    require_killswitch: bool = True,
) -> None:
    """Refuse unless public target traffic is genuinely leaving via the VPN RIGHT NOW.

    Checked in escalating order of specificity so the reported reason is the most
    actionable one. EVERY failure raises: there is no "probably fine" state, because the
    failure mode this guards against is a scan that silently runs over the platform's own
    address while reporting success.
    """
    if not status.interface_up:
        raise EgressUnhealthy(
            REASON_EGRESS_DOWN,
            f"VPN egress interface is down"
            f"{': ' + status.detail if status.detail else ''}",
        )
    if status.last_handshake_age_s is None:
        raise EgressUnhealthy(
            REASON_EGRESS_NO_HANDSHAKE,
            "VPN egress tunnel has never completed a handshake with the provider peer",
        )
    if status.last_handshake_age_s > max_handshake_age_s:
        raise EgressUnhealthy(
            REASON_EGRESS_HANDSHAKE_STALE,
            f"VPN egress last handshake was {status.last_handshake_age_s}s ago (limit "
            f"{max_handshake_age_s}s); the provider peer is not currently reachable",
        )
    if not status.default_route_in_table:
        raise EgressUnhealthy(
            REASON_EGRESS_ROUTE_MISSING,
            "the dedicated egress routing table carries no default route over the tunnel; "
            "target traffic would fall through to the platform's own path",
        )
    if not status.policy_rule_present:
        raise EgressUnhealthy(
            REASON_EGRESS_RULE_MISSING,
            "the policy routing rule that steers scan traffic into the egress table is "
            "absent; the tunnel is up but nothing is using it",
        )
    # THE LEAK CHECK, stated positively. If the MAIN table's default route were replaced by
    # the tunnel, control-plane traffic would be inside the VPN -- a different failure from
    # a leak, and one this feature promises not to cause.
    if not status.main_table_untouched:
        raise EgressUnhealthy(
            REASON_EGRESS_LEAK,
            "the main routing table's default route now points at the VPN egress tunnel. "
            "Control-plane/manager traffic must never traverse the VPN; refusing.",
        )
    if require_killswitch and not status.killswitch_active:
        raise EgressUnhealthy(
            REASON_EGRESS_KILLSWITCH_MISSING,
            "the egress kill-switch firewall is not active. Without it a tunnel failure "
            "mid-scan would let tool binaries fall back to direct egress, which is exactly "
            "the silent leak this feature exists to prevent.",
        )

    # EXIT-IP VERIFICATION. Everything above proves the tunnel and its routing exist; only
    # this proves traffic actually leaves from the VPN.
    if not status.observed_exit_ip:
        raise EgressUnhealthy(
            REASON_EGRESS_EXIT_IP_UNKNOWN,
            "the egress exit IP could not be observed. Tunnel-up and a fresh handshake do "
            "not prove traffic is using the tunnel, so an unverifiable exit IP is a "
            "refusal, not a pass.",
        )
    if status.exit_ip_age_s is not None and status.exit_ip_age_s > max_exit_ip_age_s:
        raise EgressUnhealthy(
            REASON_EGRESS_EXIT_IP_STALE,
            f"the last exit-IP observation is {status.exit_ip_age_s}s old (limit "
            f"{max_exit_ip_age_s}s); it is no longer evidence that traffic is on the VPN",
        )
    observed = str(status.observed_exit_ip).strip()
    if expected_exit_ip and observed != str(expected_exit_ip).strip():
        raise EgressUnhealthy(
            REASON_EGRESS_EXIT_IP_MISMATCH,
            f"observed egress exit IP {observed} does not match the pinned VPN exit IP "
            f"{expected_exit_ip}; traffic is not leaving where it must",
        )
    # Even without a pinned value, an exit IP that equals a KNOWN-PLATFORM address proves
    # the traffic bypassed the tunnel.
    for bad in forbidden_exit_ips or ():
        if observed == str(bad).strip():
            raise EgressUnhealthy(
                REASON_EGRESS_EXIT_IP_MISMATCH,
                f"observed egress exit IP {observed} is the platform's own direct egress "
                f"address; target traffic is NOT going through the VPN",
            )


def preflight(
    *,
    probe: EgressProbe,
    expected_exit_ip: str | None = None,
    forbidden_exit_ips=(),
    max_handshake_age_s: int = DEFAULT_MAX_HANDSHAKE_AGE_S,
    max_exit_ip_age_s: int = DEFAULT_MAX_EXIT_IP_AGE_S,
    require_killswitch: bool = True,
) -> EgressStatus:
    """Observe and validate the egress path. Returns the status, or raises."""
    status = probe.status()
    assert_egress_healthy(
        status,
        expected_exit_ip=expected_exit_ip,
        forbidden_exit_ips=forbidden_exit_ips,
        max_handshake_age_s=max_handshake_age_s,
        max_exit_ip_age_s=max_exit_ip_age_s,
        require_killswitch=require_killswitch,
    )
    logger.info(
        "vpn_egress.preflight_ok handshake_age=%ss exit_ip_age=%ss",
        status.last_handshake_age_s, status.exit_ip_age_s,
        extra={"event": "vpn_egress.preflight_ok",
               "handshake_age_s": status.last_handshake_age_s},
    )
    return status
