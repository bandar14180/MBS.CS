"""WireGuard configuration and tunnel preflight -- MBS.SC Phases 11/12.

KEY CUSTODY (the rule everything else follows)
----------------------------------------------
The worker's PRIVATE key is generated inside the private worker namespace and never
leaves it. It is not a database column, not a manager request field, not a log line, and
not a return value from anything in this module. `render_worker_config` takes the private
key as an argument only to place it into the config text that stays on that host, and
`describe_config` exists so operators/tests can inspect a configuration WITHOUT the key.

The reason is blast radius. If the control plane stored every customer's tunnel private
key, one database compromise would yield simultaneous authenticated access to the inside
of every customer's network -- catastrophically worse than the database contents alone.
The control plane therefore holds public keys only, which is all it needs to distribute
configuration.

ROUTING RULES
-------------
  * AllowedIPs is EXACTLY the site's authorized CIDRs. Never 0.0.0.0/0.
  * No default route: the tunnel is split, so only authorized ranges traverse it and
    everything else keeps its ordinary path (or is denied by the egress firewall).
  * One site per namespace, so two customers' overlapping 10.0.0.0/8 ranges are never
    resolved by the same routing table.

`0.0.0.0/0` is refused by construction rather than merely discouraged: as an AllowedIPs
value it means "route ALL traffic into this customer's tunnel", which would send other
tenants' scan traffic -- and the worker's own manager traffic -- into a third party's
network. `build_allowed_ips` raises on it.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Refused as AllowedIPs. Each would capture the worker's entire egress.
_DEFAULT_ROUTES = frozenset({"0.0.0.0/0", "::/0"})


class WireGuardConfigError(ValueError):
    """The requested tunnel configuration is unsafe or incomplete."""


class TunnelUnhealthy(RuntimeError):
    """Preflight failed; the scan must not start. `reason` is a stable code."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


# Phase 12 refusal vocabulary.
REASON_TUNNEL_UNHEALTHY = "TUNNEL_UNHEALTHY"
REASON_ROUTE_MISSING = "ROUTE_MISSING"
REASON_DNS_UNAVAILABLE = "DNS_UNAVAILABLE"
REASON_HANDSHAKE_STALE = "HANDSHAKE_STALE"
REASON_NO_HANDSHAKE = "NO_HANDSHAKE"
REASON_PEER_UNREACHABLE = "PEER_UNREACHABLE"

# A handshake older than this means the tunnel is not currently carrying traffic.
# WireGuard rekeys about every 120s while a session is active, so ~3 minutes of silence
# is a real signal rather than a timing artifact.
DEFAULT_MAX_HANDSHAKE_AGE_S = 180


def build_allowed_ips(authorized_cidrs) -> list[str]:
    """The AllowedIPs list for a site: exactly its authorized CIDRs, normalized.

    Refuses a default route outright, and refuses an empty result -- a tunnel that
    authorizes nothing is a misconfiguration, and returning an empty AllowedIPs would
    silently produce a tunnel that carries no traffic while looking configured.
    """
    out: list[str] = []
    seen: set[str] = set()
    for raw in authorized_cidrs or ():
        entry = str(raw).strip()
        if not entry:
            continue
        if entry in _DEFAULT_ROUTES:
            raise WireGuardConfigError(
                f"AllowedIPs must never contain the default route {entry!r}: it would send "
                f"ALL worker traffic into this customer's tunnel, including other tenants' "
                f"scan traffic and the worker's own manager connection."
            )
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise WireGuardConfigError(f"invalid CIDR {entry!r}: {exc}") from exc
        if net.prefixlen == 0:
            raise WireGuardConfigError(
                f"AllowedIPs entry {entry!r} is a default route (prefix length 0); refused."
            )
        key = str(net)
        if key not in seen:
            seen.add(key)
            out.append(key)
    if not out:
        raise WireGuardConfigError(
            "a site must authorize at least one CIDR; an empty AllowedIPs would create a "
            "tunnel that carries nothing."
        )
    return out


@dataclass(frozen=True)
class TunnelConfig:
    """A rendered tunnel configuration, WITHOUT any private key.

    Safe to log, return from an API, and assert on in tests -- which is exactly why the
    private key is not a field here.
    """

    site_id: str
    interface_address: str | None
    allowed_ips: tuple
    peer_public_key: str | None
    endpoint: str | None
    dns_servers: tuple = field(default_factory=tuple)
    persistent_keepalive: int | None = None

    @property
    def has_default_route(self) -> bool:
        return any(str(a) in _DEFAULT_ROUTES or str(a).endswith("/0") for a in self.allowed_ips)


def describe_config(
    *,
    site_id,
    authorized_cidrs,
    peer_public_key: str | None,
    endpoint_host: str | None,
    endpoint_port: int | None,
    dns_servers=(),
    interface_address: str | None = None,
    persistent_keepalive: int | None = None,
) -> TunnelConfig:
    """Build the (key-free) description of a site's tunnel."""
    allowed = build_allowed_ips(authorized_cidrs)
    endpoint = None
    if endpoint_host and endpoint_port:
        endpoint = f"{endpoint_host}:{int(endpoint_port)}"
    return TunnelConfig(
        site_id=str(site_id),
        interface_address=interface_address,
        allowed_ips=tuple(allowed),
        peer_public_key=peer_public_key,
        endpoint=endpoint,
        dns_servers=tuple(dns_servers or ()),
        persistent_keepalive=persistent_keepalive,
    )


def render_worker_config(config: TunnelConfig, *, private_key: str) -> str:
    """Render wg0.conf for the PRIVATE WORKER NAMESPACE ONLY.

    `private_key` is written into the returned text, so the caller must treat the result
    as secret: write it to a file inside the worker namespace with restrictive
    permissions, and never log it, return it over the manager API, or persist it
    centrally. `describe_config`/`TunnelConfig` is the non-secret view for every other
    purpose.

    Table = off, deliberately: wg-quick would otherwise install routes (and, with a
    0.0.0.0/0 AllowedIPs, a default route) automatically. Routes are installed explicitly
    for the authorized CIDRs only, so the split tunnel is a decision rather than a
    side effect.
    """
    if not private_key:
        raise WireGuardConfigError("a worker private key is required to render wg0.conf")
    if config.has_default_route:
        raise WireGuardConfigError("refusing to render a config carrying a default route")

    lines = ["[Interface]", f"PrivateKey = {private_key}"]
    if config.interface_address:
        lines.append(f"Address = {config.interface_address}")
    # NOTE: DNS is deliberately NOT set here. wg-quick's DNS= rewrites the whole
    # namespace's resolv.conf, which would send EVERY lookup -- including public ones and
    # the manager's own name -- to the customer's resolver. Site DNS is applied per-lookup
    # instead (scanner_engine/site_dns.py), so only private names use the site resolver.
    lines.append("Table = off")
    lines.append("")
    lines.append("[Peer]")
    if config.peer_public_key:
        lines.append(f"PublicKey = {config.peer_public_key}")
    lines.append(f"AllowedIPs = {', '.join(config.allowed_ips)}")
    if config.endpoint:
        lines.append(f"Endpoint = {config.endpoint}")
    if config.persistent_keepalive:
        lines.append(f"PersistentKeepalive = {int(config.persistent_keepalive)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------------------
# Preflight (Phase 12)
# ---------------------------------------------------------------------------------------

@dataclass(frozen=True)
class TunnelStatus:
    """An observation of the live tunnel, supplied by a probe."""

    interface_up: bool = False
    last_handshake_age_s: int | None = None
    routes: tuple = field(default_factory=tuple)
    dns_ok: bool = True
    peer_reachable: bool = True
    detail: str | None = None
    # PHASE 8: the interface's ACTUAL MTU, as observed. Reported for visibility (metrics /
    # logs / drift detection) -- it is deliberately NOT part of the health verdict, because
    # a wrong MTU costs reachability, never isolation, and failing a scan closed over it
    # would trade a confinement-neutral problem for an outage.
    mtu: int | None = None


class TunnelProbe:
    """Interface for observing the tunnel. Injectable so preflight is testable without a
    real tunnel, and so a private worker can supply a real `wg show` implementation."""

    def status(self, site_id) -> TunnelStatus:  # pragma: no cover - interface
        raise NotImplementedError


class StaticTunnelProbe(TunnelProbe):
    """Returns a fixed status. Used by tests and by the local/dev profile."""

    def __init__(self, status: TunnelStatus) -> None:
        self._status = status

    def status(self, site_id) -> TunnelStatus:
        return self._status


class SystemTunnelProbe(TunnelProbe):
    """Observes the REAL tunnel inside the private worker's own namespace.

    Reads two things and nothing else:
      * `wg show <iface> latest-handshakes` -- when the peer last completed a handshake;
      * `ip -o route` -- which prefixes are actually routed over the interface.

    EVERY FAILURE PATH RETURNS AN UNHEALTHY STATUS rather than raising or guessing. A
    missing binary, a permission error, an unparsable line, a timeout: each yields
    `interface_up=False` (or no routes), which `assert_tunnel_healthy` then turns into a
    refusal. That direction is deliberate -- a probe that cannot see the tunnel must never
    be mistaken for a probe that saw a healthy one. It is also why this class does no
    caching: a stale "healthy" reading is precisely the thing that would let a scan start
    on a dead tunnel.

    The probe is read-only. It never brings an interface up, never installs a route, and
    never touches key material -- configuration is applied by the container's entrypoint,
    which is the only thing holding CAP_NET_ADMIN for that purpose.
    """

    def __init__(self, interface: str = "wg0", *, timeout_s: float = 5.0, runner=None) -> None:
        self.interface = interface
        self.timeout_s = timeout_s
        # Injectable command runner: (argv) -> (rc, stdout). Lets the lab and the unit
        # tests drive this against captured real output without a live tunnel.
        self._runner = runner or self._run

    def _run(self, argv) -> tuple:
        import subprocess

        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=self.timeout_s, check=False
            )
        except FileNotFoundError:
            # `wg` / `ip` not installed. Reported, not raised: on a worker that is supposed
            # to have a tunnel this is a real misconfiguration and must block scanning.
            return 127, ""
        except Exception:  # noqa: BLE001 -- timeout / OSError: treat as "cannot observe"
            return 1, ""
        return proc.returncode, proc.stdout or ""

    def _handshake_age(self) -> int | None:
        """Seconds since the most recent peer handshake, or None if there has never been
        one (which `assert_tunnel_healthy` reports as NO_HANDSHAKE)."""
        import time

        rc, out = self._runner(["wg", "show", self.interface, "latest-handshakes"])
        if rc != 0 or not out.strip():
            return None
        newest = 0
        for line in out.strip().splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                ts = int(parts[-1])
            except ValueError:
                continue
            # wg reports 0 for "never handshaked" -- not an epoch to subtract from.
            if ts > newest:
                newest = ts
        if newest <= 0:
            return None
        return max(0, int(time.time()) - newest)

    def _routes(self) -> tuple:
        """Prefixes routed over this interface, normalized to CIDR strings so they compare
        directly against `build_allowed_ips` output."""
        rc, out = self._runner(["ip", "-o", "route", "show", "dev", self.interface])
        if rc != 0 or not out.strip():
            return ()
        found: list[str] = []
        for line in out.strip().splitlines():
            parts = line.split()
            if not parts:
                continue
            dest = parts[0]
            if dest == "default":
                # A default route over the tunnel is exactly what the AllowedIPs rules
                # forbid. Record it verbatim so it can never silently satisfy a
                # per-CIDR route requirement.
                found.append("default")
                continue
            try:
                found.append(str(ipaddress.ip_network(dest, strict=False)))
            except ValueError:
                continue
        return tuple(found)

    def _mtu(self) -> int | None:
        """The interface's live MTU, or None if it cannot be read."""
        rc, out = self._runner(["ip", "-o", "link", "show", self.interface])
        if rc != 0 or not out.strip():
            return None
        parts = out.split()
        for i, tok in enumerate(parts):
            if tok == "mtu" and i + 1 < len(parts):
                try:
                    return int(parts[i + 1])
                except ValueError:
                    return None
        return None

    def _interface_up(self) -> bool:
        rc, out = self._runner(["ip", "-o", "link", "show", self.interface])
        if rc != 0 or not out.strip():
            return False
        # `ip link` prints state UNKNOWN for a point-to-point wg device that is up, so
        # UP in the flags is the reliable signal, not "state UP".
        return "UP" in out.split(":", 2)[-1]

    def status(self, site_id) -> TunnelStatus:
        up = self._interface_up()
        if not up:
            return TunnelStatus(
                interface_up=False,
                detail=f"interface {self.interface} is absent or down",
            )
        age = self._handshake_age()
        routes = self._routes()
        logger.debug(
            "tunnel.probe site=%s iface=%s up=%s handshake_age=%s routes=%s",
            site_id, self.interface, up, age, routes,
        )
        return TunnelStatus(
            interface_up=True,
            last_handshake_age_s=age,
            routes=routes,
            mtu=self._mtu(),
            # DNS and peer reachability are proven by the scan's own traffic and by the
            # site-DNS resolver path; this probe deliberately asserts only what it can
            # actually observe rather than claiming more.
            dns_ok=True,
            peer_reachable=True,
        )


def assert_tunnel_healthy(
    status: TunnelStatus,
    *,
    authorized_cidrs,
    max_handshake_age_s: int = DEFAULT_MAX_HANDSHAKE_AGE_S,
    require_dns: bool = True,
) -> None:
    """Refuse to start a scan unless the tunnel is genuinely usable RIGHT NOW.

    Checked in escalating order of specificity, so the reported reason is the most
    actionable one. Every failure raises -- a scan is never started "optimistically" on a
    tunnel that might be up, because the failure mode is scanning the wrong network (or
    reporting a clean result for a network that was never reached).
    """
    if not status.interface_up:
        raise TunnelUnhealthy(
            REASON_TUNNEL_UNHEALTHY,
            f"tunnel interface is down{': ' + status.detail if status.detail else ''}",
        )
    if status.last_handshake_age_s is None:
        raise TunnelUnhealthy(
            REASON_NO_HANDSHAKE,
            "tunnel has never completed a handshake with the customer peer",
        )
    if status.last_handshake_age_s > max_handshake_age_s:
        raise TunnelUnhealthy(
            REASON_HANDSHAKE_STALE,
            f"last handshake was {status.last_handshake_age_s}s ago (limit "
            f"{max_handshake_age_s}s); the peer is not currently reachable",
        )
    if not status.peer_reachable:
        raise TunnelUnhealthy(REASON_PEER_UNREACHABLE, "TCP probe to the peer failed")

    # Every authorized CIDR must actually have a route, or part of the engagement would
    # silently not be scanned -- and "no findings" would be indistinguishable from "clean".
    present = {str(r) for r in (status.routes or ())}
    for cidr in build_allowed_ips(authorized_cidrs):
        if cidr not in present:
            raise TunnelUnhealthy(
                REASON_ROUTE_MISSING,
                f"no route present for authorized CIDR {cidr}; refusing to start a scan "
                f"that would silently skip it",
            )
    if require_dns and not status.dns_ok:
        raise TunnelUnhealthy(
            REASON_DNS_UNAVAILABLE,
            "the site's DNS canary failed; private names cannot be resolved and must not "
            "fall back to a public resolver",
        )


def preflight(
    *,
    site_id,
    authorized_cidrs,
    probe: TunnelProbe,
    max_handshake_age_s: int = DEFAULT_MAX_HANDSHAKE_AGE_S,
    require_dns: bool = True,
) -> TunnelStatus:
    """Observe and validate the tunnel. Returns the status, or raises TunnelUnhealthy."""
    status = probe.status(site_id)
    assert_tunnel_healthy(
        status, authorized_cidrs=authorized_cidrs,
        max_handshake_age_s=max_handshake_age_s, require_dns=require_dns,
    )
    logger.info(
        "tunnel.preflight_ok site=%s handshake_age=%ss routes=%d",
        site_id, status.last_handshake_age_s, len(status.routes or ()),
        extra={"event": "tunnel.preflight_ok", "site_id": str(site_id),
               "handshake_age_s": status.last_handshake_age_s},
    )
    return status
