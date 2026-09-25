"""VPN-egress worker bring-up: policy routing, kill-switch firewall, exit-IP verification.

WHAT THIS IS
------------
The networking step that turns a *configured* VPN-egress worker into one that provably
sends public scan traffic out of the provider's exit IP -- and that fails closed when it
cannot.

It is the egress-plane counterpart of `scanner_worker/tunnel_setup.py`, and it is a
SEPARATE MODULE for the same reason `scanner_engine/vpn_egress.py` is separate from
`scanner_engine/wireguard.py`: this path installs a `0.0.0.0/0` route, and the private-site
path must keep refusing one unconditionally. No shared function, no shared flag, no way for
a change here to relax the private tunnel.

THE THREE-PART ROUTING DESIGN
-----------------------------
A naive full tunnel replaces the main table's default route and immediately breaks the
worker: the manager connection on mbs-dispatch, the DNS the container needs, and the
WireGuard handshake to the provider itself all vanish into the tunnel (the last one being a
routing loop). The design here avoids all three:

  1. DEDICATED TABLE. `default dev wg-egress` is installed in table 51820 ONLY. The main
     table is never modified, so dispatch/manager/loopback traffic keeps its ordinary path.
     This is the invariant `assert_main_table_untouched` re-verifies as an independent
     observation afterwards.

  2. SUPPRESS-PREFIX RULE + DEFAULT LOOKUP. An `ip rule` sends traffic into table 51820
     unless it matched a more specific route in the main table. Link-local/on-link routes
     for the container's own bridges are more specific, so mbs-dispatch traffic never
     enters the tunnel, while the catch-all (anything only satisfiable by a default route
     -- i.e. every Internet target) does.

  3. FWMARK CARVE-OUT. WireGuard marks its OWN encrypted packets with the fwmark, and a
     higher-priority rule sends marked packets to the main table. Without this the
     tunnel's own UDP to the provider would be routed back into the tunnel: the classic
     full-tunnel routing loop.

THE KILL-SWITCH IS THE FIREWALL, NOT THIS PROCESS
--------------------------------------------------
`egress_guard` is in-process and cannot intercept nuclei/katana/ffuf sockets -- its own
docstring says so. So the fail-closed guarantee is enforced with iptables on the OUTPUT
chain: default DROP for new outbound connections, with narrow ACCEPTs for (a) the VPN
endpoint, (b) the dispatch subnet carrying the manager API, (c) loopback, (d) anything
leaving via `wg-egress`. If the tunnel drops, rule (d) stops matching and target traffic is
DROPPED by the kernel -- not "denied by a Python check that the tool never called".

This is why the rules are installed BEFORE the tunnel comes up: a worker that dies between
the two states must fail closed, never open.

SECRET HANDLING
---------------
Identical discipline to `tunnel_setup.py`: the provider private key is read from a file,
written to a 0600 temp file for the single `wg set` call, and unlinked immediately. Never
on argv (world-readable via /proc), never logged, never in an error message.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import subprocess
import tempfile
import time

from apps.api.scanner_engine import vpn_egress

logger = logging.getLogger(__name__)


class EgressSetupError(RuntimeError):
    """Egress bring-up failed. `reason` is stable; the message never carries key material."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


REASON_TOOLING_MISSING = "VPN_EGRESS_TOOLING_MISSING"
REASON_NO_PRIVATE_KEY = "VPN_EGRESS_PRIVATE_KEY_MISSING"
REASON_INTERFACE_FAILED = "VPN_EGRESS_INTERFACE_FAILED"
REASON_ROUTE_FAILED = "VPN_EGRESS_ROUTE_FAILED"
REASON_RULE_FAILED = "VPN_EGRESS_RULE_FAILED"
REASON_KILLSWITCH_FAILED = "VPN_EGRESS_KILLSWITCH_FAILED"
REASON_MAIN_TABLE_HIJACKED = "VPN_EGRESS_MAIN_TABLE_HIJACKED"

# The iptables chain the kill-switch lives in. A dedicated chain, not raw OUTPUT rules, so
# the policy can be inspected, re-applied idempotently and removed as a unit.
KILLSWITCH_CHAIN = "MBS_VPN_EGRESS"


def _run(argv, *, timeout: float = 10.0) -> tuple:
    """Run a command, returning (rc, stdout, stderr). Never raises on a non-zero exit."""
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        return 127, "", f"{argv[0]}: not found"
    except Exception as exc:  # noqa: BLE001 -- timeout / OSError
        return 1, "", str(exc)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def assert_tooling_present() -> None:
    """Fail LOUDLY at startup when `wg`/`ip`/`iptables` are absent.

    `iptables` is included and is NOT optional: without it the kill-switch cannot be
    installed, and a VPN-egress worker without a kill-switch is precisely the silent
    direct-fallback risk this feature exists to remove. A worker that cannot fail closed
    must not start.
    """
    missing = []
    for tool, probe_args in (
        ("wg", ["wg", "--version"]),
        ("ip", ["ip", "-Version"]),
        ("iptables", ["iptables", "--version"]),
    ):
        rc, _, _ = _run(probe_args, timeout=5)
        if rc == 127:
            missing.append(tool)
    if missing:
        raise EgressSetupError(
            REASON_TOOLING_MISSING,
            f"VPN-egress worker is missing required networking tool(s): "
            f"{', '.join(missing)}. The image must provide wireguard-tools (wg), iproute2 "
            f"(ip) and iptables; without them this worker can neither route target traffic "
            f"through the VPN nor fail closed when the VPN drops.",
        )


def read_private_key(path: str | None) -> str:
    """Read the VPN provider private key from its secret file.

    A FILE, never an env value, and never in `.env.scanner`: that file is shared with every
    scanner worker including tenant site workers, and the VPN provider credential is a
    PLATFORM secret. See the secret-injection contract in docker-compose.vpn-egress.yml.
    """
    if not path:
        raise EgressSetupError(
            REASON_NO_PRIVATE_KEY,
            "SCANNER_VPN_EGRESS_PRIVATE_KEY_FILE is not set; a VPN-egress worker cannot "
            "bring up its tunnel without the provider key. Mount it as a Docker/Vault "
            "secret -- never place it in the shared scanner env file.",
        )
    try:
        with open(path, encoding="utf-8") as fh:
            key = fh.read().strip()
    except OSError as exc:
        # The PATH is safe to name; the CONTENTS are not.
        raise EgressSetupError(
            REASON_NO_PRIVATE_KEY, f"cannot read the VPN egress key file at {path}: {exc}"
        ) from exc
    if not key:
        raise EgressSetupError(REASON_NO_PRIVATE_KEY, f"the key file at {path} is empty")
    return key


# ---------------------------------------------------------------------------------------
# Kill-switch firewall
# ---------------------------------------------------------------------------------------

def install_killswitch(
    config: vpn_egress.EgressConfig,
    *,
    dispatch_cidrs=(),
    endpoint_ip: str | None = None,
) -> None:
    """Install the deny-by-default OUTPUT policy. Idempotent.

    ORDER IS THE SECURITY PROPERTY. This is called BEFORE the tunnel is brought up, so the
    window between "process started" and "tunnel healthy" is CLOSED rather than open. A
    worker that crashes in between leaks nothing.

    The permitted set is deliberately tiny:
      * loopback                      -- in-process and probe traffic
      * the VPN endpoint (UDP)        -- the tunnel itself must be able to reach the peer
      * the dispatch CIDRs            -- the manager API, and nothing else on that plane
      * anything out `wg-egress`      -- i.e. all target traffic, but ONLY via the tunnel
      * established/related           -- return traffic for the above
    Everything else is DROPPED by the kernel, including every scanner tool binary's own
    sockets, which no in-process check could ever intercept.
    """
    iface = config.interface

    # Fresh chain each time: flush-or-create makes this idempotent across restarts without
    # ever leaving a half-applied policy visible.
    rc, _, err = _run(["iptables", "-N", KILLSWITCH_CHAIN])
    if rc != 0 and "exists" not in (err or "").lower():
        raise EgressSetupError(
            REASON_KILLSWITCH_FAILED,
            f"could not create the {KILLSWITCH_CHAIN} chain: {err.strip()}. The worker "
            f"cannot fail closed without it and must not start.",
        )
    rc, _, err = _run(["iptables", "-F", KILLSWITCH_CHAIN])
    if rc != 0:
        raise EgressSetupError(
            REASON_KILLSWITCH_FAILED,
            f"could not flush the {KILLSWITCH_CHAIN} chain: {err.strip()}",
        )

    rules: list[list[str]] = [
        # Return traffic for connections the rules below already permitted.
        ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ["-o", "lo", "-j", "ACCEPT"],
        # TARGET TRAFFIC -- permitted ONLY when it is leaving via the tunnel. This single
        # rule is the fail-closed mechanism: if wg-egress goes away, it stops matching and
        # target traffic hits the DROP below.
        ["-o", iface, "-j", "ACCEPT"],
    ]

    # The VPN endpoint itself. Without this the tunnel could never establish -- and it is
    # restricted to the one address/port, not "all UDP".
    if endpoint_ip and config.endpoint:
        try:
            port = int(str(config.endpoint).rsplit(":", 1)[1])
        except (IndexError, ValueError):
            port = 51820
        rules.append(
            ["-p", "udp", "-d", f"{endpoint_ip}/32", "--dport", str(port), "-j", "ACCEPT"]
        )

    # The manager/dispatch plane. Narrow CIDRs, supplied by configuration -- never a blanket
    # RFC1918 allowance, which would re-open exactly the private-range reachability the
    # egress worker must not have.
    for cidr in dispatch_cidrs or ():
        entry = str(cidr).strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            raise EgressSetupError(
                REASON_KILLSWITCH_FAILED,
                f"invalid dispatch CIDR {entry!r} for the egress kill-switch",
            ) from None
        if net.prefixlen == 0:
            # A /0 here would accept everything and silently defeat the whole policy.
            raise EgressSetupError(
                REASON_KILLSWITCH_FAILED,
                f"refusing a default route ({entry}) as a kill-switch dispatch exception: "
                f"it would permit ALL direct egress and defeat the kill-switch entirely.",
            )
        rules.append(["-d", str(net), "-j", "ACCEPT"])

    # DNS to the container's configured resolvers is NOT special-cased here. Resolution for
    # targets must traverse the tunnel like everything else, which is what stops a DNS leak
    # revealing the platform's address to the target's authoritative server.

    # THE DEFAULT: drop. Last rule in the chain, so every ACCEPT above is an explicit,
    # reviewable exception to a deny-by-default policy.
    rules.append(["-j", "DROP"])

    for rule in rules:
        rc, _, err = _run(["iptables", "-A", KILLSWITCH_CHAIN, *rule])
        if rc != 0:
            raise EgressSetupError(
                REASON_KILLSWITCH_FAILED,
                f"could not install kill-switch rule {' '.join(rule)}: {err.strip()}",
            )

    # Hook the chain into OUTPUT exactly once. `-C` tests for an existing jump first so a
    # restart does not stack duplicate jumps.
    rc, _, _ = _run(["iptables", "-C", "OUTPUT", "-j", KILLSWITCH_CHAIN])
    if rc != 0:
        rc, _, err = _run(["iptables", "-A", "OUTPUT", "-j", KILLSWITCH_CHAIN])
        if rc != 0:
            raise EgressSetupError(
                REASON_KILLSWITCH_FAILED,
                f"could not attach {KILLSWITCH_CHAIN} to OUTPUT: {err.strip()}",
            )

    logger.info(
        "vpn_egress.killswitch_installed chain=%s iface=%s rules=%d",
        KILLSWITCH_CHAIN, iface, len(rules),
        extra={"event": "vpn_egress.killswitch_installed"},
    )


def killswitch_active(*, chain: str = KILLSWITCH_CHAIN) -> bool:
    """Is the kill-switch chain present, hooked into OUTPUT, and ending in DROP?

    All three are checked because any one of them missing means traffic is NOT failing
    closed: an unhooked chain is inert, and a chain without its terminal DROP permits
    everything it did not explicitly match.
    """
    rc, _, _ = _run(["iptables", "-C", "OUTPUT", "-j", chain])
    if rc != 0:
        return False
    rc, out, _ = _run(["iptables", "-S", chain])
    if rc != 0 or not out.strip():
        return False
    lines = [ln.strip() for ln in out.strip().splitlines() if ln.strip()]
    return any(ln.endswith("-j DROP") for ln in lines)


# ---------------------------------------------------------------------------------------
# Tunnel + policy routing
# ---------------------------------------------------------------------------------------

def resolve_endpoint_ip(config: vpn_egress.EgressConfig) -> str | None:
    """Resolve the endpoint host to an address, and re-check it is genuinely external.

    The config-time check in `vpn_egress.assert_not_platform_address` can only inspect a
    literal. A HOSTNAME endpoint is checked HERE, against what it actually resolved to --
    which is the value the kill-switch is about to punch a hole for.
    """
    if not config.endpoint:
        return None
    host = str(config.endpoint).rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(host)
        resolved = host
    except ValueError:
        import socket

        try:
            resolved = socket.gethostbyname(host)
        except OSError as exc:
            raise EgressSetupError(
                REASON_INTERFACE_FAILED,
                f"could not resolve the VPN endpoint host {host!r}: {exc}",
            ) from exc
    try:
        vpn_egress.assert_not_platform_address(
            resolved, what="the resolved VPN egress endpoint"
        )
    except vpn_egress.VpnEgressConfigError as exc:
        raise EgressSetupError(REASON_INTERFACE_FAILED, str(exc)) from exc
    return resolved


def bring_up(config: vpn_egress.EgressConfig, *, private_key: str) -> None:
    """Create the interface and apply the provider peer. Idempotent across restarts."""
    iface = config.interface

    rc, _, err = _run(["ip", "link", "add", "dev", iface, "type", "wireguard"])
    if rc != 0 and "exists" not in err.lower():
        raise EgressSetupError(
            REASON_INTERFACE_FAILED,
            f"could not create {iface}: {err.strip() or 'unknown error'}. A VPN-egress "
            f"worker needs CAP_NET_ADMIN and a host kernel with WireGuard support.",
        )

    # Peer config. The key reaches a 0600 temp file for one call, then is unlinked.
    fd, key_path = tempfile.mkstemp(
        prefix="wg-egress-",
        dir="/run/wireguard" if os.path.isdir("/run/wireguard") else None,
    )
    try:
        _fchmod = getattr(os, "fchmod", None)
        if _fchmod is not None:
            _fchmod(fd, 0o600)
        else:  # pragma: no cover - Windows dev/CI only
            os.chmod(key_path, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(private_key)
        argv = [
            "wg", "set", iface,
            "private-key", key_path,
            # The fwmark WireGuard stamps on its OWN encrypted packets, so the rule
            # installed below can route them via the main table instead of back into the
            # tunnel. Without this the tunnel routes its own transport and never connects.
            "fwmark", str(config.fwmark),
            "peer", config.peer_public_key,
            "allowed-ips", ",".join(config.allowed_ips),
        ]
        if config.endpoint:
            argv += ["endpoint", config.endpoint]
        if config.persistent_keepalive:
            argv += ["persistent-keepalive", str(int(config.persistent_keepalive))]
        rc, _, err = _run(argv)
    finally:
        try:
            os.unlink(key_path)
        except OSError:
            pass
    if rc != 0:
        raise EgressSetupError(
            REASON_INTERFACE_FAILED,
            f"could not apply the VPN peer configuration to {iface}: {err.strip()}",
        )

    if config.interface_address:
        rc, _, err = _run(["ip", "addr", "add", config.interface_address, "dev", iface])
        if rc != 0 and "exists" not in err.lower():
            raise EgressSetupError(
                REASON_INTERFACE_FAILED,
                f"could not assign {config.interface_address} to {iface}: {err.strip()}",
            )
    if config.mtu:
        rc, _, err = _run(["ip", "link", "set", "dev", iface, "mtu", str(int(config.mtu))])
        if rc != 0:
            raise EgressSetupError(
                REASON_INTERFACE_FAILED,
                f"could not set MTU {config.mtu} on {iface}: {err.strip()}",
            )
    rc, _, err = _run(["ip", "link", "set", iface, "up"])
    if rc != 0:
        raise EgressSetupError(
            REASON_INTERFACE_FAILED, f"could not bring {iface} up: {err.strip()}"
        )


def install_policy_routing(config: vpn_egress.EgressConfig) -> None:
    """Install the default route in the DEDICATED table, plus the two `ip rule`s.

    The main routing table is NEVER touched here. That is the single most important
    property of this function, and `assert_main_table_untouched` verifies it afterwards as
    an independent observation rather than trusting that we only did what we intended.
    """
    iface = config.interface
    table = str(int(config.table))

    # 1. The full-tunnel default route -- in table 51820 ONLY.
    rc, _, err = _run(
        ["ip", "route", "replace", "default", "dev", iface, "table", table]
    )
    if rc != 0:
        raise EgressSetupError(
            REASON_ROUTE_FAILED,
            f"could not install the egress default route in table {table}: {err.strip()}",
        )

    # 2. FWMARK CARVE-OUT, at the HIGHER priority (lower number = evaluated first).
    #    WireGuard's own encrypted packets carry this mark; they must use the MAIN table or
    #    the tunnel's transport is routed into the tunnel -- an unresolvable loop.
    mark_rule = [
        "not", "from", "all", "fwmark", hex(int(config.fwmark)), "lookup", "main",
    ]
    rc, _, _ = _run(["ip", "rule", "add", "priority", "9000", *mark_rule])
    # Exit 2 = "rule already exists" on iproute2; re-running must not be an error.
    if rc not in (0, 2):
        # Fall back to explicitly checking rather than trusting the exit code alone.
        if not _rule_exists(hex(int(config.fwmark))):
            raise EgressSetupError(
                REASON_RULE_FAILED,
                "could not install the fwmark carve-out rule; without it the tunnel's own "
                "transport would be routed into the tunnel.",
            )

    # 3. SUPPRESS-PREFIX. Anything satisfied by a MORE SPECIFIC route in the main table
    #    (on-link bridges: mbs-dispatch, the egress bridge, loopback) keeps its ordinary
    #    path. Only traffic that would need a DEFAULT route -- i.e. every Internet target --
    #    falls through to the tunnel table.
    rc, _, _ = _run(
        ["ip", "rule", "add", "priority", "9100", "from", "all",
         "lookup", "main", "suppress_prefixlength", "0"]
    )
    if rc not in (0, 2):
        raise EgressSetupError(
            REASON_RULE_FAILED,
            "could not install the suppress_prefixlength rule that keeps dispatch traffic "
            "on the main table",
        )

    # 4. The catch-all into the tunnel table, at the LOWEST priority of the three.
    rc, _, _ = _run(
        ["ip", "rule", "add", "priority", "9200", "from", "all", "lookup", table]
    )
    if rc not in (0, 2):
        raise EgressSetupError(
            REASON_RULE_FAILED,
            f"could not install the policy rule directing traffic to table {table}",
        )

    logger.info(
        "vpn_egress.routing_installed iface=%s table=%s fwmark=%s",
        iface, table, hex(int(config.fwmark)),
        extra={"event": "vpn_egress.routing_installed"},
    )


def _rule_exists(needle: str) -> bool:
    rc, out, _ = _run(["ip", "rule", "show"])
    return rc == 0 and needle in (out or "")


def assert_main_table_untouched(config: vpn_egress.EgressConfig) -> None:
    """Refuse if the MAIN table's default route now points at the VPN tunnel.

    Checked as an independent observation after bring-up, not inferred from what we
    installed: a route can be inherited from a restarted container, an image's own
    configuration, or an operator's manual `ip route add`. If the main default were the
    tunnel, the manager connection and every control-plane call would be inside the VPN --
    which this feature explicitly promises not to do.
    """
    rc, out, _ = _run(["ip", "-o", "route", "show", "default", "table", "main"])
    if rc != 0:
        return  # cannot observe; the probe's own check is the backstop
    for line in (out or "").splitlines():
        if f"dev {config.interface}" in line:
            raise EgressSetupError(
                REASON_MAIN_TABLE_HIJACKED,
                f"the MAIN routing table's default route points at {config.interface} "
                f"({line.strip()}); control-plane and manager traffic would traverse the "
                f"VPN. Refusing to start.",
            )


# ---------------------------------------------------------------------------------------
# Exit-IP verification
# ---------------------------------------------------------------------------------------

def observe_exit_ip(
    *, url: str, timeout: float = 10.0, interface: str | None = None
) -> str | None:
    """Observe the address this worker presents to the Internet, or None.

    Returns None on ANY failure rather than raising, because the caller
    (`assert_egress_healthy`) already treats an unknown exit IP as a REFUSAL. Collapsing
    "could not check" into "unknown" keeps there being exactly one place that decides what
    an unverifiable exit IP means -- and that place fails closed.

    The request necessarily goes out through whatever path the routing produces, which is
    precisely what makes it evidence: if the answer is the VPN's address, target traffic is
    on the VPN, because it took the same route.
    """
    if not url:
        return None
    try:
        import httpx

        # `trust_env=False`: an HTTP(S)_PROXY inherited from the environment would route
        # this check through a proxy, and the answer would then describe the PROXY's
        # egress rather than this worker's. The check must observe the real path.
        with httpx.Client(timeout=timeout, trust_env=False) as client:
            resp = client.get(url)
            resp.raise_for_status()
            body = (resp.text or "").strip()
    except Exception as exc:  # noqa: BLE001 -- any failure is "unknown", which fails closed
        logger.warning(
            "vpn_egress.exit_ip_unobservable url=%s error=%s", url, type(exc).__name__,
            extra={"event": "vpn_egress.exit_ip_unobservable"},
        )
        return None

    candidate = body.split()[0].strip() if body else ""
    # Accept a bare address or a tiny JSON object; anything else is treated as unknown.
    if candidate.startswith("{"):
        try:
            import json

            data = json.loads(body)
            candidate = str(data.get("ip") or data.get("origin") or "").strip()
        except Exception:  # noqa: BLE001
            return None
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate


class SystemEgressProbe(vpn_egress.EgressProbe):
    """Observes the REAL egress path inside this worker's own namespace.

    Every failure path returns an UNHEALTHY field rather than raising or guessing -- the
    same discipline as `wireguard.SystemTunnelProbe`, and for the same reason: a probe that
    cannot see the path must never be mistaken for one that saw a healthy path.

    The exit IP is CACHED for `exit_ip_ttl_s` because it costs an HTTPS request, but the
    cache is reported with its age so `assert_egress_healthy` can refuse a stale
    observation. A cache that could hide staleness would defeat the check it serves.
    """

    def __init__(
        self,
        config: vpn_egress.EgressConfig,
        *,
        exit_ip_url: str = "",
        exit_ip_ttl_s: int = 60,
        timeout_s: float = 5.0,
        runner=None,
        exit_ip_observer=None,
        clock=None,
    ) -> None:
        self.config = config
        self.exit_ip_url = exit_ip_url
        self.exit_ip_ttl_s = int(exit_ip_ttl_s)
        self.timeout_s = timeout_s
        self._runner = runner or (lambda argv: _run(argv, timeout=self.timeout_s)[:2])
        self._observe = exit_ip_observer or (
            lambda: observe_exit_ip(url=self.exit_ip_url, timeout=self.timeout_s)
        )
        self._clock = clock or time.time
        self._cached_exit_ip: str | None = None
        self._cached_at: float | None = None

    # -- individual observations --------------------------------------------------------

    def _interface_up(self) -> bool:
        rc, out = self._runner(["ip", "-o", "link", "show", self.config.interface])
        if rc != 0 or not out.strip():
            return False
        return "UP" in out.split(":", 2)[-1]

    def _handshake_age(self) -> int | None:
        rc, out = self._runner(
            ["wg", "show", self.config.interface, "latest-handshakes"]
        )
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
            if ts > newest:
                newest = ts
        if newest <= 0:
            return None
        return max(0, int(self._clock()) - newest)

    def _default_route_in_table(self) -> bool:
        rc, out = self._runner(
            ["ip", "-o", "route", "show", "default", "table", str(int(self.config.table))]
        )
        if rc != 0 or not out.strip():
            return False
        return f"dev {self.config.interface}" in out

    def _policy_rule_present(self) -> bool:
        rc, out = self._runner(["ip", "rule", "show"])
        if rc != 0 or not out.strip():
            return False
        return f"lookup {int(self.config.table)}" in out

    def _main_table_untouched(self) -> bool:
        """True (the CORRECT state) when main's default is NOT the tunnel.

        An unreadable table returns False -- unknown is not "fine".
        """
        rc, out = self._runner(["ip", "-o", "route", "show", "default", "table", "main"])
        if rc != 0:
            return False
        return f"dev {self.config.interface}" not in (out or "")

    def _mtu(self) -> int | None:
        rc, out = self._runner(["ip", "-o", "link", "show", self.config.interface])
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

    def _exit_ip(self) -> tuple:
        """(address, age_seconds). A failed observation INVALIDATES the cache.

        Returning a stale-but-successful reading after a failure is exactly how a dropped
        tunnel would keep looking healthy, so a failure clears it instead.
        """
        now = self._clock()
        if (
            self._cached_exit_ip
            and self._cached_at is not None
            and (now - self._cached_at) < self.exit_ip_ttl_s
        ):
            return self._cached_exit_ip, int(now - self._cached_at)
        observed = self._observe()
        if not observed:
            self._cached_exit_ip = None
            self._cached_at = None
            return None, None
        self._cached_exit_ip = observed
        self._cached_at = now
        return observed, 0

    def invalidate_exit_ip(self) -> None:
        """Force the next observation to be fresh. Used by the mid-scan re-check."""
        self._cached_exit_ip = None
        self._cached_at = None

    def status(self) -> vpn_egress.EgressStatus:
        up = self._interface_up()
        if not up:
            return vpn_egress.EgressStatus(
                interface_up=False,
                killswitch_active=killswitch_active(),
                detail=f"interface {self.config.interface} is absent or down",
            )
        exit_ip, exit_age = self._exit_ip()
        return vpn_egress.EgressStatus(
            interface_up=True,
            last_handshake_age_s=self._handshake_age(),
            default_route_in_table=self._default_route_in_table(),
            policy_rule_present=self._policy_rule_present(),
            main_table_untouched=self._main_table_untouched(),
            observed_exit_ip=exit_ip,
            exit_ip_age_s=exit_age,
            killswitch_active=killswitch_active(),
            mtu=self._mtu(),
        )


def setup_and_verify(
    config: vpn_egress.EgressConfig,
    *,
    private_key: str,
    dispatch_cidrs=(),
    exit_ip_url: str = "",
    forbidden_exit_ips=(),
    max_handshake_age_s: int = vpn_egress.DEFAULT_MAX_HANDSHAKE_AGE_S,
    probe=None,
) -> vpn_egress.EgressStatus:
    """The full startup sequence. Returns the verified status, or raises.

    ORDER IS LOAD-BEARING:
        tooling -> KILL-SWITCH -> tunnel -> policy routing -> main-table check -> preflight

    The kill-switch goes in SECOND, before the tunnel exists, so there is never a moment
    when this worker can reach a target directly. Everything after it is a refusal to start
    rather than a warning -- a VPN-egress worker that cannot prove its egress path would
    otherwise come up and either leak or reject every job.
    """
    assert_tooling_present()
    endpoint_ip = resolve_endpoint_ip(config)

    # FAIL CLOSED FIRST.
    install_killswitch(config, dispatch_cidrs=dispatch_cidrs, endpoint_ip=endpoint_ip)

    logger.info(
        "vpn_egress.setup iface=%s endpoint=%s table=%s address=%s",
        config.interface, config.endpoint, config.table, config.interface_address,
        extra={"event": "vpn_egress.setup"},
    )
    bring_up(config, private_key=private_key)
    install_policy_routing(config)
    assert_main_table_untouched(config)

    probe = probe or SystemEgressProbe(config, exit_ip_url=exit_ip_url)
    # The SAME preflight the lease loop runs per job, so a worker that would refuse every
    # job refuses to START -- a far clearer failure than a stream of runtime refusals.
    return vpn_egress.preflight(
        probe=probe,
        expected_exit_ip=config.expected_exit_ip,
        forbidden_exit_ips=forbidden_exit_ips,
        max_handshake_age_s=max_handshake_age_s,
    )
