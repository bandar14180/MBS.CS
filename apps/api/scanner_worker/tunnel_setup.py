"""Private-worker tunnel bring-up -- the production entrypoint's networking step.

WHAT THIS IS
------------
The smallest thing that turns a *configured* private worker into a *working* one: create
`wg0`, apply the peer configuration, install exactly the site's authorized routes, verify
the tunnel is healthy, and refuse to continue if any of that fails.

WHAT IT DELIBERATELY IS NOT
---------------------------
It is NOT a second WireGuard configuration generator. The config text comes from
`scanner_engine.wireguard.render_worker_config`, and the health verdict comes from
`SystemTunnelProbe` + `preflight` -- the same code the lab E2E exercised. This module only
*applies* what those produce, so there is exactly one place where AllowedIPs, `Table = off`
and the no-default-route rule are decided.

WHY NOT wg-quick
----------------
`wg-quick up` would do most of this in one command, and is the wrong tool here twice over:

  * its `DNS=` handling rewrites the whole namespace's `/etc/resolv.conf`, which would send
    PUBLIC lookups and the manager's own hostname to the customer's resolver. Site DNS is
    applied per-lookup instead (`scanner_engine/site_dns.py`).
  * it installs routes automatically from AllowedIPs, including a default route for a
    `0.0.0.0/0` peer. `Table = off` exists precisely to stop that, so routes are installed
    here, explicitly, one authorized CIDR at a time.

SECRET HANDLING
---------------
The private key is read from a file (Docker secret / Vault-templated), written to a
0600 temp file inside the container only for the duration of the `wg set` call, and removed
immediately. It is never logged, never echoed into an error, never passed on a command line
(argv is world-readable via /proc), and never persisted anywhere the control plane can read.
`describe_config()` -- the key-free view -- is what gets logged.
"""
from __future__ import annotations

import logging
import os
import subprocess
import tempfile

from apps.api.scanner_engine import wireguard

logger = logging.getLogger(__name__)


class TunnelSetupError(RuntimeError):
    """Tunnel bring-up failed. `reason` is a stable code; the message never carries key
    material."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


REASON_TOOLING_MISSING = "WG_TOOLING_MISSING"
REASON_NO_CONFIG = "WG_CONFIG_MISSING"
REASON_NO_PRIVATE_KEY = "WG_PRIVATE_KEY_MISSING"
REASON_INTERFACE_FAILED = "WG_INTERFACE_SETUP_FAILED"
REASON_ROUTE_FAILED = "WG_ROUTE_SETUP_FAILED"
REASON_DEFAULT_ROUTE = "WG_DEFAULT_ROUTE_REFUSED"
REASON_MTU_FAILED = "WG_MTU_SETUP_FAILED"


def _run(argv, *, timeout: float = 10.0) -> tuple:
    """Run a command, returning (rc, stdout, stderr). Never raises for a non-zero exit."""
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        return 127, "", f"{argv[0]}: not found"
    except Exception as exc:  # noqa: BLE001 -- timeout/OSError
        return 1, "", str(exc)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def assert_tooling_present() -> None:
    """Fail LOUDLY at startup when `wg`/`ip` are absent.

    Without this the worker would come up looking healthy, then refuse every private scan
    with TUNNEL_UNHEALTHY -- a real deployment defect reported as a runtime symptom, which
    is exactly the confusing failure this check exists to prevent.
    """
    missing = []
    for tool, probe_args in (("wg", ["wg", "--version"]), ("ip", ["ip", "-Version"])):
        rc, _, _ = _run(probe_args, timeout=5)
        if rc == 127:
            missing.append(tool)
    if missing:
        raise TunnelSetupError(
            REASON_TOOLING_MISSING,
            f"private worker is missing required networking tool(s): {', '.join(missing)}. "
            f"The image must provide wireguard-tools (wg) and iproute2 (ip); without them "
            f"this worker can never bring up a tunnel and every private scan would be "
            f"refused.",
        )


def read_private_key(path: str | None) -> str:
    """Read the worker's WireGuard private key from its secret file.

    A file, not an environment variable: env vars appear in `docker inspect`, in crash
    dumps, and in any child process's environment. The value is returned to the caller and
    must not be logged -- callers pass it straight to `render_worker_config`.
    """
    if not path:
        raise TunnelSetupError(
            REASON_NO_PRIVATE_KEY,
            "SCANNER_WIREGUARD_PRIVATE_KEY_FILE is not set; a private worker cannot bring "
            "up its tunnel without its own key. Generate the key INSIDE this container "
            "(`wg genkey`) and mount it as a secret -- never accept one from the control "
            "plane.",
        )
    try:
        with open(path, encoding="utf-8") as fh:
            key = fh.read().strip()
    except OSError as exc:
        # The path is safe to name; the contents are not.
        raise TunnelSetupError(
            REASON_NO_PRIVATE_KEY, f"cannot read the WireGuard private key file at {path}: {exc}"
        ) from exc
    if not key:
        raise TunnelSetupError(REASON_NO_PRIVATE_KEY, f"the key file at {path} is empty")
    return key


def bring_up(
    config: wireguard.TunnelConfig, *, private_key: str, interface: str = "wg0",
    mtu: int | None = None,
) -> None:
    """Create the interface, apply the peer, and install ONLY the authorized routes.

    Idempotent enough to survive a container restart: an interface that already exists is
    reconfigured rather than treated as an error.
    """
    if config.has_default_route:
        # Belt and braces: `build_allowed_ips` already refuses a default route, so reaching
        # here would mean a caller built a TunnelConfig some other way.
        raise TunnelSetupError(
            REASON_DEFAULT_ROUTE,
            "refusing to bring up a tunnel whose AllowedIPs contain a default route: it "
            "would capture ALL worker egress into one customer's network.",
        )

    # 1. Interface. `ip link add` fails if it already exists -- that is fine, we then just
    #    reconfigure it.
    rc, _, err = _run(["ip", "link", "add", "dev", interface, "type", "wireguard"])
    if rc != 0 and "exists" not in err.lower():
        raise TunnelSetupError(
            REASON_INTERFACE_FAILED,
            f"could not create {interface}: {err.strip() or 'unknown error'}. A private "
            f"worker needs CAP_NET_ADMIN and a host kernel with WireGuard support.",
        )

    # 2. Peer configuration. The private key goes to a 0600 temp file for the duration of
    #    this one call and is removed immediately -- never on argv, never in a log.
    fd, key_path = tempfile.mkstemp(prefix="wg-", dir="/run/wireguard"
                                    if os.path.isdir("/run/wireguard") else None)
    try:
        # 0600 before anything is written. `os.fchmod` is POSIX-only -- it does not exist
        # on Windows, where this module never runs in production but IS imported by the
        # test suite and type-checked. `getattr` keeps both the runtime and mypy happy
        # without an ignore comment; `os.chmod` on the path is the equivalent fallback, and
        # mkstemp has already created the file with restrictive permissions either way.
        _fchmod = getattr(os, "fchmod", None)
        if _fchmod is not None:
            _fchmod(fd, 0o600)
        else:  # pragma: no cover - Windows dev/CI only
            os.chmod(key_path, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(private_key)
        argv = ["wg", "set", interface, "private-key", key_path]
        if config.peer_public_key:
            argv += ["peer", config.peer_public_key,
                     "allowed-ips", ",".join(config.allowed_ips)]
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
        # `err` here is wg's own message; it does not echo the key (wg reads it from the
        # file we just deleted).
        raise TunnelSetupError(
            REASON_INTERFACE_FAILED,
            f"could not apply the peer configuration to {interface}: {err.strip()}",
        )

    # 3. Address + up.
    if config.interface_address:
        rc, _, err = _run(["ip", "addr", "add", config.interface_address, "dev", interface])
        if rc != 0 and "exists" not in err.lower() and "File exists" not in err:
            raise TunnelSetupError(
                REASON_INTERFACE_FAILED,
                f"could not assign {config.interface_address} to {interface}: {err.strip()}",
            )
    # PHASE 8 -- MTU, set EXPLICITLY before the link comes up.
    #
    # WireGuard would otherwise pick its own default (1420) silently, which is right for a
    # plain 1500-byte path and wrong for a site behind PPPoE or a nested tunnel -- where the
    # symptom is not an error but large packets vanishing, so a scan reports "no response"
    # from a host that is actually up. Setting it from configuration makes the value
    # auditable and correctable per site.
    #
    # This is a REACHABILITY control, not an isolation one: an oversized packet is dropped
    # or fragmented, never re-routed, so a wrong MTU cannot move traffic outside the
    # authorized CIDR. A failure to set it is therefore reported and fatal-at-startup rather
    # than silently ignored, but it does not weaken confinement either way.
    if mtu:
        rc, _, err = _run(["ip", "link", "set", "dev", interface, "mtu", str(int(mtu))])
        if rc != 0:
            raise TunnelSetupError(
                REASON_MTU_FAILED,
                f"could not set MTU {mtu} on {interface}: {err.strip()}. Leaving the MTU "
                f"unset risks silently black-holing large packets on a reduced-MTU path.",
            )

    rc, _, err = _run(["ip", "link", "set", interface, "up"])
    if rc != 0:
        raise TunnelSetupError(
            REASON_INTERFACE_FAILED, f"could not bring {interface} up: {err.strip()}"
        )

    # 4. Routes -- EXACTLY the authorized CIDRs, one at a time, and nothing else. This is
    #    what `Table = off` delegates to us, and it is the reason a default route can never
    #    appear by accident: we never ask for one.
    for cidr in config.allowed_ips:
        if str(cidr) in ("0.0.0.0/0", "::/0") or str(cidr).endswith("/0"):
            raise TunnelSetupError(
                REASON_DEFAULT_ROUTE, f"refusing to install a default route ({cidr})"
            )
        rc, _, err = _run(["ip", "route", "replace", str(cidr), "dev", interface])
        if rc != 0:
            raise TunnelSetupError(
                REASON_ROUTE_FAILED,
                f"could not install the authorized route {cidr} on {interface}: "
                f"{err.strip()}",
            )

    logger.info(
        "tunnel.up interface=%s site=%s routes=%d",
        interface, config.site_id, len(config.allowed_ips),
        extra={"event": "tunnel.up", "site_id": str(config.site_id),
               "interface": interface},
    )


def assert_no_default_route(interface: str = "wg0") -> None:
    """Refuse to proceed if a default route points at the tunnel.

    Checked AFTER bring-up as an independent observation rather than trusting that we only
    installed what we intended: a route could be inherited from a restarted container, an
    image's own configuration, or an operator's manual `ip route add`.
    """
    rc, out, _ = _run(["ip", "-o", "route", "show", "default"])
    if rc != 0:
        return  # cannot observe; the probe's route check is the backstop
    for line in (out or "").splitlines():
        if f"dev {interface}" in line:
            raise TunnelSetupError(
                REASON_DEFAULT_ROUTE,
                f"a default route is present on {interface} ({line.strip()}); refusing to "
                f"start. All worker egress -- including other tenants' traffic and the "
                f"manager connection -- would be routed into this customer's network.",
            )


def setup_and_verify(
    config: wireguard.TunnelConfig,
    *,
    private_key: str,
    interface: str = "wg0",
    max_handshake_age_s: int = wireguard.DEFAULT_MAX_HANDSHAKE_AGE_S,
    mtu: int | None = None,
    probe=None,
) -> wireguard.TunnelStatus:
    """The full startup sequence. Returns the verified status, or raises.

    Order matters: tooling -> bring-up -> no-default-route -> live preflight. Each step is
    a precondition for the next being meaningful, and every failure is a refusal to start
    rather than a warning.
    """
    assert_tooling_present()
    logger.info(
        "tunnel.setup site=%s %s",
        config.site_id,
        # The key-free description: safe to log, and the only view that ever is.
        f"allowed_ips={list(config.allowed_ips)} endpoint={config.endpoint} "
        f"address={config.interface_address}",
        extra={"event": "tunnel.setup", "site_id": str(config.site_id)},
    )
    bring_up(config, private_key=private_key, interface=interface, mtu=mtu)
    assert_no_default_route(interface)

    probe = probe or wireguard.SystemTunnelProbe(interface)
    # The SAME preflight the lease loop runs per job -- so a worker that would refuse every
    # scan refuses to start instead, which is a far clearer failure.
    return wireguard.preflight(
        site_id=config.site_id,
        authorized_cidrs=list(config.allowed_ips),
        probe=probe,
        max_handshake_age_s=max_handshake_age_s,
    )
