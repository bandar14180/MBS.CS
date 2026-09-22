"""Scanner execution-plane entrypoint.

    python -m apps.api.scanner_worker.main

Replaces `celery worker -Q scans...` on the ISOLATED execution plane. Celery remains the
control plane's mechanism (scheduling, orphan recovery, DLQ, retention, backups, reports)
and is untouched -- this entrypoint exists because a Celery worker must reach Redis, and
the execution plane deliberately cannot.

Startup order matters and is deliberate:

  1. `enforce_execution_plane_credentials()` -- refuse to start at all if a control-plane
     credential is present. Checked FIRST, before anything else can use one.
  2. Identity from configuration -- worker_id / pool_id / site_id / manager URL / token.
     Incomplete identity is fatal: a worker that cannot say who it is cannot be authorized,
     and guessing would be exactly the wrong failure mode.
  3. Tunnel probe, for a private worker only.
  4. PRIVATE WORKERS ONLY: bring the tunnel up and verify it (see _prepare_private_tunnel).
     A private worker that cannot prove a healthy tunnel refuses to start rather than
     coming up and rejecting every job it is offered.
  5. Lease loop.
"""
from __future__ import annotations

import asyncio
import logging
import sys

from apps.api.celery_app.startup_security import (
    ExecutionPlaneCredentialError,
    enforce_execution_plane_credentials,
)
from apps.api.core.config import configure_networking, get_settings
from apps.api.scanner_engine import result_sink
from apps.api.scanner_worker.executor import ManagerResultReporter, build_executor
from apps.api.scanner_worker.lease_loop import (
    REASON_AUTH_FAILED,
    BackoffPolicy,
    LeaseLoop,
    ManagerClient,
    WorkerIdentity,
)

logger = logging.getLogger(__name__)


def _build_tunnel_probe(identity: WorkerIdentity):
    """The tunnel probe for a private worker, or None for a public one.

    Returning None for a PUBLIC worker is correct: it has no tunnel, and
    `preflight_private_job` only consults a probe for a private job.

    A private worker gets a SystemTunnelProbe, which reads `wg show` / `ip route` inside
    this container's own network namespace. That probe is itself fail-closed: a missing
    binary, a down interface or an unreadable handshake all yield an unhealthy status,
    which `preflight_private_job` turns into a refusal. So a misconfigured private worker
    blocks scanning rather than scanning blind.
    """
    if not identity.is_private:
        return None
    from apps.api.scanner_engine.wireguard import SystemTunnelProbe

    interface = (get_settings().scanner_wireguard_interface or "wg0").strip()
    logger.info(
        "scanner_worker.tunnel_probe site=%s interface=%s",
        identity.site_id, interface,
        extra={"event": "scanner_worker.tunnel_probe", "site_id": identity.site_id},
    )
    return SystemTunnelProbe(interface)


def _build_egress_config(settings=None):
    """The (key-free) VPN egress configuration from settings, or raise VpnEgressConfigError."""
    from apps.api.scanner_engine import vpn_egress

    s = settings or get_settings()
    return vpn_egress.describe_config(
        interface=s.scanner_vpn_egress_interface,
        interface_address=s.scanner_vpn_egress_address,
        peer_public_key=s.scanner_vpn_egress_peer_public_key,
        endpoint_host=s.scanner_vpn_egress_endpoint_host,
        endpoint_port=s.scanner_vpn_egress_endpoint_port,
        table=s.scanner_vpn_egress_table,
        fwmark=s.scanner_vpn_egress_fwmark,
        mtu=s.scanner_vpn_egress_mtu,
        expected_exit_ip=(s.scanner_vpn_egress_expected_exit_ip or None),
    )


def _build_egress_probe(identity: WorkerIdentity):
    """The VPN egress probe for a vpn-mode worker, or None for a direct one.

    None for a DIRECT worker is correct and is not a weakening: `preflight_egress_job`
    only consults a probe when the worker is in vpn mode, and a direct worker has no VPN
    path to verify. On a VPN worker, by contrast, a None probe is a REFUSAL -- which is
    why a configuration failure here raises rather than quietly returning None.
    """
    if not identity.is_vpn_egress:
        return None
    from apps.api.scanner_worker.egress_setup import SystemEgressProbe

    settings = get_settings()
    config = _build_egress_config(settings)
    logger.info(
        "scanner_worker.egress_probe interface=%s table=%s",
        config.interface, config.table,
        extra={"event": "scanner_worker.egress_probe"},
    )
    return SystemEgressProbe(
        config,
        exit_ip_url=settings.scanner_vpn_egress_exit_ip_url,
        # Deliberately shorter than the mid-scan recheck interval, so a recheck always
        # gets a fresh observation rather than one taken before the last check.
        exit_ip_ttl_s=min(
            60, max(10, int(settings.scanner_vpn_egress_recheck_seconds or 60) // 2)
        ),
    )


def build_loop(settings=None) -> LeaseLoop:
    """Assemble the lease loop from configuration. Raises RuntimeError on bad identity."""
    settings = settings or get_settings()
    identity = WorkerIdentity.from_settings(settings)

    missing = [
        name for name, value in (
            ("SCANNER_WORKER_ID", identity.worker_id),
            ("SCANNER_POOL_ID", identity.pool_id),
            ("SCANNER_MANAGER_URL", identity.manager_url),
            ("SCANNER_WORKER_TOKEN", identity.token),
        ) if not value
    ]
    if missing:
        raise RuntimeError(
            "scanner worker cannot start without a complete identity; missing: "
            + ", ".join(missing)
            + ". The manager authorizes every request against this worker's own row, so an "
            "incomplete identity cannot be authorized for anything."
        )

    client = ManagerClient(identity)
    # ManagerResultSink holds ONLY the worker identity + manager URL. No database session,
    # no S3 client, no credential for either -- that is what lets the scanner image drop
    # them entirely.
    sink = result_sink.ManagerResultSink(
        manager_url=identity.manager_url,
        worker_id=identity.worker_id,
        token=identity.token,
    )
    return LeaseLoop(
        identity,
        client,
        executor=build_executor(reporter=ManagerResultReporter(sink)),
        backoff=BackoffPolicy(),
        tunnel_probe=_build_tunnel_probe(identity),
        egress_probe=_build_egress_probe(identity),
    )


async def _prepare_private_tunnel(loop) -> None:
    """Bring up and verify this private worker's tunnel BEFORE it leases anything.

    Only runs for a private worker (a public one has no tunnel and no site). It fetches the
    site's PUBLIC configuration from the manager -- which reads the site from this worker's
    own row, so a worker cannot ask for another customer's tunnel -- renders the config with
    the EXISTING production generator, applies it, and runs the EXISTING preflight.

    A failure here refuses to start. That is deliberate: a private worker that cannot prove
    its tunnel is healthy would otherwise come up and reject every job at lease time, which
    reports a deployment fault as a stream of runtime refusals.
    """
    from apps.api.scanner_engine import wireguard
    from apps.api.scanner_worker import tunnel_setup

    settings = get_settings()
    identity = loop.identity
    interface = (settings.scanner_wireguard_interface or "wg0").strip()

    # Fail fast and clearly if the image lacks wg/ip, rather than surfacing it later as
    # TUNNEL_UNHEALTHY on every scan.
    tunnel_setup.assert_tooling_present()

    site = await loop.client.site_config()
    if site.get("status") != "active":
        raise RuntimeError(
            f"private site {site.get('site_id')} is '{site.get('status')}', not 'active'; "
            f"refusing to start."
        )

    # THE EXISTING generator -- not a second one.
    config = wireguard.describe_config(
        site_id=site.get("site_id") or identity.site_id,
        authorized_cidrs=site.get("authorized_cidrs") or [],
        peer_public_key=site.get("peer_public_key"),
        endpoint_host=site.get("wg_endpoint_host"),
        endpoint_port=site.get("wg_endpoint_port"),
        dns_servers=site.get("dns_servers") or (),
        interface_address=settings.scanner_wireguard_address or None,
        persistent_keepalive=site.get("wg_persistent_keepalive"),
    )
    private_key = tunnel_setup.read_private_key(settings.scanner_wireguard_private_key_file)
    status = tunnel_setup.setup_and_verify(
        config, private_key=private_key, interface=interface,
        # PHASE 8: both come from configuration, so an operator can tune a site's tunnel
        # without a code change and the effective values are visible in the logs below.
        max_handshake_age_s=settings.scanner_wireguard_max_handshake_age_s,
        mtu=settings.scanner_wireguard_mtu,
    )
    # P7-3: install the site-DNS TRANSPORT, now that the tunnel the resolvers live behind is
    # verified up. Before this, nothing in production ever called `set_backend()`, so every
    # private HOSTNAME lookup failed closed (private IP/CIDR targets were unaffected).
    #
    # Installed ONCE, here, and deliberately carrying NO site state: the resolver address
    # travels per-scan on `ScanNetworkPolicy.dns_servers` (task-local), so this global is a
    # pure "send this query to that resolver" transport and cannot leak between sites or
    # between concurrent scans. See the module docstring in scanner_engine/site_dns.py.
    #
    # A worker whose image somehow lacks dnspython keeps the fail-closed default rather than
    # refusing to start: private IP/CIDR scanning still works, and hostname lookups keep
    # refusing exactly as they do today.
    from apps.api.scanner_engine import site_dns

    dns_ready = site_dns.install_default_backend()

    # Deliberately does NOT log the key or the config text -- only the key-free view.
    # `dns_servers` is a COUNT, never the addresses: a customer's internal resolver
    # addresses are site configuration, not something to scatter through logs.
    logger.info(
        "scanner_worker.tunnel_ready site=%s handshake_age=%ss routes=%d mtu=%s "
        "site_dns_backend=%s resolvers=%d",
        config.site_id, status.last_handshake_age_s, len(status.routes), status.mtu,
        "installed" if dns_ready else "unavailable", len(config.dns_servers or ()),
        extra={"event": "scanner_worker.tunnel_ready", "site_id": str(config.site_id)},
    )


async def _prepare_vpn_egress(loop) -> None:
    """Install the kill-switch, bring up the VPN tunnel, and PROVE egress before leasing.

    Only runs for a vpn-mode worker. A failure here refuses to start, for the same reason
    `_prepare_private_tunnel` does: a VPN-egress worker that cannot prove its path would
    otherwise come up and reject every job, reporting a deployment fault as a stream of
    runtime refusals.

    The stronger reason is specific to this path, though. The kill-switch is installed
    BEFORE the tunnel (see `egress_setup.setup_and_verify`), so the window between process
    start and a verified tunnel is CLOSED rather than open. Starting the lease loop without
    completing this sequence would mean a worker that can reach targets directly.

    Unlike the private path, this needs NOTHING from the manager: the VPN is platform
    infrastructure, not tenant configuration, so its parameters come from this worker's own
    settings and its secret from its own mounted file. That is also why the credential
    never travels over the manager boundary.
    """
    from apps.api.scanner_engine import vpn_egress
    from apps.api.scanner_worker import egress_setup

    settings = get_settings()
    try:
        config = _build_egress_config(settings)
    except vpn_egress.VpnEgressConfigError as exc:
        raise RuntimeError(f"VPN egress configuration is unusable: {exc}") from exc

    private_key = egress_setup.read_private_key(
        settings.scanner_vpn_egress_private_key_file
    )
    status = egress_setup.setup_and_verify(
        config,
        private_key=private_key,
        dispatch_cidrs=settings.vpn_egress_dispatch_cidr_list,
        exit_ip_url=settings.scanner_vpn_egress_exit_ip_url,
        forbidden_exit_ips=settings.vpn_egress_forbidden_exit_ip_list,
        max_handshake_age_s=settings.scanner_vpn_egress_max_handshake_age_s,
        probe=loop.egress_probe,
    )

    try:
        from apps.api.core.observability import record_vpn_egress_state

        record_vpn_egress_state(
            loop.identity.pool_id,
            up=True,
            handshake_age_s=status.last_handshake_age_s,
            exit_ip_verified=True,
        )
    except Exception:  # noqa: BLE001 -- metrics must never block startup
        pass

    # The observed exit IP IS logged, deliberately: it is the platform's own VPN exit
    # address, not tenant data, and it is the single most useful line an operator has when
    # asking "is this worker actually on the VPN?".
    logger.info(
        "scanner_worker.vpn_egress_ready interface=%s exit_ip=%s handshake_age=%ss "
        "killswitch=%s table=%s",
        config.interface, status.observed_exit_ip, status.last_handshake_age_s,
        "active" if status.killswitch_active else "MISSING", config.table,
        extra={"event": "scanner_worker.vpn_egress_ready",
               "exit_ip": status.observed_exit_ip},
    )


async def _announce_liveness(loop) -> None:
    """Heartbeat ONCE, before any private tunnel work, to establish authenticated liveness.

    WHY THIS ORDERING EXISTS (P8-F private recovery). A private worker used to do tunnel
    setup first, and `_prepare_private_tunnel` begins with `GET /v1/site-config` -- an
    endpoint behind `authenticated_worker`, which refuses a `suspended` worker. So a
    suspended private worker died at startup, exit 2, before `loop.run()` (and therefore
    before its first heartbeat) was ever reached:

        suspended private worker -> /v1/site-config -> 403 -> startup_failed -> exit 2
                                 -> lease loop never starts -> never heartbeats

    That made the documented recovery order -- heartbeat, verify healthy, then reactivate --
    impossible to satisfy for a private worker: the one thing an operator was told to check
    could never happen while the worker was suspended. Verified live on `worker-site-lab-a`.

    Putting a heartbeat FIRST fixes the ordering without touching a single authorization
    rule. An ACTIVE private worker now proves authenticated liveness (and refreshes
    `last_seen_at`) before the slower, failure-prone tunnel bring-up, so the operator's
    verification step is reachable. A SUSPENDED worker is still refused here, exactly as it
    was refused at /v1/site-config -- the refusal simply happens at the step whose failure
    actually explains the situation, and names the recovery command.

    THIS IS NOT A BYPASS, and the distinction matters:
      * the heartbeat is itself an AUTHENTICATED endpoint. A worker with no credential, a
        bad credential, a revoked or a suspended row is refused here too.
      * no authorization rule, dependency, or status set is modified anywhere.
      * it grants no ability to LEASE. Leasing still requires `assert_worker_may_lease`
        server-side, and a private job additionally requires `preflight_private_job` to
        observe a healthy tunnel at lease time -- which is the gate that actually keeps an
        unrouted private scan from running, independently of this function.

    NO FALSE HEALTH. The state sent is whatever `observe_tunnel_health()` actually
    observes; for a private worker whose tunnel is not up yet that is `unhealthy`, and it is
    reported as such. This announces "I am authenticated and alive", never "I am ready to
    scan" -- and because the per-job gate is separate, a worker cannot scan on the strength
    of this call regardless of what it reports.
    """
    await loop.client.heartbeat(**loop.health_payload())


async def _run() -> tuple[dict, str | None]:
    """Run the lease loop. Returns (stats, fatal_reason).

    `fatal_reason` is non-None ONLY when the loop stopped because this worker's identity
    was refused -- see `LeaseLoop.fatal_reason`. It is returned alongside the stats rather
    than raised because the stats are still worth logging in that case.

    ORDER IS LOAD-BEARING for a private worker: authenticated liveness, THEN tunnel setup,
    then the lease loop. See `_announce_liveness`.
    """
    loop = build_loop()
    if loop.identity.is_private:
        await _announce_liveness(loop)
        await _prepare_private_tunnel(loop)
    elif loop.identity.is_vpn_egress:
        # NOTE THE ORDER, which is the OPPOSITE of the private path's, and deliberately so.
        # `_announce_liveness` makes an outbound call to the manager; on a VPN-egress
        # worker the kill-switch that permits that call does not exist yet, so heartbeating
        # first would be refused by our own (not-yet-installed) firewall or, worse, would
        # succeed over a path we are about to close. Egress is prepared FIRST, and the
        # heartbeat then rides the same verified path every later call uses.
        #
        # The private path's reason for heartbeating first (P8-F: a suspended worker must
        # be able to prove liveness before the failure-prone tunnel step) does not apply
        # here: this step needs nothing from the manager, so it cannot be blocked by a
        # suspended row the way /v1/site-config was.
        await _prepare_vpn_egress(loop)
        await _announce_liveness(loop)
    loop.install_signal_handlers()
    stats = await loop.run()
    return stats, loop.fatal_reason


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    settings = get_settings()

    # (1) Credential guard FIRST -- before any other startup work could touch a secret.
    try:
        enforce_execution_plane_credentials()
    except ExecutionPlaneCredentialError as exc:
        logger.error("scanner_worker.refusing_to_start %s", exc)
        return 2

    # Honour proxy / custom-CA settings for the scanner tool binaries (same call the Celery
    # task makes). Idempotent, and touches no credential.
    configure_networking(settings)

    try:
        stats, fatal_reason = asyncio.run(_run())
    except RuntimeError as exc:
        # Covers an incomplete identity, TunnelSetupError, and LeaseError -- all
        # RuntimeError subclasses. The message names WHAT failed and never carries key
        # material.
        reason = getattr(exc, "reason", None)
        if reason == REASON_AUTH_FAILED:
            # IDENTITY REFUSED DURING STARTUP. Same condition, same exit code (3) and same
            # actionable message as a refusal inside the loop -- see the `fatal_reason`
            # branch below. Without this branch the two indistinguishable situations
            # produced different codes (2 vs 3) and only one of them told the operator what
            # to do, which is precisely how the private worker's recovery path stayed
            # unexplained: a suspended private worker reported a generic `startup_failed`
            # that named no remedy.
            logger.error(
                "scanner_worker.exit_fatal reason=%s %s -- this worker's identity was "
                "refused by the manager; restarting will not help until an operator acts "
                "(see: python -m apps.api.ops.reactivate_worker)",
                reason, exc,
                extra={"event": "scanner_worker.exit_fatal", "reason": reason},
            )
            return 3
        logger.error(
            "scanner_worker.startup_failed%s %s",
            f" reason={reason}" if reason else "", exc,
            extra={"event": "scanner_worker.startup_failed", "reason": reason},
        )
        return 2
    except KeyboardInterrupt:
        logger.info("scanner_worker.interrupted")
        return 0
    if fatal_reason:
        # IDENTITY REFUSED -- exit NON-ZERO so the failure is visible as a failure.
        #
        # THE INCIDENT THIS CLOSES. This path used to `return 0`, so a worker whose
        # credential was permanently refused (revoked / suspended / unknown) exited exactly
        # like a clean shutdown. Docker's `restart: unless-stopped` then restarted it, and
        # `docker ps` reported `Restarting (0)` -- an exit code that reads as success.
        # Observed live: 58 restarts over four days against a 403 WORKER_SUSPENDED, with no
        # non-zero code, no unhealthy marker, and the only actionable string buried in logs.
        #
        # A TRANSIENT failure never reaches here: a manager outage or transport error is
        # retried with bounded backoff inside the loop and does not terminate it, so this
        # cannot turn a network blip into a crash loop. Only a refusal that no retry can
        # clear sets `fatal_reason`.
        logger.error(
            "scanner_worker.exit_fatal reason=%s stats=%s -- this worker's identity was "
            "refused by the manager; restarting will not help until an operator acts "
            "(see: python -m apps.api.ops.reactivate_worker)",
            fatal_reason, stats,
            extra={"event": "scanner_worker.exit_fatal", "reason": fatal_reason},
        )
        return 3
    logger.info("scanner_worker.exit stats=%s", stats)
    return 0


if __name__ == "__main__":
    sys.exit(main())
