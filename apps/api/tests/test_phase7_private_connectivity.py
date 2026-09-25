"""MBS.SC PHASE 7 -- private connectivity, as exercised against a live tunnel.

WHY THIS FILE EXISTS ALONGSIDE test_scanner_egress_wireguard.py
---------------------------------------------------------------
That file proves the CONFIGURATION LAYER in isolation: AllowedIPs generation, default-route
refusal, config rendering, probe parsing. This file pins the properties that were verified
END TO END in the Phase 7 lab (infra/lab/phase7/) -- the ones that can only be stated once a
real worker, a real manager and a real tunnel have been stood up together:

  * the tunnel a site produces is SITE-SPECIFIC, derived from that site's own authorized
    CIDRs and nothing else;
  * a private worker's routing table carries EXACTLY the authorized prefixes -- no default
    route, and nothing belonging to another customer;
  * an address outside AllowedIPs is refused even when a route is forced at it (WireGuard's
    cryptographic routing, not just the kernel routing table, is the boundary);
  * the whole private path fails CLOSED at both the startup and the per-job gate;
  * adding WireGuard does not weaken the Phase 1/2 control-plane isolation.

The live evidence for each is recorded in the Phase 7 report. These tests are the executable
regression guard for the same properties, so a change that silently widens the tunnel is
caught without having to rebuild the lab.

Pure and offline: every probe here is a StaticTunnelProbe or a captured-output runner. No
container, no network, no database.
"""
from pathlib import Path

import pytest
import yaml

from apps.api.scanner_engine import wireguard as wg
from apps.api.scanner_worker import tunnel_setup


# The lab's actual parameters (infra/lab/phase7/docker-compose.lab.yml + provision script).
SITE_A_CIDRS = ["10.90.0.0/24"]
CUSTOMER_B_CIDR = "10.91.0.0/24"
CUSTOMER_B_HOST = "10.91.0.20"


# =======================================================================================
# 1. SITE-SPECIFIC CONFIGURATION
# =======================================================================================

def test_allowed_ips_come_only_from_the_sites_own_cidrs():
    """A site's tunnel carries that site's CIDRs and nothing else.

    Verified live: the lab site authorized 10.90.0.0/24, and `wg show wg0` reported
    `allowed ips: 10.90.0.0/24` -- exactly one prefix."""
    assert wg.build_allowed_ips(SITE_A_CIDRS) == ["10.90.0.0/24"]
    # Another customer's range is absent unless that customer's site authorizes it.
    assert CUSTOMER_B_CIDR not in wg.build_allowed_ips(SITE_A_CIDRS)


def test_two_sites_never_share_an_allowed_ips_set():
    """Site isolation begins at configuration: each site's AllowedIPs is derived from its
    OWN row, so one customer's prefixes cannot appear in another's tunnel."""
    site_a = wg.describe_config(
        site_id="site-a", authorized_cidrs=SITE_A_CIDRS, peer_public_key="A" * 44,
        endpoint_host="10.92.0.10", endpoint_port=51820,
    )
    site_b = wg.describe_config(
        site_id="site-b", authorized_cidrs=[CUSTOMER_B_CIDR], peer_public_key="B" * 44,
        endpoint_host="10.92.0.11", endpoint_port=51820,
    )
    assert set(site_a.allowed_ips).isdisjoint(set(site_b.allowed_ips))
    assert site_a.site_id != site_b.site_id


def test_a_sites_config_never_carries_a_private_key_field():
    """Key custody: TunnelConfig is the key-free view, and it is what everything except the
    one render call handles. Verified live: /v1/site-config returned public keys only, and
    `private_sites` has no column that could hold a private key."""
    cfg = wg.describe_config(
        site_id="site-a", authorized_cidrs=SITE_A_CIDRS, peer_public_key="A" * 44,
        endpoint_host="10.92.0.10", endpoint_port=51820,
    )
    assert not any("private" in f.lower() for f in cfg.__dataclass_fields__)


# =======================================================================================
# 2. DEFAULT-ROUTE PREVENTION  (0.0.0.0/0 and ::/0)
# =======================================================================================

@pytest.mark.parametrize("route", ["0.0.0.0/0", "::/0"])
def test_default_route_refused_in_allowed_ips(route):
    with pytest.raises(wg.WireGuardConfigError):
        wg.build_allowed_ips([route])


@pytest.mark.parametrize("route", ["0.0.0.0/0", "::/0"])
def test_default_route_refused_at_bring_up_even_if_config_is_hand_built(route):
    """`bring_up` re-checks rather than trusting that build_allowed_ips ran.

    A TunnelConfig constructed directly (bypassing describe_config) must still be refused --
    which is what makes the guarantee structural rather than dependent on one call path."""
    cfg = wg.TunnelConfig(
        site_id="site-a", interface_address="10.99.0.2/32", allowed_ips=(route,),
        peer_public_key="A" * 44, endpoint="10.92.0.10:51820",
    )
    assert cfg.has_default_route
    with pytest.raises(tunnel_setup.TunnelSetupError) as exc:
        tunnel_setup.bring_up(cfg, private_key="x" * 44, interface="wg-test")
    assert exc.value.reason == tunnel_setup.REASON_DEFAULT_ROUTE


def test_rendering_a_default_route_config_is_refused():
    cfg = wg.TunnelConfig(
        site_id="site-a", interface_address="10.99.0.2/32", allowed_ips=("0.0.0.0/0",),
        peer_public_key="A" * 44, endpoint="10.92.0.10:51820",
    )
    with pytest.raises(wg.WireGuardConfigError):
        wg.render_worker_config(cfg, private_key="x" * 44)


def test_observed_default_route_on_the_interface_is_refused_after_bring_up():
    """`assert_no_default_route` is an INDEPENDENT observation of the live routing table.

    It catches a default route that was never in AllowedIPs -- inherited from a restarted
    container, an image default, or a manual `ip route add`. Verified live: with the lab
    tunnel up, `ip route show default` pointed at eth1, never wg0."""
    def _runner_with_default(argv):
        if argv[:3] == ["ip", "-o", "route"]:
            return 0, "default via 10.99.0.1 dev wg0 \n"
        return 0, ""

    original = tunnel_setup._run
    try:
        tunnel_setup._run = lambda argv, **kw: (
            (0, "default via 10.99.0.1 dev wg0 \n", "")
            if argv[:2] == ["ip", "-o"] else (0, "", "")
        )
        with pytest.raises(tunnel_setup.TunnelSetupError) as exc:
            tunnel_setup.assert_no_default_route("wg0")
        assert exc.value.reason == tunnel_setup.REASON_DEFAULT_ROUTE
    finally:
        tunnel_setup._run = original


# =======================================================================================
# 3. AUTHORIZED vs UNAUTHORIZED ROUTING
# =======================================================================================

def test_probe_reports_exactly_the_authorized_prefix_as_routed():
    """The lab's real routing table had ONE route on wg0: 10.90.0.0/24."""
    probe = wg.StaticTunnelProbe(
        wg.TunnelStatus(interface_up=True, last_handshake_age_s=5,
                        routes=("10.90.0.0/24",))
    )
    status = wg.preflight(site_id="site-a", authorized_cidrs=SITE_A_CIDRS, probe=probe)
    assert status.interface_up
    assert tuple(status.routes) == ("10.90.0.0/24",)


def test_customer_b_prefix_is_not_routed_and_preflight_notices_if_it_is_claimed():
    """A site authorized for A must not be satisfied by a tunnel routing only B.

    This is the configuration-side statement of the live Customer-B test, where
    10.91.0.20 timed out while being provably alive from inside its own network."""
    probe = wg.StaticTunnelProbe(
        wg.TunnelStatus(interface_up=True, last_handshake_age_s=5,
                        routes=(CUSTOMER_B_CIDR,))
    )
    with pytest.raises(wg.TunnelUnhealthy):
        wg.preflight(site_id="site-a", authorized_cidrs=SITE_A_CIDRS, probe=probe)


def test_an_unauthorized_host_is_outside_every_authorized_network():
    """Customer B's host is not inside site A's authorized space, by arithmetic.

    The live test forced a route for this address into wg0 and WireGuard still refused the
    packet -- AllowedIPs is cryptographic routing, so the kernel route was not sufficient."""
    import ipaddress

    nets = [ipaddress.ip_network(c) for c in SITE_A_CIDRS]
    addr = ipaddress.ip_address(CUSTOMER_B_HOST)
    assert not any(addr in n for n in nets)


# =======================================================================================
# 4. FAIL-CLOSED
# =======================================================================================

@pytest.mark.parametrize(
    "status,label",
    [
        (wg.TunnelStatus(interface_up=False), "interface down"),
        (wg.TunnelStatus(interface_up=True, last_handshake_age_s=None), "never handshaked"),
        (wg.TunnelStatus(interface_up=True, last_handshake_age_s=99999,
                         routes=("10.90.0.0/24",)), "handshake stale"),
        (wg.TunnelStatus(interface_up=True, last_handshake_age_s=5, routes=()), "no routes"),
    ],
)
def test_every_unhealthy_tunnel_state_refuses_the_scan(status, label):
    """Verified live: `ip link set wg0 down` made preflight refuse with TUNNEL_UNHEALTHY,
    and the authorized target became unreachable rather than falling back to another path."""
    with pytest.raises(wg.TunnelUnhealthy), pytest.MonkeyPatch().context():
        wg.preflight(site_id="site-a", authorized_cidrs=SITE_A_CIDRS,
                     probe=wg.StaticTunnelProbe(status))


def test_a_private_job_without_a_probe_is_refused():
    """No probe -> no private scanning. A worker that cannot demonstrate tunnel health must
    not scan: 'no findings' would otherwise be indistinguishable from 'never reached it'."""
    from apps.api.scanner_worker.lease_loop import LeaseError, preflight_private_job

    job = {"network_zone": "private", "site_id": "site-a",
           "authorized_cidrs": SITE_A_CIDRS}
    with pytest.raises(LeaseError) as exc:
        preflight_private_job(job, probe=None)
    assert exc.value.reason == "TUNNEL_UNHEALTHY"


def test_a_public_job_is_unaffected_by_tunnel_health():
    """Public scanning must not be collateral damage of a private-site tunnel failure.
    Verified live alongside the fail-closed test."""
    from apps.api.scanner_worker.lease_loop import preflight_private_job

    preflight_private_job({"network_zone": "public"}, probe=None)  # must not raise


def test_probe_that_cannot_observe_the_tunnel_reports_unhealthy():
    """A missing `wg`/`ip`, a timeout, or a permission error must read as UNHEALTHY --
    never as healthy. This is the direction that makes the whole gate trustworthy."""
    probe = wg.SystemTunnelProbe("wg0", runner=lambda argv: (127, ""))
    status = probe.status("site-a")
    assert not status.interface_up or not status.routes
    # And the gate built on it refuses, rather than treating "cannot see" as "healthy".
    with pytest.raises(wg.TunnelUnhealthy):
        wg.preflight(site_id="site-a", authorized_cidrs=SITE_A_CIDRS, probe=probe)


# =======================================================================================
# 5. PHASE 1/2 REGRESSION -- WireGuard must not open a control-plane path
# =======================================================================================

def test_tunnel_config_never_authorizes_a_control_plane_destination():
    """AllowedIPs is the customer's space; the control plane is never in it.

    Verified live with the tunnel UP: mysql/redis/minio/api/ollama all failed to resolve
    from inside the private worker, while scanner-manager remained reachable."""
    cfg = wg.describe_config(
        site_id="site-a", authorized_cidrs=SITE_A_CIDRS, peer_public_key="A" * 44,
        endpoint_host="10.92.0.10", endpoint_port=51820,
    )
    rendered = wg.render_worker_config(cfg, private_key="x" * 44)
    for forbidden in ("0.0.0.0/0", "::/0"):
        assert forbidden not in rendered
    # The manager is reached over the worker's ordinary egress, never over the tunnel.
    assert "AllowedIPs = 10.90.0.0/24" in rendered


def test_rendered_config_does_not_set_wg_quick_dns():
    """wg-quick's DNS= would rewrite the whole namespace resolver, sending every lookup --
    including the manager's own name -- to the customer's DNS. Site DNS is per-lookup."""
    cfg = wg.describe_config(
        site_id="site-a", authorized_cidrs=SITE_A_CIDRS, peer_public_key="A" * 44,
        endpoint_host="10.92.0.10", endpoint_port=51820,
        dns_servers=["10.90.0.53"],
    )
    rendered = wg.render_worker_config(cfg, private_key="x" * 44)
    assert "DNS =" not in rendered
    assert "Table = off" in rendered


def test_render_puts_the_key_in_the_text_but_never_in_the_description():
    """The only artifact carrying the private key is the rendered file, which stays inside
    the worker namespace. Its key-free description is what everything else handles."""
    cfg = wg.describe_config(
        site_id="site-a", authorized_cidrs=SITE_A_CIDRS, peer_public_key="A" * 44,
        endpoint_host="10.92.0.10", endpoint_port=51820,
    )
    secret = "PRIVATEKEYMATERIAL" + "x" * 26
    rendered = wg.render_worker_config(cfg, private_key=secret)
    assert secret in rendered           # it must be in the file the worker writes
    assert secret not in repr(cfg)      # and nowhere in the shareable description
    assert secret not in str(cfg)


# =======================================================================================
# 6. P7-1 -- THE PRIVILEGE-DROP MECHANISM IN THE SHIPPED TEMPLATE
# =======================================================================================
# These inspect the DEPLOYMENT MANIFEST, not the Python code, because P7-1 was a manifest
# defect: `user: "10001:10001"` + `cap_add: [NET_ADMIN]` yields an EMPTY effective capability
# set (Docker leaves CapInh/CapAmb at 0 for a non-root user, so the capability reaches only
# the BOUNDING set), and `ip link add ... type wireguard` therefore failed with EPERM. The
# fix is an inline entrypoint that starts as root with three capabilities and drops to uid
# 10001 via setpriv, raising CAP_NET_ADMIN into the AMBIENT set so it survives the switch.
#
# Measured on the real image:
#     root      CapPrm=0000000000001000  CapEff=0000000000001000
#     uid 10001 CapPrm=0000000000000000  CapEff=0000000000000000   (CapBnd=...1000)
#     after setpriv drop: uid=10001  CapPrm/CapEff/CapAmb=0000000000001000

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PRIVATE_SITE_COMPOSE = _REPO_ROOT / "infra" / "docker-compose.private-site.yml"
_LAB_COMPOSE = _REPO_ROOT / "infra" / "lab" / "phase7" / "docker-compose.lab.yml"
_WORKER_DOCKERFILE = _REPO_ROOT / "infra" / "docker" / "Dockerfile.worker"

# The security keys that MUST be identical between the shipped template and the lab, so the
# lab cannot quietly prove a weaker configuration than the one that ships.
_POSTURE_KEYS = (
    "entrypoint", "cap_drop", "cap_add", "security_opt", "read_only", "sysctls",
)


def _private_site_service() -> dict:
    if not _PRIVATE_SITE_COMPOSE.is_file():
        pytest.skip("infra/ not bind-mounted in this environment")
    doc = yaml.safe_load(_PRIVATE_SITE_COMPOSE.read_text(encoding="utf-8"))
    return doc["services"]["worker-site-SITE_SLUG"]


def _lab_worker_service() -> dict:
    if not _LAB_COMPOSE.is_file():
        pytest.skip("Phase 7 lab not present in this environment")
    doc = yaml.safe_load(_LAB_COMPOSE.read_text(encoding="utf-8"))
    return doc["services"]["worker-site-lab-a"]


def _entrypoint_script(service: dict) -> str:
    ep = service.get("entrypoint")
    assert isinstance(ep, list) and len(ep) >= 3, "entrypoint must be an exec-form list"
    return ep[2]


def test_template_drops_to_uid_10001_before_running_the_worker():
    """The long-lived worker must NOT run as root. The drop is the entrypoint's whole job."""
    script = _entrypoint_script(_private_site_service())
    assert "setpriv" in script
    assert "--reuid=10001" in script
    assert "--regid=10001" in script
    # `exec` so the worker becomes PID 1 and receives Docker's stop signal directly.
    assert "exec setpriv" in script


def test_template_retains_only_net_admin_in_the_ambient_set():
    """CAP_NET_ADMIN must survive the drop (the per-job `wg show` probe needs it), and it
    must be the ONLY capability that does -- SETUID/SETGID are consumed by the drop."""
    script = _entrypoint_script(_private_site_service())
    assert "--ambient-caps=+net_admin" in script
    for forbidden in ("setuid", "setgid", "sys_admin", "net_raw", "+all", "all"):
        assert f"--ambient-caps=+{forbidden}" not in script


def test_template_starts_privileged_and_hands_the_uid_to_the_entrypoint():
    """`user:` decides what the ENTRYPOINT starts as, not what the worker ends as.

    It must be root: Docker applies `user:` before any capability can be raised into the
    ambient set, so `user: "10001:10001"` left the entrypoint with CapPrm=CapEff=0 -- the
    original defect. The image's own default is `USER appuser`, so omitting the key entirely
    is equally broken (observed: setpriv failed with "setgroups failed: Operation not
    permitted"). The drop to 10001 is the entrypoint's job, asserted separately above."""
    svc = _private_site_service()
    assert svc.get("user") == "0:0"
    # ...and the entrypoint MUST then drop, or this would just be a root container.
    assert "--reuid=10001" in _entrypoint_script(svc)


def test_template_keeps_cap_drop_all_and_grants_only_the_three_needed():
    svc = _private_site_service()
    assert svc["cap_drop"] == ["ALL"]
    assert set(svc["cap_add"]) == {"NET_ADMIN", "SETUID", "SETGID"}


@pytest.mark.parametrize("forbidden", ["SYS_ADMIN", "NET_RAW", "ALL", "SYS_PTRACE", "DAC_OVERRIDE"])
def test_template_does_not_grant_broader_capabilities(forbidden):
    assert forbidden not in _private_site_service()["cap_add"]


def test_template_preserves_every_other_security_control():
    """P7-1 must not have relaxed anything else while fixing the capability problem."""
    svc = _private_site_service()
    assert svc["security_opt"] == ["no-new-privileges:true"]
    assert svc["read_only"] is True
    assert svc["sysctls"]["net.ipv4.ip_forward"] == "0"
    assert svc.get("privileged") is not True
    # Key material stays on tmpfs, never a persistent layer.
    assert any(t.startswith("/run/wireguard:") for t in svc["tmpfs"])
    # Scanner env file only -- no control-plane credentials (Phase 2).
    assert svc["env_file"] == ["../.env.scanner"]
    # The private key is delivered as a FILE, never an env value.
    assert "SCANNER_WIREGUARD_PRIVATE_KEY_FILE" in svc["environment"]
    assert not any(k.endswith("PRIVATE_KEY") for k in svc["environment"])


def test_template_fails_loudly_when_setpriv_is_absent():
    """A missing setpriv must stop the container, not silently leave it running as root."""
    script = _entrypoint_script(_private_site_service())
    assert "command -v setpriv" in script
    assert "exit 1" in script


def test_dockerfile_pins_the_privilege_drop_tooling():
    """setpriv/capsh were transitive base-image deps; P7-1 names them so a base bump cannot
    remove the mechanism the private worker depends on."""
    if not _WORKER_DOCKERFILE.is_file():
        pytest.skip("infra/ not bind-mounted in this environment")
    text = _WORKER_DOCKERFILE.read_text(encoding="utf-8")
    assert "util-linux" in text
    assert "libcap2-bin" in text
    # Still installed alongside the WireGuard tooling, in one layer.
    assert "wireguard-tools" in text


def test_lab_worker_matches_the_production_security_posture():
    """The lab must exercise the SHIPPED configuration, not a relaxed copy of it.

    This is the guard that keeps the Phase 7 live proof honest: if someone re-adds a
    `user: "0:0"` workaround to the lab, or widens its capabilities, this fails."""
    prod = _private_site_service()
    lab = _lab_worker_service()
    for key in _POSTURE_KEYS:
        assert lab.get(key) == prod.get(key), f"lab/production posture diverged on {key!r}"
    # The lab must start from the same uid as production, too.
    assert lab.get("user") == prod.get("user")
