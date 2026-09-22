"""MBS.SC -- egress restriction, split-horizon DNS, and WireGuard safety.

Covers the execution plane's outbound boundary:
  * a scanner may not reach any control-plane service (Property A, in-process layer);
  * a redirect cannot escalate an authorized public scan into an internal one;
  * a private hostname never leaks to a public resolver;
  * a tunnel is never configured with a default route, and never carries a private key
    into anything the control plane persists;
  * a scan does not start on an unhealthy tunnel.
"""
import uuid

import pytest

from apps.api.core.config import get_settings
from apps.api.scanner_engine import egress_guard, net_policy, site_dns, wireguard


@pytest.fixture
def private_scanning_enabled(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "scan_allow_private_targets", True)
    monkeypatch.setattr(s, "scan_allowed_cidrs", ["10.0.0.0/8"])
    return s


@pytest.fixture
def site_policy():
    return net_policy.build_private_policy(
        workspace_id=uuid.uuid4(), scan_id=uuid.uuid4(), site_id=uuid.uuid4(),
        authorized_cidrs=["10.0.0.0/16"], dns_servers=["10.0.0.53"],
    )


# ---------------------------------------------------------------------------------------
# EGRESS: control plane is unreachable (tests 1-6 of the required matrix)
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("service", [
    "mysql", "redis", "minio", "api", "prometheus", "alertmanager",
    "ollama", "web", "nginx", "beat", "worker-default", "postgres",
])
def test_scanner_cannot_reach_control_plane_services(service, private_scanning_enabled):
    """Every control-plane service name is refused, by name, before any resolution."""
    with pytest.raises(egress_guard.EgressDenied) as exc:
        egress_guard.assert_destination_allowed(service)
    assert exc.value.reason == egress_guard.REASON_CONTROL_PLANE


@pytest.mark.parametrize("dest", [
    "http://mysql:3306/", "redis:6379", "http://minio:9000/evidence",
    "http://api:8000/api/v1/scans", "mysql.mbs-core", "api.default.svc.cluster.local",
])
def test_control_plane_denied_in_every_url_shape(dest, private_scanning_enabled):
    """URL, host:port, bare name and qualified compose/k8s names all resolve to the same
    refusal -- a different spelling is not a bypass."""
    with pytest.raises(egress_guard.EgressDenied) as exc:
        egress_guard.assert_destination_allowed(dest)
    assert exc.value.reason == egress_guard.REASON_CONTROL_PLANE


def test_scanner_may_reach_the_manager(private_scanning_enabled):
    """The one permitted control-plane endpoint (test 7)."""
    egress_guard.assert_destination_allowed(
        "http://scanner-manager:8100/v1/lease", manager_host="scanner-manager"
    )


def test_manager_exemption_is_exact_not_a_prefix(private_scanning_enabled):
    """A lookalike host must not inherit the manager's exemption."""
    with pytest.raises(egress_guard.EgressDenied):
        egress_guard.assert_destination_allowed(
            "http://scanner-manager.evil.example/", manager_host="scanner-manager"
        )


def test_unauthorized_internal_target_is_denied(private_scanning_enabled, site_policy):
    """Test 9: an internal address outside the site's authorized CIDRs is refused."""
    with pytest.raises(egress_guard.EgressDenied) as exc:
        egress_guard.assert_destination_allowed("http://10.50.0.5/", policy=site_policy)
    assert exc.value.reason == egress_guard.REASON_NOT_AUTHORIZED


def test_authorized_private_target_is_allowed(private_scanning_enabled, site_policy):
    egress_guard.assert_destination_allowed("http://10.0.5.5/", policy=site_policy)


def test_loopback_and_metadata_are_denied(private_scanning_enabled, site_policy):
    for dest in ("http://127.0.0.1:8000/", "http://169.254.169.254/latest/meta-data/",
                 "http://[::1]:6379/", "http://100.64.0.1/"):
        with pytest.raises(egress_guard.EgressDenied):
            egress_guard.assert_destination_allowed(dest, policy=site_policy)


# ---------------------------------------------------------------------------------------
# REDIRECTS (Phase 8): an authorized public scan must not become an internal one
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("redirect_to", [
    "http://10.0.0.5/admin",                      # RFC1918
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata
    "http://127.0.0.1:8000/api/v1/scans",         # loopback to the API
    "http://mysql:3306/",                         # control-plane service by name
    "http://[::ffff:10.0.0.5]/",                  # IPv4-mapped IPv6
])
def test_redirect_to_internal_is_blocked(redirect_to, private_scanning_enabled):
    """A 302 confers no authority: the redirect target gets the same decision the
    original destination would have got. Public scan -> public-only policy."""
    public = net_policy.build_public_policy(workspace_id=uuid.uuid4())
    with pytest.raises(egress_guard.EgressDenied):
        egress_guard.assert_redirect_allowed(
            "http://scanme.example.com/", redirect_to, policy=public
        )


def test_redirect_into_another_tenants_cidr_is_blocked(private_scanning_enabled, site_policy):
    """Tenant A's scan redirected into 10.50/16 (not A's range) is refused."""
    with pytest.raises(egress_guard.EgressDenied):
        egress_guard.assert_redirect_allowed(
            "http://10.0.5.5/", "http://10.50.0.5/", policy=site_policy
        )


# ---------------------------------------------------------------------------------------
# DNS (Phase 9)
# ---------------------------------------------------------------------------------------

def test_private_names_resolve_through_the_site_resolver():
    """Test 25: a private lookup goes to the site's resolver, not the OS resolver."""
    seen = []

    def backend(hostname, resolver):
        seen.append((hostname, resolver))
        return ["10.0.0.42"]

    site_dns.set_backend(backend)
    try:
        addrs = site_dns.resolve_via_site_dns("db.internal.acme", resolvers=["10.0.0.53"])
        assert addrs == ["10.0.0.42"]
        assert seen == [("db.internal.acme", "10.0.0.53")]
    finally:
        site_dns.reset_backend()


def test_private_dns_never_falls_back_to_a_public_resolver():
    """Test 26 -- the leak test. With no backend installed, a private lookup must RAISE
    rather than quietly using the system/public resolver."""
    site_dns.reset_backend()
    with pytest.raises(site_dns.SiteDNSUnavailable, match="refusing to resolve"):
        site_dns.resolve_via_site_dns("secret.internal.acme", resolvers=["10.0.0.53"])


def test_resolver_failure_is_explicit_not_silent():
    """Test 27: an unreachable resolver fails clearly and does not return an address."""
    def failing(hostname, resolver):
        raise OSError("connection refused")

    site_dns.set_backend(failing)
    try:
        with pytest.raises(site_dns.SiteDNSUnavailable) as exc:
            site_dns.resolve_via_site_dns(
                "db.internal.acme", resolvers=["10.0.0.53"], attempts=1
            )
        assert "refusing to fall back" in str(exc.value)
    finally:
        site_dns.reset_backend()


def test_empty_answer_is_a_failure_not_a_pass():
    """A resolver that answers with nothing must not be read as success."""
    site_dns.set_backend(lambda h, r: [])
    try:
        with pytest.raises(site_dns.SiteDNSUnavailable):
            site_dns.resolve_via_site_dns("nx.internal.acme", resolvers=["10.0.0.53"], attempts=1)
    finally:
        site_dns.reset_backend()


def test_site_dns_failure_is_a_gaierror_subclass():
    """Existing callers treat gaierror as 'unresolvable, fail cleanly'; a resolver outage
    must degrade the same way rather than crashing the pipeline."""
    import socket

    assert issubclass(site_dns.SiteDNSUnavailable, socket.gaierror)


def test_a_public_scan_does_not_use_site_dns(private_scanning_enabled):
    """A public policy names no resolvers, so the OS resolver path is used unchanged."""
    public = net_policy.build_public_policy(workspace_id=uuid.uuid4())
    assert public.dns_servers == ()
    assert public.is_private is False


# ---------------------------------------------------------------------------------------
# WIREGUARD (Phase 11)
# ---------------------------------------------------------------------------------------

def test_allowed_ips_are_exactly_the_authorized_cidrs():
    """Test 30."""
    assert wireguard.build_allowed_ips(["10.0.0.0/16", "192.168.5.0/24"]) == [
        "10.0.0.0/16", "192.168.5.0/24"
    ]


@pytest.mark.parametrize("default_route", ["0.0.0.0/0", "::/0"])
def test_default_route_is_refused(default_route):
    """Test 29: a default route would capture ALL worker egress into one customer's
    tunnel -- including other tenants' traffic and the manager connection."""
    with pytest.raises(wireguard.WireGuardConfigError, match="default route"):
        wireguard.build_allowed_ips([default_route, "10.0.0.0/16"])


def test_empty_allowed_ips_is_refused():
    with pytest.raises(wireguard.WireGuardConfigError, match="at least one CIDR"):
        wireguard.build_allowed_ips([])


def test_rendered_config_has_no_default_route_and_no_wg_quick_dns():
    cfg = wireguard.describe_config(
        site_id=uuid.uuid4(), authorized_cidrs=["10.0.0.0/16"],
        peer_public_key="PEERPUBKEY=", endpoint_host="vpn.acme.example", endpoint_port=51820,
        dns_servers=["10.0.0.53"], interface_address="10.99.0.2/32",
        persistent_keepalive=25,
    )
    text = wireguard.render_worker_config(cfg, private_key="WORKERPRIVATEKEY=")
    assert "AllowedIPs = 10.0.0.0/16" in text
    assert "0.0.0.0/0" not in text
    assert "Table = off" in text
    # wg-quick's DNS= would rewrite the whole namespace resolver, sending public lookups
    # (and the manager's own name) to the customer -- site DNS is per-lookup instead.
    assert "\nDNS =" not in text
    assert "Endpoint = vpn.acme.example:51820" in text


def test_config_description_never_contains_a_private_key():
    """Test 32: the key-free view is what gets logged/returned/persisted."""
    cfg = wireguard.describe_config(
        site_id=uuid.uuid4(), authorized_cidrs=["10.0.0.0/16"],
        peer_public_key="PEERPUBKEY=", endpoint_host="vpn.acme.example", endpoint_port=51820,
    )
    blob = repr(cfg) + str(cfg.__dict__ if hasattr(cfg, "__dict__") else cfg)
    assert "PrivateKey" not in blob
    assert not any("private" in f.lower() for f in cfg.__dataclass_fields__)


def test_private_key_is_never_a_persisted_site_column():
    """Test 32 (schema half): no column on PrivateSite may hold a private key."""
    from apps.api.modules.private_sites.models import PrivateSite

    columns = {c.name.lower() for c in PrivateSite.__table__.columns}
    for name in columns:
        assert "private_key" not in name, f"PrivateSite.{name} looks like private key storage"
        assert not (name.endswith("_key") and "public" not in name), \
            f"PrivateSite.{name} may hold non-public key material"
    # The public halves ARE expected.
    assert "peer_public_key" in columns
    assert "worker_public_key" in columns


def test_render_refuses_without_a_private_key():
    cfg = wireguard.describe_config(
        site_id=uuid.uuid4(), authorized_cidrs=["10.0.0.0/16"],
        peer_public_key="P=", endpoint_host="h", endpoint_port=1,
    )
    with pytest.raises(wireguard.WireGuardConfigError):
        wireguard.render_worker_config(cfg, private_key="")


# ---------------------------------------------------------------------------------------
# TUNNEL HEALTH (Phase 12)
# ---------------------------------------------------------------------------------------

def _status(**kw):
    base = dict(interface_up=True, last_handshake_age_s=10,
                routes=("10.0.0.0/16",), dns_ok=True, peer_reachable=True)
    base.update(kw)
    return wireguard.TunnelStatus(**base)


def test_healthy_tunnel_passes_preflight():
    """Test 16 (the positive case)."""
    status = wireguard.preflight(
        site_id=uuid.uuid4(), authorized_cidrs=["10.0.0.0/16"],
        probe=wireguard.StaticTunnelProbe(_status()),
    )
    assert status.interface_up


@pytest.mark.parametrize("status,expected", [
    (_status(interface_up=False), wireguard.REASON_TUNNEL_UNHEALTHY),
    (_status(last_handshake_age_s=None), wireguard.REASON_NO_HANDSHAKE),
    (_status(last_handshake_age_s=9999), wireguard.REASON_HANDSHAKE_STALE),
    (_status(peer_reachable=False), wireguard.REASON_PEER_UNREACHABLE),
    (_status(routes=()), wireguard.REASON_ROUTE_MISSING),
    (_status(dns_ok=False), wireguard.REASON_DNS_UNAVAILABLE),
])
def test_unhealthy_tunnel_blocks_the_scan(status, expected):
    """Tests 17/18: every unhealthy condition REFUSES with a specific, actionable reason
    -- a scan is never started optimistically on a tunnel that might be up."""
    with pytest.raises(wireguard.TunnelUnhealthy) as exc:
        wireguard.preflight(
            site_id=uuid.uuid4(), authorized_cidrs=["10.0.0.0/16"],
            probe=wireguard.StaticTunnelProbe(status),
        )
    assert exc.value.reason == expected


def test_missing_route_for_one_of_several_cidrs_blocks():
    """A partially-routed tunnel would silently skip part of the engagement, making
    'no findings' indistinguishable from 'not scanned'."""
    status = _status(routes=("10.0.0.0/16",))
    with pytest.raises(wireguard.TunnelUnhealthy) as exc:
        wireguard.assert_tunnel_healthy(
            status, authorized_cidrs=["10.0.0.0/16", "192.168.5.0/24"]
        )
    assert exc.value.reason == wireguard.REASON_ROUTE_MISSING
    assert "192.168.5.0/24" in exc.value.message


# ---------------------------------------------------------------------------------------
# SystemTunnelProbe -- the probe that reads a REAL tunnel.
#
# Driven with output captured verbatim from the disposable WireGuard lab (a real kernel
# tunnel to a throwaway peer), so these assert against what `wg`/`ip` actually print rather
# than against invented strings. The probe is read-only and must be fail-closed: anything it
# cannot observe has to become "unhealthy", never "assumed fine".
# ---------------------------------------------------------------------------------------

def _fake_runner(mapping):
    """Command runner returning captured output. Any unlisted command 'fails'."""
    def run(argv):
        return mapping.get(" ".join(argv), (1, ""))
    return run


# Captured from the lab: `ip -o link show wg0` on a live tunnel.
_LAB_LINK_UP = (
    0, "3: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN "
       "mode DEFAULT group default qlen 1000 link/none \n"
)
# Captured from the lab: one route, exactly the authorized CIDR.
_LAB_ROUTES = (0, "10.80.0.0/16 dev wg0 scope link \n")


def test_system_probe_reads_a_healthy_tunnel():
    """The lab's real state: interface up, recent handshake, exactly the authorized route."""
    import time

    recent = int(time.time()) - 30
    probe = wireguard.SystemTunnelProbe("wg0", runner=_fake_runner({
        "ip -o link show wg0": _LAB_LINK_UP,
        "ip -o route show dev wg0": _LAB_ROUTES,
        "wg show wg0 latest-handshakes": (0, f"dHsyX9zj3ciibKR7i50pOJnuLnxMqklY=\t{recent}\n"),
    }))
    status = probe.status("lab-site")
    assert status.interface_up is True
    assert status.routes == ("10.80.0.0/16",)
    assert 0 <= status.last_handshake_age_s <= 60
    # And the whole preflight passes for the CIDR that is actually routed.
    wireguard.preflight(site_id="lab", authorized_cidrs=["10.80.0.0/16"], probe=probe)


def test_system_probe_reports_never_handshaked_as_no_handshake():
    """`wg` prints 0 for a peer that has never completed a handshake -- that is NOT an
    epoch to subtract from, and must not read as 'a very old handshake'."""
    probe = wireguard.SystemTunnelProbe("wg0", runner=_fake_runner({
        "ip -o link show wg0": _LAB_LINK_UP,
        "ip -o route show dev wg0": _LAB_ROUTES,
        "wg show wg0 latest-handshakes": (0, "somekey=\t0\n"),
    }))
    assert probe.status("lab").last_handshake_age_s is None
    with pytest.raises(wireguard.TunnelUnhealthy) as exc:
        wireguard.preflight(site_id="lab", authorized_cidrs=["10.80.0.0/16"], probe=probe)
    assert exc.value.reason == wireguard.REASON_NO_HANDSHAKE


@pytest.mark.parametrize("broken", [
    "ip -o link show wg0",          # interface gone
    "ip -o route show dev wg0",     # no routes
    "wg show wg0 latest-handshakes",  # wg unavailable
])
def test_system_probe_is_fail_closed_when_it_cannot_observe(broken):
    """A missing binary, a permission error or an unreadable interface must REFUSE the
    scan. A probe that cannot see the tunnel must never be mistaken for one that saw a
    healthy tunnel."""
    import time

    mapping = {
        "ip -o link show wg0": _LAB_LINK_UP,
        "ip -o route show dev wg0": _LAB_ROUTES,
        "wg show wg0 latest-handshakes": (0, f"k=\t{int(time.time()) - 10}\n"),
    }
    mapping[broken] = (127, "")  # command not found
    probe = wireguard.SystemTunnelProbe("wg0", runner=_fake_runner(mapping))
    with pytest.raises(wireguard.TunnelUnhealthy):
        wireguard.preflight(site_id="lab", authorized_cidrs=["10.80.0.0/16"], probe=probe)


def test_system_probe_surfaces_a_default_route_instead_of_hiding_it():
    """A default route over the tunnel is what AllowedIPs forbids. It is recorded verbatim
    as 'default' so it can never silently satisfy a per-CIDR route requirement."""
    import time

    probe = wireguard.SystemTunnelProbe("wg0", runner=_fake_runner({
        "ip -o link show wg0": _LAB_LINK_UP,
        "ip -o route show dev wg0": (0, "default dev wg0 scope link \n"),
        "wg show wg0 latest-handshakes": (0, f"k=\t{int(time.time()) - 10}\n"),
    }))
    status = probe.status("lab")
    assert "default" in status.routes
    # A default route does NOT satisfy the authorized CIDR.
    with pytest.raises(wireguard.TunnelUnhealthy) as exc:
        wireguard.preflight(site_id="lab", authorized_cidrs=["10.80.0.0/16"], probe=probe)
    assert exc.value.reason == wireguard.REASON_ROUTE_MISSING


def test_system_probe_blocks_a_cidr_the_tunnel_does_not_route():
    """The lab's negative case: the site claims 10.90.0.0/16 but only 10.80.0.0/16 is
    routed, so the scan is refused rather than silently leaving part of it unscanned."""
    import time

    probe = wireguard.SystemTunnelProbe("wg0", runner=_fake_runner({
        "ip -o link show wg0": _LAB_LINK_UP,
        "ip -o route show dev wg0": _LAB_ROUTES,
        "wg show wg0 latest-handshakes": (0, f"k=\t{int(time.time()) - 10}\n"),
    }))
    with pytest.raises(wireguard.TunnelUnhealthy) as exc:
        wireguard.preflight(site_id="lab", authorized_cidrs=["10.90.0.0/16"], probe=probe)
    assert exc.value.reason == wireguard.REASON_ROUTE_MISSING


def test_a_private_worker_gets_a_real_probe_not_none():
    """Regression: `_build_tunnel_probe` used to return None for a private worker, which
    made private scanning permanently fail-closed (safe, but non-functional)."""
    from apps.api.scanner_worker.lease_loop import WorkerIdentity
    from apps.api.scanner_worker.main import _build_tunnel_probe

    private = WorkerIdentity(worker_id="w", pool_id="p", site_id=str(uuid.uuid4()),
                             manager_url="http://m:8100", token="t")
    probe = _build_tunnel_probe(private)
    assert isinstance(probe, wireguard.SystemTunnelProbe)

    # A PUBLIC worker still gets None -- it has no tunnel and needs no probe.
    public = WorkerIdentity(worker_id="w", pool_id="public-default", site_id=None,
                            manager_url="http://m:8100", token="t")
    assert _build_tunnel_probe(public) is None
