"""MBS.SC -- DEDICATED VPN EGRESS for public scanner traffic.

    Public VPN Scanner -> Dedicated VPN/WireGuard Egress -> Internet Target

WHAT THESE TESTS ARE ACTUALLY PROTECTING
-----------------------------------------
The failure this feature exists to prevent is NOT "the scan breaks". It is a scan that
SUCCEEDS while its traffic left from the platform's own address -- reported as a normal,
completed scan, with nothing downstream to reveal it. Every fail-closed assertion below
exists because the alternative failure is silent.

Four groups, in the order a packet meets them:

  1. THE PRIVATE PATH IS UNCHANGED. `build_allowed_ips` still refuses a default route,
     the private tunnel is still split, and no new code path can relax either. These are
     regression LOCKS: they fail if someone "unifies" the two tunnel implementations.
  2. EGRESS HEALTH IS FAIL-CLOSED. Every degraded observation -- down, stale, no route, no
     rule, no kill-switch, unknown/stale/mismatched exit IP -- refuses.
  3. ROUTING AND ISOLATION. The main table keeps its default route (control plane stays
     reachable), the kill-switch denies by default, and the two worker roles cannot be
     combined or cross-assigned.
  4. LEASE AUTHORIZATION. A vpn-required scan cannot be handed to a direct worker, on
     either side of the boundary.

Deterministic: no Docker, no network, no live tunnel. Probes and command runners are
injected, which is the same technique the private-tunnel tests use.
"""
from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

import pytest
import yaml

from apps.api.core.config import Settings, get_settings
from apps.api.scanner_engine import vpn_egress, wireguard
from apps.api.scanner_worker import egress_setup, lease_loop

REPO_ROOT = Path(__file__).resolve().parents[3]
BASE_COMPOSE = REPO_ROOT / "infra" / "docker-compose.yml"
VPN_COMPOSE = REPO_ROOT / "infra" / "docker-compose.vpn-egress.yml"
SITE_COMPOSE = REPO_ROOT / "infra" / "docker-compose.private-site.yml"


def _compose(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def healthy_status(**overrides) -> vpn_egress.EgressStatus:
    """A fully healthy egress observation. Tests degrade ONE field at a time from here, so
    each failure assertion is unambiguous about which condition caused it."""
    base = dict(
        interface_up=True,
        last_handshake_age_s=10,
        default_route_in_table=True,
        policy_rule_present=True,
        main_table_untouched=True,
        observed_exit_ip="185.199.109.200",
        exit_ip_age_s=5,
        killswitch_active=True,
        mtu=1420,
    )
    base.update(overrides)
    return vpn_egress.EgressStatus(**base)


def egress_config(**overrides) -> vpn_egress.EgressConfig:
    kwargs = dict(
        interface_address="10.66.66.2/32",
        peer_public_key="cHViOnBlZXI=",
        endpoint_host="185.199.108.153",
        endpoint_port=51820,
    )
    kwargs.update(overrides)
    return vpn_egress.describe_config(**kwargs)


# =======================================================================================
# 1. THE PRIVATE PATH IS UNCHANGED  (regression locks)
# =======================================================================================

@pytest.mark.parametrize("default_route", ["0.0.0.0/0", "::/0"])
def test_private_build_allowed_ips_still_refuses_default_routes(default_route):
    """THE LOCK. The VPN-egress feature adds a FULL tunnel elsewhere; this must not have
    softened the private path's refusal, which is what keeps one customer's tunnel from
    capturing every other tenant's traffic."""
    with pytest.raises(wireguard.WireGuardConfigError):
        wireguard.build_allowed_ips([default_route])


@pytest.mark.parametrize("zero_prefix", ["0.0.0.0/0", "10.0.0.0/0", "::/0"])
def test_private_build_allowed_ips_refuses_any_prefixlen_zero(zero_prefix):
    """Refused by PREFIX LENGTH, not by string match -- so a novel spelling of a default
    route cannot slip past."""
    with pytest.raises(wireguard.WireGuardConfigError):
        wireguard.build_allowed_ips([zero_prefix])


def test_private_allowed_ips_are_still_exactly_the_authorized_cidrs():
    """The private tunnel stays SPLIT. A full tunnel here would be the exact defect the
    VPN-egress design was kept separate to avoid introducing."""
    assert wireguard.build_allowed_ips(["10.1.0.0/16", "192.168.5.0/24"]) == [
        "10.1.0.0/16", "192.168.5.0/24"
    ]


def test_private_render_still_refuses_a_default_route_config():
    config = wireguard.TunnelConfig(
        site_id="s1", interface_address="10.99.0.2/32",
        allowed_ips=("0.0.0.0/0",), peer_public_key="k", endpoint="host:51820",
    )
    with pytest.raises(wireguard.WireGuardConfigError):
        wireguard.render_worker_config(config, private_key="secret")


def test_the_two_tunnel_modules_do_not_share_an_allowed_ips_builder():
    """Structural lock: `vpn_egress` must not reach into `wireguard.build_allowed_ips`.

    If it did, the full tunnel would need a bypass flag on that function -- and one bad
    call site would then re-open the PRIVATE path to 0.0.0.0/0. Keeping them disjoint is
    what lets the private refusal stay unconditional."""
    import ast

    path = REPO_ROOT / "apps" / "api" / "scanner_engine" / "vpn_egress.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))

    # Parsed rather than grepped, deliberately: the module's own docstring DISCUSSES
    # `build_allowed_ips` at length (explaining why the two paths are separate), and a
    # plain substring search would trip on that prose. What must be absent is a real
    # import or a real call, which is what the AST shows.
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            imported += [f"{node.module}.{a.name}" for a in node.names]
    assert not any("wireguard" in name for name in imported), \
        f"vpn_egress imports the private tunnel module: {imported}"

    called = {
        node.func.id for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    } | {
        node.func.attr for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "build_allowed_ips" not in called, \
        "vpn_egress calls the private path's AllowedIPs builder"


def test_vpn_egress_is_a_full_tunnel_by_construction():
    """The inverse of the private rule, stated positively: this tunnel IS 0.0.0.0/0, and
    it is not a parameter -- a 'partial' VPN egress would silently send some target
    traffic out the platform's own address."""
    config = egress_config()
    assert config.allowed_ips == ("0.0.0.0/0",)
    assert config.is_full_tunnel


# =======================================================================================
# 2. EGRESS HEALTH IS FAIL-CLOSED
# =======================================================================================

def test_healthy_egress_passes_preflight():
    status = vpn_egress.preflight(probe=vpn_egress.StaticEgressProbe(healthy_status()))
    assert status.observed_exit_ip == "185.199.109.200"


@pytest.mark.parametrize("overrides,expected", [
    ({"interface_up": False}, vpn_egress.REASON_EGRESS_DOWN),
    ({"last_handshake_age_s": None}, vpn_egress.REASON_EGRESS_NO_HANDSHAKE),
    ({"last_handshake_age_s": 9999}, vpn_egress.REASON_EGRESS_HANDSHAKE_STALE),
    ({"default_route_in_table": False}, vpn_egress.REASON_EGRESS_ROUTE_MISSING),
    ({"policy_rule_present": False}, vpn_egress.REASON_EGRESS_RULE_MISSING),
    ({"main_table_untouched": False}, vpn_egress.REASON_EGRESS_LEAK),
    ({"killswitch_active": False}, vpn_egress.REASON_EGRESS_KILLSWITCH_MISSING),
    ({"observed_exit_ip": None}, vpn_egress.REASON_EGRESS_EXIT_IP_UNKNOWN),
    ({"exit_ip_age_s": 9999}, vpn_egress.REASON_EGRESS_EXIT_IP_STALE),
])
def test_every_degraded_observation_refuses(overrides, expected):
    """One field degraded at a time. EVERY one is a refusal -- there is no 'probably fine'
    state, because the alternative is a scan running over an unverified path."""
    probe = vpn_egress.StaticEgressProbe(healthy_status(**overrides))
    with pytest.raises(vpn_egress.EgressUnhealthy) as exc:
        vpn_egress.preflight(probe=probe)
    assert exc.value.reason == expected


def test_exit_ip_mismatch_against_a_pinned_address_refuses():
    """Tunnel-up + handshake + routes + rules ALL healthy, and it still refuses: the
    observed exit IP is not the VPN's. This is the check that catches traffic which never
    entered the tunnel despite the tunnel being perfectly alive."""
    probe = vpn_egress.StaticEgressProbe(healthy_status(observed_exit_ip="185.199.110.99"))
    with pytest.raises(vpn_egress.EgressUnhealthy) as exc:
        vpn_egress.preflight(probe=probe, expected_exit_ip="185.199.109.200")
    assert exc.value.reason == vpn_egress.REASON_EGRESS_EXIT_IP_MISMATCH


def test_observing_the_platforms_own_address_refuses_even_without_a_pin():
    """The unpinned case still catches the important failure: seeing the platform's own
    direct egress address is positive proof the VPN was bypassed."""
    probe = vpn_egress.StaticEgressProbe(healthy_status(observed_exit_ip="93.184.216.34"))
    with pytest.raises(vpn_egress.EgressUnhealthy) as exc:
        vpn_egress.preflight(probe=probe, forbidden_exit_ips=["93.184.216.34"])
    assert exc.value.reason == vpn_egress.REASON_EGRESS_EXIT_IP_MISMATCH


def test_matching_pinned_exit_ip_passes():
    probe = vpn_egress.StaticEgressProbe(healthy_status(observed_exit_ip="185.199.109.200"))
    vpn_egress.preflight(probe=probe, expected_exit_ip="185.199.109.200",
                         forbidden_exit_ips=["93.184.216.34"])


def test_a_non_public_vpn_endpoint_is_refused():
    """The VPN endpoint is one of the very few destinations the kill-switch lets out
    directly, so a platform-internal 'endpoint' would be a hole straight through the
    egress policy."""
    for bad in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254"):
        with pytest.raises(vpn_egress.VpnEgressConfigError):
            egress_config(endpoint_host=bad)


def test_incomplete_egress_configuration_is_refused():
    with pytest.raises(vpn_egress.VpnEgressConfigError):
        egress_config(peer_public_key="")
    with pytest.raises(vpn_egress.VpnEgressConfigError):
        egress_config(endpoint_host="")
    with pytest.raises(vpn_egress.VpnEgressConfigError):
        egress_config(interface_address="")


def test_rendered_egress_config_never_appears_in_the_key_free_view():
    """Same discipline as the private tunnel: `EgressConfig` carries no private key, so it
    is safe to log and assert on. The key exists only in the rendered text."""
    config = egress_config()
    assert "supersecretkey" not in repr(config)
    rendered = vpn_egress.render_egress_config(config, private_key="supersecretkey")
    assert "supersecretkey" in rendered
    # Table = off: wg-quick would otherwise install 0.0.0.0/0 into the MAIN table and
    # capture the manager connection.
    assert "Table = off" in rendered
    assert "AllowedIPs = 0.0.0.0/0" in rendered
    # DNS= is never set -- it would rewrite the whole namespace resolver.
    assert "DNS =" not in rendered


def test_render_refuses_without_a_private_key():
    with pytest.raises(vpn_egress.VpnEgressConfigError):
        vpn_egress.render_egress_config(egress_config(), private_key="")


# =======================================================================================
# 3. ROUTING, KILL-SWITCH, AND THE SYSTEM PROBE
# =======================================================================================

class FakeRunner:
    """Records argv and replays canned (rc, stdout) by command prefix."""

    def __init__(self, responses: dict) -> None:
        self.responses = responses
        self.calls: list[list] = []

    def __call__(self, argv):
        self.calls.append(list(argv))
        key = " ".join(str(a) for a in argv)
        for prefix, result in self.responses.items():
            if key.startswith(prefix):
                return result
        return 1, ""


def test_policy_routing_never_writes_to_the_main_table():
    """THE CONTROL-PLANE INVARIANT. Every route this installs must name the dedicated
    table. A default route in the main table would put the manager connection, and every
    control-plane call, inside the VPN."""
    config = egress_config()
    calls = []

    def fake_run(argv, timeout=10.0):
        calls.append(list(argv))
        return 0, "", ""

    import apps.api.scanner_worker.egress_setup as mod

    original = mod._run
    mod._run = fake_run
    try:
        egress_setup.install_policy_routing(config)
    finally:
        mod._run = original

    route_cmds = [c for c in calls if c[:2] == ["ip", "route"]]
    assert route_cmds, "no route was installed at all"
    for cmd in route_cmds:
        assert "table" in cmd, f"route installed without a table: {cmd}"
        assert str(config.table) in cmd, f"route not in the dedicated table: {cmd}"
        assert "main" not in cmd, f"route written to the MAIN table: {cmd}"


def test_policy_routing_installs_the_fwmark_carve_out():
    """Without the fwmark rule the tunnel's own encrypted UDP is routed back into the
    tunnel -- the classic full-tunnel loop, which simply never connects."""
    config = egress_config()
    calls = []

    def fake_run(argv, timeout=10.0):
        calls.append(list(argv))
        return 0, "", ""

    import apps.api.scanner_worker.egress_setup as mod

    original = mod._run
    mod._run = fake_run
    try:
        egress_setup.install_policy_routing(config)
    finally:
        mod._run = original

    flat = [" ".join(c) for c in calls]
    assert any("fwmark" in f and "lookup main" in f for f in flat), \
        "the fwmark carve-out to the main table was not installed"
    assert any("suppress_prefixlength 0" in f for f in flat), \
        "the suppress_prefixlength rule that keeps dispatch traffic on main is missing"
    assert any(f"lookup {config.table}" in f for f in flat), \
        "the catch-all rule into the egress table is missing"


def test_main_table_hijack_is_detected_and_refused():
    """Verified as an INDEPENDENT observation after bring-up, not inferred from what we
    installed: a route can be inherited from a restarted container or added by an
    operator."""
    config = egress_config()

    def fake_run(argv, timeout=10.0):
        return 0, f"default dev {config.interface} scope link", ""

    import apps.api.scanner_worker.egress_setup as mod

    original = mod._run
    mod._run = fake_run
    try:
        with pytest.raises(egress_setup.EgressSetupError) as exc:
            egress_setup.assert_main_table_untouched(config)
    finally:
        mod._run = original
    assert exc.value.reason == egress_setup.REASON_MAIN_TABLE_HIJACKED


def test_main_table_with_an_ordinary_default_route_is_accepted():
    """The CORRECT state: main's default is the container's own gateway, so control-plane
    traffic keeps its ordinary path."""
    config = egress_config()

    def fake_run(argv, timeout=10.0):
        return 0, "default via 172.20.0.1 dev eth0", ""

    import apps.api.scanner_worker.egress_setup as mod

    original = mod._run
    mod._run = fake_run
    try:
        egress_setup.assert_main_table_untouched(config)  # must not raise
    finally:
        mod._run = original


def test_killswitch_denies_by_default_and_permits_only_the_narrow_set():
    """The kill-switch is a FIREWALL, not a Python check: it must end in DROP, and the
    only path to a target must be `-o wg-egress`."""
    config = egress_config()
    calls = []

    def fake_run(argv, timeout=10.0):
        calls.append(list(argv))
        # `-C OUTPUT -j CHAIN` must report "not present" so the jump gets appended.
        if argv[:2] == ["iptables", "-C"]:
            return 1, "", ""
        return 0, "", ""

    import apps.api.scanner_worker.egress_setup as mod

    original = mod._run
    mod._run = fake_run
    try:
        egress_setup.install_killswitch(
            config, dispatch_cidrs=["172.20.0.0/16"], endpoint_ip="185.199.108.153"
        )
    finally:
        mod._run = original

    appended = [" ".join(c) for c in calls if c[:2] == ["iptables", "-A"]]
    # Rules INSIDE the chain only -- the `-A OUTPUT -j MBS_VPN_EGRESS` jump that hooks the
    # chain up is appended to OUTPUT, not to the chain, and is asserted separately below.
    chain_rules = [
        a for a in appended
        if a.startswith(f"iptables -A {egress_setup.KILLSWITCH_CHAIN}")
    ]

    # Terminal DROP, and it must be LAST -- a DROP before the ACCEPTs would deny everything.
    assert chain_rules[-1].endswith("-j DROP"), f"chain does not end in DROP: {chain_rules}"
    # Target traffic permitted ONLY out the tunnel.
    assert any(f"-o {config.interface} -j ACCEPT" in r for r in chain_rules)
    # The VPN endpoint, restricted to one address and port -- not "all UDP".
    assert any("185.199.108.153/32" in r and "--dport 51820" in r for r in chain_rules)
    # The dispatch plane, so the manager stays reachable.
    assert any("172.20.0.0/16" in r and "ACCEPT" in r for r in chain_rules)
    # And the chain is actually hooked into OUTPUT, or it would be inert.
    assert any("OUTPUT -j " + egress_setup.KILLSWITCH_CHAIN in a for a in appended)


def test_killswitch_refuses_a_default_route_dispatch_exception():
    """A /0 'exception' would accept everything and silently defeat the entire policy."""
    config = egress_config()

    def fake_run(argv, timeout=10.0):
        return 0, "", ""

    import apps.api.scanner_worker.egress_setup as mod

    original = mod._run
    mod._run = fake_run
    try:
        with pytest.raises(egress_setup.EgressSetupError) as exc:
            egress_setup.install_killswitch(
                config, dispatch_cidrs=["0.0.0.0/0"], endpoint_ip="185.199.108.153"
            )
    finally:
        mod._run = original
    assert exc.value.reason == egress_setup.REASON_KILLSWITCH_FAILED


def test_killswitch_is_installed_before_the_tunnel_comes_up():
    """ORDER IS THE SECURITY PROPERTY. A worker that dies between start and a healthy
    tunnel must fail closed, so the firewall must precede the interface."""
    config = egress_config()
    order = []

    def fake_run(argv, timeout=10.0):
        if argv[0] == "iptables":
            order.append("firewall")
            if argv[:2] == ["iptables", "-C"]:
                return 1, "", ""
        elif argv[:3] == ["ip", "link", "add"]:
            order.append("tunnel")
        return 0, "", ""

    import apps.api.scanner_worker.egress_setup as mod

    original = mod._run
    mod._run = fake_run
    try:
        egress_setup.assert_tooling_present()
        endpoint_ip = egress_setup.resolve_endpoint_ip(config)
        egress_setup.install_killswitch(
            config, dispatch_cidrs=["172.20.0.0/16"], endpoint_ip=endpoint_ip
        )
        egress_setup.bring_up(config, private_key="k")
    finally:
        mod._run = original

    assert "firewall" in order and "tunnel" in order
    assert order.index("firewall") < order.index("tunnel"), \
        "the tunnel was created before the kill-switch: the startup window is open"


def test_missing_iptables_refuses_to_start():
    """A VPN-egress worker without a kill-switch cannot fail closed, so it must not run."""
    def fake_run(argv, timeout=10.0):
        if argv[0] == "iptables":
            return 127, "", "iptables: not found"
        return 0, "ok", ""

    import apps.api.scanner_worker.egress_setup as mod

    original = mod._run
    mod._run = fake_run
    try:
        with pytest.raises(egress_setup.EgressSetupError) as exc:
            egress_setup.assert_tooling_present()
    finally:
        mod._run = original
    assert exc.value.reason == egress_setup.REASON_TOOLING_MISSING
    assert "iptables" in exc.value.message


def test_missing_private_key_file_refuses_to_start():
    with pytest.raises(egress_setup.EgressSetupError) as exc:
        egress_setup.read_private_key("")
    assert exc.value.reason == egress_setup.REASON_NO_PRIVATE_KEY
    with pytest.raises(egress_setup.EgressSetupError):
        egress_setup.read_private_key("/nonexistent/path/to/key")


def test_system_probe_reads_a_healthy_path():
    import time

    now = int(time.time())
    config = egress_config()
    runner = FakeRunner({
        f"ip -o link show {config.interface}": (
            0, f"5: {config.interface}: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 ..."
        ),
        f"wg show {config.interface} latest-handshakes": (0, f"peerkey\t{now - 20}"),
        f"ip -o route show default table {config.table}": (
            0, f"default dev {config.interface} scope link"
        ),
        "ip rule show": (0, f"9200:\tfrom all lookup {config.table}"),
        "ip -o route show default table main": (0, "default via 172.20.0.1 dev eth0"),
    })
    probe = egress_setup.SystemEgressProbe(
        config, runner=runner, exit_ip_observer=lambda: "185.199.109.200"
    )
    status = probe.status()
    assert status.interface_up
    assert status.last_handshake_age_s is not None and status.last_handshake_age_s < 60
    assert status.default_route_in_table
    assert status.policy_rule_present
    assert status.main_table_untouched
    assert status.observed_exit_ip == "185.199.109.200"


def test_system_probe_reports_down_when_it_cannot_observe():
    """A probe that cannot see the path must NEVER be mistaken for one that saw a healthy
    path -- the same discipline as SystemTunnelProbe."""
    config = egress_config()
    runner = FakeRunner({})  # everything returns rc=1
    probe = egress_setup.SystemEgressProbe(
        config, runner=runner, exit_ip_observer=lambda: None
    )
    status = probe.status()
    assert status.interface_up is False
    with pytest.raises(vpn_egress.EgressUnhealthy):
        vpn_egress.assert_egress_healthy(status)


def test_system_probe_detects_a_hijacked_main_table():
    import time

    now = int(time.time())
    config = egress_config()
    runner = FakeRunner({
        f"ip -o link show {config.interface}": (0, f"5: {config.interface}: <UP> mtu 1420"),
        f"wg show {config.interface} latest-handshakes": (0, f"peerkey\t{now - 5}"),
        f"ip -o route show default table {config.table}": (
            0, f"default dev {config.interface}"
        ),
        "ip rule show": (0, f"9200:\tfrom all lookup {config.table}"),
        # The MAIN table's default now points at the tunnel: control-plane traffic would
        # be inside the VPN.
        "ip -o route show default table main": (0, f"default dev {config.interface}"),
    })
    probe = egress_setup.SystemEgressProbe(
        config, runner=runner, exit_ip_observer=lambda: "185.199.109.200"
    )
    assert probe.status().main_table_untouched is False


def test_a_failed_exit_ip_observation_invalidates_the_cache():
    """A stale-but-successful reading returned after a failure is exactly how a dropped
    tunnel would keep looking healthy."""
    config = egress_config()
    answers = ["185.199.109.200", None]
    probe = egress_setup.SystemEgressProbe(
        config, runner=FakeRunner({}), exit_ip_observer=lambda: answers.pop(0),
        exit_ip_ttl_s=0,
    )
    assert probe._exit_ip()[0] == "185.199.109.200"
    assert probe._exit_ip()[0] is None, "a failed observation returned a cached value"


def test_exit_ip_observation_ignores_ambient_proxy_settings(monkeypatch):
    """An inherited HTTP(S)_PROXY would make the answer describe the PROXY's egress, not
    this worker's -- which is not evidence of anything."""
    source = (REPO_ROOT / "apps" / "api" / "scanner_worker" / "egress_setup.py").read_text(
        encoding="utf-8"
    )
    assert "trust_env=False" in source


def test_unparsable_exit_ip_response_is_unknown_not_accepted():
    assert egress_setup.observe_exit_ip(url="") is None


# =======================================================================================
# 4. WORKER-SIDE: PER-JOB PREFLIGHT, MODE MISMATCH, MID-SCAN LOSS
# =======================================================================================

def public_job(**overrides) -> dict:
    job = {
        "scan_id": str(uuid.uuid4()),
        "workspace_id": str(uuid.uuid4()),
        "execution_token": str(uuid.uuid4()),
        "network_zone": "public",
        "site_id": None,
        "target": {"id": str(uuid.uuid4()), "type": "domain", "value": "example.com"},
    }
    job.update(overrides)
    return job


def vpn_identity(**overrides) -> lease_loop.WorkerIdentity:
    kwargs = dict(
        worker_id="worker-vpn-egress", pool_id="public-vpn-egress",
        manager_url="http://scanner-manager:8100", token="t", egress_mode="vpn",
    )
    kwargs.update(overrides)
    return lease_loop.WorkerIdentity(**kwargs)


def direct_identity(**overrides) -> lease_loop.WorkerIdentity:
    kwargs = dict(
        worker_id="worker", pool_id="public-default",
        manager_url="http://scanner-manager:8100", token="t", egress_mode="direct",
    )
    kwargs.update(overrides)
    return lease_loop.WorkerIdentity(**kwargs)


def test_a_vpn_worker_with_no_probe_refuses_the_job():
    """A missing probe is a REFUSAL, not a pass: without one we cannot show target traffic
    is on the VPN, and 'probably still tunnelled' is not a basis for scanning."""
    with pytest.raises(lease_loop.LeaseError) as exc:
        lease_loop.preflight_egress_job(
            public_job(), identity=vpn_identity(), probe=None
        )
    assert exc.value.reason == lease_loop.REASON_EGRESS_UNHEALTHY


def test_a_direct_worker_needs_no_egress_probe():
    """Unchanged behaviour for every existing deployment: a direct worker has no VPN path
    to verify, so this gate is a no-op for it."""
    lease_loop.preflight_egress_job(public_job(), identity=direct_identity(), probe=None)


def test_unhealthy_egress_refuses_the_job_with_the_specific_reason():
    probe = vpn_egress.StaticEgressProbe(healthy_status(observed_exit_ip=None))
    with pytest.raises(lease_loop.LeaseError) as exc:
        lease_loop.preflight_egress_job(
            public_job(), identity=vpn_identity(), probe=probe
        )
    assert exc.value.reason == vpn_egress.REASON_EGRESS_EXIT_IP_UNKNOWN


def test_healthy_egress_admits_the_job():
    probe = vpn_egress.StaticEgressProbe(healthy_status())
    lease_loop.preflight_egress_job(public_job(), identity=vpn_identity(), probe=probe)


def test_a_vpn_required_job_is_refused_by_a_direct_worker():
    """The worker's INDEPENDENT restatement of the manager's rule. A compromised or
    impersonated manager still cannot make a direct worker run a scan that was required to
    leave via the VPN -- which would have run from the platform's own address."""
    job = public_job(required_egress_mode="vpn")
    with pytest.raises(lease_loop.LeaseError) as exc:
        lease_loop.validate_leased_job(job, direct_identity())
    assert exc.value.reason == lease_loop.REASON_EGRESS_MODE_MISMATCH


def test_a_direct_required_job_is_refused_by_a_vpn_worker():
    """Fails closed in BOTH directions: misattributing ordinary traffic to the shared exit
    IP consumes its reputation on behalf of scans that never asked for it."""
    job = public_job(required_egress_mode="direct")
    with pytest.raises(lease_loop.LeaseError) as exc:
        lease_loop.validate_leased_job(job, vpn_identity())
    assert exc.value.reason == lease_loop.REASON_EGRESS_MODE_MISMATCH


def test_a_job_with_no_requirement_runs_on_either_worker():
    """Backwards compatibility: every scan created before this feature carries no
    requirement and must keep working on any public worker."""
    lease_loop.validate_leased_job(public_job(), direct_identity())
    lease_loop.validate_leased_job(public_job(), vpn_identity())


def test_a_vpn_worker_still_cannot_take_a_private_job():
    """The VPN worker is a PUBLIC worker with no site binding, so the existing zone/site
    gate refuses private work -- which is what stops the full tunnel from ever becoming a
    path into a customer network."""
    job = public_job(
        network_zone="private", site_id=str(uuid.uuid4()),
        authorized_cidrs=["10.0.0.0/16"],
    )
    with pytest.raises(lease_loop.LeaseError) as exc:
        lease_loop.validate_leased_job(job, vpn_identity())
    assert exc.value.reason in (
        lease_loop.REASON_SITE_MISMATCH, lease_loop.REASON_WORKER_UNAUTHORIZED,
    )


def test_a_vpn_scan_still_gets_a_public_only_policy():
    """net_policy is untouched by this feature: a VPN-egress scan authorizes NO private
    CIDR. The VPN changes which public IP traffic leaves from, never what may be reached."""
    policy = lease_loop.build_policy_for_job(public_job(required_egress_mode="vpn"))
    assert policy.network_zone == "public"
    assert policy.is_private is False
    assert policy.authorized_cidrs == ()
    import ipaddress
    assert policy.allows_private_ip(ipaddress.ip_address("10.0.0.5")) is False


def test_identity_egress_mode_is_explicit_not_inferred():
    """Declared, never derived from the presence of a key file: a secret that failed to
    mount must not silently downgrade a VPN worker to a direct one."""
    assert vpn_identity().is_vpn_egress is True
    assert direct_identity().is_vpn_egress is False
    # A public worker that merely HAS egress settings is still direct unless it says so.
    assert lease_loop.WorkerIdentity(
        worker_id="w", pool_id="p", egress_mode="direct"
    ).is_vpn_egress is False


# -- mid-scan loss ----------------------------------------------------------------------

class FlappingProbe(vpn_egress.EgressProbe):
    """Healthy for `healthy_calls` observations, then permanently unhealthy."""

    def __init__(self, healthy_calls: int = 1) -> None:
        self.calls = 0
        self.healthy_calls = healthy_calls

    def status(self) -> vpn_egress.EgressStatus:
        self.calls += 1
        if self.calls <= self.healthy_calls:
            return healthy_status()
        return healthy_status(interface_up=False, detail="tunnel dropped")


def test_midscan_egress_loss_cancels_the_scan(monkeypatch):
    """THE CENTRAL MID-SCAN TEST. Per-job preflight gates the START of a scan and says
    nothing about the next 40 minutes. A tunnel that dies mid-scan must FAIL the scan, not
    let the remaining tools continue over direct egress and report a completed scan."""
    settings = get_settings()
    monkeypatch.setattr(settings, "scanner_vpn_egress_recheck_seconds", 5, raising=False)
    monkeypatch.setattr(settings, "scanner_vpn_egress_expected_exit_ip", "", raising=False)

    loop = lease_loop.LeaseLoop(
        vpn_identity(), client=None, egress_probe=FlappingProbe(healthy_calls=0),
    )

    async def run_it():
        # Interval is clamped to >= 5s, so drive the sleep instead of waiting on it.
        async def no_sleep(_seconds):
            return None

        monkeypatch.setattr(asyncio, "sleep", no_sleep)
        with pytest.raises(lease_loop.LeaseError) as exc:
            await loop._watch_egress_while_running()
        return exc.value

    err = asyncio.run(run_it())
    assert err.reason == lease_loop.REASON_EGRESS_LOST_MIDSCAN


def test_midscan_watchdog_treats_an_unreadable_probe_as_loss(monkeypatch):
    """Unknown is NOT healthy. This is the one place the egress watchdog deliberately
    differs from the heartbeat, which swallows everything: a missed heartbeat costs
    liveness reporting, while a missed egress check costs the guarantee the scan is sold
    on."""
    settings = get_settings()
    monkeypatch.setattr(settings, "scanner_vpn_egress_recheck_seconds", 5, raising=False)

    class ExplodingProbe(vpn_egress.EgressProbe):
        def status(self):
            raise OSError("probe exploded")

    loop = lease_loop.LeaseLoop(
        vpn_identity(), client=None, egress_probe=ExplodingProbe()
    )

    async def run_it():
        async def no_sleep(_seconds):
            return None

        monkeypatch.setattr(asyncio, "sleep", no_sleep)
        with pytest.raises(lease_loop.LeaseError) as exc:
            await loop._watch_egress_while_running()
        return exc.value

    err = asyncio.run(run_it())
    assert err.reason == lease_loop.REASON_EGRESS_LOST_MIDSCAN


def test_midscan_watchdog_forces_a_fresh_exit_ip_observation(monkeypatch):
    """A cached reading taken before the tunnel dropped is exactly the evidence that would
    hide the drop, so the watchdog must invalidate it first."""
    settings = get_settings()
    monkeypatch.setattr(settings, "scanner_vpn_egress_recheck_seconds", 5, raising=False)

    invalidated = []

    class RecordingProbe(vpn_egress.EgressProbe):
        def invalidate_exit_ip(self):
            invalidated.append(True)

        def status(self):
            return healthy_status(interface_up=False)

    loop = lease_loop.LeaseLoop(
        vpn_identity(), client=None, egress_probe=RecordingProbe()
    )

    async def run_it():
        async def no_sleep(_seconds):
            return None

        monkeypatch.setattr(asyncio, "sleep", no_sleep)
        with pytest.raises(lease_loop.LeaseError):
            await loop._watch_egress_while_running()

    asyncio.run(run_it())
    assert invalidated, "the watchdog accepted a cached exit-IP observation"


def test_a_direct_worker_gets_no_watchdog():
    """No VPN path, nothing to lose; the watchdog must not fire for a direct worker."""
    loop = lease_loop.LeaseLoop(direct_identity(), client=None, egress_probe=None)
    assert loop.identity.is_vpn_egress is False
    assert loop.egress_probe is None


def test_an_egress_refusal_is_classified_as_a_job_rejection(monkeypatch):
    """CLASSIFICATION MATTERS (the O-1 lesson). An egress refusal must increment
    `rejected` and hand the scan back as FAILED -- not escape to the transport handler,
    where it would be logged as `manager_unavailable` and leave the scan sitting
    `running` until the orphan reaper noticed."""
    completions = []

    class FakeClient:
        async def lease(self, *a, **k):
            return []

        async def complete(self, scan_id, token, status, reason=None):
            completions.append((scan_id, status, reason))
            return {}

        async def heartbeat(self, **kw):
            return {}

    loop = lease_loop.LeaseLoop(
        vpn_identity(), client=FakeClient(),
        egress_probe=vpn_egress.StaticEgressProbe(healthy_status(interface_up=False)),
        executor=lambda job, policy: None,
    )

    async def fake_safe_complete(scan_id, token, status, reason=None):
        completions.append((scan_id, status, reason))

    monkeypatch.setattr(loop, "_safe_complete", fake_safe_complete)
    asyncio.run(loop._handle_job(public_job()))

    assert loop.stats["rejected"] == 1
    assert completions and completions[0][1] == "failed"
    assert completions[0][2] == vpn_egress.REASON_EGRESS_DOWN


# =======================================================================================
# 5. CONFIGURATION AND STARTUP VALIDATION
# =======================================================================================

def _exec_plane_settings(**overrides) -> Settings:
    env = dict(
        ENVIRONMENT="production",
        SCANNER_EXECUTION_PLANE="true",
        SCANNER_MANAGER_URL="http://scanner-manager:8100",
        SCANNER_WORKER_ID="worker-vpn-egress",
        SCANNER_POOL_ID="public-vpn-egress",
        SCANNER_WORKER_TOKEN="t" * 32,
    )
    env.update(overrides)
    return Settings(**{k.lower(): v for k, v in env.items()})


def test_vpn_mode_without_its_secrets_refuses_to_start():
    """Every one of these gaps produces the same dangerous symptom if left to runtime: a
    worker that believes it is a VPN worker while traffic leaves over the platform's own
    address. Fail at startup instead."""
    settings = _exec_plane_settings(
        SCANNER_EGRESS_MODE="vpn",
        SCANNER_VPN_EGRESS_DISPATCH_CIDRS="172.20.0.0/16",
    )
    with pytest.raises(RuntimeError) as exc:
        settings.validate_production()
    message = str(exc.value)
    assert "SCANNER_VPN_EGRESS_PRIVATE_KEY_FILE" in message
    assert "SCANNER_VPN_EGRESS_PEER_PUBLIC_KEY" in message


def test_vpn_mode_without_dispatch_cidrs_refuses_to_start():
    """The kill-switch denies by default, so an unnamed manager plane means the worker
    cannot reach its manager. Better to say so at startup than to look mysteriously
    disconnected."""
    settings = _exec_plane_settings(
        SCANNER_EGRESS_MODE="vpn",
        SCANNER_VPN_EGRESS_PRIVATE_KEY_FILE="/run/secrets/vpn_egress_private_key",
        SCANNER_VPN_EGRESS_PEER_PUBLIC_KEY="k",
        SCANNER_VPN_EGRESS_ENDPOINT_HOST="185.199.108.153",
        SCANNER_VPN_EGRESS_ADDRESS="10.66.66.2/32",
    )
    with pytest.raises(RuntimeError) as exc:
        settings.validate_production()
    assert "SCANNER_VPN_EGRESS_DISPATCH_CIDRS" in str(exc.value)


def test_vpn_mode_cannot_be_combined_with_a_site_binding():
    """The two roles are mutually exclusive: a container holding a customer's tunnel must
    never also be the platform's internet exit."""
    settings = _exec_plane_settings(
        SCANNER_EGRESS_MODE="vpn",
        SCANNER_SITE_ID=str(uuid.uuid4()),
        SCANNER_VPN_EGRESS_PRIVATE_KEY_FILE="/run/secrets/k",
        SCANNER_VPN_EGRESS_PEER_PUBLIC_KEY="k",
        SCANNER_VPN_EGRESS_ENDPOINT_HOST="185.199.108.153",
        SCANNER_VPN_EGRESS_ADDRESS="10.66.66.2/32",
        SCANNER_VPN_EGRESS_DISPATCH_CIDRS="172.20.0.0/16",
    )
    with pytest.raises(RuntimeError) as exc:
        settings.validate_production()
    assert "SCANNER_SITE_ID" in str(exc.value)


def test_an_unrecognised_egress_mode_is_refused_not_defaulted():
    """An unrecognised value must never fall back to direct -- that would be a silent
    downgrade to scanning from the platform's own address."""
    settings = _exec_plane_settings(SCANNER_EGRESS_MODE="vpnn")
    with pytest.raises(RuntimeError) as exc:
        settings.validate_production()
    assert "SCANNER_EGRESS_MODE" in str(exc.value)


def test_direct_mode_is_the_default_and_needs_nothing_extra():
    """Every existing deployment keeps working unchanged."""
    settings = _exec_plane_settings()
    assert settings.scanner_egress_mode == "direct"
    assert settings.vpn_egress_enabled is False
    settings.validate_production()  # must not raise


def test_a_fully_configured_vpn_worker_validates():
    settings = _exec_plane_settings(
        SCANNER_EGRESS_MODE="vpn",
        SCANNER_VPN_EGRESS_PRIVATE_KEY_FILE="/run/secrets/vpn_egress_private_key",
        SCANNER_VPN_EGRESS_PEER_PUBLIC_KEY="k",
        SCANNER_VPN_EGRESS_ENDPOINT_HOST="185.199.108.153",
        SCANNER_VPN_EGRESS_ADDRESS="10.66.66.2/32",
        SCANNER_VPN_EGRESS_DISPATCH_CIDRS="172.20.0.0/16",
    )
    settings.validate_production()
    assert settings.vpn_egress_enabled is True
    assert settings.vpn_egress_dispatch_cidr_list == ["172.20.0.0/16"]


# =======================================================================================
# 6. MANAGER-SIDE LEASE AUTHORIZATION
# =======================================================================================

class FakeWorker:
    def __init__(self, pool_id: str, worker_id: str = "w", site_id=None) -> None:
        self.pool_id = pool_id
        self.worker_id = worker_id
        self.site_id = site_id
        self.workspace_id = None
        self.status = "active"
        self.revoked_at = None


def test_worker_egress_mode_is_derived_from_persisted_pool_membership():
    """Derived from `pool_id` -- already persisted, operator-controlled and enforced at
    every authorization boundary -- rather than from anything the worker says about
    itself. A worker's self-description must never decide what it may be handed."""
    from apps.api.modules.scanner_workers import service as workers_service

    assert workers_service.worker_egress_mode(FakeWorker("public-vpn-egress")) == "vpn"
    assert workers_service.worker_egress_mode(FakeWorker("public-default")) == "direct"


def test_a_vpn_required_scan_is_refused_to_a_direct_worker():
    """THE CENTRAL MANAGER-SIDE TEST. Without this the scan runs from the platform's own
    address, succeeds, and reports normally -- with nothing downstream to reveal it."""
    from apps.api.modules.scanner_workers import service as workers_service

    with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
        workers_service.assert_worker_egress_mode(FakeWorker("public-default"), "vpn")
    assert exc.value.reason == workers_service.REASON_EGRESS_MODE_MISMATCH


def test_a_vpn_required_scan_is_allowed_on_a_vpn_worker():
    from apps.api.modules.scanner_workers import service as workers_service

    workers_service.assert_worker_egress_mode(FakeWorker("public-vpn-egress"), "vpn")


def test_a_direct_required_scan_is_refused_to_a_vpn_worker():
    from apps.api.modules.scanner_workers import service as workers_service

    with pytest.raises(workers_service.WorkerNotAuthorized):
        workers_service.assert_worker_egress_mode(FakeWorker("public-vpn-egress"), "direct")


def test_a_scan_with_no_requirement_is_allowed_anywhere():
    from apps.api.modules.scanner_workers import service as workers_service

    workers_service.assert_worker_egress_mode(FakeWorker("public-default"), None)
    workers_service.assert_worker_egress_mode(FakeWorker("public-vpn-egress"), "")


def test_a_private_scan_never_requires_vpn_egress():
    """Private traffic goes into the customer's tunnel, not out to the Internet. Pushing
    it through a platform VPN would be pointless and a cross-plane violation."""
    from apps.api.scanner_manager.app import required_scan_egress_mode

    class FakeScan:
        config = {"site_id": str(uuid.uuid4()), "required_egress_mode": "vpn"}

    assert required_scan_egress_mode(FakeScan()) is None


def test_a_public_scan_requirement_is_read_from_its_config():
    from apps.api.scanner_manager.app import required_scan_egress_mode

    class VpnScan:
        config = {"required_egress_mode": "vpn"}

    class PlainScan:
        config = {}

    assert required_scan_egress_mode(VpnScan()) == "vpn"
    assert required_scan_egress_mode(PlainScan()) is None


# =======================================================================================
# 7. COMPOSE / NETWORK TOPOLOGY
# =======================================================================================

@pytest.mark.skipif(not VPN_COMPOSE.exists(), reason="vpn-egress compose not present")
def test_egress_worker_is_not_on_core_edge_or_any_site_network():
    """STRUCTURAL ISOLATION. Enforced by Docker itself, so it holds even if every line of
    Python in this repo is ignored."""
    compose = _compose(VPN_COMPOSE)
    networks = compose["services"]["worker-vpn-egress"]["networks"]
    assert "mbs-core" not in networks, "the egress worker must have no route to a datastore"
    assert "mbs-edge" not in networks
    assert not any(str(n).startswith("mbs-site-") for n in networks), \
        "the egress worker must never be on a tenant site network"
    # It needs exactly these two: its own egress plane, and dispatch to reach the manager.
    assert "mbs-vpn-egress" in networks
    assert "mbs-dispatch" in networks


@pytest.mark.skipif(not VPN_COMPOSE.exists(), reason="vpn-egress compose not present")
def test_egress_worker_declares_no_site_binding():
    """No SCANNER_SITE_ID: it is a PUBLIC worker. With one it would be a private-site
    worker too, which config validation refuses outright."""
    compose = _compose(VPN_COMPOSE)
    env = compose["services"]["worker-vpn-egress"]["environment"]
    assert "SCANNER_SITE_ID" not in env
    assert env["SCANNER_EGRESS_MODE"] == "vpn"


@pytest.mark.skipif(not SITE_COMPOSE.exists(), reason="private-site compose not present")
def test_site_workers_are_not_on_the_egress_network():
    """The converse isolation: a tenant's site worker must never reach the platform VPN
    plane."""
    compose = _compose(SITE_COMPOSE)
    for name, svc in compose.get("services", {}).items():
        networks = svc.get("networks") or []
        assert "mbs-vpn-egress" not in networks, f"{name} is on the VPN egress network"


@pytest.mark.skipif(not SITE_COMPOSE.exists(), reason="private-site compose not present")
def test_the_private_site_template_is_unchanged_in_shape():
    """Regression lock on the private path's own topology: still its own per-site network,
    still no egress-plane membership, still no full tunnel."""
    raw = SITE_COMPOSE.read_text(encoding="utf-8")
    assert "0.0.0.0/0" not in raw, "a default route appeared in the private-site template"
    compose = _compose(SITE_COMPOSE)
    svc = compose["services"]["worker-site-SITE_SLUG"]
    assert "mbs-core" not in svc["networks"]
    assert svc["environment"]["SCANNER_WIREGUARD_INTERFACE"] == "wg0"


@pytest.mark.skipif(not VPN_COMPOSE.exists(), reason="vpn-egress compose not present")
def test_the_two_workers_use_different_interface_names():
    """`wg0` vs `wg-egress`: identical names would make logs, probes and operator commands
    ambiguous at exactly the moment clarity matters."""
    vpn_env = _compose(VPN_COMPOSE)["services"]["worker-vpn-egress"]["environment"]
    site_env = _compose(SITE_COMPOSE)["services"]["worker-site-SITE_SLUG"]["environment"]
    assert vpn_env["SCANNER_VPN_EGRESS_INTERFACE"] != site_env["SCANNER_WIREGUARD_INTERFACE"]


@pytest.mark.skipif(not VPN_COMPOSE.exists(), reason="vpn-egress compose not present")
def test_the_vpn_provider_key_is_a_file_secret_not_an_env_value():
    """A PLATFORM secret, and not in .env.scanner -- that file is shared with every tenant
    site worker, and an env var appears in `docker inspect` and every child process."""
    svc = _compose(VPN_COMPOSE)["services"]["worker-vpn-egress"]
    env = svc["environment"]
    assert "SCANNER_VPN_EGRESS_PRIVATE_KEY_FILE" in env
    assert "SCANNER_VPN_EGRESS_PRIVATE_KEY" not in env
    assert "vpn_egress_private_key" in svc["secrets"]
    # The key must not be smuggled in through the shared tenant env file either.
    scanner_env = REPO_ROOT / ".env.scanner.example"
    if scanner_env.exists():
        assert "VPN_EGRESS_PRIVATE_KEY=" not in scanner_env.read_text(encoding="utf-8")


@pytest.mark.skipif(not VPN_COMPOSE.exists(), reason="vpn-egress compose not present")
def test_egress_worker_drops_all_capabilities_except_the_three_it_needs():
    svc = _compose(VPN_COMPOSE)["services"]["worker-vpn-egress"]
    assert svc["cap_drop"] == ["ALL"]
    assert set(svc["cap_add"]) == {"NET_ADMIN", "SETUID", "SETGID"}
    assert "NET_RAW" not in svc["cap_add"]
    assert svc["read_only"] is True
    assert "no-new-privileges:true" in svc["security_opt"]
    assert svc.get("privileged") is not True
    # A tunnel ENDPOINT, not a router: forwarding would let a compromised worker bridge
    # the VPN to the dispatch plane.
    assert str(svc["sysctls"]["net.ipv4.ip_forward"]) == "0"


@pytest.mark.skipif(not VPN_COMPOSE.exists(), reason="vpn-egress compose not present")
def test_the_egress_network_is_separate_from_the_direct_scan_plane():
    """A direct public worker and the VPN worker must not share a broadcast domain."""
    vpn = _compose(VPN_COMPOSE)
    assert "mbs-vpn-egress" in vpn["networks"]
    base = _compose(BASE_COMPOSE)
    assert "mbs-scan-egress" in base["networks"]
    assert _compose(VPN_COMPOSE)["services"]["worker-vpn-egress"]["networks"] != \
        base["services"]["worker"]["networks"]


def test_the_worker_image_provides_iptables_for_the_killswitch():
    """Without iptables the kill-switch cannot exist, and the worker refuses to start --
    so a missing package is a deployment failure, not a silent downgrade."""
    dockerfile = (REPO_ROOT / "infra" / "docker" / "Dockerfile.worker").read_text(
        encoding="utf-8"
    )
    assert "iptables" in dockerfile
