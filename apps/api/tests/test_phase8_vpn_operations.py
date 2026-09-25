"""MBS.SC PHASE 8 -- VPN operations & hardening.

Covers the eight Phase-8 controls as behaviour, not as configuration:

  1. tunnel health          5. key rotation
  2. handshake monitoring   6. revocation
  3. DNS leak prevention    7. emergency disconnect
  4. MTU handling           8. private queue draining

Most of these were already implemented in Phases 7 and earlier; these tests exist to PROVE
them rather than to re-state them, and to lock the four Phase-8 additions:
a configurable handshake threshold, explicit MTU, emergency-disconnect coverage of
in-flight work, and the key-rotation invariants.

Everything runs against the injectable seams (`SystemTunnelProbe(runner=...)`,
`StaticTunnelProbe`, a scripted manager transport), so no live tunnel, no privileged
container and no key material are required.
"""
import asyncio
import uuid

import pytest

from apps.api.core.config import get_settings
from apps.api.scanner_engine import net_policy, site_dns, wireguard
from apps.api.scanner_worker import lease_loop, tunnel_setup


def _runner(mapping, *, default=(0, "", "")):
    """(rc, stdout, stderr) per command line -- tunnel_setup's 3-tuple contract."""
    calls = []

    def run(argv, timeout=10.0):
        calls.append(list(argv))
        return mapping.get(" ".join(argv), default)

    run.calls = calls
    return run


def _probe_runner(mapping, *, default=(1, "")):
    """(rc, stdout) per command line -- SystemTunnelProbe's 2-tuple contract."""
    def run(argv):
        return mapping.get(" ".join(argv), default)
    return run


_LINK_UP = "5: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN\n"
_ROUTES = "10.80.0.0/16 dev wg0 scope link \n"


def _healthy_probe(*, mtu_line: str = _LINK_UP, age_offset: int = 10):
    import time

    return wireguard.SystemTunnelProbe("wg0", runner=_probe_runner({
        "ip -o link show wg0": (0, mtu_line),
        "ip -o route show dev wg0": (0, _ROUTES),
        "wg show wg0 latest-handshakes": (0, f"peerkey=\t{int(time.time()) - age_offset}\n"),
    }))


def _config(cidrs=("10.80.0.0/16",)):
    return wireguard.describe_config(
        site_id=uuid.uuid4(), authorized_cidrs=list(cidrs),
        peer_public_key="PEERPUB=", endpoint_host="203.0.113.9", endpoint_port=51820,
        interface_address="10.99.0.2/32", persistent_keepalive=25,
    )


# =======================================================================================
# CONTROL 1 -- TUNNEL HEALTH
# =======================================================================================

def test_healthy_tunnel_passes_every_gate():
    """wg0 up, correct route, fresh handshake, no default route -> preflight PASSES."""
    probe = _healthy_probe()
    status = probe.status("site")
    assert status.interface_up is True
    assert status.routes == ("10.80.0.0/16",)
    assert "default" not in status.routes
    wireguard.preflight(site_id="site", authorized_cidrs=["10.80.0.0/16"], probe=probe)


@pytest.mark.parametrize("broken,expected", [
    ("ip -o link show wg0", wireguard.REASON_TUNNEL_UNHEALTHY),      # interface gone
    ("ip -o route show dev wg0", wireguard.REASON_ROUTE_MISSING),    # route gone
    ("wg show wg0 latest-handshakes", wireguard.REASON_NO_HANDSHAKE),
])
def test_each_tunnel_component_failing_fails_closed(broken, expected):
    """Control 1's FAIL paths. A component the probe cannot observe must never be read as
    healthy -- each one refuses the scan with its own specific reason."""
    import time

    mapping = {
        "ip -o link show wg0": (0, _LINK_UP),
        "ip -o route show dev wg0": (0, _ROUTES),
        "wg show wg0 latest-handshakes": (0, f"k=\t{int(time.time()) - 10}\n"),
    }
    mapping[broken] = (127, "")
    probe = wireguard.SystemTunnelProbe("wg0", runner=_probe_runner(mapping))
    with pytest.raises(wireguard.TunnelUnhealthy) as exc:
        wireguard.preflight(site_id="s", authorized_cidrs=["10.80.0.0/16"], probe=probe)
    assert exc.value.reason == expected


def test_a_default_route_never_satisfies_an_authorized_cidr():
    """Tunnel failure must not be papered over by a catch-all route."""
    import time

    probe = wireguard.SystemTunnelProbe("wg0", runner=_probe_runner({
        "ip -o link show wg0": (0, _LINK_UP),
        "ip -o route show dev wg0": (0, "default dev wg0 scope link \n"),
        "wg show wg0 latest-handshakes": (0, f"k=\t{int(time.time()) - 10}\n"),
    }))
    with pytest.raises(wireguard.TunnelUnhealthy) as exc:
        wireguard.preflight(site_id="s", authorized_cidrs=["10.80.0.0/16"], probe=probe)
    assert exc.value.reason == wireguard.REASON_ROUTE_MISSING


def test_tunnel_failure_never_falls_back_to_the_public_internet():
    """The decisive isolation property: an unhealthy tunnel REFUSES, it does not reroute.

    `preflight_private_job` raising is what stops execution; there is no branch anywhere
    that downgrades a private job to a public one.
    """
    job = {"scan_id": str(uuid.uuid4()), "execution_token": str(uuid.uuid4()),
           "network_zone": "private", "site_id": str(uuid.uuid4()),
           "authorized_cidrs": ["10.80.0.0/16"], "target": {"value": "10.80.0.50"}}
    dead = wireguard.StaticTunnelProbe(wireguard.TunnelStatus(interface_up=False))
    with pytest.raises(lease_loop.LeaseError) as exc:
        lease_loop.preflight_private_job(job, probe=dead)
    assert exc.value.reason == wireguard.REASON_TUNNEL_UNHEALTHY

    # And the policy built for that job authorizes ONLY the site's CIDRs -- never a
    # public fallback.
    policy = lease_loop.build_policy_for_job(job)
    assert policy.is_private is True
    assert [str(c) for c in policy.authorized_cidrs] == ["10.80.0.0/16"]


# =======================================================================================
# CONTROL 2 -- HANDSHAKE MONITORING
# =======================================================================================

def test_fresh_handshake_accepted_stale_rejected():
    fresh = wireguard.TunnelStatus(interface_up=True, last_handshake_age_s=30,
                                   routes=("10.80.0.0/16",))
    wireguard.assert_tunnel_healthy(fresh, authorized_cidrs=["10.80.0.0/16"])

    stale = wireguard.TunnelStatus(interface_up=True, last_handshake_age_s=10_000,
                                   routes=("10.80.0.0/16",))
    with pytest.raises(wireguard.TunnelUnhealthy) as exc:
        wireguard.assert_tunnel_healthy(stale, authorized_cidrs=["10.80.0.0/16"])
    assert exc.value.reason == wireguard.REASON_HANDSHAKE_STALE


def test_the_stale_threshold_is_explicit_and_configurable():
    """PHASE 8 ADDITION. The threshold used to be a hardcoded constant with no setting."""
    settings = get_settings()
    assert hasattr(settings, "scanner_wireguard_max_handshake_age_s")
    assert settings.scanner_wireguard_max_handshake_age_s == 180  # documented default

    # A caller-supplied threshold is honoured in BOTH directions.
    status = wireguard.TunnelStatus(interface_up=True, last_handshake_age_s=300,
                                    routes=("10.80.0.0/16",))
    wireguard.assert_tunnel_healthy(status, authorized_cidrs=["10.80.0.0/16"],
                                    max_handshake_age_s=600)   # tolerant -> passes
    with pytest.raises(wireguard.TunnelUnhealthy):
        wireguard.assert_tunnel_healthy(status, authorized_cidrs=["10.80.0.0/16"],
                                        max_handshake_age_s=60)  # strict -> refuses


def test_the_configured_threshold_reaches_the_startup_path():
    """The setting must actually be plumbed, not merely declared."""
    import inspect

    from apps.api.scanner_worker import main as worker_main

    src = inspect.getsource(worker_main._prepare_private_tunnel)
    assert "scanner_wireguard_max_handshake_age_s" in src
    assert "scanner_wireguard_mtu" in src


def test_a_stale_tunnel_blocks_private_execution_but_not_public():
    """Control 2's isolation requirement: public scanning is unaffected."""
    stale = wireguard.StaticTunnelProbe(wireguard.TunnelStatus(
        interface_up=True, last_handshake_age_s=9999, routes=("10.80.0.0/16",)))
    private_job = {"scan_id": "s", "execution_token": str(uuid.uuid4()),
                   "network_zone": "private", "site_id": str(uuid.uuid4()),
                   "authorized_cidrs": ["10.80.0.0/16"], "target": {"value": "10.80.0.5"}}
    with pytest.raises(lease_loop.LeaseError):
        lease_loop.preflight_private_job(private_job, probe=stale)

    # A PUBLIC job never consults the tunnel at all -- even with the same dead probe.
    public_job = dict(private_job, network_zone="public", site_id=None, authorized_cidrs=[])
    lease_loop.preflight_private_job(public_job, probe=stale)  # must not raise


# =======================================================================================
# CONTROL 3 -- DNS LEAK PREVENTION
# =======================================================================================

def test_private_lookup_uses_the_site_resolver():
    seen = []
    site_dns.set_backend(lambda h, r: (seen.append((h, r)), ["10.80.0.42"])[1])
    try:
        assert site_dns.resolve_via_site_dns("db.internal", resolvers=["10.80.0.53"]) \
            == ["10.80.0.42"]
        assert seen == [("db.internal", "10.80.0.53")]
    finally:
        site_dns.reset_backend()


def test_a_site_without_dns_fails_closed_and_never_uses_a_public_resolver():
    """Control 3's core negative: no backend -> RAISE, never fall through to the OS/public
    resolver. The message names the refusal explicitly."""
    site_dns.reset_backend()
    with pytest.raises(site_dns.SiteDNSUnavailable, match="refusing to resolve"):
        site_dns.resolve_via_site_dns("secret.internal", resolvers=["10.80.0.53"])

    # An empty resolver list is equally a refusal, not an invitation to use the default.
    with pytest.raises(site_dns.SiteDNSUnavailable, match="refusing public fallback"):
        site_dns.resolve_via_site_dns("secret.internal", resolvers=[])


def test_no_public_resolver_is_hardcoded_anywhere_in_the_dns_path():
    """Proves the absence of 8.8.8.8 / 1.1.1.1 style fallbacks in the resolution CODE.

    Docstrings legitimately NAME those addresses while explaining why they are not used, so
    a plain substring scan would fail for documenting the very property it is testing.
    Docstring nodes are therefore identified by position and skipped; every other string
    constant is executable data and must not carry a public resolver.
    """
    import ast
    from pathlib import Path

    public_resolvers = ("8.8.8.8", "1.1.1.1", "8.8.4.4", "9.9.9.9", "208.67.222.222")
    for rel in ("apps/api/scanner_engine/site_dns.py",
                "apps/api/scanner_engine/net_guard.py"):
        tree = ast.parse(Path(rel).read_text(encoding="utf-8"))

        # A docstring is the first statement of a module/class/function and is an
        # Expr-wrapped string constant. Collect those exact node ids to skip.
        doc_ids = set()
        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            if isinstance(body, list) and body:
                first = body[0]
                if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                        and isinstance(first.value.value, str)):
                    doc_ids.add(id(first.value))

        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in doc_ids):
                for public in public_resolvers:
                    assert public not in node.value, (
                        f"{rel}:{node.lineno} embeds the public resolver {public} in a "
                        f"runtime string -- a private lookup could leak to it"
                    )


def test_site_dns_failure_degrades_like_any_resolution_failure():
    """SiteDNSUnavailable subclasses socket.gaierror so existing callers treat a resolver
    outage as 'unresolvable' rather than crashing the pipeline."""
    import socket

    assert issubclass(site_dns.SiteDNSUnavailable, socket.gaierror)


def test_the_rendered_config_never_hijacks_the_namespace_resolver():
    """wg-quick's DNS= would rewrite /etc/resolv.conf for the WHOLE namespace, sending
    public lookups and the manager's own hostname to the customer."""
    cfg = wireguard.describe_config(
        site_id=uuid.uuid4(), authorized_cidrs=["10.80.0.0/16"],
        peer_public_key="P=", endpoint_host="h", endpoint_port=1,
        dns_servers=["10.80.0.53"],   # the site HAS resolvers...
    )
    text = wireguard.render_worker_config(cfg, private_key="k" * 32)
    assert "\nDNS =" not in text and "\nDNS=" not in text  # ...but they never land here
    assert "Table = off" in text


def test_dns_is_bound_to_the_correct_site_context():
    """Two sites' resolvers must not bleed: the policy carries its own site's resolvers."""
    a = net_policy.build_private_policy(
        workspace_id=uuid.uuid4(), scan_id=None, site_id=uuid.uuid4(),
        authorized_cidrs=["10.80.0.0/16"], dns_servers=["10.80.0.53"])
    b = net_policy.build_private_policy(
        workspace_id=uuid.uuid4(), scan_id=None, site_id=uuid.uuid4(),
        authorized_cidrs=["10.90.0.0/16"], dns_servers=["10.90.0.53"])
    assert a.dns_servers == ("10.80.0.53",)
    assert b.dns_servers == ("10.90.0.53",)
    # A PUBLIC policy carries none, so it can never reach a site resolver.
    assert net_policy.build_public_policy(workspace_id=uuid.uuid4()).dns_servers == ()


# =======================================================================================
# CONTROL 4 -- MTU HANDLING (Phase 8 addition)
# =======================================================================================

def test_mtu_is_explicitly_configured_not_silently_inherited():
    settings = get_settings()
    assert hasattr(settings, "scanner_wireguard_mtu")
    # WireGuard's own IPv4-over-IPv4 default; set explicitly so it is auditable.
    assert settings.scanner_wireguard_mtu == 1420


def test_bring_up_applies_the_configured_mtu_before_the_link_comes_up():
    """Order matters: setting MTU after `link set up` can leave a window at the wrong size."""
    import unittest.mock as m

    run = _runner({})
    with m.patch.object(tunnel_setup, "_run", run), \
         m.patch.object(tunnel_setup.os.path, "isdir", lambda p: False):
        tunnel_setup.bring_up(_config(), private_key="k" * 32, interface="wg0", mtu=1412)

    flat = [" ".join(c) for c in run.calls]
    mtu_idx = next(i for i, c in enumerate(flat) if "mtu 1412" in c)
    up_idx = next(i for i, c in enumerate(flat) if c == "ip link set wg0 up")
    assert mtu_idx < up_idx, "MTU was applied after the interface came up"


def test_an_mtu_failure_is_visible_and_fatal_not_silent():
    """A wrong MTU black-holes large packets; failing to SET it must not pass unnoticed."""
    import unittest.mock as m

    run = _runner({"ip link set dev wg0 mtu 1412": (1, "", "RTNETLINK: invalid argument")})
    with m.patch.object(tunnel_setup, "_run", run), \
         m.patch.object(tunnel_setup.os.path, "isdir", lambda p: False):
        with pytest.raises(tunnel_setup.TunnelSetupError) as exc:
            tunnel_setup.bring_up(_config(), private_key="k" * 32, mtu=1412)
    assert exc.value.reason == tunnel_setup.REASON_MTU_FAILED


def test_mtu_is_observable_for_drift_detection():
    """The probe reports the LIVE MTU so a mismatch is visible in logs/metrics."""
    probe = _healthy_probe(mtu_line=_LINK_UP.replace("mtu 1420", "mtu 1412"))
    assert probe.status("site").mtu == 1412


def test_the_mtu_override_is_operator_reachable_and_documented():
    """An MTU that cannot be corrected in the field is not a handled MTU.

    A wrong MTU black-holes large packets SILENTLY -- nothing errors, a live host just
    stops answering -- so the operator needs both a lever and the symptom description that
    tells them to reach for it. The lever is asserted by binding the real env var through
    Settings (not by reading the source), and the runbook must carry the symptom, the
    per-path values and the verification command.
    """
    import os
    import unittest.mock as m
    from pathlib import Path

    from apps.api.core.config import Settings

    # The lever actually binds -- this is the env var an operator sets in the site's compose.
    with m.patch.dict(os.environ, {"SCANNER_WIREGUARD_MTU": "1412"}):
        assert Settings().scanner_wireguard_mtu == 1412

    doc = Path("docs/runbooks/private-scanning.md").read_text(encoding="utf-8")
    assert "SCANNER_WIREGUARD_MTU" in doc, "the operator lever is undocumented"
    # The failure is a black-hole, not an error; the runbook must say so.
    assert "black-hol" in doc.lower()
    assert "1412" in doc, "the PPPoE value operators most often need is missing"
    # And the reason code the worker can actually emit at startup must be triageable.
    assert tunnel_setup.REASON_MTU_FAILED in doc


def test_mtu_is_not_part_of_the_health_verdict():
    """Deliberate: a wrong MTU costs REACHABILITY, never isolation (an oversized packet is
    dropped or fragmented, never re-routed), so it must not fail an otherwise-good tunnel."""
    odd = wireguard.TunnelStatus(interface_up=True, last_handshake_age_s=10,
                                 routes=("10.80.0.0/16",), mtu=1280)
    wireguard.assert_tunnel_healthy(odd, authorized_cidrs=["10.80.0.0/16"])  # must not raise


def test_mtu_handling_cannot_widen_the_authorized_set():
    """Whatever the MTU, routing is still exactly the authorized CIDRs."""
    import unittest.mock as m

    run = _runner({})
    with m.patch.object(tunnel_setup, "_run", run), \
         m.patch.object(tunnel_setup.os.path, "isdir", lambda p: False):
        tunnel_setup.bring_up(_config(("10.80.0.0/16",)), private_key="k" * 32, mtu=1280)
    routes = {c[3] for c in run.calls if c[:2] == ["ip", "route"]}
    assert routes == {"10.80.0.0/16"}


# =======================================================================================
# CONTROL 5 -- KEY ROTATION
# =======================================================================================

def test_rotation_never_widens_allowed_ips_or_changes_the_site_binding():
    """The security invariant of rotation: only the KEY changes."""
    site = uuid.uuid4()
    before = wireguard.describe_config(
        site_id=site, authorized_cidrs=["10.80.0.0/16"], peer_public_key="OLDPUB=",
        endpoint_host="203.0.113.9", endpoint_port=51820, interface_address="10.99.0.2/32")
    after = wireguard.describe_config(
        site_id=site, authorized_cidrs=["10.80.0.0/16"], peer_public_key="NEWPUB=",
        endpoint_host="203.0.113.9", endpoint_port=51820, interface_address="10.99.0.2/32")

    assert after.allowed_ips == before.allowed_ips     # not widened
    assert after.site_id == before.site_id             # binding intact
    assert after.peer_public_key != before.peer_public_key
    assert after.has_default_route is False


def test_a_rotation_that_tries_to_widen_the_cidrs_is_refused():
    with pytest.raises(wireguard.WireGuardConfigError, match="default route"):
        wireguard.describe_config(
            site_id=uuid.uuid4(), authorized_cidrs=["0.0.0.0/0"], peer_public_key="NEW=",
            endpoint_host="h", endpoint_port=1)


def test_no_private_key_is_ever_persisted_centrally():
    """Rotation changes nothing about custody: the DB holds PUBLIC halves only."""
    from apps.api.modules.private_sites.models import PrivateSite

    columns = {c.name.lower() for c in PrivateSite.__table__.columns}
    assert "peer_public_key" in columns and "worker_public_key" in columns
    for name in columns:
        assert "private_key" not in name
        assert not (name.endswith("_key") and "public" not in name)


def test_the_key_never_reaches_argv_or_a_log_during_rotation():
    """argv is world-readable via /proc; a rotation must not expose the new key there."""
    import unittest.mock as m

    secret = "ROTATEDKEY0123456789abcdefghijklmnopqrstuv="
    run = _runner({})
    with m.patch.object(tunnel_setup, "_run", run), \
         m.patch.object(tunnel_setup.os.path, "isdir", lambda p: False):
        tunnel_setup.bring_up(_config(), private_key=secret, interface="wg0")
    assert secret not in " ".join(" ".join(c) for c in run.calls)


def test_the_rotation_procedure_is_documented():
    """Rotation is manual BY DESIGN (automating it would make the control plane handle a
    private key), so the procedure must exist in the runbook."""
    from pathlib import Path

    doc = Path("docs/runbooks/private-scanning.md").read_text(encoding="utf-8")
    assert "key rotation" in doc.lower()
    assert "wg genkey" in doc
    # The two ordering rules that make rotation zero-downtime and complete.
    assert "add the new key before removing the old" in doc.lower()
    assert "remove the OLD peer" in doc


# =======================================================================================
# CONTROL 6 -- REVOCATION
# =======================================================================================

def test_revocation_cannot_be_bypassed_by_reshaping_the_job():
    """A revoked worker is refused at AUTHENTICATION, before any job field is consulted --
    so changing pool/site/zone/CIDR cannot route around it."""
    from apps.api.modules.scanner_workers import service as ws
    from apps.api.modules.scanner_workers.models import ScannerWorker

    revoked = ScannerWorker(id=uuid.uuid4(), worker_id="wk", pool_id="p",
                            site_id=uuid.uuid4(), workspace_id=uuid.uuid4(),
                            status="revoked")
    with pytest.raises(ws.WorkerNotAuthorized) as exc:
        ws.assert_worker_active(revoked)
    assert exc.value.reason == ws.REASON_WORKER_REVOKED

    # Every composite gate also refuses, whatever the caller claims about the work.
    for kwargs in (
        {"workspace_id": revoked.workspace_id, "site_id": revoked.site_id},
        {"workspace_id": uuid.uuid4(), "site_id": uuid.uuid4()},       # different tenant
        {"workspace_id": revoked.workspace_id, "site_id": None},       # "make it public"
        {"workspace_id": revoked.workspace_id, "site_id": revoked.site_id,
         "pool_id": "other-pool"},
    ):
        with pytest.raises(ws.WorkerNotAuthorized):
            ws.assert_worker_may_take_scan(revoked, **kwargs)


def test_a_revoked_site_cannot_be_scanned_by_its_own_worker():
    from apps.api.modules.private_sites import service as sites
    from apps.api.modules.private_sites.models import PrivateSite

    for status in ("revoked", "suspended"):
        site = PrivateSite(id=uuid.uuid4(), workspace_id=uuid.uuid4(), name="s",
                           authorized_cidrs=["10.80.0.0/16"], dns_servers=[],
                           dns_search_domains=[], status=status)
        with pytest.raises(sites.PrivateSiteNotAuthorized):
            sites.assert_site_scannable(site)


def test_a_stale_execution_token_cannot_be_reused():
    """Fencing is the same mechanism Phase 8 relies on -- a job with an invalid token is
    refused before execution."""
    identity = lease_loop.WorkerIdentity(
        worker_id="wk", pool_id="p", site_id=str(uuid.uuid4()),
        manager_url="http://m:8100", token="t")
    base = {"scan_id": str(uuid.uuid4()), "network_zone": "private",
            "site_id": identity.site_id, "authorized_cidrs": ["10.80.0.0/16"],
            "pool_id": "p", "target": {"value": "10.80.0.5"}}
    for bad_token in (None, "", "not-a-uuid"):
        with pytest.raises(lease_loop.LeaseError) as exc:
            lease_loop.validate_leased_job(dict(base, execution_token=bad_token), identity)
        assert exc.value.reason == lease_loop.REASON_EXECUTION_TOKEN_INVALID


# =======================================================================================
# CONTROL 7 -- EMERGENCY DISCONNECT (Phase 8 fix: now covers in-flight work)
# =======================================================================================

def test_the_emergency_switch_exists_and_defaults_off():
    assert get_settings().private_scanning_emergency_disable is False


def test_emergency_disconnect_blocks_in_flight_private_work_not_just_new_leases():
    """PHASE 8 FIX. The switch previously guarded only /v1/lease, so an already-leased
    private scan could keep POSTing tool-results and evidence while the operator believed
    private scanning was stopped. It is now enforced in the gate every scan-scoped request
    passes through."""
    import inspect

    from apps.api.scanner_manager import app as manager_app

    gate = inspect.getsource(manager_app._authorize_scan_for_worker)
    assert "private_scanning_emergency_disable" in gate, (
        "the emergency switch is not enforced on in-flight scan-scoped requests"
    )
    assert "PRIVATE_SCANNING_EMERGENCY_DISABLED" in gate
    # And it is still enforced at lease time.
    lease = inspect.getsource(manager_app.lease_jobs)
    assert "private_disabled" in lease


def test_the_emergency_switch_only_affects_private_work():
    """Public scanning must keep running -- the check sits inside the private branch."""
    import inspect

    from apps.api.scanner_manager import app as manager_app

    gate = inspect.getsource(manager_app._authorize_scan_for_worker)
    private_branch = gate.split("if site_uuid is not None:", 1)[1]
    assert "private_scanning_emergency_disable" in private_branch, (
        "the emergency check is outside the private-site branch -- it would also stop "
        "public scanning"
    )


def test_emergency_disconnect_is_enforced_control_plane_side():
    """It must not depend on reaching a (possibly compromised or offline) scanner host."""
    import inspect

    from apps.api.scanner_manager import app as manager_app

    src = inspect.getsource(manager_app)
    assert "private_scanning_emergency_disable" in src


# =======================================================================================
# CONTROL 8 -- PRIVATE QUEUE DRAINING
# =======================================================================================

def test_a_draining_worker_leases_nothing_new():
    """'draining' is the graceful-decommission state: finish in flight, take nothing new.

    BOTH halves are asserted here now. This previously checked `assert_worker_active`,
    which gates AUTHENTICATION and therefore every endpoint -- so the state it described
    would have cut a decommissioning worker off from the very calls its running scan needs
    to report through, losing the results of the work it was meant to be allowed to finish.
    The lease refusal now lives in `assert_worker_may_lease`, asked at `/v1/lease` alone.
    """
    from apps.api.modules.scanner_workers import service as ws
    from apps.api.modules.scanner_workers.models import (
        LEASE_ELIGIBLE_STATUSES,
        ScannerWorker,
    )

    assert LEASE_ELIGIBLE_STATUSES == frozenset({"active"})
    draining = ScannerWorker(id=uuid.uuid4(), worker_id="wk", pool_id="p",
                             site_id=None, workspace_id=None, status="draining")
    # Takes nothing new.
    with pytest.raises(ws.WorkerNotAuthorized) as exc:
        ws.assert_worker_may_lease(draining)
    assert exc.value.reason == ws.REASON_WORKER_DRAINING
    # ...and finishes what it holds: still authenticated, so tool-results, evidence,
    # heartbeat and lease/complete for the in-flight scan all remain available.
    ws.assert_worker_active(draining)


def test_a_private_job_never_falls_back_to_the_public_pool():
    """Control 8's isolation rule: private work must not silently migrate to public.

    Routing refuses to place a private scan anywhere but its own site queue, and the
    worker-side check refuses a public job on a private worker (and vice versa).
    """
    from apps.api.scanner_engine.scan_routing import (
        JobNotForThisWorker,
        assert_job_matches_worker,
        queue_for_scan,
    )

    site = uuid.uuid4()
    assert queue_for_scan(network_zone="private", site_id=site) == f"scans.private.{site}"
    # A private scan with no site cannot be routed at all -- it does NOT default to public.
    with pytest.raises(ValueError, match="refusing to fall back to the public queue"):
        queue_for_scan(network_zone="private", site_id=None)

    # A private worker refuses public work; a public worker refuses private work.
    with pytest.raises(JobNotForThisWorker):
        assert_job_matches_worker(job_network_zone="public", job_site_id=None,
                                  worker_site_id=str(site))
    with pytest.raises(JobNotForThisWorker):
        assert_job_matches_worker(job_network_zone="private", job_site_id=str(site),
                                  worker_site_id=None)


def test_a_recovered_private_job_keeps_its_site_and_zone_authorization():
    """After a failure/recovery cycle the job must not lose its private binding -- that is
    what would let it be picked up as public work."""
    site = str(uuid.uuid4())
    job = {"scan_id": str(uuid.uuid4()), "workspace_id": str(uuid.uuid4()),
           "execution_token": str(uuid.uuid4()), "network_zone": "private",
           "site_id": site, "authorized_cidrs": ["10.80.0.0/16"],
           "dns_servers": ["10.80.0.53"], "target": {"value": "10.80.0.50"}}
    policy = lease_loop.build_policy_for_job(job)
    assert policy.is_private is True
    assert str(policy.site_id) == site
    assert [str(c) for c in policy.authorized_cidrs] == ["10.80.0.0/16"]


def test_a_worker_whose_tunnel_died_rejects_and_reports_rather_than_running():
    """Failure -> recovery cycle at the worker: the job is refused with its reason and
    handed back, so the reaper/lease model can recover it rather than it hanging."""
    import asyncio

    calls = []

    async def transport(method, url, *, headers=None, json=None):
        calls.append((url, json))
        if url.endswith("/v1/lease"):
            return {"jobs": [{
                "scan_id": str(uuid.uuid4()), "workspace_id": str(uuid.uuid4()),
                "execution_token": str(uuid.uuid4()), "network_zone": "private",
                "site_id": str(uuid.uuid4()),           # a site this worker is NOT bound to
                "authorized_cidrs": ["10.80.0.0/16"],
                "target": {"value": "10.80.0.50"}, "pool_id": "p",
            }]}
        return {"accepted": True, "status": "failed"}

    identity = lease_loop.WorkerIdentity(
        worker_id="wk", pool_id="p", site_id=str(uuid.uuid4()),
        manager_url="http://m:8100", token="t")
    loop = lease_loop.LeaseLoop(
        identity, lease_loop.ManagerClient(identity, transport=transport),
        executor=None, max_iterations=1,
        backoff=lease_loop.BackoffPolicy(base_seconds=0.001, max_seconds=0.002,
                                         idle_seconds=0.001),
    )
    stats = asyncio.run(loop.run())
    assert stats["rejected"] == 1
    completes = [j for (u, j) in calls if u.endswith("/v1/lease/complete")]
    assert completes and completes[0]["status"] == "failed"
    assert completes[0]["reason"] == lease_loop.REASON_SITE_MISMATCH


# =======================================================================================
# CONTROL 9 -- TUNNEL HEALTH REPORTING  (Phase 8 Tier 1: P8-A + P8-B)
# =======================================================================================
# THE GAP THESE CLOSE. `ManagerClient.heartbeat` has always ACCEPTED health_state and
# handshake_age_s, but the sole caller (`_heartbeat_while_running`) passed neither and only
# ran while a scan was executing. So a private worker with a healthy tunnel sat in the
# database as health_state='unknown', last_seen_at=NULL -- verified live -- and
# `record_tunnel_state()` had ZERO call sites anywhere in the codebase, which made
# MbsPrivateTunnelDown and MbsTunnelHandshakeStale structurally incapable of firing.
#
# ADDITIVE ONLY. None of this gates anything: `preflight_private_job` is untouched and is
# still what refuses a job. These tests assert that separation explicitly.


def _identity(*, private=True, pool="private-lab-a"):
    return lease_loop.WorkerIdentity(
        worker_id="wk", pool_id=pool,
        site_id=str(uuid.uuid4()) if private else None,
        manager_url="http://m:8100", token="t",
    )


def _loop(identity, probe, *, transport=None, max_iterations=1):
    return lease_loop.LeaseLoop(
        identity,
        lease_loop.ManagerClient(identity, transport=transport),
        executor=None, tunnel_probe=probe, max_iterations=max_iterations,
        backoff=lease_loop.BackoffPolicy(base_seconds=0.001, max_seconds=0.002,
                                         idle_seconds=0.001, heartbeat_seconds=0.0),
    )


def _recording_transport(calls):
    async def transport(method, url, **kw):
        calls.append((url, kw.get("json") or {}))
        if url.endswith("/v1/lease"):
            return {"jobs": []}
        return {"ok": True}
    return transport


# --- the health verdict itself ---------------------------------------------------------

def test_healthy_tunnel_reports_healthy_with_a_handshake_age():
    loop = _loop(_identity(), _healthy_probe(age_offset=7))
    state, age, detail = loop.observe_tunnel_health()
    assert state == "healthy"
    assert age is not None and age >= 0
    assert detail is None


@pytest.mark.parametrize(
    "status,expected_reason",
    [
        (wireguard.TunnelStatus(interface_up=False), wireguard.REASON_TUNNEL_UNHEALTHY),
        (wireguard.TunnelStatus(interface_up=True, last_handshake_age_s=None),
         wireguard.REASON_NO_HANDSHAKE),
        (wireguard.TunnelStatus(interface_up=True, last_handshake_age_s=5, routes=()),
         wireguard.REASON_ROUTE_MISSING),
        (wireguard.TunnelStatus(interface_up=True, last_handshake_age_s=999999,
                                routes=("10.80.0.0/16",)),
         wireguard.REASON_HANDSHAKE_STALE),
    ],
)
def test_every_unhealthy_state_reports_unhealthy_with_the_actionable_reason(
    status, expected_reason
):
    """The reason must name the MOST ACTIONABLE cause -- a down interface has no routes
    BECAUSE it is down, and reporting ROUTE_MISSING would send an operator to the wrong
    place. Mirrors assert_tunnel_healthy's own ordering."""
    loop = _loop(_identity(), wireguard.StaticTunnelProbe(status))
    state, _age, detail = loop.observe_tunnel_health()
    assert state == "unhealthy"
    assert detail == expected_reason


def test_an_unobservable_probe_reports_unhealthy_never_healthy():
    """A metric that says healthy for a tunnel it cannot see is worse than no metric."""
    class _Boom:
        def status(self, site_id):
            raise OSError("wg binary missing")

    state, age, detail = _loop(_identity(), _Boom()).observe_tunnel_health()
    assert state == "unhealthy"
    assert age is None
    assert "probe failed" in (detail or "")


def test_a_public_worker_reports_healthy_with_no_handshake_age():
    """A public worker has no tunnel; claiming an age would invent one."""
    state, age, detail = _loop(_identity(private=False), None).observe_tunnel_health()
    assert (state, age, detail) == ("healthy", None, None)


def test_the_report_uses_the_configured_stale_threshold_not_a_private_copy():
    """The report and the per-job gate must never disagree about what 'stale' means."""
    configured = get_settings().scanner_wireguard_max_handshake_age_s
    assert lease_loop._max_handshake_age_s() == configured


# --- P8-B: the heartbeat now carries health -------------------------------------------

def test_heartbeat_includes_health_state_and_handshake_age():
    calls = []
    loop = _loop(_identity(), _healthy_probe(age_offset=11),
                 transport=_recording_transport(calls))
    asyncio.run(loop.report_health())
    beats = [body for (url, body) in calls if url.endswith("/v1/heartbeat")]
    assert beats, "no heartbeat was sent"
    assert beats[0]["health_state"] == "healthy"
    assert beats[0]["handshake_age_s"] is not None


def test_heartbeat_reports_unhealthy_when_the_tunnel_is_down():
    calls = []
    probe = wireguard.StaticTunnelProbe(wireguard.TunnelStatus(interface_up=False))
    loop = _loop(_identity(), probe, transport=_recording_transport(calls))
    asyncio.run(loop.report_health())
    beat = [b for (u, b) in calls if u.endswith("/v1/heartbeat")][0]
    assert beat["health_state"] == "unhealthy"
    assert beat["detail"] == wireguard.REASON_TUNNEL_UNHEALTHY


def test_an_idle_worker_heartbeats_without_any_scan():
    """THE Phase 8 gap: a worker with no work never reported at all, which is exactly the
    state a tunnel-down alert needs to observe."""
    calls = []
    loop = _loop(_identity(), _healthy_probe(), transport=_recording_transport(calls),
                 max_iterations=1)
    stats = asyncio.run(loop.run())
    beats = [b for (u, b) in calls if u.endswith("/v1/heartbeat")]
    assert beats, "an idle worker sent no heartbeat"
    assert all("scan_id" not in b for b in beats), "an idle beat must not name a scan"
    assert stats["leased"] == 0


def test_a_heartbeat_failure_never_breaks_the_worker():
    """Liveness reporting is best-effort: a manager outage must not stop leasing."""
    async def failing(method, url, **kw):
        if url.endswith("/v1/heartbeat"):
            raise RuntimeError("manager down")
        return {"jobs": []}

    loop = _loop(_identity(), _healthy_probe(), transport=failing, max_iterations=1)
    stats = asyncio.run(loop.run())  # must not raise
    assert stats["leased"] == 0


# --- P8-A: record_tunnel_state now has a real call path --------------------------------

def test_record_tunnel_state_is_actually_called(monkeypatch):
    seen = []
    import apps.api.core.observability as obs

    monkeypatch.setattr(
        obs, "record_tunnel_state",
        lambda pool_id, *, up, handshake_age_s=None: seen.append(
            (pool_id, up, handshake_age_s)),
    )
    loop = _loop(_identity(pool="private-lab-a"), _healthy_probe(age_offset=9),
                 transport=_recording_transport([]))
    asyncio.run(loop.report_health())
    assert seen, "record_tunnel_state was never called"
    pool, up, age = seen[0]
    assert pool == "private-lab-a"
    assert up is True
    assert age is not None


def test_the_metric_reports_down_for_an_unhealthy_tunnel(monkeypatch):
    """A metric that can report up=1 for a broken tunnel would make the alert useless."""
    seen = []
    import apps.api.core.observability as obs

    monkeypatch.setattr(
        obs, "record_tunnel_state",
        lambda pool_id, *, up, handshake_age_s=None: seen.append(up),
    )
    probe = wireguard.StaticTunnelProbe(wireguard.TunnelStatus(interface_up=False))
    loop = _loop(_identity(), probe, transport=_recording_transport([]))
    asyncio.run(loop.report_health())
    assert seen == [False]


def test_a_public_worker_emits_no_tunnel_metric(monkeypatch):
    """Emitting up=1 for a pool with no tunnel would dilute the tunnel-down alert."""
    seen = []
    import apps.api.core.observability as obs

    monkeypatch.setattr(
        obs, "record_tunnel_state",
        lambda pool_id, *, up, handshake_age_s=None: seen.append(pool_id),
    )
    loop = _loop(_identity(private=False), None, transport=_recording_transport([]))
    asyncio.run(loop.report_health())
    assert seen == []


def test_a_metric_failure_never_breaks_the_heartbeat(monkeypatch):
    calls = []
    import apps.api.core.observability as obs

    def _boom(*a, **kw):
        raise RuntimeError("prometheus exploded")

    monkeypatch.setattr(obs, "record_tunnel_state", _boom)
    loop = _loop(_identity(), _healthy_probe(), transport=_recording_transport(calls))
    asyncio.run(loop.report_health())
    assert [b for (u, b) in calls if u.endswith("/v1/heartbeat")], "heartbeat was lost"


# --- INVARIANTS: Phase 7 behaviour is unchanged ----------------------------------------

def test_reporting_does_not_gate_anything_phase7_still_refuses():
    """THE CRITICAL SEPARATION. Health REPORTING must not become health ENFORCEMENT: the
    per-job fail-closed gate is still `preflight_private_job`, unchanged and independent."""
    down = wireguard.StaticTunnelProbe(wireguard.TunnelStatus(interface_up=False))
    job = {"network_zone": "private", "site_id": "s",
           "authorized_cidrs": ["10.80.0.0/16"]}
    with pytest.raises(lease_loop.LeaseError) as exc:
        lease_loop.preflight_private_job(job, probe=down)
    assert exc.value.reason == lease_loop.REASON_TUNNEL_UNHEALTHY
    # ...and the reporting path agrees rather than contradicting it.
    assert _loop(_identity(), down).observe_tunnel_health()[0] == "unhealthy"


def test_public_scanning_is_unaffected_by_tunnel_health():
    """A public job never consults a probe, before or after this change."""
    lease_loop.preflight_private_job({"network_zone": "public"}, probe=None)


def test_reporting_never_widens_the_authorized_set():
    """The health verdict is judged against the routes the tunnel ACTUALLY carries; it
    holds no copy of the site's authorization and cannot grant anything."""
    probe = wireguard.StaticTunnelProbe(
        wireguard.TunnelStatus(interface_up=True, last_handshake_age_s=5,
                               routes=("10.80.0.0/16",))
    )
    assert _loop(_identity(), probe).observe_tunnel_health()[0] == "healthy"
    # A job for an UNAUTHORIZED range is still refused by the gate, which judges the job's
    # own authorized_cidrs -- not the routes the report happened to look at.
    job = {"network_zone": "private", "site_id": "s",
           "authorized_cidrs": ["10.91.0.0/24"]}
    with pytest.raises(lease_loop.LeaseError):
        lease_loop.preflight_private_job(job, probe=probe)


# =======================================================================================
# CONTROL 7 (continued) -- EMERGENCY DISCONNECT: SUBMISSION-PATH VERDICTS
#
# BEHAVIOURAL, deliberately. The three tests above this block assert that the emergency
# switch APPEARS in the manager's gate -- a structural invariant worth keeping, but it
# proves only that the string is present, never that a worker actually stops. These drive
# the real executor pipeline and assert what it DOES when the control plane refuses a
# submission.
#
# The distinction under test, and the reason it is not one rule:
#   401/403      -> the control plane has DECIDED. Stop before the next tool.
#   5xx/transport-> the control plane never decided. Continue (incident 615d0e0b).
# =======================================================================================

class _Raw:
    def __init__(self):
        self.command = "stub"
        self.stdout = "evidence-bytes"
        self.stderr = ""
        self.exit_code = 0


def _p8_registry(executed, names=("alpha", "beta", "gamma")):
    """Ordered no-network runners that record the fact they ran."""
    from apps.api.scanner_engine.tool_runners.base import BaseToolRunner

    registry = {}
    for phase, name in enumerate(names, start=1):

        class _Runner(BaseToolRunner):
            applicable_target_types = None

            def __init__(self, _name=name, _phase=phase):
                self.name = _name
                self.version = "0.0.0"
                self.phase = _phase

            async def run(self, target_value, config, discovered):  # noqa: ANN001
                executed.append(self.name)
                return _Raw()

            def parse(self, raw):  # noqa: ANN001
                return []

        registry[name] = _Runner
    return registry


def _http_error(code):
    """The exact shape `result_sink._post` raises for a manager HTTP status."""
    import httpx

    request = httpx.Request("POST", "http://manager/v1/tool-results")
    return httpx.HTTPStatusError(
        str(code), request=request, response=httpx.Response(code, request=request)
    )


class _P8Reporter:
    """A reporter that fails ONE named submission path with a given exception."""

    def __init__(self, *, failing, exc, fail_from_tool="alpha"):
        self.failing = failing
        self.exc = exc
        self.fail_from_tool = fail_from_tool
        self.started = []
        self.results = []
        self.evidence = []

    def _maybe_raise(self, path, tool):
        if path == self.failing and tool == self.fail_from_tool:
            raise self.exc

    async def submit_tool_started(self, **kw):
        tool = kw.get("tool_name")
        self.started.append(tool)
        self._maybe_raise("tool_started", tool)
        return {"ok": True}

    async def submit_tool_result(self, **kw):
        tool = kw.get("tool_name")
        self.results.append(tool)
        self._maybe_raise("tool_result", tool)
        return {"ok": True}

    async def submit_evidence(self, **kw):
        tool = kw.get("tool_name")
        self.evidence.append(tool)
        self._maybe_raise("evidence", tool)
        return {"ok": True}


def _run_p8_pipeline(reporter, executed):
    from apps.api.scanner_worker.executor import execute_leased_job

    job = {
        "scan_id": str(uuid.uuid4()),
        "execution_token": str(uuid.uuid4()),
        "target": {"value": "example.test", "type": "domain"},
        "requested_modules": ["alpha", "beta", "gamma"],
        "config": {},
    }
    return asyncio.run(execute_leased_job(
        job, None, reporter=reporter, registry=_p8_registry(executed),
    ))


# --- 1. tool-result verdict vs outage ----------------------------------------------------

def test_emergency_403_on_tool_result_stops_before_the_next_tool():
    """THE HEADLINE EMERGENCY-DISCONNECT PROPERTY, driven through the real executor.

    The operator flips the switch while 'alpha' is running. Its result POST is the first
    call to see the refusal. 'alpha' keeps the status it earned; 'beta' never starts.
    """
    executed = []
    reporter = _P8Reporter(failing="tool_result", exc=_http_error(403))
    outcome = _run_p8_pipeline(reporter, executed)

    assert executed == ["alpha"], f"a tool ran after the control plane refused: {executed}"
    assert reporter.started == ["alpha"], (
        f"a ToolRun was opened for a tool that must never start: {reporter.started}"
    )
    # The refused execution still reports what it actually did -- the refusal is not
    # turned into a fabricated scan-level failure. `completed_with_errors` is included
    # because alpha's result POST was the call that got refused, so its result was never
    # persisted and executor.py downgrades on persistence_failures (a scan whose findings
    # never reached the manager must not read as a clean `completed`).
    assert outcome in ("completed", "completed_with_errors", "failed")


def test_emergency_401_on_tool_result_stops_before_the_next_tool():
    """401 is the same verdict as 403 -- an unauthenticated worker is equally refused."""
    executed = []
    reporter = _P8Reporter(failing="tool_result", exc=_http_error(401))
    _run_p8_pipeline(reporter, executed)

    assert executed == ["alpha"]
    assert reporter.started == ["alpha"]


@pytest.mark.parametrize("code", [500, 502, 503, 504])
def test_a_5xx_on_tool_result_still_fails_open(code):
    """INCIDENT 615d0e0b. A manager 5xx is an outage, never a verdict.

    This is the behaviour that must survive the emergency-disconnect change: the tool RAN,
    only its persistence failed, and every later tool is still capable of running.
    """
    executed = []
    reporter = _P8Reporter(failing="tool_result", exc=_http_error(code))
    outcome = _run_p8_pipeline(reporter, executed)

    assert executed == ["alpha", "beta", "gamma"], (
        f"a {code} unwound the tool loop -- 615d0e0b regression: {executed}"
    )
    # FAILS OPEN, which is what 615d0e0b is about: the scan is NOT `failed`, because the
    # tools really did run against the target. It is `completed_with_errors` rather than a
    # clean `completed` because the results were LOST -- executor.py downgrades on
    # persistence_failures so a scan whose findings never reached the manager stays
    # distinguishable from one that genuinely persisted everything. Contrast
    # test_public_scanning_is_untouched_by_the_submission_verdict below, where nothing fails
    # to submit and the outcome is a plain `completed`.
    assert outcome != "failed", "a manager outage must never be reported as a failed scan"
    assert outcome == "completed_with_errors"


@pytest.mark.parametrize("exc_factory", [
    lambda: __import__("httpx").ReadTimeout("timed out"),
    lambda: __import__("httpx").ConnectError("connection reset"),
    lambda: ConnectionError("transport failure"),
])
def test_a_transport_failure_on_tool_result_still_fails_open(exc_factory):
    """Timeouts, resets and DNS failures never reached a decision: continue."""
    executed = []
    reporter = _P8Reporter(failing="tool_result", exc=exc_factory())
    _run_p8_pipeline(reporter, executed)

    assert executed == ["alpha", "beta", "gamma"]


# --- 2. the other two submission paths ---------------------------------------------------

def test_emergency_403_on_tool_started_stops_before_the_next_tool():
    """A refusal on the PROGRESS call is still a verdict.

    'alpha' is allowed to finish -- it was already decided on, and killing it would lose
    partial output for no security gain -- but 'beta' never starts.
    """
    executed = []
    reporter = _P8Reporter(failing="tool_started", exc=_http_error(403))
    _run_p8_pipeline(reporter, executed)

    assert executed == ["alpha"], f"a tool started after a refusal: {executed}"
    assert "beta" not in reporter.started


def test_a_5xx_on_tool_started_still_fails_open():
    """Progress reporting stays cosmetic for an outage: losing it costs a UI counter."""
    executed = []
    reporter = _P8Reporter(failing="tool_started", exc=_http_error(503))
    _run_p8_pipeline(reporter, executed)

    assert executed == ["alpha", "beta", "gamma"]


def test_emergency_403_on_evidence_stops_before_the_next_tool():
    """A refusal on the EVIDENCE call is a verdict too."""
    executed = []
    reporter = _P8Reporter(failing="evidence", exc=_http_error(403))
    _run_p8_pipeline(reporter, executed)

    assert executed == ["alpha"], f"a tool ran after an evidence refusal: {executed}"


def test_a_5xx_on_evidence_still_fails_open():
    """Evidence loss is acceptable data loss for an outage, exactly as before."""
    executed = []
    reporter = _P8Reporter(failing="evidence", exc=_http_error(500))
    _run_p8_pipeline(reporter, executed)

    assert executed == ["alpha", "beta", "gamma"]


# --- 3. the classifier itself ------------------------------------------------------------

def test_only_401_403_and_409_are_treated_as_authoritative_verdicts():
    """The whole contract in one table. Nothing else may become a stop signal.

    409 joined 401/403 with the Lifecycle Integrity work (Prompt 9): it is
    EXECUTION_SUPERSEDED from `_assert_execution_token` -- the manager has decided this
    execution no longer owns the scan. Treating it as a mere outage is what left a
    superseded executor running further tools against the target unbounded, since every
    later fenced write loses the same race and is reclassified as another "outage".
    It is a VERDICT, not an outage, so it belongs on the True side of this table.

    Everything else stays False: 400/404/429 and every 5xx are outages or client errors the
    manager may recover from, and a code this table does not know must never stop a scan.
    """
    from apps.api.scanner_worker import executor as executor_mod

    verdicts = {
        401: True, 403: True, 409: True,
        400: False, 404: False, 429: False,
        500: False, 502: False, 503: False, 504: False,
    }
    for code, expected in verdicts.items():
        assert executor_mod._is_authoritative_refusal(_http_error(code)) is expected, (
            f"HTTP {code} was classified wrongly"
        )

    # The lease/probe transport expresses the same refusal as a LeaseError.
    assert executor_mod._is_authoritative_refusal(
        lease_loop.LeaseError(lease_loop.REASON_AUTH_FAILED, "403")
    ) is True
    # ...but a non-auth LeaseError is an outage.
    assert executor_mod._is_authoritative_refusal(
        lease_loop.LeaseError(lease_loop.REASON_MANAGER_UNAVAILABLE, "503")
    ) is False
    # An exception carrying no HTTP response at all is never a verdict.
    assert executor_mod._is_authoritative_refusal(ValueError("boom")) is False


def test_a_refusal_latch_is_never_cleared_by_a_later_success():
    """Write-once. A single refusal ends the pipeline even if the next call would succeed."""
    from apps.api.scanner_worker import executor as executor_mod

    latch = {"reason": None}
    executor_mod._note_refusal(latch, _http_error(403), scan_id=uuid.uuid4(),
                               tool="alpha", event="test.refused")
    assert latch["reason"] == "revoked"
    # A second observation cannot downgrade or overwrite it.
    executor_mod._note_refusal(latch, _http_error(401), scan_id=uuid.uuid4(),
                               tool="beta", event="test.refused")
    assert latch["reason"] == "revoked"


# --- 4. scope: the emergency contract is not widened -------------------------------------

def test_the_submission_verdict_never_kills_a_running_tool():
    """Cooperative, exactly like the probe path: no kill/terminate/cancel was introduced."""
    import ast
    import inspect

    from apps.api.scanner_worker import executor as executor_mod

    tree = ast.parse(inspect.getsource(executor_mod))
    forbidden = {"terminate_and_reap", "kill", "terminate", "cancel"}
    called = {
        (getattr(n.func, "attr", None) or getattr(n.func, "id", None))
        for n in ast.walk(tree) if isinstance(n, ast.Call)
    }
    assert not (called & forbidden), f"a termination path was introduced: {called & forbidden}"


def test_public_scanning_is_untouched_by_the_submission_verdict():
    """The verdict is the CONTROL PLANE's answer, not a zone rule.

    A public scan whose submissions all succeed runs its whole pipeline: nothing in this
    change gates on zone, site or the emergency flag worker-side, so public engagements
    behave exactly as they did. (The emergency switch itself remains private-only, and is
    enforced in the manager's gate -- untouched by this task.)
    """
    executed = []
    reporter = _P8Reporter(failing=None, exc=RuntimeError("never raised"))
    outcome = _run_p8_pipeline(reporter, executed)

    assert executed == ["alpha", "beta", "gamma"]
    assert outcome == "completed"
    assert reporter.started == ["alpha", "beta", "gamma"]
