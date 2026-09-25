"""MBS.SC -- private-worker deployment: tooling, tunnel bring-up, secret handling.

Covers `scanner_worker/tunnel_setup.py`, the production entrypoint's networking step. The
module shells out to `wg`/`ip`, so every test here drives it through the injectable command
runner with output captured from the disposable lab -- no live tunnel, no privileged
container, no key material.

The properties under test are all fail-closed ones. A private worker that cannot prove its
tunnel is healthy must refuse to START, rather than coming up and rejecting every job it is
offered: a deployment fault reported as a stream of runtime refusals is far harder to
diagnose than one reported at startup.
"""
import os
import uuid

import pytest

from apps.api.scanner_engine import wireguard
from apps.api.scanner_worker import tunnel_setup


def _runner(mapping, *, default=(0, "", "")):
    """Command runner returning canned (rc, stdout, stderr) per command line."""
    calls = []

    def run(argv, timeout=10.0):
        calls.append(list(argv))
        return mapping.get(" ".join(argv), default)

    run.calls = calls
    return run


def _config(cidrs=("10.80.0.0/16",), **over):
    kwargs = dict(
        site_id=uuid.uuid4(),
        authorized_cidrs=list(cidrs),
        peer_public_key="dHsyX9zj3ciibKR7i50pOJnuLnxMqklYD+TyEV0EkAc=",
        endpoint_host="172.24.0.2", endpoint_port=51820,
        interface_address="10.99.0.2/32", persistent_keepalive=25,
    )
    kwargs.update(over)
    return wireguard.describe_config(**kwargs)


# ---------------------------------------------------------------------------------------
# Tooling
# ---------------------------------------------------------------------------------------

def test_missing_tooling_fails_loudly_at_startup(monkeypatch):
    """The exact deployment gap this work closed: without wg/ip the worker used to start
    and then refuse every private scan with TUNNEL_UNHEALTHY."""
    monkeypatch.setattr(tunnel_setup, "_run",
                        lambda argv, timeout=10.0: (127, "", f"{argv[0]}: not found"))
    with pytest.raises(tunnel_setup.TunnelSetupError) as exc:
        tunnel_setup.assert_tooling_present()
    assert exc.value.reason == tunnel_setup.REASON_TOOLING_MISSING
    # Names BOTH tools, so an operator fixes the image in one pass.
    assert "wg" in exc.value.message and "ip" in exc.value.message


def test_tooling_present_passes(monkeypatch):
    monkeypatch.setattr(tunnel_setup, "_run", lambda argv, timeout=10.0: (0, "v1.0", ""))
    tunnel_setup.assert_tooling_present()  # must not raise


def test_only_a_missing_binary_counts_as_missing(monkeypatch):
    """A tool that exists but exits non-zero for another reason is NOT 'missing' -- only
    rc 127 (not found) is, so a transient failure does not masquerade as a bad image."""
    monkeypatch.setattr(tunnel_setup, "_run", lambda argv, timeout=10.0: (1, "", "boom"))
    tunnel_setup.assert_tooling_present()  # must not raise


# ---------------------------------------------------------------------------------------
# Secret handling
# ---------------------------------------------------------------------------------------

def test_private_key_must_come_from_a_file(tmp_path):
    """An env var would appear in `docker inspect`, crash dumps and every child process's
    environment. The key is read from a mounted secret file instead."""
    with pytest.raises(tunnel_setup.TunnelSetupError) as exc:
        tunnel_setup.read_private_key(None)
    assert exc.value.reason == tunnel_setup.REASON_NO_PRIVATE_KEY
    # The guidance says to generate it IN the worker, not to accept one from the platform.
    assert "never accept one from the control plane" in exc.value.message


def test_empty_or_unreadable_key_file_is_refused(tmp_path):
    empty = tmp_path / "empty.key"
    empty.write_text("")
    with pytest.raises(tunnel_setup.TunnelSetupError) as exc:
        tunnel_setup.read_private_key(str(empty))
    assert exc.value.reason == tunnel_setup.REASON_NO_PRIVATE_KEY

    with pytest.raises(tunnel_setup.TunnelSetupError) as exc2:
        tunnel_setup.read_private_key(str(tmp_path / "does-not-exist.key"))
    assert exc2.value.reason == tunnel_setup.REASON_NO_PRIVATE_KEY


def test_key_file_contents_are_returned_stripped(tmp_path):
    key = tmp_path / "k"
    key.write_text("  ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg=  \n")
    assert tunnel_setup.read_private_key(str(key)).endswith("=")


def test_the_private_key_never_reaches_argv(monkeypatch, tmp_path):
    """argv is world-readable through /proc, so the key goes to a 0600 temp file that is
    unlinked immediately -- never onto a command line."""
    secret = "SUPERSECRETKEYVALUE0123456789abcdefghijklmn="
    run = _runner({})
    monkeypatch.setattr(tunnel_setup, "_run", run)
    monkeypatch.setattr(tunnel_setup.os.path, "isdir", lambda p: False)

    tunnel_setup.bring_up(_config(), private_key=secret, interface="wg0")

    flat = " ".join(" ".join(c) for c in run.calls)
    assert secret not in flat, "the private key was passed on a command line"
    # It was handed over by PATH, and `wg set` was told to read that file.
    assert any("private-key" in c for c in (" ".join(x) for x in run.calls))


def test_the_temp_key_file_is_removed(monkeypatch, tmp_path):
    """The key must not survive the call that used it."""
    captured = {}

    def fake_run(argv, timeout=10.0):
        if "private-key" in argv:
            captured["path"] = argv[argv.index("private-key") + 1]
            # It exists while wg is reading it...
            captured["existed"] = os.path.exists(captured["path"])
        return 0, "", ""

    monkeypatch.setattr(tunnel_setup, "_run", fake_run)
    monkeypatch.setattr(tunnel_setup.os.path, "isdir", lambda p: False)
    tunnel_setup.bring_up(_config(), private_key="k" * 32, interface="wg0")

    assert captured.get("existed") is True
    assert not os.path.exists(captured["path"]), "the key file outlived the wg call"


# ---------------------------------------------------------------------------------------
# Routing: exactly the authorized CIDRs, never a default route
# ---------------------------------------------------------------------------------------

def test_only_the_authorized_cidrs_are_routed(monkeypatch):
    run = _runner({})
    monkeypatch.setattr(tunnel_setup, "_run", run)
    monkeypatch.setattr(tunnel_setup.os.path, "isdir", lambda p: False)

    tunnel_setup.bring_up(_config(("10.80.0.0/16", "192.168.5.0/24")),
                          private_key="k" * 32, interface="wg0")

    routes = [c for c in run.calls if c[:2] == ["ip", "route"]]
    installed = {c[3] for c in routes}
    assert installed == {"10.80.0.0/16", "192.168.5.0/24"}
    # And NOTHING resembling a default route was requested.
    assert not any(r.endswith("/0") or r == "default" for r in installed)


def test_bring_up_refuses_a_default_route_in_the_config(monkeypatch):
    """`build_allowed_ips` already refuses one; this is the second gate, in case a
    TunnelConfig were built some other way."""
    monkeypatch.setattr(tunnel_setup, "_run", _runner({}))
    cfg = wireguard.TunnelConfig(
        site_id=str(uuid.uuid4()), interface_address="10.99.0.2/32",
        allowed_ips=("0.0.0.0/0",), peer_public_key="p", endpoint="h:1",
    )
    with pytest.raises(tunnel_setup.TunnelSetupError) as exc:
        tunnel_setup.bring_up(cfg, private_key="k" * 32)
    assert exc.value.reason == tunnel_setup.REASON_DEFAULT_ROUTE


def test_an_unexpected_default_route_blocks_startup(monkeypatch):
    """Checked as an INDEPENDENT observation after bring-up: a default route could be
    inherited from a restarted container or added by hand."""
    monkeypatch.setattr(tunnel_setup, "_run", _runner({
        "ip -o route show default": (0, "default dev wg0 scope link \n", ""),
    }))
    with pytest.raises(tunnel_setup.TunnelSetupError) as exc:
        tunnel_setup.assert_no_default_route("wg0")
    assert exc.value.reason == tunnel_setup.REASON_DEFAULT_ROUTE


def test_a_default_route_on_another_interface_is_fine(monkeypatch):
    """The container legitimately has a default route on eth0/eth1 -- that is how it
    reaches the manager. Only one pointing at the TUNNEL is a problem."""
    monkeypatch.setattr(tunnel_setup, "_run", _runner({
        "ip -o route show default": (0, "default via 172.24.0.1 dev eth1 \n", ""),
    }))
    tunnel_setup.assert_no_default_route("wg0")  # must not raise


def test_interface_creation_failure_is_reported_with_the_capability_hint(monkeypatch):
    monkeypatch.setattr(tunnel_setup, "_run", _runner({
        "ip link add dev wg0 type wireguard": (1, "", "Operation not permitted"),
    }))
    with pytest.raises(tunnel_setup.TunnelSetupError) as exc:
        tunnel_setup.bring_up(_config(), private_key="k" * 32)
    assert exc.value.reason == tunnel_setup.REASON_INTERFACE_FAILED
    assert "CAP_NET_ADMIN" in exc.value.message


def test_an_existing_interface_is_reconfigured_not_treated_as_an_error(monkeypatch):
    """A container restart leaves wg0 behind; bring-up must be idempotent."""
    run = _runner({
        "ip link add dev wg0 type wireguard": (1, "", "RTNETLINK answers: File exists"),
    })
    monkeypatch.setattr(tunnel_setup, "_run", run)
    monkeypatch.setattr(tunnel_setup.os.path, "isdir", lambda p: False)
    tunnel_setup.bring_up(_config(), private_key="k" * 32)  # must not raise
    assert any(c[:2] == ["ip", "route"] for c in run.calls)


# ---------------------------------------------------------------------------------------
# The whole startup sequence
# ---------------------------------------------------------------------------------------

def test_setup_and_verify_runs_the_existing_preflight(monkeypatch):
    """Startup uses the SAME preflight the lease loop runs per job, so a worker that would
    refuse every scan refuses to start instead."""
    monkeypatch.setattr(tunnel_setup, "_run", _runner({}))
    monkeypatch.setattr(tunnel_setup.os.path, "isdir", lambda p: False)
    healthy = wireguard.StaticTunnelProbe(wireguard.TunnelStatus(
        interface_up=True, last_handshake_age_s=5, routes=("10.80.0.0/16",),
        dns_ok=True, peer_reachable=True,
    ))
    status = tunnel_setup.setup_and_verify(
        _config(), private_key="k" * 32, interface="wg0", probe=healthy
    )
    assert status.interface_up is True


@pytest.mark.parametrize("status,expected", [
    (wireguard.TunnelStatus(interface_up=False), wireguard.REASON_TUNNEL_UNHEALTHY),
    (wireguard.TunnelStatus(interface_up=True, last_handshake_age_s=None),
     wireguard.REASON_NO_HANDSHAKE),
    (wireguard.TunnelStatus(interface_up=True, last_handshake_age_s=9999,
                            routes=("10.80.0.0/16",)), wireguard.REASON_HANDSHAKE_STALE),
    (wireguard.TunnelStatus(interface_up=True, last_handshake_age_s=5, routes=()),
     wireguard.REASON_ROUTE_MISSING),
])
def test_an_unhealthy_tunnel_refuses_startup(monkeypatch, status, expected):
    """Every unhealthy condition stops the worker BEFORE the lease loop starts."""
    monkeypatch.setattr(tunnel_setup, "_run", _runner({}))
    monkeypatch.setattr(tunnel_setup.os.path, "isdir", lambda p: False)
    with pytest.raises(wireguard.TunnelUnhealthy) as exc:
        tunnel_setup.setup_and_verify(
            _config(), private_key="k" * 32, probe=wireguard.StaticTunnelProbe(status)
        )
    assert exc.value.reason == expected


def test_no_error_message_ever_contains_the_private_key(monkeypatch):
    """A security check must not itself become the thing that prints a secret."""
    secret = "LEAKME0123456789abcdefghijklmnopqrstuvwxyz="
    monkeypatch.setattr(tunnel_setup, "_run", _runner({
        "ip link add dev wg0 type wireguard": (1, "", "Operation not permitted"),
    }))
    with pytest.raises(tunnel_setup.TunnelSetupError) as exc:
        tunnel_setup.bring_up(_config(), private_key=secret)
    assert secret not in str(exc.value)
    assert secret not in exc.value.message


# ---------------------------------------------------------------------------------------
# Entrypoint wiring
# ---------------------------------------------------------------------------------------

def test_a_public_worker_skips_tunnel_setup_entirely():
    """A public worker has no tunnel and no site -- startup must not try to build one.

    Asserted against the entrypoint's actual source: `_run()` guards the tunnel step on
    `identity.is_private`, so a public worker never reaches `_prepare_private_tunnel`.
    Checking the guard (rather than running the coroutine) keeps this a unit test while
    still failing if someone removes the condition.
    """
    import inspect

    from apps.api.scanner_worker import main as worker_main
    from apps.api.scanner_worker.lease_loop import WorkerIdentity

    src = inspect.getsource(worker_main._run)
    assert "if loop.identity.is_private:" in src, (
        "the entrypoint no longer guards tunnel setup on a private identity -- a public "
        "worker would try to build a tunnel it has no site or key for"
    )
    assert "_prepare_private_tunnel" in src

    public = WorkerIdentity(worker_id="w", pool_id="public-default", site_id=None,
                            manager_url="http://m:8100", token="t")
    assert public.is_private is False
    private = WorkerIdentity(worker_id="w", pool_id="p", site_id=str(uuid.uuid4()),
                             manager_url="http://m:8100", token="t")
    assert private.is_private is True


def test_private_startup_refuses_a_non_active_site(monkeypatch):
    """A suspended/revoked site must stop the worker at startup, not at first lease."""
    import asyncio

    from apps.api.scanner_worker.lease_loop import WorkerIdentity
    from apps.api.scanner_worker.main import _prepare_private_tunnel

    monkeypatch.setattr(tunnel_setup, "assert_tooling_present", lambda: None)

    class _Client:
        async def site_config(self):
            return {"site_id": str(uuid.uuid4()), "status": "suspended",
                    "authorized_cidrs": ["10.80.0.0/16"]}

    class _Loop:
        identity = WorkerIdentity(worker_id="w", pool_id="p", site_id=str(uuid.uuid4()),
                                  manager_url="http://m:8100", token="t")
        client = _Client()

    with pytest.raises(RuntimeError, match="not 'active'"):
        asyncio.run(_prepare_private_tunnel(_Loop()))
