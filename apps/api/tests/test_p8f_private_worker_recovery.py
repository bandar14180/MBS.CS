"""MBS.SC PHASE 8 (P8-F) -- private-worker recovery ORDERING.

THE BLOCKER THIS CLOSES
-----------------------
A private worker used to do tunnel setup before its first heartbeat, and
`_prepare_private_tunnel` begins with `GET /v1/site-config` -- an endpoint behind
`authenticated_worker`, which refuses a `suspended` worker. So a suspended private worker
died at startup before `loop.run()` (and therefore before any heartbeat) was reached:

    suspended private worker -> /v1/site-config -> 403 -> startup_failed -> exit 2
                             -> lease loop never starts -> never heartbeats

That made the documented recovery order -- heartbeat, verify healthy, THEN reactivate --
impossible to satisfy for a private worker: the one thing an operator was told to verify
could never happen while the worker was suspended. Verified live on `worker-site-lab-a`,
whose identity, credentials, pool, site and workspace bindings were all valid and whose
network reachability was proven (an HTTP 403 requires a completed round-trip).

THE FIX, AND WHAT IT IS NOT
---------------------------
Ordering only: `_run()` now heartbeats once (`_announce_liveness`) BEFORE tunnel setup for
a private worker. No authorization rule, dependency, or status set changed anywhere.

  * the heartbeat is itself an AUTHENTICATED endpoint -- a suspended worker is still
    refused, just at the step whose failure explains the situation and names the remedy;
  * `/v1/site-config` is NOT opened to suspended workers;
  * leasing still requires `assert_worker_may_lease`, and a private job additionally
    requires `preflight_private_job` to observe a healthy tunnel AT LEASE TIME -- the gate
    that actually prevents an unrouted private scan, independently of startup order.

These tests pin both the new ordering and every guard that must NOT have moved.
"""
import asyncio
import inspect
import uuid

import pytest

from apps.api.scanner_worker import main as worker_main
from apps.api.scanner_worker.lease_loop import (
    REASON_AUTH_FAILED,
    BackoffPolicy,
    LeaseError,
    LeaseLoop,
    WorkerIdentity,
)


def _identity(private=True):
    return WorkerIdentity(
        worker_id="wk-lab", pool_id="private-lab-a" if private else "public-default",
        site_id=str(uuid.uuid4()) if private else None,
        manager_url="http://manager:8100", token="t",
    )


class _Client:
    """Manager stand-in recording call ORDER -- the property under test."""

    def __init__(self, *, heartbeat_error=None, site_error=None):
        self.calls: list[str] = []
        self.heartbeat_error = heartbeat_error
        self.site_error = site_error
        self.heartbeat_bodies: list[dict] = []

    async def heartbeat(self, **kw):
        self.calls.append("heartbeat")
        self.heartbeat_bodies.append(kw)
        if self.heartbeat_error:
            raise self.heartbeat_error
        return {"ok": True, "worker_id": "wk-lab", "status": "active"}

    async def site_config(self):
        self.calls.append("site_config")
        if self.site_error:
            raise self.site_error
        return {"site_id": str(uuid.uuid4()), "status": "active",
                "authorized_cidrs": ["10.80.0.0/16"]}

    async def lease(self, max_jobs=1):
        self.calls.append("lease")
        return []

    async def complete(self, **kw):
        return {"accepted": True}


class _Probe:
    """Tunnel probe stand-in. `up=False` models a tunnel not yet brought up.

    A probe that cannot observe a healthy tunnel raises, which is what makes
    `observe_tunnel_health()` fail toward `unhealthy` -- the property the no-false-health
    tests below rely on.
    """

    def __init__(self, up=False):
        self.up = up

    def status(self):
        from apps.api.scanner_engine import wireguard

        if self.up:
            return None
        raise wireguard.TunnelUnhealthy(
            wireguard.REASON_NO_HANDSHAKE, "no handshake yet"
        )


def _loop(client, *, private=True, probe=None):
    loop = LeaseLoop(_identity(private), client, executor=None, max_iterations=1,
                     tunnel_probe=probe)
    loop.backoff = BackoffPolicy(base_seconds=0, max_seconds=0, idle_seconds=0,
                                 heartbeat_seconds=0)
    return loop


# =========================================================================================
# C. ACTIVE private worker: heartbeat BEFORE tunnel setup
# =========================================================================================

def test_heartbeat_happens_before_site_config_for_a_private_worker(monkeypatch):
    """THE ORDERING FIX. An active private worker must establish authenticated liveness
    before the slower, failure-prone tunnel bring-up -- so the operator's verification step
    is reachable."""
    client = _Client()
    loop = _loop(client)

    monkeypatch.setattr(worker_main, "build_loop", lambda *a, **k: loop)
    monkeypatch.setattr(worker_main, "_prepare_private_tunnel",
                        lambda lp: client.site_config())

    asyncio.run(worker_main._run())

    assert "heartbeat" in client.calls and "site_config" in client.calls
    assert client.calls.index("heartbeat") < client.calls.index("site_config"), (
        f"heartbeat must precede site_config; got {client.calls}"
    )


def test_the_entrypoint_orders_liveness_before_tunnel_setup():
    """Asserted against the entrypoint's real source, so reordering the two steps fails
    here even if a mock elsewhere would still pass."""
    src = inspect.getsource(worker_main._run)
    assert "_announce_liveness" in src
    assert "_prepare_private_tunnel" in src
    assert src.index("_announce_liveness") < src.index("_prepare_private_tunnel"), (
        "tunnel setup must not run before authenticated liveness -- that ordering is the "
        "P8-F private-recovery blocker"
    )
    # The public-worker guard must still be intact.
    assert "if loop.identity.is_private:" in src


def test_a_public_worker_does_not_get_the_extra_heartbeat(monkeypatch):
    """Scope check: the pre-tunnel heartbeat is private-only.

    A public worker has no tunnel step to order around, and `run()` already heartbeats
    first, so `_announce_liveness` must not run for it at all. Asserted by patching
    `_announce_liveness` itself rather than by counting heartbeats: the loop also emits its
    own rate-limited idle beat (`backoff.heartbeat_seconds`, zeroed in this fixture), so a
    raw count would conflate the two and pass for the wrong reason.
    """
    client = _Client()
    loop = _loop(client, private=False)
    announced: list[str] = []

    monkeypatch.setattr(worker_main, "build_loop", lambda *a, **k: loop)

    async def _spy(lp):
        announced.append(lp.identity.worker_id)

    monkeypatch.setattr(worker_main, "_announce_liveness", _spy)

    asyncio.run(worker_main._run())
    assert announced == [], "a public worker must not take the private pre-tunnel path"
    assert "site_config" not in client.calls


# =========================================================================================
# E(5). NO FALSE HEALTH
# =========================================================================================

def test_the_pre_tunnel_heartbeat_reports_unhealthy_not_ready():
    """A private worker whose tunnel is not up yet must say so. The heartbeat announces
    "authenticated and alive", never "ready to scan" -- inventing a healthy state to make
    startup pass would be exactly the false signal that makes a metric untrustworthy."""
    loop = _loop(_Client(), probe=_Probe(up=False))
    payload = loop.health_payload()
    assert payload["health_state"] == "unhealthy", payload
    assert payload["detail"]


def test_health_payload_matches_what_report_health_observes():
    """`health_payload` is a projection of the SAME `observe_tunnel_health()` the loop's own
    heartbeat uses -- not a second health model that could disagree with it."""
    loop = _loop(_Client(), probe=_Probe(up=False))
    state, age, detail = loop.observe_tunnel_health()
    assert loop.health_payload() == {
        "health_state": state, "detail": detail, "handshake_age_s": age
    }


# =========================================================================================
# A/D. SUSPENDED private worker: still refused, now with an actionable exit
# =========================================================================================

def test_a_suspended_private_worker_is_still_refused_at_the_heartbeat(monkeypatch):
    """NO BYPASS. The heartbeat is an authenticated endpoint: a suspended worker is refused
    there too. The fix changed WHICH step reports the refusal, never whether it happens."""
    client = _Client(
        heartbeat_error=LeaseError(REASON_AUTH_FAILED, 'manager refused (403): WORKER_SUSPENDED')
    )
    loop = _loop(client)
    monkeypatch.setattr(worker_main, "build_loop", lambda *a, **k: loop)
    monkeypatch.setattr(worker_main, "enforce_execution_plane_credentials", lambda: None)
    monkeypatch.setattr(worker_main, "configure_networking", lambda s: None)

    rc = worker_main.main()
    assert rc == 3, "an identity refusal during startup must exit 3, like one in the loop"
    # It never reached tunnel setup -- so it cannot have touched /v1/site-config.
    assert "site_config" not in client.calls


def test_a_suspended_private_worker_never_reaches_site_config(monkeypatch):
    """`/v1/site-config` is NOT opened to suspended workers, and is not even attempted:
    the refusal now happens one step earlier."""
    client = _Client(
        heartbeat_error=LeaseError(REASON_AUTH_FAILED, "403 WORKER_SUSPENDED")
    )
    loop = _loop(client)
    monkeypatch.setattr(worker_main, "build_loop", lambda *a, **k: loop)

    with pytest.raises(LeaseError):
        asyncio.run(worker_main._run())
    assert client.calls == ["heartbeat"]


def test_a_startup_refusal_and_a_loop_refusal_exit_the_same_way(monkeypatch):
    """Both are the same condition -- this worker's identity is refused and no retry can
    clear it -- so both must exit 3 and both must name the recovery command. They used to
    differ (2 vs 3), which is how the private worker's remedy went unstated."""
    monkeypatch.setattr(worker_main, "enforce_execution_plane_credentials", lambda: None)
    monkeypatch.setattr(worker_main, "configure_networking", lambda s: None)

    # (a) refused during STARTUP (private: at the pre-tunnel heartbeat)
    startup = _loop(_Client(heartbeat_error=LeaseError(REASON_AUTH_FAILED, "403")))
    monkeypatch.setattr(worker_main, "build_loop", lambda *a, **k: startup)
    assert worker_main.main() == 3

    # (b) refused INSIDE the loop (public: at lease)
    class _LeaseRefused(_Client):
        async def lease(self, max_jobs=1):
            raise LeaseError(REASON_AUTH_FAILED, "403")

    in_loop = _loop(_LeaseRefused(), private=False)
    monkeypatch.setattr(worker_main, "build_loop", lambda *a, **k: in_loop)
    assert worker_main.main() == 3


def test_a_non_auth_startup_failure_still_exits_2(monkeypatch):
    """Only an IDENTITY refusal maps to 3. A genuine deployment fault (bad site, missing
    tooling, unusable key) keeps its existing exit 2 -- the two must stay distinguishable."""
    client = _Client()
    loop = _loop(client)
    monkeypatch.setattr(worker_main, "build_loop", lambda *a, **k: loop)
    monkeypatch.setattr(worker_main, "enforce_execution_plane_credentials", lambda: None)
    monkeypatch.setattr(worker_main, "configure_networking", lambda s: None)

    async def _bad_site(lp):
        raise RuntimeError("private site is 'suspended', not 'active'; refusing to start.")

    monkeypatch.setattr(worker_main, "_prepare_private_tunnel", _bad_site)
    assert worker_main.main() == 2


# =========================================================================================
# F/G. Guards that must NOT have moved
# =========================================================================================

def test_no_self_reactivation_exists_in_the_worker():
    """The worker must never be able to change its own status. Asserted across the whole
    execution-plane package: no status write, no reactivation call, anywhere."""
    from pathlib import Path

    pkg = Path(worker_main.__file__).parent
    for path in pkg.glob("*.py"):
        src = path.read_text(encoding="utf-8")
        assert "reactivate_worker" not in src or "ops.reactivate_worker" in src, (
            f"{path.name} references reactivation other than as operator guidance"
        )
        assert "status = 'active'" not in src and 'status = "active"' not in src, (
            f"{path.name} appears to write a worker status"
        )


def test_the_per_job_tunnel_gate_is_untouched():
    """The gate that ACTUALLY prevents an unrouted private scan is per-job and independent
    of startup order. Deferring tunnel setup is therefore safe: a private job with no
    healthy tunnel is still refused at lease time, fail-closed."""
    from apps.api.scanner_worker.lease_loop import preflight_private_job

    with pytest.raises(LeaseError) as exc:
        preflight_private_job({"network_zone": "private", "site_id": "s"}, probe=None)
    assert exc.value.reason  # a missing probe is a REFUSAL, not a pass


def test_reactivation_still_refuses_every_forbidden_status():
    """F. The operator recovery guard is unchanged by this work -- `suspended` only."""
    from apps.api.modules.scanner_workers.models import (
        LEASE_ELIGIBLE_STATUSES,
        WORKING_STATUSES,
    )

    assert LEASE_ELIGIBLE_STATUSES == frozenset({"active"})
    assert WORKING_STATUSES == frozenset({"active", "draining"})
    src = inspect.getsource(
        __import__("apps.api.modules.scanner_workers.service", fromlist=["x"]).reactivate_worker
    )
    # The atomic guard: only `suspended`, and never a revoked row.
    assert "status = 'suspended'" in src and "revoked_at IS NULL" in src


def test_reactivation_does_not_touch_pool_site_or_workspace():
    """G. A recovery tool that could move a worker between tenants would be a tenancy bug."""
    src = inspect.getsource(
        __import__("apps.api.modules.scanner_workers.service", fromlist=["x"]).reactivate_worker
    )
    update = src[src.index("UPDATE scanner_workers"):src.index("WHERE worker_id")]
    for column in ("pool_id", "site_id", "workspace_id", "token_hash", "last_seen_at"):
        assert column not in update, f"reactivation must not write {column}"
