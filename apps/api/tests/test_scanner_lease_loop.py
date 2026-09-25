"""MBS.SC -- worker-side lease loop (the Celery-consumption replacement).

Covers the 26 required cases for the lease mechanism. The manager is driven through an
injected transport rather than a live server, so these tests exercise the WORKER's
behaviour: what it accepts, what it refuses, and what it does when the manager misbehaves.
The manager's own authorization is tested separately (test_scanner_manager_http.py drives
the real ASGI app).

The single most important property here: the worker re-validates every leased job against
its OWN configured identity. A hostile or misconfigured manager must not be able to make
this worker scan another tenant's network, so most tests below hand the worker a job the
manager "approved" and assert it is refused anyway.
"""
import asyncio
import uuid

import pytest

from apps.api.scanner_engine import net_policy, wireguard
from apps.api.scanner_worker import lease_loop
from apps.api.scanner_worker.lease_loop import (
    BackoffPolicy,
    LeaseError,
    LeaseLoop,
    ManagerClient,
    WorkerIdentity,
    build_policy_for_job,
    preflight_private_job,
    validate_leased_job,
)

PUBLIC_WORKER = WorkerIdentity(
    worker_id="wk-public-1", pool_id="public-default", site_id=None,
    manager_url="http://scanner-manager:8100", token="tok-public",
)
SITE_A = str(uuid.uuid4())
SITE_B = str(uuid.uuid4())
PRIVATE_WORKER = WorkerIdentity(
    worker_id="wk-private-a", pool_id="private-a", site_id=SITE_A,
    manager_url="http://scanner-manager:8100", token="tok-private",
)


def _public_job(**over):
    job = {
        "scan_id": str(uuid.uuid4()),
        "workspace_id": str(uuid.uuid4()),
        "execution_token": str(uuid.uuid4()),
        "network_zone": "public",
        "site_id": None,
        "target": {"id": str(uuid.uuid4()), "type": "domain", "value": "scanme.example.com"},
        "requested_modules": ["httpx"],
        "authorized_cidrs": [],
        "dns_servers": [],
        "pool_id": None,
    }
    job.update(over)
    return job


def _private_job(**over):
    job = _public_job()
    job.update({
        "network_zone": "private", "site_id": SITE_A,
        "target": {"id": str(uuid.uuid4()), "type": "ip_range", "value": "10.0.5.0/24"},
        "authorized_cidrs": ["10.0.0.0/16"], "dns_servers": ["10.0.0.53"],
        "pool_id": "private-a",
    })
    job.update(over)
    return job


class FakeTransport:
    """Scripted manager. Records every call so tests can assert what the worker did."""

    def __init__(self, *, lease_jobs=None, complete_result=None, fail_lease_times=0,
                 fail_complete_times=0, auth_fail=False):
        self.calls = []
        self._lease_batches = list(lease_jobs or [])
        self._complete_result = complete_result or {"accepted": True, "status": "completed"}
        self._fail_lease_times = fail_lease_times
        self._fail_complete_times = fail_complete_times
        self._auth_fail = auth_fail

    async def __call__(self, method, url, *, headers=None, json=None):
        self.calls.append((url, json, headers))
        if self._auth_fail:
            raise LeaseError(lease_loop.REASON_AUTH_FAILED, "manager refused this worker (403)")
        if url.endswith("/v1/lease"):
            if self._fail_lease_times > 0:
                self._fail_lease_times -= 1
                raise ConnectionError("manager unreachable")
            jobs = self._lease_batches.pop(0) if self._lease_batches else []
            return {"jobs": jobs}
        if url.endswith("/v1/lease/complete"):
            if self._fail_complete_times > 0:
                self._fail_complete_times -= 1
                raise ConnectionError("manager unreachable")
            return self._complete_result
        if url.endswith("/v1/heartbeat"):
            return {"ok": True}
        return {}

    def completed_calls(self):
        return [j for (u, j, _) in self.calls if u.endswith("/v1/lease/complete")]


def _loop(identity, transport, *, executor=None, probe=None, max_iterations=1):
    client = ManagerClient(identity, transport=transport)
    return LeaseLoop(
        identity, client, executor=executor, tunnel_probe=probe,
        backoff=BackoffPolicy(base_seconds=0.001, max_seconds=0.002, idle_seconds=0.001),
        max_iterations=max_iterations,
    )


# =======================================================================================
# 1-3: obtaining work
# =======================================================================================

def test_worker_obtains_a_public_job_through_the_lease_endpoint():
    """Requirement 1: the public path works end to end through /v1/lease."""
    job = _public_job()
    seen = {}

    async def executor(j, policy):
        seen["job"] = j
        seen["policy"] = policy
        return "completed"

    transport = FakeTransport(lease_jobs=[[job]])
    loop = _loop(PUBLIC_WORKER, transport, executor=executor)
    stats = asyncio.run(loop.run())

    assert seen["job"]["scan_id"] == job["scan_id"]
    assert seen["policy"].is_private is False
    assert stats["leased"] == 1 and stats["completed"] == 1
    # The terminal write carried the token the lease issued.
    done = transport.completed_calls()
    assert done and done[0]["execution_token"] == job["execution_token"]
    assert done[0]["status"] == "completed"


def test_worker_obtains_an_authorized_private_job_with_a_healthy_tunnel():
    """Requirement 2 + 13: private work runs only behind a healthy tunnel."""
    job = _private_job()
    healthy = wireguard.StaticTunnelProbe(wireguard.TunnelStatus(
        interface_up=True, last_handshake_age_s=5, routes=("10.0.0.0/16",),
        dns_ok=True, peer_reachable=True,
    ))
    seen = {}

    async def executor(j, policy):
        seen["policy"] = policy
        return "completed"

    transport = FakeTransport(lease_jobs=[[job]])
    loop = _loop(PRIVATE_WORKER, transport, executor=executor, probe=healthy)
    stats = asyncio.run(loop.run())

    assert stats["completed"] == 1
    policy = seen["policy"]
    assert policy.is_private is True
    assert str(policy.site_id) == SITE_A
    assert [str(n) for n in policy.authorized_cidrs] == ["10.0.0.0/16"]
    assert policy.dns_servers == ("10.0.0.53",)


def test_no_available_job_is_idle_not_an_error():
    """Requirement 3: an empty lease is normal, and must not spin."""
    transport = FakeTransport(lease_jobs=[[]])
    loop = _loop(PUBLIC_WORKER, transport, executor=None)
    stats = asyncio.run(loop.run())
    assert stats["idle"] == 1
    assert stats["leased"] == 0
    assert transport.completed_calls() == []


# =======================================================================================
# 4-7: manager and credential failures
# =======================================================================================

def test_manager_temporarily_unavailable_is_retried_with_backoff():
    """Requirement 4: a transient outage backs off and recovers, never bypassed."""
    job = _public_job()

    async def executor(j, policy):
        return "completed"

    transport = FakeTransport(lease_jobs=[[job]], fail_lease_times=2)
    loop = _loop(PUBLIC_WORKER, transport, executor=executor, max_iterations=5)
    stats = asyncio.run(loop.run())
    assert stats["completed"] == 1, "worker never recovered after a transient outage"


def test_authentication_failure_stops_the_loop_instead_of_hammering():
    """Requirement 5 + 6: a refused credential (revoked/unknown worker) is terminal.

    Retrying a dead credential can never succeed and would only load the manager, so the
    loop stops and lets the container restart surface the problem.
    """
    transport = FakeTransport(auth_fail=True)
    loop = _loop(PUBLIC_WORKER, transport, executor=None, max_iterations=10)
    stats = asyncio.run(loop.run())
    assert stats["leased"] == 0
    # Stopped early rather than burning all 10 iterations.
    assert len([c for c in transport.calls if c[0].endswith("/v1/lease")]) == 1


def test_worker_never_falls_back_to_redis_or_the_database():
    """Requirements 23-26 (worker side): the loop's only outbound dependency is the manager.

    Checked against the IMPORT GRAPH via the AST, not against the file's text. A substring
    scan matches the module docstring -- which legitimately explains why Celery and Redis
    are gone -- and would fail for describing the very property it is testing. What matters
    is what the module actually imports.
    """
    import ast

    from apps.api.scanner_worker import executor as executor_mod

    forbidden_roots = {"redis", "celery", "boto3", "botocore", "sqlalchemy", "aiomysql", "pymysql"}
    for module in (lease_loop, executor_mod):
        tree = ast.parse(open(module.__file__, encoding="utf-8").read())
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
                # `from apps.api.celery_app...` -- catch the second segment too.
                parts = node.module.split(".")
                if len(parts) > 2:
                    imported.add(parts[2].replace("_app", ""))
        leaked = imported & forbidden_roots
        assert not leaked, (
            f"{module.__name__} imports {sorted(leaked)} -- the execution plane must reach "
            f"the control plane ONLY through the scanner-manager"
        )


# =======================================================================================
# 8-13: per-job authorization (the worker refusing what the manager 'approved')
# =======================================================================================

def test_wrong_site_job_is_refused_and_reported():
    """Requirement 10: tenant A's worker refuses a job for tenant B's site."""
    job = _private_job(site_id=SITE_B, pool_id="private-a")
    with pytest.raises(LeaseError) as exc:
        validate_leased_job(job, PRIVATE_WORKER)
    assert exc.value.reason == lease_loop.REASON_SITE_MISMATCH


def test_wrong_pool_job_is_refused():
    """Requirement 9."""
    job = _private_job(pool_id="private-b")
    with pytest.raises(LeaseError) as exc:
        validate_leased_job(job, PRIVATE_WORKER)
    assert exc.value.reason == lease_loop.REASON_POOL_MISMATCH


def test_public_worker_refuses_a_private_job():
    """Requirement 8: a worker with no tunnel must never attempt private work."""
    with pytest.raises(LeaseError) as exc:
        validate_leased_job(_private_job(), PUBLIC_WORKER)
    assert exc.value.reason == lease_loop.REASON_WORKER_UNAUTHORIZED


def test_private_worker_refuses_a_public_job():
    """A machine holding a customer tunnel must not also scan the open internet."""
    with pytest.raises(LeaseError) as exc:
        validate_leased_job(_public_job(), PRIVATE_WORKER)
    assert exc.value.reason == lease_loop.REASON_WORKER_UNAUTHORIZED


def test_private_job_without_authorized_cidrs_is_refused():
    """Requirement 12: an empty CIDR list must never read as 'unrestricted'."""
    with pytest.raises(LeaseError) as exc:
        validate_leased_job(_private_job(authorized_cidrs=[]), PRIVATE_WORKER)
    assert exc.value.reason == lease_loop.REASON_CIDR_NOT_AUTHORIZED


def test_job_without_an_execution_token_is_refused():
    """Requirement 14: unfenced work is never executed."""
    for bad in (None, "", "not-a-uuid"):
        with pytest.raises(LeaseError) as exc:
            validate_leased_job(_public_job(execution_token=bad), PUBLIC_WORKER)
        assert exc.value.reason == lease_loop.REASON_EXECUTION_TOKEN_INVALID


def test_job_without_a_target_is_refused():
    with pytest.raises(LeaseError) as exc:
        validate_leased_job(_public_job(target={}), PUBLIC_WORKER)
    assert exc.value.reason == lease_loop.REASON_MISSING_TARGET


def test_a_rejected_job_is_reported_failed_not_silently_dropped():
    """A refused job must be handed back with its reason, so it does not sit 'running'
    until the orphan reaper notices."""
    job = _private_job(site_id=SITE_B)  # wrong site for this worker
    executed = []

    async def executor(j, policy):
        executed.append(j)
        return "completed"

    transport = FakeTransport(lease_jobs=[[job]])
    loop = _loop(PRIVATE_WORKER, transport, executor=executor)
    stats = asyncio.run(loop.run())

    assert executed == [], "a job that failed validation was executed anyway"
    assert stats["rejected"] == 1
    done = transport.completed_calls()
    assert done and done[0]["status"] == "failed"
    assert done[0]["reason"] == lease_loop.REASON_SITE_MISMATCH


# =======================================================================================
# Tunnel health (requirement 13)
# =======================================================================================

@pytest.mark.parametrize("status,expected", [
    (wireguard.TunnelStatus(interface_up=False), wireguard.REASON_TUNNEL_UNHEALTHY),
    (wireguard.TunnelStatus(interface_up=True, last_handshake_age_s=None),
     wireguard.REASON_NO_HANDSHAKE),
    (wireguard.TunnelStatus(interface_up=True, last_handshake_age_s=9999,
                            routes=("10.0.0.0/16",)), wireguard.REASON_HANDSHAKE_STALE),
    (wireguard.TunnelStatus(interface_up=True, last_handshake_age_s=5, routes=()),
     wireguard.REASON_ROUTE_MISSING),
    (wireguard.TunnelStatus(interface_up=True, last_handshake_age_s=5,
                            routes=("10.0.0.0/16",), dns_ok=False),
     wireguard.REASON_DNS_UNAVAILABLE),
])
def test_unhealthy_tunnel_blocks_a_private_job(status, expected):
    with pytest.raises(LeaseError) as exc:
        preflight_private_job(_private_job(), probe=wireguard.StaticTunnelProbe(status))
    assert exc.value.reason == expected


def test_private_job_without_a_tunnel_probe_is_refused():
    """No probe = no proof the tunnel is up = no scan. Fail closed."""
    with pytest.raises(LeaseError) as exc:
        preflight_private_job(_private_job(), probe=None)
    assert exc.value.reason == lease_loop.REASON_TUNNEL_UNHEALTHY


def test_public_job_needs_no_tunnel_probe():
    preflight_private_job(_public_job(), probe=None)  # must not raise


# =======================================================================================
# O-1 -- an UNUSABLE authorized_cidrs set is a REJECTED JOB, not a transport failure
# =======================================================================================

@pytest.mark.parametrize("cidrs", [
    ["0.0.0.0/0"],          # the Phase 9 adversarial input: a default route
    ["::/0"],               # its IPv6 twin
    ["10.0.0.0/16", "0.0.0.0/0"],   # smuggled in alongside a legitimate CIDR
    ["not-a-cidr"],         # malformed
    ["10.0.0.0/16", "999.999.999.999/8"],  # one good, one malformed
])
def test_an_unusable_cidr_set_is_rejected_as_a_lease_error(cidrs):
    """O-1: `build_allowed_ips` refuses these with WireGuardConfigError (a ValueError).

    That is a property of the LEASED JOB, so preflight must translate it into a LeaseError
    -- the vocabulary `_handle_job` actually catches. Before the fix it escaped as a bare
    ValueError and `run()` classified it as a manager transport problem.
    """
    healthy = wireguard.StaticTunnelProbe(wireguard.TunnelStatus(
        interface_up=True, last_handshake_age_s=5, routes=("10.0.0.0/16",)))
    with pytest.raises(LeaseError) as exc:
        preflight_private_job(_private_job(authorized_cidrs=cidrs), probe=healthy)
    assert exc.value.reason == lease_loop.REASON_CIDR_NOT_AUTHORIZED


def test_a_forged_default_route_job_is_rejected_not_reported_unavailable(caplog):
    """O-1 end to end, through the REAL loop: the full rejection path must run.

    Proves all five O-1 properties at once: the job is rejected, it is handed back as
    FAILED with the right reason, `stats["rejected"]` counts it, the scan NEVER executes,
    and the run is not misclassified as `manager_unavailable`.
    """
    executed = []

    async def executor(j, policy):
        executed.append(j)
        return "completed"

    healthy = wireguard.StaticTunnelProbe(wireguard.TunnelStatus(
        interface_up=True, last_handshake_age_s=5, routes=("10.0.0.0/16",)))
    job = _private_job(authorized_cidrs=["0.0.0.0/0"])
    transport = FakeTransport(lease_jobs=[[job]])
    loop = _loop(PRIVATE_WORKER, transport, executor=executor, probe=healthy)

    with caplog.at_level("WARNING"):
        stats = asyncio.run(loop.run())

    assert executed == [], "a job with a default-route CIDR was EXECUTED"
    assert stats["rejected"] == 1, "the rejection was not counted"
    assert stats["completed"] == 0 and stats["failed"] == 0

    done = transport.completed_calls()
    assert done, "the scan was never handed back; it would sit 'running' until reaped"
    assert done[0]["status"] == "failed"
    assert done[0]["reason"] == lease_loop.REASON_CIDR_NOT_AUTHORIZED

    events = [r.getMessage() for r in caplog.records]
    assert any("lease_loop.job_rejected" in e for e in events), \
        "the job-rejection path did not run"
    assert not any("manager_unavailable" in e for e in events), \
        "O-1 regression: a bad job is still reported as a manager transport failure"


def test_the_o1_catch_does_not_swallow_transport_or_programming_errors():
    """O-1's catch must stay NARROW.

    A transport failure and an unexpected programming error must keep their EXISTING
    paths, or the fix would have turned real infrastructure problems into "bad job".
    """
    # 1. Transport failure -> still the backoff/retry path, NOT a rejection.
    transport = FakeTransport(lease_jobs=[[_public_job()]], fail_lease_times=1)

    async def ok(j, policy):
        return "completed"

    loop = _loop(PUBLIC_WORKER, transport, executor=ok, max_iterations=3)
    stats = asyncio.run(loop.run())
    assert stats["rejected"] == 0, "a transport outage was miscounted as a rejected job"
    assert stats["completed"] == 1, "the worker did not recover from a transient outage"

    # 2. An unexpected error from the PROBE is not a WireGuardConfigError and must not be
    #    translated into a job rejection by the new except clause.
    class ExplodingProbe(wireguard.TunnelProbe):
        def status(self, site_id):
            raise MemoryError("something genuinely unexpected")

    with pytest.raises(MemoryError):
        preflight_private_job(_private_job(), probe=ExplodingProbe())


# =======================================================================================
# 15-17: fencing, duplicates, concurrency
# =======================================================================================

def test_superseded_lease_is_not_retried_and_not_counted_successful():
    """Requirement 15 + 21: losing the fencing race is reported, never overwritten.

    `accepted: false` means another executor owns the row now (requeued on shutdown,
    reclaimed after a reap, or cancelled). Retrying would be an attempt to clobber them.
    """
    job = _public_job()

    async def executor(j, policy):
        return "completed"

    transport = FakeTransport(
        lease_jobs=[[job]],
        complete_result={"accepted": False, "reason": "reclaimed_by_new_owner",
                         "status": "running"},
    )
    loop = _loop(PUBLIC_WORKER, transport, executor=executor)
    stats = asyncio.run(loop.run())

    assert stats["completed"] == 0, "a superseded execution was counted as successful"
    assert len(transport.completed_calls()) == 1, "a superseded write was retried"


def test_duplicate_delivery_of_the_same_scan_is_handled():
    """Requirement 16: the same scan delivered twice runs with the token it was given
    each time; the manager's fencing decides which is authoritative."""
    job = _public_job()
    runs = []

    async def executor(j, policy):
        runs.append(j["execution_token"])
        return "completed"

    # Same scan_id twice, DIFFERENT tokens (as a real re-lease would produce).
    dup = dict(job, execution_token=str(uuid.uuid4()))
    transport = FakeTransport(lease_jobs=[[job], [dup]])
    loop = _loop(PUBLIC_WORKER, transport, executor=executor, max_iterations=2)
    asyncio.run(loop.run())

    assert len(runs) == 2
    tokens = [c["execution_token"] for c in transport.completed_calls()]
    assert tokens == runs, "the terminal write did not carry each execution's own token"


def test_concurrent_workers_do_not_share_policy():
    """Requirement 17: two loops in one process must not observe each other's policy."""
    job_a = _private_job(authorized_cidrs=["10.1.0.0/16"], site_id=SITE_A)
    worker_b_site = SITE_B
    job_b = _private_job(authorized_cidrs=["10.2.0.0/16"], site_id=worker_b_site,
                         pool_id="private-b")
    identity_b = WorkerIdentity(worker_id="wk-private-b", pool_id="private-b",
                                site_id=worker_b_site, manager_url="http://m:8100",
                                token="t")
    observed = {}
    healthy = wireguard.StaticTunnelProbe(wireguard.TunnelStatus(
        interface_up=True, last_handshake_age_s=5,
        routes=("10.1.0.0/16", "10.2.0.0/16"), dns_ok=True, peer_reachable=True))

    def make_executor(key):
        async def executor(j, policy):
            await asyncio.sleep(0)  # force interleaving
            observed[key] = [str(n) for n in net_policy.current().authorized_cidrs]
            await asyncio.sleep(0)
            assert net_policy.current().site_id == policy.site_id
            return "completed"
        return executor

    async def scenario():
        la = _loop(PRIVATE_WORKER, FakeTransport(lease_jobs=[[job_a]]),
                   executor=make_executor("a"), probe=healthy)
        lb = _loop(identity_b, FakeTransport(lease_jobs=[[job_b]]),
                   executor=make_executor("b"), probe=healthy)
        await asyncio.gather(la.run(), lb.run())

    asyncio.run(scenario())
    assert observed["a"] == ["10.1.0.0/16"]
    assert observed["b"] == ["10.2.0.0/16"]
    assert net_policy.current() is None, "policy leaked out of the loops"


# =======================================================================================
# 18-20: shutdown and result-submission reliability
# =======================================================================================

def test_graceful_shutdown_stops_leasing_new_work():
    """Requirement 18: request_stop() ends the loop without abandoning in-flight work."""
    job = _public_job()
    started = asyncio.Event()

    async def scenario():
        transport = FakeTransport(lease_jobs=[[job], [job], [job]])
        loop = _loop(PUBLIC_WORKER, transport, executor=None, max_iterations=None)

        async def executor(j, policy):
            started.set()
            await asyncio.sleep(0.02)   # still running when stop arrives
            return "completed"

        loop.executor = executor
        task = asyncio.ensure_future(loop.run())
        await started.wait()
        loop.request_stop()
        stats = await asyncio.wait_for(task, timeout=5)
        return stats, transport

    stats, transport = asyncio.run(scenario())
    # The in-flight scan was allowed to finish and report.
    assert stats["completed"] >= 1
    assert transport.completed_calls()[0]["status"] == "completed"


def test_result_submission_retries_a_transient_outage():
    """Requirement 19: a transient failure on the terminal write is retried."""
    job = _public_job()

    async def executor(j, policy):
        return "completed"

    transport = FakeTransport(lease_jobs=[[job]], fail_complete_times=2)
    loop = _loop(PUBLIC_WORKER, transport, executor=executor)
    stats = asyncio.run(loop.run())
    assert stats["completed"] == 1
    assert len(transport.completed_calls()) == 3, "the terminal write was not retried"


def test_manager_unavailable_during_submission_never_reports_success():
    """Requirement 20 -- the important one: if the authoritative write is not accepted,
    the scan is NOT reported successful. The orphan reaper is the backstop."""
    job = _public_job()

    async def executor(j, policy):
        return "completed"

    transport = FakeTransport(lease_jobs=[[job]], fail_complete_times=99)
    loop = _loop(PUBLIC_WORKER, transport, executor=executor)
    stats = asyncio.run(loop.run())
    assert stats["completed"] == 0, "scan reported successful without an accepted write"


def test_an_executor_exception_does_not_kill_the_loop():
    """One failing scan must not take the worker down."""
    async def boom(j, policy):
        raise RuntimeError("tool exploded")

    transport = FakeTransport(lease_jobs=[[_public_job()], [_public_job()]])
    loop = _loop(PUBLIC_WORKER, transport, executor=boom, max_iterations=2)
    stats = asyncio.run(loop.run())
    assert stats["failed"] == 2
    assert all(c["status"] == "failed" for c in transport.completed_calls())


# =======================================================================================
# Policy construction
# =======================================================================================

def test_public_job_yields_a_public_only_policy():
    policy = build_policy_for_job(_public_job())
    assert policy.is_private is False
    assert policy.authorized_cidrs == ()


def test_private_policy_carries_exactly_the_leased_cidrs():
    policy = build_policy_for_job(_private_job(authorized_cidrs=["10.0.0.0/16", "bad", ""]))
    assert [str(n) for n in policy.authorized_cidrs] == ["10.0.0.0/16"]


def test_backoff_is_bounded_and_jittered():
    b = BackoffPolicy(base_seconds=1.0, max_seconds=8.0)
    draws = [b.next_delay() for _ in range(20)]
    assert all(0 <= d <= 8.0 for d in draws), "backoff exceeded its ceiling"
    assert len(set(round(d, 6) for d in draws)) > 1, "no jitter -- workers would sync up"


# =======================================================================================
# END-TO-END: the REAL lease loop against the REAL manager app.
#
# Everything above drives the loop with a scripted transport. This drives the loop against
# the actual FastAPI manager over its real routes, so the two halves are proven to fit --
# a lease loop that agreed only with a mock would be worthless.
# =======================================================================================

def test_worker_obtains_and_completes_real_work_through_the_manager():
    """THE acceptance test: a credential-free worker gets authorized work from the manager,
    executes it, and records the outcome -- with no database, broker, or object store."""
    import uuid as _uuid

    from fastapi.testclient import TestClient
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.core.db import get_db
    from apps.api.modules.projects.models import Project, Target
    from apps.api.modules.scanner_workers import service as workers_service
    from apps.api.modules.scanner_workers.models import ScannerWorker
    from apps.api.modules.scans.models import Scan
    from apps.api.modules.users.models import User
    from apps.api.modules.workspaces.models import Workspace
    from apps.api.scanner_manager.app import app as manager_app

    def _engine():
        return create_async_engine(get_settings().database_url, poolclass=StaticPool)

    seeded = {}

    async def seed():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    user = User(email=f"e2e-{_uuid.uuid4()}@t.local", password_hash="x",
                                full_name="e2e")
                    s.add(user)
                    await s.flush()
                    ws = Workspace(name=f"e2e-{_uuid.uuid4().hex[:8]}", owner_user_id=user.id)
                    s.add(ws)
                    await s.flush()
                    proj = Project(id=_uuid.uuid4(), workspace_id=ws.id, name="e2e",
                                   created_by=user.id)
                    s.add(proj)
                    await s.flush()
                    # PUBLIC target -- the public scanning path through the new mechanism.
                    tgt = Target(id=_uuid.uuid4(), project_id=proj.id, type="domain",
                                 value="scanme.example.com", added_by=user.id,
                                 network_zone="public", site_id=None)
                    s.add(tgt)
                    await s.flush()
                    scan = Scan(id=_uuid.uuid4(), workspace_id=ws.id, project_id=proj.id,
                                target_id=tgt.id, initiated_by=user.id, scan_type="recon",
                                status="queued",
                                config={"requested_modules": ["httpx"],
                                        "network_zone": "public", "site_id": None})
                    s.add(scan)
                    tok = workers_service.generate_worker_token()
                    wk = ScannerWorker(
                        id=_uuid.uuid4(), worker_id=f"wk-e2e-{_uuid.uuid4().hex[:6]}",
                        pool_id="public-default", site_id=None, workspace_id=None,
                        status="active", token_hash=workers_service.hash_worker_token(tok),
                    )
                    s.add(wk)
                    await s.flush()
                    await s.commit()
                    seeded.update(scan_id=str(scan.id), worker_id=wk.worker_id, token=tok,
                                  ws=str(ws.id))
        finally:
            await engine.dispose()

    asyncio.run(seed())

    async def _override_db():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    yield s
        finally:
            await engine.dispose()

    manager_app.dependency_overrides[get_db] = _override_db
    http = TestClient(manager_app)

    # Bridge the worker's async transport onto the (sync) TestClient. This is the ONLY
    # adaptation -- the loop, its validation and its fencing are the production code paths.
    async def transport(method, url, *, headers=None, json=None):
        path = url.split("8100", 1)[-1] if "8100" in url else url
        resp = http.request(method, path, headers=headers, json=json)
        if resp.status_code in (401, 403):
            raise lease_loop.LeaseError(lease_loop.REASON_AUTH_FAILED, resp.text)
        resp.raise_for_status()
        return resp.json()

    identity = WorkerIdentity(
        worker_id=seeded["worker_id"], pool_id="public-default", site_id=None,
        manager_url="http://scanner-manager:8100", token=seeded["token"],
    )
    executed = {}

    async def executor(job, policy):
        # A stub in place of the tool binaries (not installed in CI, and this test must not
        # touch the network). Everything up to and including this call -- lease, claim,
        # token issue, worker-side re-validation, policy binding -- is production code.
        executed["job"] = job
        executed["policy_private"] = policy.is_private
        return "completed"

    try:
        loop = _loop(identity, transport, executor=executor, max_iterations=1)
        stats = asyncio.run(loop.run())
    finally:
        manager_app.dependency_overrides.clear()

    assert executed, "the worker never received a job from the real manager"
    assert executed["job"]["scan_id"] == seeded["scan_id"]
    assert executed["job"]["target"]["value"] == "scanme.example.com"
    assert executed["policy_private"] is False, "a public scan got a private policy"
    assert stats["completed"] == 1, "the fenced terminal write was not accepted"


# =======================================================================================
# COOPERATIVE CANCELLATION (Phase 1)
#
# The lease worker has no database, so it asks the manager -- through the read-only
# /v1/scan-status probe -- whether a scan is still its to run, BETWEEN tools. These tests
# pin the properties that make that safe: it stops before the next tool, it never touches
# the tool already running, it never opens a ToolRun for a tool it skips, and a failed
# probe leaves the scan running exactly as before.
# =======================================================================================

class _RecordingReporter:
    """Records every progress/result submission so a skipped tool is provably absent."""

    def __init__(self):
        self.started = []
        self.results = []

    async def submit_tool_started(self, **kw):
        self.started.append(kw.get("tool_name"))
        return {"ok": True}

    async def submit_tool_result(self, **kw):
        self.results.append(kw.get("tool_name"))
        return {"ok": True}

    async def submit_evidence(self, **kw):
        return {"ok": True}


def _stub_registry(executed, *, names=("alpha", "beta", "gamma"), on_run=None):
    """A registry of ordered no-network runners that append their name when they run."""
    from apps.api.scanner_engine.tool_runners.base import BaseToolRunner

    class _Raw:
        def __init__(self):
            self.command = "stub"
            self.stdout = ""
            self.stderr = ""
            self.exit_code = 0

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
                if on_run is not None:
                    await on_run(self.name)
                return _Raw()

            def parse(self, raw):  # noqa: ANN001
                return []

        registry[name] = _Runner
    return registry


def _exec_job(**over):
    job = {
        "scan_id": str(uuid.uuid4()),
        "execution_token": str(uuid.uuid4()),
        "target": {"value": "example.test", "type": "domain"},
        "requested_modules": ["alpha", "beta", "gamma"],
        "config": {},
    }
    job.update(over)
    return job


def _run_executor(registry, reporter, probe, job=None):
    from apps.api.scanner_worker.executor import execute_leased_job

    return asyncio.run(execute_leased_job(
        job or _exec_job(), None,
        reporter=reporter, registry=registry, stop_probe=probe,
    ))


def _probe_after(n, reason):
    """A probe that answers None for the first `n` calls, then `reason` forever."""
    state = {"calls": 0}

    async def probe():
        state["calls"] += 1
        return None if state["calls"] <= n else reason

    probe.state = state
    return probe


def test_cancelled_scan_stops_before_the_next_tool():
    """The gap this closes: a cancelled scan used to run every remaining tool."""
    executed = []
    reporter = _RecordingReporter()
    # The probe is called at the TOP of each iteration: the 1st call clears 'alpha', the
    # 2nd (before 'beta') reports the cancellation.
    outcome = _run_executor(_stub_registry(executed), reporter, _probe_after(1, "cancelled"))

    assert executed == ["alpha"], f"a tool ran after cancellation: {executed}"
    assert "beta" not in executed and "gamma" not in executed
    # The first tool completed normally, so the execution still reports what it did.
    assert reporter.results == ["alpha"]
    assert outcome == "completed"


def test_no_tool_run_row_is_opened_for_a_cancelled_scan():
    """The check must precede submit_tool_started, not just the runner call.

    Otherwise the manager opens a ToolRun row for a tool that never runs, and the orphan
    reconciler later has to invent a terminal status for it.
    """
    executed = []
    reporter = _RecordingReporter()
    _run_executor(_stub_registry(executed), reporter, _probe_after(1, "cancelled"))

    assert reporter.started == ["alpha"], (
        f"a start was announced for a skipped tool: {reporter.started}"
    )
    assert "beta" not in reporter.started


def test_revoked_execution_stops_before_the_next_tool():
    """Same cooperative stop for the ownership-loss reason, not just cancellation."""
    executed = []
    reporter = _RecordingReporter()
    _run_executor(_stub_registry(executed), reporter, _probe_after(2, "revoked"))

    assert executed == ["alpha", "beta"]
    assert "gamma" not in executed
    assert "gamma" not in reporter.started


def test_scan_status_probe_failure_does_not_abort_the_scan():
    """FAIL-OPEN. A manager outage must never read as a cancellation.

    This is the property that makes it safe to put a network call in the tool loop: if the
    probe cannot answer, the pipeline behaves exactly as it did before this check existed.
    """
    executed = []
    reporter = _RecordingReporter()

    async def broken_probe():
        raise ConnectionError("manager unreachable")

    outcome = _run_executor(_stub_registry(executed), reporter, broken_probe)

    assert executed == ["alpha", "beta", "gamma"], (
        f"a probe failure stopped a healthy scan: {executed}"
    )
    assert outcome == "completed"


def test_a_refused_probe_stops_the_scan_unlike_a_transport_failure():
    """A 401/403 is a VERDICT, not an outage -- and the two must not be conflated.

    `ManagerClient._request` already turns a 401/403 into LeaseError(REASON_AUTH_FAILED):
    the manager has decided this worker may no longer act on this scan (credential
    revoked, site suspended, private scanning emergency-disabled). Continuing would mean
    running tools against a customer network after the control plane explicitly refused
    this execution -- so it stops, where the transport failure above continues.
    """
    refused = []
    transport = []

    async def refusing_probe():
        raise LeaseError(lease_loop.REASON_AUTH_FAILED,
                         "manager refused this worker (403): PRIVATE_SCANNING_EMERGENCY_DISABLED")

    async def unreachable_probe():
        raise ConnectionError("manager unreachable")

    refused_reporter = _RecordingReporter()
    _run_executor(_stub_registry(refused), refused_reporter, refusing_probe)
    _run_executor(_stub_registry(transport), _RecordingReporter(), unreachable_probe)

    # The verdict stops the pipeline before the FIRST tool -- the probe runs at the top of
    # the loop, so nothing has started yet.
    assert refused == [], f"a refused execution kept running tools: {refused}"
    assert refused_reporter.started == [], "a ToolRun was opened after the manager refused"
    # The outage does not.
    assert transport == ["alpha", "beta", "gamma"]
    assert refused != transport, "a 403 verdict was treated like a transport failure"


def test_a_non_auth_lease_error_still_fails_open():
    """Only the AUTH refusal is a verdict; other lease-level errors are still outages."""
    executed = []

    async def unavailable_probe():
        raise LeaseError(lease_loop.REASON_MANAGER_UNAVAILABLE, "upstream 503")

    _run_executor(_stub_registry(executed), _RecordingReporter(), unavailable_probe)
    assert executed == ["alpha", "beta", "gamma"]


def test_an_unrecognised_stop_reason_is_ignored():
    """Fail-open extends to answers this build does not understand."""
    executed = []

    async def odd_probe():
        return "something-new"

    _run_executor(_stub_registry(executed), _RecordingReporter(), odd_probe)
    assert executed == ["alpha", "beta", "gamma"]


def test_no_probe_configured_behaves_exactly_as_before():
    """The probe is optional: an executor built without one runs the full pipeline."""
    executed = []
    _run_executor(_stub_registry(executed), _RecordingReporter(), None)
    assert executed == ["alpha", "beta", "gamma"]


def test_a_running_tool_is_not_killed_by_cancellation():
    """The cancellation is COOPERATIVE: a tool already running always finishes.

    Cancellation lands WHILE 'alpha' is mid-run. The executor must not cancel its task,
    terminate it, or reap it -- run_with_timeout keeps partial output precisely because a
    tool is allowed to finish, and a killed tool would lose it.
    """
    executed = []
    finished = []
    cancelled_mid_run = {"done": False}

    async def on_run(name):
        # The scan is cancelled while this tool is executing.
        cancelled_mid_run["done"] = True
        await asyncio.sleep(0)  # a real suspension point: a cancel would land here
        finished.append(name)   # only reached if the runner was NOT cancelled

    async def probe():
        return "cancelled" if cancelled_mid_run["done"] else None

    reporter = _RecordingReporter()
    _run_executor(_stub_registry(executed, on_run=on_run), reporter, probe)

    assert finished == ["alpha"], "the running tool was interrupted"
    assert executed == ["alpha"], f"a later tool started after cancellation: {executed}"
    # It ran to completion, so its result was reported like any other finished tool.
    assert reporter.results == ["alpha"]


def test_the_executor_never_terminates_a_tool_process():
    """Structural guard: Phase 1 introduced no kill path into the executor.

    Walks the parsed AST rather than the source text, so the module's own prose about
    `terminate_and_reap` (which lives INSIDE the runners, not here) cannot satisfy or
    trip this check -- only a real call can.
    """
    import ast as _ast
    import inspect as _inspect

    from apps.api.scanner_worker import executor as executor_mod

    tree = _ast.parse(_inspect.getsource(executor_mod))
    forbidden = {"terminate_and_reap", "kill", "terminate", "cancel"}
    called = set()
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Call):
            func = node.func
            name = getattr(func, "attr", None) or getattr(func, "id", None)
            if name:
                called.add(name)
    assert not (called & forbidden), (
        f"executor gained a termination path: {sorted(called & forbidden)}"
    )


def test_a_cancelled_scan_does_not_overwrite_its_terminal_state():
    """The worker still reports its outcome, and the manager still refuses it.

    Cooperative cancellation deliberately does NOT change the terminal-write contract:
    _safe_complete runs as always and the manager answers accepted=false /
    already_terminal, so the 'cancelled' row survives. This pins that the two mechanisms
    compose rather than one replacing the other.
    """
    executed = []
    job = _exec_job()
    reporter = _RecordingReporter()

    transport = FakeTransport(
        lease_jobs=[[_public_job(scan_id=job["scan_id"],
                                 execution_token=job["execution_token"])]],
        complete_result={"accepted": False, "reason": "already_terminal",
                         "status": "cancelled"},
    )

    async def executor(leased_job, policy, *, stop_probe=None):
        from apps.api.scanner_worker.executor import execute_leased_job

        return await execute_leased_job(
            leased_job, policy, reporter=reporter,
            registry=_stub_registry(executed), stop_probe=stop_probe,
        )

    loop = _loop(PUBLIC_WORKER, transport, executor=executor)
    asyncio.run(loop.run())

    # The terminal write was attempted and refused -- never suppressed, never retried into
    # an overwrite of the cancelled state.
    completions = transport.completed_calls()
    assert len(completions) == 1, completions
    assert completions[0]["status"] in ("completed", "failed")
    assert loop.stats["completed"] == 0, "a refused completion was counted successful"


def test_the_loop_passes_a_bound_probe_to_the_executor():
    """The wiring: the executor receives a working probe for THIS scan and token."""
    seen = {}
    job = _public_job()

    transport = FakeTransport(lease_jobs=[[job]])

    async def executor(leased_job, policy, *, stop_probe=None):
        seen["probe"] = stop_probe
        seen["reason"] = await stop_probe()
        return "completed"

    loop = _loop(PUBLIC_WORKER, transport, executor=executor)
    asyncio.run(loop.run())

    assert seen["probe"] is not None, "the executor was not given a stop probe"
    # FakeTransport answers unknown paths with {}, i.e. no stop_reason -> keep going.
    assert seen["reason"] is None
    urls = [u for (u, _, _) in transport.calls if "/v1/scan-status" in u]
    assert urls, "the probe did not query /v1/scan-status"
    assert job["scan_id"] in urls[0] and job["execution_token"] in urls[0]


def test_a_two_argument_executor_still_works():
    """Back-compat: the stop_probe keyword is only passed to executors that accept it."""
    calls = []

    async def legacy_executor(leased_job, policy):
        calls.append(leased_job["scan_id"])
        return "completed"

    transport = FakeTransport(lease_jobs=[[_public_job()]])
    loop = _loop(PUBLIC_WORKER, transport, executor=legacy_executor)
    asyncio.run(loop.run())

    assert len(calls) == 1, "a two-argument executor was not called exactly once"
    assert loop.stats["completed"] == 1
