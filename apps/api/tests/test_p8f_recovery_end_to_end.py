"""P8-F RECOVERY, end to end through the real manager endpoints.

WHAT THIS PROVES THAT THE UNIT TESTS CANNOT
-------------------------------------------
`test_p8f_worker_reactivation.py` proves the state transition and its guards by calling the
service directly. That is necessary but not sufficient: the incident was not "a column had
the wrong value", it was "every HTTP endpoint the worker needs returned 403, so the scan was
never claimed and Subfinder never ran".

So this suite drives the ACTUAL endpoints -- POST /v1/heartbeat and POST /v1/lease -- across
the full recovery, and asserts on the scan row the lease produces:

    suspended  -> 403 on heartbeat, 403 on lease, scan stays queued   (the incident)
    reactivate -> 200 on heartbeat, last_seen_at refreshed
               -> 200 on lease, scan claimed: queued -> running
               -> the leased job carries the requested tools, subfinder first

The scan used here is shaped like the stranded one (35706539-…, www.lincoln.edu.my): a
PUBLIC target with the full 12-tool pipeline, `status='queued'`, `execution_token` NULL.
"""
import asyncio
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.core.deps import get_db
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scanner_workers import service as workers_service
from apps.api.modules.scanner_workers.models import ScannerWorker
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_manager.app import app as manager_app

# The pipeline the stranded scan requested, in registry phase order.
PIPELINE = ["subfinder", "amass", "dnsx", "httpx", "whatweb", "naabu",
            "nmap", "katana", "ffuf", "arjun", "nuclei", "nuclei-dast"]


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _seed(session):
    """A PUBLIC scan awaiting lease + a SUSPENDED public worker -- the incident's shape."""
    user = User(email=f"p8f-{uuid.uuid4()}@t.local", password_hash="x", full_name="p8f")
    session.add(user)
    await session.flush()
    ws = Workspace(name=f"p8f-{uuid.uuid4().hex[:8]}", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    project = Project(id=uuid.uuid4(), workspace_id=ws.id, name="p8f-p", created_by=user.id)
    session.add(project)
    await session.flush()
    target = Target(id=uuid.uuid4(), project_id=project.id, type="domain",
                    value="www.example-authorized.test", added_by=user.id,
                    network_zone="public", site_id=None)
    session.add(target)
    await session.flush()
    scan = Scan(
        id=uuid.uuid4(), workspace_id=ws.id, project_id=project.id, target_id=target.id,
        initiated_by=user.id, scan_type="web", status="queued",
        # celery_task_id deliberately NULL: this is a LEASE-dispatched scan.
        config={"site_id": None, "network_zone": "public", "requested_modules": PIPELINE},
        execution_token=None,
    )
    session.add(scan)
    token = workers_service.generate_worker_token()
    worker = ScannerWorker(
        id=uuid.uuid4(), worker_id=f"wk-pub-{uuid.uuid4().hex[:6]}",
        pool_id="public-default", site_id=None, workspace_id=None,
        status="suspended",  # <-- the incident state
        last_health_detail="stale: no worker heartbeat for 600s",
        token_hash=workers_service.hash_worker_token(token),
    )
    session.add(worker)
    await session.flush()
    return {"scan_id": scan.id, "worker_id": worker.worker_id, "token": token}


@pytest.fixture
def env():
    """Manager TestClient + a suspended public worker and its queued scan.

    Engine-per-loop for the same reason `test_scanner_manager_http.manager_env` documents:
    TestClient drives the app on its own loop, and an AsyncEngine binds pooled connections
    to the loop that created them.
    """
    state = {}

    async def seed():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    state.update(await _seed(s))
                    await s.commit()
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
    client = TestClient(manager_app)
    try:
        yield client, state
    finally:
        manager_app.dependency_overrides.clear()


def _auth(state):
    return {"X-Worker-Id": state["worker_id"], "Authorization": f"Bearer {state['token']}"}


def _reactivate(worker_id, reason="runtime validation"):
    async def _go():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    await workers_service.reactivate_worker(s, worker_id, reason=reason)
                    await s.commit()
        finally:
            await engine.dispose()

    asyncio.run(_go())


def _scan(scan_id):
    async def _go():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    row = await s.scalar(select(Scan).where(Scan.id == scan_id))
                    await s.refresh(row)
                    return {"status": row.status, "execution_token": row.execution_token,
                            "celery_task_id": row.celery_task_id}
        finally:
            await engine.dispose()

    return asyncio.run(_go())


def _worker_row(worker_id):
    async def _go():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    row = await s.scalar(
                        select(ScannerWorker).where(ScannerWorker.worker_id == worker_id)
                    )
                    await s.refresh(row)
                    return {"status": row.status, "last_seen_at": row.last_seen_at}
        finally:
            await engine.dispose()

    return asyncio.run(_go())


# --- Test 1 + 3 + 4: the incident, then the recovery, through real HTTP ------------------

def test_suspended_worker_is_refused_and_the_scan_stays_queued(env):
    """THE INCIDENT, reproduced: exactly the two 403s the live worker crash-looped on, and
    the consequence -- the scan is never claimed."""
    client, state = env
    hb = client.post("/v1/heartbeat", json={"health_state": "healthy"}, headers=_auth(state))
    assert hb.status_code == 403
    assert hb.json()["detail"] == workers_service.REASON_WORKER_SUSPENDED

    lease = client.post("/v1/lease", json={"max_jobs": 1}, headers=_auth(state))
    assert lease.status_code == 403
    assert lease.json()["detail"] == workers_service.REASON_WORKER_SUSPENDED

    row = _scan(state["scan_id"])
    assert row["status"] == "queued"
    assert row["execution_token"] is None  # _claim_scan never ran


def test_after_reactivation_heartbeat_succeeds_and_refreshes_liveness(env):
    """Test 3. The self-sealing loop is broken: the worker can now write `last_seen_at`
    itself, which is what makes it stop being stale."""
    client, state = env
    before = _worker_row(state["worker_id"])
    assert before["status"] == "suspended"

    _reactivate(state["worker_id"])

    hb = client.post("/v1/heartbeat", json={"health_state": "healthy"}, headers=_auth(state))
    assert hb.status_code == 200
    assert hb.json()["status"] == "active"

    after = _worker_row(state["worker_id"])
    assert after["status"] == "active"
    assert after["last_seen_at"] is not None
    # Refreshed BY THE WORKER's own heartbeat -- reactivation deliberately did not write it.
    if before["last_seen_at"] is not None:
        assert after["last_seen_at"] > before["last_seen_at"]


# --- Test 5 + 6: queued -> running, and the first tool ------------------------------------

def test_after_reactivation_lease_claims_the_scan_queued_to_running(env):
    """TEST 5 -- THE SUCCESS CRITERION. The transition that never happened in production:
    a real POST /v1/lease drives `_claim_scan`, moving the scan queued -> running and
    stamping the execution token that fences every subsequent write."""
    client, state = env
    _reactivate(state["worker_id"])

    lease = client.post("/v1/lease", json={"max_jobs": 5}, headers=_auth(state))
    assert lease.status_code == 200
    jobs = lease.json()["jobs"]
    assert len(jobs) >= 1

    leased = [j for j in jobs if str(j.get("scan_id")) == str(state["scan_id"])]
    assert leased, "the reactivated worker was not handed its queued scan"

    row = _scan(state["scan_id"])
    assert row["status"] == "running"          # queued -> running
    assert row["execution_token"] is not None  # claimed, and fenced


def test_the_leased_job_carries_the_full_pipeline_with_subfinder_first(env):
    """TEST 6 -- the first tool. Asserts the leased job authorizes the same 12-tool pipeline
    the scan requested, with subfinder present and FIRST in registry phase order.

    This is the honest boundary of an offline test: it proves the worker is authorized to
    run Subfinder and receives it as the first phase. Actually executing the binary and
    writing a ToolRun row needs the scanner image and a real authorized target -- that is
    runtime validation, not a unit test, and is reported separately.
    """
    client, state = env
    _reactivate(state["worker_id"])

    lease = client.post("/v1/lease", json={"max_jobs": 5}, headers=_auth(state))
    assert lease.status_code == 200
    job = next(j for j in lease.json()["jobs"]
               if str(j.get("scan_id")) == str(state["scan_id"]))

    modules = job.get("requested_modules") or (job.get("config") or {}).get("requested_modules")
    assert modules, f"the leased job carries no tool list: {sorted(job)}"
    assert "subfinder" in modules
    assert modules[0] == "subfinder", "subfinder must be the first phase of the pipeline"
    assert set(modules) == set(PIPELINE), "the leased pipeline differs from the requested one"


# --- The guard that must NOT be weakened -------------------------------------------------

def test_a_revoked_worker_is_still_refused_after_the_recovery_path_exists(env):
    """Adding a recovery path must not create a way back for a REVOKED worker. Proven at
    the HTTP layer, not just in the service: revocation stays terminal end to end."""
    client, state = env

    async def _revoke():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    await workers_service.revoke_worker(
                        s, state["worker_id"], reason="test: terminal"
                    )
                    await s.commit()
        finally:
            await engine.dispose()

    asyncio.run(_revoke())

    # The recovery path refuses it...
    with pytest.raises(workers_service.WorkerNotReactivatable):
        _reactivate(state["worker_id"])

    # ...and so does every endpoint.
    assert client.post("/v1/lease", json={"max_jobs": 1},
                       headers=_auth(state)).status_code == 403
    assert _scan(state["scan_id"])["status"] == "queued"
