"""MBS.SC -- scanner-manager boundary exercised over HTTP.

`test_scanner_manager_authz.py` tests the authorization FUNCTIONS. This file drives the
actual FastAPI app the way a worker (or a compromised worker) would: real requests, real
headers, real status codes. That distinction matters -- a check that exists in a service
module but is not wired into the endpoint protects nothing, and only an HTTP-level test
can tell the two apart.
"""
import asyncio
import base64
import uuid

import pytest
from fastapi.testclient import TestClient

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.core.db import get_db
from apps.api.modules.private_sites.models import PrivateSite
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scanner_workers import service as workers_service
from apps.api.modules.scanner_workers.models import ScannerWorker
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_manager.app import app as manager_app

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _seed_tenant(session, label):
    user = User(email=f"{label}-{uuid.uuid4()}@t.local", password_hash="x", full_name=label)
    session.add(user)
    await session.flush()
    ws = Workspace(name=f"{label}-{uuid.uuid4().hex[:8]}", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    site = PrivateSite(
        id=uuid.uuid4(), workspace_id=ws.id, name=f"{label}-site",
        authorized_cidrs=["10.0.0.0/16"], dns_servers=["10.0.0.53"], dns_search_domains=[],
        status="active", scanner_pool_id=f"pool-{label}",
    )
    session.add(site)
    await session.flush()
    project = Project(id=uuid.uuid4(), workspace_id=ws.id, name=f"{label}-p", created_by=user.id)
    session.add(project)
    await session.flush()
    target = Target(id=uuid.uuid4(), project_id=project.id, type="ip_range",
                    value="10.0.5.0/24", added_by=user.id, network_zone="private",
                    site_id=site.id)
    session.add(target)
    await session.flush()
    scan = Scan(id=uuid.uuid4(), workspace_id=ws.id, project_id=project.id,
                target_id=target.id, initiated_by=user.id, scan_type="recon",
                status="queued",
                # `requested_modules` is the AUTHORIZED tool list a submitted tool_name is
                # checked against, and `execution_token` is what fences a result write to
                # the current lease -- both are what the endpoints validate, so the fixture
                # has to carry them for any happy-path assertion to mean anything.
                config={"site_id": str(site.id), "network_zone": "private",
                        "requested_modules": ["nuclei", "httpx", "naabu"]},
                execution_token=uuid.uuid4())
    session.add(scan)
    token = workers_service.generate_worker_token()
    worker = ScannerWorker(
        id=uuid.uuid4(), worker_id=f"wk-{label}-{uuid.uuid4().hex[:6]}",
        pool_id=f"pool-{label}", site_id=site.id, workspace_id=ws.id, status="active",
        token_hash=workers_service.hash_worker_token(token),
    )
    session.add(worker)
    await session.flush()
    return {"ws": ws.id, "site": site, "scan": scan, "worker": worker, "token": token}


@pytest.fixture
def manager_env():
    """A live manager TestClient plus two seeded tenants.

    ENGINE-PER-LOOP, deliberately. `TestClient` drives the ASGI app on its OWN event loop,
    while this fixture seeds with `asyncio.run` on a different one. An AsyncEngine binds its
    pooled connections to the loop that created them, so sharing one engine across the two
    fails inside aiomysql with a bare `AttributeError: 'NoneType' object has no attribute
    'send'` (a closed transport from the dead loop) rather than anything that looks like a
    database problem -- diagnosed the hard way.

    So: seeding gets its own engine, and the `get_db` override builds a fresh engine per
    request on whatever loop is currently running, disposing it afterwards. Slower than a
    shared pool, and correct.
    """
    state = {}

    async def seed():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    state["a"] = await _seed_tenant(s, "alpha")
                    state["b"] = await _seed_tenant(s, "bravo")
                    await s.commit()
                # Detach plain values so no ORM object is touched after its session/loop dies.
                for key in ("a", "b"):
                    entry = state[key]
                    state[key] = {
                        "ws": entry["ws"],
                        "site_id": entry["site"].id,
                        "scan_id": entry["scan"].id,
                        "project_id": entry["scan"].project_id,
                        "execution_token": entry["scan"].execution_token,
                        "worker_id": entry["worker"].worker_id,
                        "token": entry["token"],
                    }
        finally:
            await engine.dispose()

    asyncio.run(seed())

    async def _override_db():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                # admin_bypass: the manager binds the workspace itself from the scan row
                # after authorizing the worker; without it the tenancy filter would reject
                # the bootstrap read of `scans` in this test session.
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


def _auth(entry):
    return {"X-Worker-Id": entry["worker_id"],
            "Authorization": f"Bearer {entry['token']}"}


# ---------------------------------------------------------------------------------------
# Authentication at the HTTP layer
# ---------------------------------------------------------------------------------------

def test_health_is_open_but_discloses_nothing(manager_env):
    client, _ = manager_env
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_requests_without_a_credential_are_rejected(manager_env):
    client, state = manager_env
    assert client.post("/v1/lease", json={"max_jobs": 1}).status_code == 401
    # An id with no secret is not a credential.
    r = client.post("/v1/lease", json={"max_jobs": 1},
                    headers={"X-Worker-Id": state["a"]["worker_id"]})
    assert r.status_code == 401


def test_a_wrong_token_is_rejected(manager_env):
    client, state = manager_env
    r = client.post("/v1/lease", json={"max_jobs": 1}, headers={
        "X-Worker-Id": state["a"]["worker_id"],
        "Authorization": "Bearer not-the-real-token",
    })
    assert r.status_code == 403
    assert r.json()["detail"] == workers_service.REASON_BAD_CREDENTIAL


def test_tenant_a_worker_cannot_use_tenant_b_token(manager_env):
    """The classic credential-swap: A's id with B's secret."""
    client, state = manager_env
    r = client.post("/v1/lease", json={"max_jobs": 1}, headers={
        "X-Worker-Id": state["a"]["worker_id"],
        "Authorization": f"Bearer {state['b']['token']}",
    })
    assert r.status_code == 403


# ---------------------------------------------------------------------------------------
# Cross-tenant refusal over HTTP
# ---------------------------------------------------------------------------------------

def test_worker_cannot_submit_evidence_for_another_tenants_scan(manager_env):
    """THE evidence test (requirement 14 / 19): A's authenticated worker attaches evidence
    to B's scan and must be refused."""
    client, state = manager_env
    payload = {
        "scan_id": str(state["b"]["scan_id"]),          # <-- another tenant's scan
        "tool_run_id": None,
        "content_type": "text/plain",
        "content_b64": base64.b64encode(b"stolen").decode(),
        # Even a VALID token for B's scan must not help: the tenant check runs first.
        "execution_token": str(state["b"]["execution_token"]),
    }
    r = client.post("/v1/evidence", json=payload, headers=_auth(state["a"]))
    assert r.status_code == 403, r.text
    assert r.json()["detail"] in {
        workers_service.REASON_WRONG_SITE,
        workers_service.REASON_WRONG_WORKSPACE,
        "SCAN_NOT_AUTHORIZED",
    }


def test_worker_cannot_submit_tool_results_for_another_tenants_scan(manager_env):
    client, state = manager_env
    r = client.post("/v1/tool-results", headers=_auth(state["a"]), json={
        "scan_id": str(state["b"]["scan_id"]),
        "tool_run_id": str(uuid.uuid4()),
        "tool_name": "nuclei",
        "execution_token": str(state["b"]["execution_token"]),
        "status": "completed",
        "findings": [],
    })
    assert r.status_code == 403


def test_an_unknown_scan_id_is_403_not_404(manager_env):
    """A 404 would let a worker probe which scan ids exist platform-wide."""
    client, state = manager_env
    r = client.post("/v1/tool-results", headers=_auth(state["a"]), json={
        "scan_id": str(uuid.uuid4()), "tool_run_id": str(uuid.uuid4()),
        "tool_name": "nuclei", "execution_token": str(uuid.uuid4()),
        "status": "completed", "findings": [],
    })
    assert r.status_code == 403


def test_site_config_returns_only_the_workers_own_site_and_no_private_key(manager_env):
    """The endpoint takes NO site parameter, so a worker cannot ask for another
    customer's tunnel; and the response carries public key material only."""
    client, state = manager_env
    r = client.get("/v1/site-config", headers=_auth(state["a"]))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["site_id"] == str(state["a"]["site_id"])
    assert body["site_id"] != str(state["b"]["site_id"])
    blob = " ".join(str(v) for v in body.values()).lower()
    assert "privatekey" not in blob and "private_key" not in blob
    assert set(body) == {
        "site_id", "status", "authorized_cidrs", "dns_servers", "dns_search_domains",
        "wg_endpoint_host", "wg_endpoint_port", "peer_public_key", "wg_persistent_keepalive",
    }


def test_revoked_worker_is_refused_by_every_endpoint(manager_env):
    """Revocation is enforced at authentication, so one row update cuts the worker off
    everywhere at once -- without needing to reach the scanner host."""
    client, state = manager_env
    entry = state["a"]
    assert client.post("/v1/heartbeat", json={}, headers=_auth(entry)).status_code == 200

    async def revoke():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    await workers_service.revoke_worker(
                        s, entry["worker_id"], reason="test"
                    )
                    await s.commit()
        finally:
            await engine.dispose()

    asyncio.run(revoke())

    for path, body in (("/v1/heartbeat", {}), ("/v1/lease", {"max_jobs": 1})):
        r = client.post(path, json=body, headers=_auth(entry))
        assert r.status_code == 403, f"{path} still served a revoked worker"
    assert client.get("/v1/site-config", headers=_auth(entry)).status_code == 403


def test_lease_returns_only_the_workers_own_tenant_jobs(manager_env):
    """A lease is filtered by the worker's OWN binding, so B's queued scan can never
    appear in A's lease response."""
    client, state = manager_env
    r = client.post("/v1/lease", json={"max_jobs": 10}, headers=_auth(state["a"]))
    assert r.status_code == 200, r.text
    ids = {j["scan_id"] for j in r.json()["jobs"]}
    assert str(state["b"]["scan_id"]) not in ids, "leaked another tenant's scan"
    for job in r.json()["jobs"]:
        assert job["workspace_id"] == str(state["a"]["ws"])


def test_evidence_digest_mismatch_is_rejected(manager_env):
    """A claimed sha256 that disagrees with the bytes is refused outright -- the mismatch
    itself is the signal, so we do not silently store the real digest."""
    client, state = manager_env
    r = client.post("/v1/evidence", headers=_auth(state["a"]), json={
        "scan_id": str(state["a"]["scan_id"]),
        "content_type": "text/plain",
        "content_b64": base64.b64encode(b"real content").decode(),
        "sha256": "0" * 64,
        "execution_token": str(state["a"]["execution_token"]),
    })
    assert r.status_code == 400
    assert r.json()["detail"] == "EVIDENCE_DIGEST_MISMATCH"


def test_oversized_and_wrong_type_evidence_are_rejected(manager_env):
    client, state = manager_env
    scan_id = str(state["a"]["scan_id"])
    r = client.post("/v1/evidence", headers=_auth(state["a"]), json={
        "scan_id": scan_id, "content_type": "application/x-shellscript",
        "content_b64": base64.b64encode(b"#!/bin/sh").decode(),
        "execution_token": str(state["a"]["execution_token"]),
    })
    assert r.status_code == 400
    r = client.post("/v1/evidence", headers=_auth(state["a"]), json={
        "scan_id": scan_id, "content_type": "text/plain",
        "content_b64": base64.b64encode(b"").decode(),
        "execution_token": str(state["a"]["execution_token"]),
    })
    assert r.status_code == 400


# ---------------------------------------------------------------------------------------
# LEASE CLAIM + FENCED COMPLETION (the Celery-consumption replacement)
# ---------------------------------------------------------------------------------------

def test_lease_atomically_claims_and_issues_an_execution_token(manager_env):
    """A lease must CLAIM, not merely select.

    Before this, /v1/lease returned candidate rows without touching them, so two workers
    polling concurrently would both receive the same scan. The lease now goes through the
    same conditional UPDATE that has always fenced Celery redelivery.
    """
    client, state = manager_env
    r = client.post("/v1/lease", json={"max_jobs": 5}, headers=_auth(state["a"]))
    assert r.status_code == 200, r.text
    jobs = r.json()["jobs"]
    assert jobs, "worker leased nothing despite an authorized queued scan"

    job = jobs[0]
    # The token is issued SERVER-SIDE; a worker never chooses its own fencing token.
    assert job["execution_token"]
    uuid.UUID(job["execution_token"])
    # The execution plan is complete enough to run without a database.
    assert job["target"]["value"], "job carries no target value"
    assert job["network_zone"] in ("public", "private")
    assert job["workspace_id"] == str(state["a"]["ws"])

    # A SECOND lease must not hand out the same scan again -- it is now 'running'.
    r2 = client.post("/v1/lease", json={"max_jobs": 5}, headers=_auth(state["a"]))
    assert job["scan_id"] not in {j["scan_id"] for j in r2.json()["jobs"]}, (
        "the same scan was leased twice -- the claim is not atomic"
    )


def test_the_lease_payload_carries_no_credential(manager_env):
    """The execution plan must not leak anything credential-shaped."""
    client, state = manager_env
    jobs = client.post("/v1/lease", json={"max_jobs": 1},
                       headers=_auth(state["a"])).json()["jobs"]
    assert jobs
    blob = str(jobs[0]).lower()
    for forbidden in ("password", "secret", "token_hash", "privatekey", "private_key",
                      "mysql://", "redis://", "s3_", "access_key"):
        assert forbidden not in blob, f"lease payload leaked {forbidden!r}"


def test_completion_requires_the_matching_execution_token(manager_env):
    """Fencing: a wrong token cannot finalise someone else's scan."""
    client, state = manager_env
    job = client.post("/v1/lease", json={"max_jobs": 1},
                      headers=_auth(state["a"])).json()["jobs"][0]

    r = client.post("/v1/lease/complete", headers=_auth(state["a"]), json={
        "scan_id": job["scan_id"], "execution_token": str(uuid.uuid4()),  # WRONG token
        "status": "completed",
    })
    assert r.status_code == 200
    assert r.json()["accepted"] is False, "a wrong execution token finalised the scan"

    # The right token wins.
    r = client.post("/v1/lease/complete", headers=_auth(state["a"]), json={
        "scan_id": job["scan_id"], "execution_token": job["execution_token"],
        "status": "completed",
    })
    assert r.json()["accepted"] is True, r.text

    # ...and it cannot be finalised twice.
    r = client.post("/v1/lease/complete", headers=_auth(state["a"]), json={
        "scan_id": job["scan_id"], "execution_token": job["execution_token"],
        "status": "completed",
    })
    assert r.json()["accepted"] is False, "a terminal scan was finalised again"


def test_worker_cannot_invent_a_lifecycle_status(manager_env):
    """Only 'completed'/'failed' are accepted -- a worker must not name arbitrary states."""
    client, state = manager_env
    job = client.post("/v1/lease", json={"max_jobs": 1},
                      headers=_auth(state["a"])).json()["jobs"][0]
    for bad in ("cancelled", "queued", "running", "deleted"):
        r = client.post("/v1/lease/complete", headers=_auth(state["a"]), json={
            "scan_id": job["scan_id"], "execution_token": job["execution_token"],
            "status": bad,
        })
        assert r.status_code == 400, f"manager accepted invented status {bad!r}"


def test_lease_payload_carries_non_default_tool_config(manager_env):
    """F2-01: an allowlisted, non-default tool_config knob set at scan creation must
    survive into the lease payload's `config` key -- previously `_build_job_payload`
    never copied it, so the runner always saw an empty config regardless of what the
    caller requested."""
    client, state = manager_env

    async def _set_tool_config():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    scan = await s.get(Scan, state["a"]["scan_id"])
                    scan.config = {
                        **scan.config,
                        "timeout_seconds": 900,
                        "nuclei_tags": "cve,exposure",
                        "ffuf_rate": 42,
                    }
                    await s.commit()
        finally:
            await engine.dispose()

    asyncio.run(_set_tool_config())

    jobs = client.post("/v1/lease", json={"max_jobs": 1},
                       headers=_auth(state["a"])).json()["jobs"]
    assert jobs
    config = jobs[0]["config"]
    assert config["timeout_seconds"] == 900
    assert config["nuclei_tags"] == "cve,exposure"
    assert config["ffuf_rate"] == 42


def test_lease_payload_config_omits_orchestration_keys(manager_env):
    """F2-01 security boundary: `scan.config` also carries orchestration/safety keys
    (requested_modules, network_zone, site_id, ...) at its top level. The lease payload's
    `config` must be filtered to ONLY the tool-runner allowlist, so a worker never
    receives an orchestration key disguised as tool config."""
    client, state = manager_env
    jobs = client.post("/v1/lease", json={"max_jobs": 1},
                       headers=_auth(state["a"])).json()["jobs"]
    assert jobs
    config = jobs[0]["config"]
    for orchestration_key in ("requested_modules", "network_zone", "site_id",
                               "use_agent", "exploitation_enabled"):
        assert orchestration_key not in config, (
            f"lease payload config leaked orchestration key {orchestration_key!r}"
        )


def test_lease_payload_default_tool_config_is_empty(manager_env):
    """F2-01 regression: a scan created with no tool_config must still lease with an
    empty (not missing) config, so the runner falls back to its own defaults exactly
    as before this fix."""
    client, state = manager_env
    jobs = client.post("/v1/lease", json={"max_jobs": 1},
                       headers=_auth(state["a"])).json()["jobs"]
    assert jobs
    assert jobs[0]["config"] == {}


def test_manager_accepts_completed_with_errors_as_a_terminal_status(manager_env):
    """F2-02: the lease path must be able to report the same 3-way outcome the Celery
    orchestrator does. Previously only 'completed'/'failed' were accepted, so a worker
    could never report a scan where some tools failed/timed out but others succeeded."""
    client, state = manager_env
    job = client.post("/v1/lease", json={"max_jobs": 1},
                      headers=_auth(state["a"])).json()["jobs"][0]

    r = client.post("/v1/lease/complete", headers=_auth(state["a"]), json={
        "scan_id": job["scan_id"], "execution_token": job["execution_token"],
        "status": "completed_with_errors",
    })
    assert r.status_code == 200, r.text
    assert r.json()["accepted"] is True

    async def _read_status():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    scan = await s.get(Scan, uuid.UUID(job["scan_id"]))
                    return scan.status
        finally:
            await engine.dispose()

    assert asyncio.run(_read_status()) == "completed_with_errors"


def test_worker_cannot_complete_another_tenants_scan(manager_env):
    """Cross-tenant completion is refused even with a syntactically valid token."""
    client, state = manager_env
    r = client.post("/v1/lease/complete", headers=_auth(state["a"]), json={
        "scan_id": str(state["b"]["scan_id"]), "execution_token": str(uuid.uuid4()),
        "status": "completed",
    })
    assert r.status_code == 403


def test_two_workers_cannot_lease_the_same_scan(manager_env):
    """Requirement: worker A leases job X; worker B must not get job X.

    Both workers here are legitimately authorized for their own tenants, so this isolates
    the CLAIM (not the authorization) as the thing preventing double delivery.
    """
    client, state = manager_env
    a_jobs = client.post("/v1/lease", json={"max_jobs": 10},
                         headers=_auth(state["a"])).json()["jobs"]
    b_jobs = client.post("/v1/lease", json={"max_jobs": 10},
                         headers=_auth(state["b"])).json()["jobs"]
    a_ids = {j["scan_id"] for j in a_jobs}
    b_ids = {j["scan_id"] for j in b_jobs}
    assert not (a_ids & b_ids), "the same scan was leased to two workers"


# ---------------------------------------------------------------------------------------
# ORPHAN RECOVERY over HTTP: the reaper revokes a lease, the straggler is refused
# ---------------------------------------------------------------------------------------

def test_heartbeat_refreshes_scan_liveness_only_for_the_owning_token(manager_env):
    """A leased scan must be able to report liveness (or the reaper cannot tell a healthy
    long scan from a dead worker) -- but ONLY through the token that owns it."""
    client, state = manager_env
    job = client.post("/v1/lease", json={"max_jobs": 1},
                      headers=_auth(state["a"])).json()["jobs"][0]

    # Owning token -> the scan's heartbeat is stamped.
    r = client.post("/v1/heartbeat", headers=_auth(state["a"]), json={
        "health_state": "healthy",
        "scan_id": job["scan_id"], "execution_token": job["execution_token"],
    })
    assert r.status_code == 200, r.text
    assert r.json()["scan_heartbeat"] is True

    # A worker heartbeat with no scan named still works (plain liveness).
    r = client.post("/v1/heartbeat", headers=_auth(state["a"]), json={})
    assert r.status_code == 200
    assert r.json()["scan_heartbeat"] is False


def test_heartbeat_cannot_name_another_tenants_scan(manager_env):
    """Naming a scan in a heartbeat must not become a cross-tenant read."""
    client, state = manager_env
    r = client.post("/v1/heartbeat", headers=_auth(state["a"]), json={
        "scan_id": str(state["b"]["scan_id"]), "execution_token": str(uuid.uuid4()),
    })
    assert r.status_code == 403


def test_orphan_recovery_then_straggler_is_refused_over_http(manager_env):
    """THE end-to-end orphan case, driven through the real manager.

    Worker leases a scan, is 'lost', the reaper recovers it (clearing the token), and the
    straggler's completion is then refused -- it cannot overwrite the recovered state.
    """
    import asyncio as _asyncio

    from sqlalchemy import text as _text
    from sqlalchemy.ext.asyncio import async_sessionmaker as _maker
    from sqlalchemy.ext.asyncio import create_async_engine as _mk_engine
    from sqlalchemy.pool import StaticPool as _Static

    from apps.api.scanner_engine.orchestrator import reap_orphaned_scans

    client, state = manager_env
    job = client.post("/v1/lease", json={"max_jobs": 1},
                      headers=_auth(state["a"])).json()["jobs"][0]
    assert job["execution_token"]

    async def age_and_reap():
        engine = _mk_engine(get_settings().database_url, poolclass=_Static)
        try:
            async with _maker(engine, expire_on_commit=False)() as s:
                with tenancy.admin_bypass():
                    # Simulate the worker going silent (backdate its liveness only).
                    await s.execute(
                        _text("UPDATE scans SET last_heartbeat_at = "
                              "DATE_SUB(NOW(6), INTERVAL 900 SECOND), started_at = "
                              "DATE_SUB(NOW(6), INTERVAL 900 SECOND) WHERE id = :id"),
                        {"id": job["scan_id"]})
                    await s.commit()
                    n = await reap_orphaned_scans(s, timeout_seconds=3600,
                                                  stale_heartbeat_seconds=300)
                    await s.commit()
                    row = (await s.execute(
                        _text("SELECT status, execution_token FROM scans WHERE id = :id"),
                        {"id": job["scan_id"]})).first()
                    return n, row[0], row[1]
        finally:
            await engine.dispose()

    reaped, status, tok = _asyncio.run(age_and_reap())
    assert reaped >= 1, "the abandoned lease was not detected"
    assert status == "failed"
    assert tok is None, "the reaper did not revoke the dead worker's token"

    # The straggler returns and tries to finalise. REFUSED -- not accepted, not an error.
    r = client.post("/v1/lease/complete", headers=_auth(state["a"]), json={
        "scan_id": job["scan_id"], "execution_token": job["execution_token"],
        "status": "completed",
    })
    assert r.status_code == 200
    assert r.json()["accepted"] is False, (
        "a worker whose lease was reaped overwrote the recovered scan"
    )

    # And a heartbeat from the revoked token no longer refreshes the scan either.
    r = client.post("/v1/heartbeat", headers=_auth(state["a"]), json={
        "scan_id": job["scan_id"], "execution_token": job["execution_token"],
    })
    assert r.status_code == 200
    # The stamp is fenced, so nothing was refreshed even though the call succeeded.
    async def still_failed():
        engine = _mk_engine(get_settings().database_url, poolclass=_Static)
        try:
            async with _maker(engine, expire_on_commit=False)() as s:
                with tenancy.admin_bypass():
                    return (await s.execute(
                        _text("SELECT status FROM scans WHERE id = :id"),
                        {"id": job["scan_id"]})).scalar()
        finally:
            await engine.dispose()

    assert _asyncio.run(still_failed()) == "failed", "a revoked lease resurrected the scan"


def test_a_recovered_scan_can_be_leased_again(manager_env):
    """After recovery the scan must be claimable by an authorized worker -- otherwise
    recovery would simply lose the work."""
    import asyncio as _asyncio

    from sqlalchemy import text as _text
    from sqlalchemy.ext.asyncio import async_sessionmaker as _maker
    from sqlalchemy.ext.asyncio import create_async_engine as _mk_engine
    from sqlalchemy.pool import StaticPool as _Static

    from apps.api.scanner_engine.orchestrator import reap_orphaned_scans

    client, state = manager_env
    first = client.post("/v1/lease", json={"max_jobs": 1},
                        headers=_auth(state["a"])).json()["jobs"][0]

    async def age_and_reap():
        engine = _mk_engine(get_settings().database_url, poolclass=_Static)
        try:
            async with _maker(engine, expire_on_commit=False)() as s:
                with tenancy.admin_bypass():
                    await s.execute(
                        _text("UPDATE scans SET last_heartbeat_at = "
                              "DATE_SUB(NOW(6), INTERVAL 900 SECOND), started_at = "
                              "DATE_SUB(NOW(6), INTERVAL 900 SECOND) WHERE id = :id"),
                        {"id": first["scan_id"]})
                    await s.commit()
                    await reap_orphaned_scans(s, timeout_seconds=3600,
                                              stale_heartbeat_seconds=300)
                    await s.commit()
        finally:
            await engine.dispose()

    _asyncio.run(age_and_reap())

    second = client.post("/v1/lease", json={"max_jobs": 5},
                         headers=_auth(state["a"])).json()["jobs"]
    ids = {j["scan_id"] for j in second}
    assert first["scan_id"] in ids, "a recovered scan could not be leased again"
    reclaimed = next(j for j in second if j["scan_id"] == first["scan_id"])
    assert reclaimed["execution_token"] != first["execution_token"], (
        "the reclaim reused the dead execution token"
    )


# ---------------------------------------------------------------------------------------
# /v1/scan-status -- the cooperative cancellation probe (Phase 1)
# ---------------------------------------------------------------------------------------

def _set_scan(scan_id, **cols):
    """Write scan columns directly, the way a cancel / reap / re-claim would."""
    import asyncio as _asyncio

    from sqlalchemy import text as _text
    from sqlalchemy.ext.asyncio import async_sessionmaker as _maker
    from sqlalchemy.ext.asyncio import create_async_engine as _mk_engine
    from sqlalchemy.pool import StaticPool as _Static

    assignments = ", ".join(f"{k} = :{k}" for k in cols)
    params = {k: (str(v) if v is not None else None) for k, v in cols.items()}
    params["id"] = str(scan_id)

    async def _go():
        engine = _mk_engine(get_settings().database_url, poolclass=_Static)
        try:
            async with _maker(engine, expire_on_commit=False)() as s:
                with tenancy.admin_bypass():
                    await s.execute(
                        _text(f"UPDATE scans SET {assignments} WHERE id = :id"), params
                    )
                    await s.commit()
        finally:
            await engine.dispose()

    _asyncio.run(_go())


def _read_scan(scan_id):
    import asyncio as _asyncio

    from sqlalchemy import text as _text
    from sqlalchemy.ext.asyncio import async_sessionmaker as _maker
    from sqlalchemy.ext.asyncio import create_async_engine as _mk_engine
    from sqlalchemy.pool import StaticPool as _Static

    async def _go():
        engine = _mk_engine(get_settings().database_url, poolclass=_Static)
        try:
            async with _maker(engine, expire_on_commit=False)() as s:
                with tenancy.admin_bypass():
                    row = (await s.execute(
                        _text("SELECT status, execution_token, started_at, completed_at, "
                              "last_heartbeat_at, queued_at FROM scans WHERE id = :id"),
                        {"id": str(scan_id)},
                    )).first()
            return tuple(row) if row is not None else None
        finally:
            await engine.dispose()

    return _asyncio.run(_go())


def _probe(client, entry, *, scan_id=None, execution_token=None):
    return client.get("/v1/scan-status", headers=_auth(entry), params={
        "scan_id": str(scan_id if scan_id is not None else entry["scan_id"]),
        "execution_token": str(
            execution_token if execution_token is not None else entry["execution_token"]
        ),
    })


def test_scan_status_requires_worker_authorization(manager_env):
    """The probe is scoped exactly like every other scan-scoped endpoint here."""
    client, state = manager_env
    a, b = state["a"], state["b"]

    # No credential at all.
    assert client.get("/v1/scan-status", params={
        "scan_id": str(a["scan_id"]),
        "execution_token": str(a["execution_token"]),
    }).status_code == 401

    # Tenant A's worker asking about tenant B's scan -- with B's real token, so the only
    # thing standing between it and the answer is the authorization gate.
    assert _probe(client, a, scan_id=b["scan_id"],
                  execution_token=b["execution_token"]).status_code == 403

    # An unknown scan is 403, not 404: a 404 would make this an existence oracle.
    assert _probe(client, a, scan_id=uuid.uuid4()).status_code == 403

    # Its OWN scan is answerable.
    own = _probe(client, a)
    assert own.status_code == 200, own.text
    assert "stop_reason" in own.json()


def test_scan_status_reports_cancelled_and_revoked(manager_env):
    """The three answers, straight from the shared `_execution_stop_reason`."""
    client, state = manager_env
    a = state["a"]

    # The fixture scan is 'queued' with a token: not running, so this execution does not
    # own it -> revoked.
    assert _probe(client, a).json()["stop_reason"] == "revoked"

    # Running and owned by this token -> keep going.
    _set_scan(a["scan_id"], status="running", execution_token=a["execution_token"])
    assert _probe(client, a).json()["stop_reason"] is None

    # A later executor re-claimed it -> revoked for us.
    assert _probe(client, a, execution_token=uuid.uuid4()).json()["stop_reason"] == "revoked"

    # Cancelled wins over everything, and is reported as itself rather than as 'revoked'.
    _set_scan(a["scan_id"], status="cancelled")
    assert _probe(client, a).json()["stop_reason"] == "cancelled"


def test_scan_status_is_read_only(manager_env):
    """No write of any kind: status, token, timestamps, heartbeat, lease, finalization."""
    client, state = manager_env
    a = state["a"]
    _set_scan(a["scan_id"], status="running", execution_token=a["execution_token"])

    before = _read_scan(a["scan_id"])
    for _ in range(3):
        assert _probe(client, a).status_code == 200
    assert _read_scan(a["scan_id"]) == before, "the probe mutated the scan row"

    # It is also not a lease: the scan is still 'running' under the SAME token, and no
    # terminal state was written.
    status, token = before[0], before[1]
    assert status == "running"
    assert str(token) == str(a["execution_token"])

    # And a probe that answers 'cancelled' still writes nothing.
    _set_scan(a["scan_id"], status="cancelled")
    cancelled_before = _read_scan(a["scan_id"])
    assert _probe(client, a).json()["stop_reason"] == "cancelled"
    assert _read_scan(a["scan_id"]) == cancelled_before


# ---------------------------------------------------------------------------------------
# QUEUE DRAINING (Phase 8) -- the full lifecycle over real HTTP
#
# BEHAVIOURAL. `draining` was enforced but unreachable: nothing in the repository set it,
# and had anything done so naively the worker would have been cut off at AUTHENTICATION --
# losing the results of the very scan it was supposed to be allowed to finish. These tests
# drive the real ASGI app and pin both halves of the contract at once:
#
#     draining  ->  /v1/lease            REFUSED
#     draining  ->  everything else      ACCEPTED
# ---------------------------------------------------------------------------------------

def _set_worker_status(worker_id, status, *, revoked_at=None):
    """Set a worker's status directly, the way an operator action would."""
    import asyncio as _asyncio

    from sqlalchemy import text as _text
    from sqlalchemy.ext.asyncio import async_sessionmaker as _maker
    from sqlalchemy.ext.asyncio import create_async_engine as _mk_engine
    from sqlalchemy.pool import StaticPool as _Static

    async def _go():
        engine = _mk_engine(get_settings().database_url, poolclass=_Static)
        try:
            async with _maker(engine, expire_on_commit=False)() as s:
                with tenancy.admin_bypass():
                    await s.execute(
                        _text("UPDATE scanner_workers SET status = :st, revoked_at = :rv "
                              "WHERE worker_id = :wid"),
                        {"st": status, "rv": revoked_at, "wid": worker_id},
                    )
                    await s.commit()
        finally:
            await engine.dispose()

    _asyncio.run(_go())


def _read_worker_status(worker_id):
    import asyncio as _asyncio

    from sqlalchemy import text as _text
    from sqlalchemy.ext.asyncio import async_sessionmaker as _maker
    from sqlalchemy.ext.asyncio import create_async_engine as _mk_engine
    from sqlalchemy.pool import StaticPool as _Static

    async def _go():
        engine = _mk_engine(get_settings().database_url, poolclass=_Static)
        try:
            async with _maker(engine, expire_on_commit=False)() as s:
                with tenancy.admin_bypass():
                    row = (await s.execute(
                        _text("SELECT status, token_hash, pool_id, site_id, workspace_id "
                              "FROM scanner_workers WHERE worker_id = :wid"),
                        {"wid": worker_id},
                    )).first()
            return tuple(row) if row is not None else None
        finally:
            await engine.dispose()

    return _asyncio.run(_go())


def _drain(worker_id, reason="planned decommission"):
    """Call the real service-layer drain, as the operator CLI does."""
    import asyncio as _asyncio

    from sqlalchemy.ext.asyncio import async_sessionmaker as _maker
    from sqlalchemy.ext.asyncio import create_async_engine as _mk_engine
    from sqlalchemy.pool import StaticPool as _Static

    from apps.api.modules.scanner_workers import service as _ws

    async def _go():
        engine = _mk_engine(get_settings().database_url, poolclass=_Static)
        try:
            async with _maker(engine, expire_on_commit=False)() as s:
                with tenancy.admin_bypass():
                    worker = await _ws.drain_worker(s, worker_id, reason=reason)
                    await s.commit()
                    return worker.status
        finally:
            await engine.dispose()

    return _asyncio.run(_go())


def test_drain_transitions_active_to_draining(manager_env):
    """The operator action itself: one column, nothing else."""
    _, state = manager_env
    wid = state["a"]["worker_id"]

    before = _read_worker_status(wid)
    assert before[0] == "active"

    assert _drain(wid) == "draining"

    after = _read_worker_status(wid)
    assert after[0] == "draining"
    # Identity, pool, binding and CREDENTIAL are untouched -- a draining worker must still
    # be able to authenticate in order to finish reporting.
    assert after[1] == before[1], "draining destroyed the credential (that is revocation)"
    assert after[2:] == before[2:], "draining altered pool/site/workspace binding"


def test_a_draining_worker_is_refused_a_new_lease(manager_env):
    """The queue half of the contract, over real HTTP."""
    client, state = manager_env
    entry = state["a"]

    # Active: the lease endpoint answers normally.
    assert client.post("/v1/lease", json={"max_jobs": 1},
                       headers=_auth(entry)).status_code == 200

    _drain(entry["worker_id"])

    r = client.post("/v1/lease", json={"max_jobs": 1}, headers=_auth(entry))
    assert r.status_code == 403, r.text
    # Refused as DRAINING specifically, not as a generic "not active": an operator reading
    # this must be able to tell a deliberate decommission from an unapproved worker.
    assert "DRAINING" in r.text


def test_a_draining_worker_can_still_heartbeat(manager_env):
    """Liveness must survive draining, or the orphan reaper would kill the in-flight scan."""
    client, state = manager_env
    entry = state["a"]
    _drain(entry["worker_id"])

    r = client.post("/v1/heartbeat", json={"health_state": "healthy"}, headers=_auth(entry))
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True


def test_a_draining_worker_can_still_submit_tool_results(manager_env):
    """The in-flight half of the contract: the scan it already holds reports normally."""
    client, state = manager_env
    entry = state["a"]

    # Put the scan into the state an in-flight execution is in, owned by this worker's
    # token, then drain the worker mid-scan.
    _set_scan(entry["scan_id"], status="running", execution_token=entry["execution_token"])
    _drain(entry["worker_id"])

    tool_run_id = str(uuid.uuid4())
    started = client.post("/v1/tool-started", json={
        "scan_id": str(entry["scan_id"]), "tool_run_id": tool_run_id,
        "tool_name": "httpx", "execution_token": str(entry["execution_token"]),
    }, headers=_auth(entry))
    assert started.status_code == 200, f"a draining worker could not announce its tool: {started.text}"

    result = client.post("/v1/tool-results", json={
        "scan_id": str(entry["scan_id"]), "tool_run_id": tool_run_id,
        "tool_name": "httpx", "status": "completed", "findings": [],
        "execution_token": str(entry["execution_token"]),
    }, headers=_auth(entry))
    assert result.status_code == 200, f"a draining worker lost its tool result: {result.text}"


def test_a_draining_worker_is_authorized_to_submit_evidence(manager_env):
    """Evidence is the one in-flight path whose STORAGE needs MinIO.

    Split from the tool-result test on purpose: the authorization decision (does a draining
    worker get past the gate?) is what this change is responsible for, and it must be
    provable without an object store. So this asserts the gate was PASSED -- any status
    other than 403/401 means the drain did not block it -- and tolerates a storage-layer
    failure when MinIO is unreachable, which it is from a host outside the compose network.
    """
    client, state = manager_env
    entry = state["a"]

    _set_scan(entry["scan_id"], status="running", execution_token=entry["execution_token"])
    _drain(entry["worker_id"])

    # The tool run must EXIST before evidence can reference it: `evidence.tool_run_id` is a
    # real FK to `tool_runs`. Announcing it first (as the sibling tool-result test does)
    # is also what an in-flight execution actually does. Previously this posted a random
    # uuid, which only survived because MinIO was unreachable from the host and the test
    # skipped before the insert -- with a reachable object store it died on the FK instead
    # of testing the authorization gate it exists for.
    tool_run_id = str(uuid.uuid4())
    started = client.post("/v1/tool-started", json={
        "scan_id": str(entry["scan_id"]), "tool_run_id": tool_run_id,
        "tool_name": "httpx", "execution_token": str(entry["execution_token"]),
    }, headers=_auth(entry))
    assert started.status_code == 200, f"a draining worker could not announce its tool: {started.text}"

    payload = {
        "scan_id": str(entry["scan_id"]), "tool_run_id": tool_run_id,
        "content_b64": base64.b64encode(b"raw output").decode(),
        "content_type": "text/plain",
        "execution_token": str(entry["execution_token"]),
    }
    try:
        evidence = client.post("/v1/evidence", json=payload, headers=_auth(entry))
    except Exception as exc:  # noqa: BLE001
        # Reaching the OBJECT STORE is itself proof the authorization gate was passed --
        # a refused request never gets near MinIO. Only a storage-reachability error is
        # tolerated here; anything else is a real failure and is re-raised.
        text = f"{type(exc).__name__}: {exc}"
        if "minio" not in text.lower() and "getaddrinfo" not in text.lower():
            raise
        pytest.skip(f"evidence STORAGE unreachable from this host (gate was passed): {text}")

    assert evidence.status_code not in (401, 403), (
        f"a draining worker was REFUSED at the evidence gate: "
        f"{evidence.status_code} {evidence.text}"
    )


def test_a_draining_worker_can_complete_its_existing_lease(manager_env):
    """The last call an in-flight scan makes must still be accepted."""
    client, state = manager_env
    entry = state["a"]

    _set_scan(entry["scan_id"], status="running", execution_token=entry["execution_token"])
    _drain(entry["worker_id"])

    r = client.post("/v1/lease/complete", json={
        "scan_id": str(entry["scan_id"]),
        "execution_token": str(entry["execution_token"]),
        "status": "completed",
    }, headers=_auth(entry))
    assert r.status_code == 200, r.text
    assert r.json()["accepted"] is True, "a draining worker could not finish its own scan"


def test_draining_persists_and_still_refuses_leases_after_a_restart(manager_env):
    """A restart re-reads the row; nothing resets it to active."""
    client, state = manager_env
    entry = state["a"]
    _drain(entry["worker_id"])

    # A "restart" is, from the manager's point of view, simply the worker authenticating
    # again on a fresh connection -- which every request here already does.
    assert _read_worker_status(entry["worker_id"])[0] == "draining"
    assert client.post("/v1/heartbeat", json={"health_state": "healthy"},
                       headers=_auth(entry)).status_code == 200
    assert client.post("/v1/lease", json={"max_jobs": 1},
                       headers=_auth(entry)).status_code == 403
    assert _read_worker_status(entry["worker_id"])[0] == "draining"


def test_revoke_wins_over_drain(manager_env):
    """A revoked worker can never be walked back into a draining (still-authenticated) one.

    This is the concurrency invariant: the transition is conditional on `status='active'`,
    so a drain that arrives after a revoke matches zero rows and refuses.
    """
    from apps.api.modules.scanner_workers import service as ws

    _, state = manager_env
    wid = state["a"]["worker_id"]

    _set_worker_status(wid, "revoked", revoked_at="2026-01-01 00:00:00")
    with pytest.raises(ws.WorkerNotDrainable):
        _drain(wid)
    assert _read_worker_status(wid)[0] == "revoked", "drain resurrected a revoked worker"


@pytest.mark.parametrize("status", ["revoked", "suspended", "pending", "draining"])
def test_only_an_active_worker_can_be_drained(status, manager_env):
    """Every other starting state is refused, and nothing is written."""
    from apps.api.modules.scanner_workers import service as ws

    _, state = manager_env
    wid = state["a"]["worker_id"]
    _set_worker_status(wid, status)

    with pytest.raises(ws.WorkerNotDrainable):
        _drain(wid)
    assert _read_worker_status(wid)[0] == status, "a refused drain still wrote to the row"


def test_draining_an_unknown_worker_is_refused(manager_env):
    from apps.api.modules.scanner_workers import service as ws

    with pytest.raises(ws.WorkerNotAuthorized):
        _drain(f"no-such-worker-{uuid.uuid4().hex[:8]}")


def test_revoked_and_suspended_remain_refused_everywhere(manager_env):
    """NO AUTHORIZATION REGRESSION. Splitting the two authorities must not have widened
    anything: the statuses that were refused at authentication still are."""
    client, state = manager_env
    entry = state["a"]

    for status in ("revoked", "suspended"):
        _set_worker_status(entry["worker_id"], status,
                           revoked_at="2026-01-01 00:00:00" if status == "revoked" else None)
        for path, payload in (
            ("/v1/lease", {"max_jobs": 1}),
            ("/v1/heartbeat", {"health_state": "healthy"}),
        ):
            r = client.post(path, json=payload, headers=_auth(entry))
            assert r.status_code == 403, f"{status} worker was served {path}: {r.text}"


def test_drain_preserves_public_and_private_worker_boundaries(manager_env):
    """Draining tenant A's worker says nothing about, and does nothing to, tenant B's."""
    _, state = manager_env
    a, b = state["a"], state["b"]

    before_b = _read_worker_status(b["worker_id"])
    _drain(a["worker_id"])

    assert _read_worker_status(a["worker_id"])[0] == "draining"
    assert _read_worker_status(b["worker_id"]) == before_b, "draining one worker altered another"


def test_drain_records_an_audit_event(manager_env):
    """The operator action is evidenced, using the existing scanner_ops mechanism."""
    import asyncio as _asyncio

    from sqlalchemy import text as _text
    from sqlalchemy.ext.asyncio import async_sessionmaker as _maker
    from sqlalchemy.ext.asyncio import create_async_engine as _mk_engine
    from sqlalchemy.pool import StaticPool as _Static

    from apps.api.modules.audit import scanner_ops
    from apps.api.modules.scanner_workers import service as _ws

    _, state = manager_env
    wid = state["a"]["worker_id"]

    async def _go():
        engine = _mk_engine(get_settings().database_url, poolclass=_Static)
        try:
            async with _maker(engine, expire_on_commit=False)() as s:
                with tenancy.admin_bypass():
                    worker = await _ws.drain_worker(s, wid, reason="scheduled host patching")
                    written = await scanner_ops.record_worker_drained(
                        s, worker_id=worker.worker_id, reason="scheduled host patching",
                        actor="oncall-x", workspace_id=worker.workspace_id,
                        site_id=worker.site_id,
                    )
                    await s.commit()
                    rows = (await s.execute(
                        _text("SELECT event, detail FROM platform_audit_events "
                              "WHERE event = :e ORDER BY created_at DESC LIMIT 1"),
                        {"e": scanner_ops.EVENT_WORKER_DRAINED},
                    )).all()
            return written, [tuple(r) for r in rows]
        finally:
            await engine.dispose()

    written, rows = _asyncio.run(_go())
    assert written is True
    assert rows, "no audit row was written for the drain"
    detail = rows[0][1]
    assert wid in detail
    assert "scheduled host patching" in detail
    assert "oncall-x" in detail
    # The FROM state matters when reconstructing what a retired worker could have held.
    assert "previous_status=active" in detail
    assert "new_status=draining" in detail


def test_drain_does_not_stop_anything(manager_env):
    """Draining is COOPERATIVE: it is a state change, never a process control.

    Structural, and deliberately narrow -- it guards the one property that would be both
    easy to add later and wrong: a drain that kills the running tool.
    """
    import ast
    import inspect

    from apps.api.modules.scanner_workers import service as ws

    tree = ast.parse(inspect.getsource(ws.drain_worker))
    called = {
        (getattr(n.func, "attr", None) or getattr(n.func, "id", None))
        for n in ast.walk(tree) if isinstance(n, ast.Call)
    }
    for forbidden in ("kill", "terminate", "cancel", "revoke_worker", "signal"):
        assert forbidden not in called, f"drain_worker gained a process-control path: {forbidden}"
