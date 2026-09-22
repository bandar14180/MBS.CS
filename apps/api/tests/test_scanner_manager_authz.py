"""MBS.SC -- scanner-manager boundary authorization.

These tests attack the manager the way a compromised scanner worker would: with valid
credentials for ONE worker, trying to reach another tenant's jobs, sites and evidence.

The property under test is that authorization inputs are never taken from the request.
A worker may name a scan id; it may not name the workspace, site or pool that authorizes
it. So every attack below reduces to "worker A presents its own real credential and asks
for something belonging to B", which is exactly the compromise case that matters.
"""
import asyncio
import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.private_sites import service as sites_service
from apps.api.modules.private_sites.models import PrivateSite
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scanner_workers import service as workers_service
from apps.api.modules.scanner_workers.models import ScannerWorker
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine import result_sink


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _tenant(session, label, *, cidrs=("10.0.0.0/16",), site_status="active"):
    """One workspace + user + project + target + ACTIVE private site + a private worker
    bound to that site + a queued private scan. Returns a dict of the ids."""
    user = User(email=f"{label}-{uuid.uuid4()}@t.local", password_hash="x", full_name=label)
    session.add(user)
    await session.flush()
    ws = Workspace(name=f"{label}-{uuid.uuid4().hex[:8]}", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    site = PrivateSite(
        id=uuid.uuid4(), workspace_id=ws.id, name=f"{label}-site",
        authorized_cidrs=list(cidrs), dns_servers=["10.0.0.53"], dns_search_domains=[],
        status=site_status, scanner_pool_id=f"pool-{label}",
    )
    session.add(site)
    await session.flush()
    project = Project(id=uuid.uuid4(), workspace_id=ws.id, name=f"{label}-proj",
                      created_by=user.id)
    session.add(project)
    await session.flush()
    target = Target(id=uuid.uuid4(), project_id=project.id, type="ip_range",
                    value="10.0.5.0/24", added_by=user.id,
                    network_zone="private", site_id=site.id)
    session.add(target)
    await session.flush()
    scan = Scan(id=uuid.uuid4(), workspace_id=ws.id, project_id=project.id,
                target_id=target.id, initiated_by=user.id, scan_type="recon",
                status="queued", config={"site_id": str(site.id), "network_zone": "private"})
    session.add(scan)
    token = workers_service.generate_worker_token()
    worker = ScannerWorker(
        id=uuid.uuid4(), worker_id=f"wk-{label}-{uuid.uuid4().hex[:6]}",
        pool_id=f"pool-{label}", site_id=site.id, workspace_id=ws.id,
        status="active", token_hash=workers_service.hash_worker_token(token),
    )
    session.add(worker)
    await session.flush()
    return {
        "ws": ws.id, "user": user.id, "site": site, "project": project.id,
        "target": target.id, "scan": scan, "worker": worker, "token": token,
    }


# ---------------------------------------------------------------------------------------
# Worker authentication
# ---------------------------------------------------------------------------------------

def test_worker_id_alone_is_not_a_credential():
    """Knowing a worker id must not authenticate -- the secret is the credential."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    a = await _tenant(s, "a")
                    await s.commit()
                with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
                    await workers_service.authenticate_worker(
                        s, worker_id=a["worker"].worker_id, token="not-the-token"
                    )
                assert exc.value.reason == workers_service.REASON_BAD_CREDENTIAL
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_worker_cannot_present_another_workers_token():
    """B's valid token, presented as A, fails: the row is found by the CLAIMED id and the
    secret is checked against THAT row."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    a = await _tenant(s, "a")
                    b = await _tenant(s, "b")
                    await s.commit()
                with pytest.raises(workers_service.WorkerNotAuthorized):
                    await workers_service.authenticate_worker(
                        s, worker_id=a["worker"].worker_id, token=b["token"]
                    )
                # ...while each worker's own token still works.
                got = await workers_service.authenticate_worker(
                    s, worker_id=a["worker"].worker_id, token=a["token"]
                )
                assert got.worker_id == a["worker"].worker_id
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_unknown_worker_is_indistinguishable_from_bad_credential():
    """Refusal messages must not let an attacker enumerate valid worker ids."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
                    await workers_service.authenticate_worker(
                        s, worker_id="no-such-worker", token="x"
                    )
                assert exc.value.message == "Worker authentication failed."
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_token_is_never_recoverable_from_the_database():
    """Only a hash is stored, so a database read cannot yield a usable credential."""
    token = workers_service.generate_worker_token()
    stored = workers_service.hash_worker_token(token)
    assert token not in stored
    assert len(stored) == 64  # sha256 hex
    assert stored == workers_service.hash_worker_token(token)  # deterministic


# ---------------------------------------------------------------------------------------
# CROSS-TENANT: the compromise cases
# ---------------------------------------------------------------------------------------

def test_worker_cannot_take_another_tenants_scan():
    """Tenant A's worker, fully authenticated, is refused tenant B's scan."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    a = await _tenant(s, "a")
                    b = await _tenant(s, "b")
                    await s.commit()
                # A's worker on A's own scan: allowed.
                workers_service.assert_worker_may_take_scan(
                    a["worker"], workspace_id=a["ws"], site_id=a["site"].id
                )
                # A's worker on B's scan: refused (wrong site AND wrong workspace).
                with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
                    workers_service.assert_worker_may_take_scan(
                        a["worker"], workspace_id=b["ws"], site_id=b["site"].id
                    )
                assert exc.value.reason in {
                    workers_service.REASON_WRONG_SITE,
                    workers_service.REASON_WRONG_WORKSPACE,
                }
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_worker_cannot_use_another_tenants_site_even_within_its_own_workspace():
    """Swapping ONLY the site id (keeping the right workspace) is still refused."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    a = await _tenant(s, "a")
                    b = await _tenant(s, "b")
                    await s.commit()
                with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
                    workers_service.assert_worker_may_take_scan(
                        a["worker"], workspace_id=a["ws"], site_id=b["site"].id
                    )
                assert exc.value.reason == workers_service.REASON_WRONG_SITE
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_public_worker_cannot_take_a_private_job():
    """A worker with no tunnel must never be handed a private-site scan."""
    public_worker = ScannerWorker(
        id=uuid.uuid4(), worker_id="wk-public", pool_id="public-default",
        site_id=None, workspace_id=None, status="active",
    )
    with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
        workers_service.assert_worker_may_take_scan(
            public_worker, workspace_id=uuid.uuid4(), site_id=uuid.uuid4()
        )
    assert exc.value.reason == workers_service.REASON_PUBLIC_WORKER_PRIVATE_JOB


def test_private_worker_cannot_take_a_public_job():
    """A machine holding a customer tunnel must not also scan arbitrary internet hosts."""
    private_worker = ScannerWorker(
        id=uuid.uuid4(), worker_id="wk-private", pool_id="pool-a",
        site_id=uuid.uuid4(), workspace_id=uuid.uuid4(), status="active",
    )
    with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
        workers_service.assert_worker_may_take_scan(
            private_worker, workspace_id=private_worker.workspace_id, site_id=None
        )
    assert exc.value.reason == workers_service.REASON_PRIVATE_WORKER_PUBLIC_JOB


def test_wrong_pool_is_refused():
    worker = ScannerWorker(
        id=uuid.uuid4(), worker_id="wk-1", pool_id="pool-a",
        site_id=None, workspace_id=None, status="active",
    )
    with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
        workers_service.assert_worker_may_take_scan(
            worker, workspace_id=uuid.uuid4(), site_id=None, pool_id="pool-b"
        )
    assert exc.value.reason == workers_service.REASON_WRONG_POOL


# ---------------------------------------------------------------------------------------
# REVOCATION / SUSPENSION (Phase 13)
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("status,expected", [
    ("revoked", workers_service.REASON_WORKER_REVOKED),
    ("suspended", workers_service.REASON_WORKER_SUSPENDED),
    ("pending", workers_service.REASON_WORKER_NOT_ACTIVE),
])
def test_only_active_workers_may_take_work(status, expected):
    """Statuses refused at AUTHENTICATION, i.e. on every endpoint at once.

    `draining` is deliberately NOT in this list any more (Phase 8 queue draining): it is
    refused at the LEASE boundary only, so a decommissioning worker can still report the
    scan it already holds. `test_a_draining_worker_may_act_but_may_not_lease` below pins
    both halves of that.
    """
    worker = ScannerWorker(
        id=uuid.uuid4(), worker_id=f"wk-{status}", pool_id="p",
        site_id=None, workspace_id=None, status=status,
    )
    with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
        workers_service.assert_worker_active(worker)
    assert exc.value.reason == expected


@pytest.mark.parametrize("status,expected", [
    ("revoked", workers_service.REASON_WORKER_REVOKED),
    ("suspended", workers_service.REASON_WORKER_SUSPENDED),
    ("pending", workers_service.REASON_WORKER_NOT_ACTIVE),
    ("draining", workers_service.REASON_WORKER_DRAINING),
])
def test_only_active_workers_may_take_NEW_work(status, expected):
    """The narrower authority: every non-active status is refused a new lease.

    This is the property `assert_worker_active` used to carry for `draining` too. Splitting
    the two questions must not have made any status leasable that was not leasable before.
    """
    worker = ScannerWorker(
        id=uuid.uuid4(), worker_id=f"wk-{status}", pool_id="p",
        site_id=None, workspace_id=None, status=status,
    )
    with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
        workers_service.assert_worker_may_lease(worker)
    assert exc.value.reason == expected


def test_a_draining_worker_may_act_but_may_not_lease():
    """THE DRAINING CONTRACT, in one test: finish in-flight work, take nothing new."""
    worker = ScannerWorker(
        id=uuid.uuid4(), worker_id="wk-draining", pool_id="p",
        site_id=None, workspace_id=None, status="draining",
    )
    # May act -- this is what gates authentication, and therefore tool-results, evidence,
    # heartbeat and lease/complete for the scan it is already running.
    workers_service.assert_worker_active(worker)
    # May NOT be handed anything new.
    with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
        workers_service.assert_worker_may_lease(worker)
    assert exc.value.reason == workers_service.REASON_WORKER_DRAINING


def test_revocation_destroys_the_credential_and_blocks_future_auth():
    """Revocation must work control-plane side, without reaching the worker host, and
    must leave no stored secret that a later bug could re-accept."""
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    a = await _tenant(s, "a")
                    await s.commit()
                    wid, token = a["worker"].worker_id, a["token"]
                    # Works before revocation.
                    w = await workers_service.authenticate_worker(s, worker_id=wid, token=token)
                    workers_service.assert_worker_active(w)

                    await workers_service.revoke_worker(s, wid, reason="suspected compromise")
                    await s.commit()

                    # The credential no longer authenticates at all.
                    with pytest.raises(workers_service.WorkerNotAuthorized):
                        await workers_service.authenticate_worker(s, worker_id=wid, token=token)
                    refreshed = await s.get(ScannerWorker, a["worker"].id)
                    assert refreshed.status == "revoked"
                    assert refreshed.token_hash is None
                    assert refreshed.revoked_at is not None
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_suspended_site_blocks_scanning_even_for_its_own_worker():
    async def scenario():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    a = await _tenant(s, "a", site_status="suspended")
                    await s.commit()
                with tenancy.workspace_scope(a["ws"]):
                    with pytest.raises(sites_service.PrivateSiteNotAuthorized) as exc:
                        await sites_service.build_scan_network_policy(
                            s, workspace_id=a["ws"], scan_id=a["scan"].id,
                            network_zone="private", site_id=a["site"].id,
                        )
                assert exc.value.reason == sites_service.REASON_SITE_SUSPENDED
        finally:
            await engine.dispose()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------------------
# EVIDENCE INTEGRITY (Phase 6)
# ---------------------------------------------------------------------------------------

def test_evidence_digest_is_computed_not_trusted():
    content = b"nmap output"
    digest = result_sink.validate_evidence(content, "text/plain")
    assert digest == result_sink.sha256_hex(content)
    # A different byte string cannot produce the same digest.
    assert result_sink.validate_evidence(b"other", "text/plain") != digest


def test_evidence_size_limit_is_enforced():
    too_big = b"x" * (result_sink.MAX_EVIDENCE_BYTES + 1)
    with pytest.raises(result_sink.EvidenceRejected, match="over the"):
        result_sink.validate_evidence(too_big, "text/plain")


def test_evidence_empty_content_is_rejected():
    with pytest.raises(result_sink.EvidenceRejected, match="empty"):
        result_sink.validate_evidence(b"", "text/plain")


def test_evidence_content_type_is_allowlisted():
    with pytest.raises(result_sink.EvidenceRejected, match="not an allowed"):
        result_sink.validate_evidence(b"data", "application/x-shellscript")
    # A charset parameter must not defeat the check.
    assert result_sink.validate_evidence(b"data", "text/plain; charset=utf-8")


def test_manager_result_sink_carries_no_storage_credentials():
    """The execution-plane sink must hold only identity + manager URL -- no DB session,
    no S3 client, no storage credential of any kind."""
    sink = result_sink.ManagerResultSink(
        manager_url="http://scanner-manager:8100", worker_id="wk-1", token="t"
    )
    state = vars(sink)
    assert set(state) == {"manager_url", "worker_id", "_token", "_client"}
    for key, value in state.items():
        assert "s3" not in key.lower() and "db" not in key.lower()
        assert not hasattr(value, "put_object"), "sink holds an object-store client"


# ---------------------------------------------------------------------------------------
# EMERGENCY CONTROLS (Phase 13)
# ---------------------------------------------------------------------------------------

def test_emergency_disable_setting_exists_and_defaults_to_off():
    """The kill switch must exist, default to OFF (so it cannot surprise a deployment),
    and be readable by the manager."""
    from apps.api.core.config import get_settings

    assert get_settings().private_scanning_emergency_disable is False


def test_lease_consults_the_emergency_disable(monkeypatch):
    """The switch must be enforced by the MANAGER, not by the scanner host.

    An emergency control that required reaching the scanner would be useless in exactly
    the situation it exists for -- a compromised or unreachable worker. This asserts the
    lease endpoint reads the setting server-side.
    """
    from pathlib import Path

    source = Path("apps/api/scanner_manager/app.py").read_text(encoding="utf-8")
    lease = source.split("async def lease_jobs", 1)[1].split("\n@app.", 1)[0]
    assert "private_scanning_emergency_disable" in lease, (
        "the lease endpoint does not consult the emergency disable"
    )
    # And a private job is skipped when it is set.
    assert "if site_uuid is not None and private_disabled:" in lease
    assert "continue" in lease


def test_revoking_a_worker_is_recorded_as_a_metric():
    """Revocation must be observable -- an operator action this severe should page."""
    from pathlib import Path

    source = Path("apps/api/modules/scanner_workers/service.py").read_text(encoding="utf-8")
    revoke = source.split("async def revoke_worker", 1)[1]
    assert "record_worker_revoked" in revoke
