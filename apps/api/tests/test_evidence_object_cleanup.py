"""P1-1: evidence OBJECTS must be deleted, not just their database rows.

THE GAP THIS PINS. Workspace deletion and retention removed the `evidence` rows (the FK
cascade is correct) but left the artifacts in the bucket forever, because cleanup only ever
deleted the `tool-runs/{tool_run_id}/` prefix. Two families were never reached:

    vulnerabilities/{vulnerability_id}/screenshot-*.png       -- screenshot evidence
    workspaces/{workspace_id}/remediation/{item_id}/proof-*   -- human-uploaded proof

A row-count assertion passed the whole time. These tests therefore assert on the OBJECT
STORE, via the same StorageProvider the application uses -- never on row counts alone.

They are skipped when object storage is unreachable (a DB-only dev box), the same way the DR
integration tests skip without mysqldump: a silent pass would be worse than a visible skip.
"""
import uuid

import pytest

from apps.api.core.config import get_settings
from apps.api.scanner_engine.storage_provider import get_storage_provider


def _storage_available() -> bool:
    """Probe the evidence bucket with a real round-trip. Anything unreachable -> skip."""
    try:
        store = get_storage_provider(get_settings().s3_bucket_evidence)
        key = f"_probe/{uuid.uuid4()}.txt"
        store.put(key, b"probe")
        store.delete(key)
        return True
    except Exception:  # noqa: BLE001 -- environment, not a defect under test
        return False


pytestmark = pytest.mark.skipif(
    not _storage_available(),
    reason="object storage unreachable; evidence-object cleanup needs a live bucket",
)


def _evidence_store():
    return get_storage_provider(get_settings().s3_bucket_evidence)


def _exists(key: str) -> bool:
    try:
        _evidence_store().get(key)
        return True
    except Exception:  # noqa: BLE001 -- provider raises on a missing key
        return False


def _put(key: str, body: bytes = b"evidence-bytes") -> str:
    store = _evidence_store()
    store.put(key, body)
    return f"s3://{get_settings().s3_bucket_evidence}/{key}"


# =============================================================================================
# WORKSPACE DELETION (requirements 1-6)
# =============================================================================================

def test_workspace_deletion_removes_evidence_objects_not_just_rows(client) -> None:
    """The full chain: object created -> object exists -> workspace deleted -> rows gone AND
    object gone. Deliberately asserts on the bucket, because the row assertion alone is what
    let this ship."""
    import asyncio

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.modules.projects.models import Project, Target
    from apps.api.modules.remediation.models import RemediationEvidence, RemediationItem
    from apps.api.modules.scans.models import Scan
    from apps.api.modules.users.models import User
    from apps.api.modules.vulnerabilities.models import Vulnerability
    from apps.api.modules.workspaces.models import Workspace
    from apps.api.modules.workspaces.tenant_service import perform_workspace_deletion
    from apps.api.scanner_engine.models import Evidence, ToolRun

    ws_id = uuid.uuid4()
    vuln_id = uuid.uuid4()
    item_id = uuid.uuid4()
    # The two key shapes the old cleanup never reached.
    shot_key = f"vulnerabilities/{vuln_id}/screenshot-{uuid.uuid4().hex[:16]}.png"
    proof_key = f"workspaces/{ws_id}/remediation/{item_id}/proof-{uuid.uuid4().hex[:16]}.txt"

    # 1-2) create the objects and prove they exist
    shot_uri = _put(shot_key, b"\x89PNG fake")
    proof_uri = _put(proof_key, b"the patch")
    assert _exists(shot_key), "fixture failed: screenshot object was not stored"
    assert _exists(proof_key), "fixture failed: proof object was not stored"

    async def _seed_and_delete():
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                with tenancy.admin_bypass():
                    u = User(email=f"ev-{uuid.uuid4()}@t.local", password_hash="x", full_name="E")
                    s.add(u)
                    await s.flush()
                    ws = Workspace(id=ws_id, name=f"ev-{uuid.uuid4().hex[:8]}", owner_user_id=u.id)
                    s.add(ws)
                    await s.flush()
                    proj = Project(workspace_id=ws.id, name="p", created_by=u.id)
                    s.add(proj)
                    await s.flush()
                    tgt = Target(project_id=proj.id, type="domain",
                                 value=f"{uuid.uuid4()}.test", criticality="low", added_by=u.id)
                    s.add(tgt)
                    await s.flush()
                    scan = Scan(workspace_id=ws.id, project_id=proj.id, target_id=tgt.id,
                                initiated_by=u.id, scan_type="vuln", status="completed", config={})
                    s.add(scan)
                    await s.flush()
                    run = ToolRun(scan_id=scan.id, tool_name="nuclei", tool_version="3",
                                  status="completed", command_hash="h")
                    s.add(run)
                    await s.flush()
                    vuln = Vulnerability(id=vuln_id, project_id=proj.id,
                                         fingerprint=f"t|m|{uuid.uuid4()}", title="V",
                                         severity="high", status="open")
                    s.add(vuln)
                    await s.flush()

                    # Screenshot evidence: linked to the tool run, keyed by VULNERABILITY.
                    shot = Evidence(tool_run_id=run.id, evidence_type="screenshot",
                                    storage_uri=shot_uri, checksum="a" * 64)
                    # Remediation proof: NULL tool run, owned via remediation_evidence.
                    proof = Evidence(tool_run_id=None, evidence_type="remediation_proof",
                                     storage_uri=proof_uri, checksum="b" * 64)
                    s.add_all([shot, proof])
                    await s.flush()
                    item = RemediationItem(id=item_id, workspace_id=ws.id, project_id=proj.id,
                                           issue_key=f"template:{uuid.uuid4().hex[:8]}", title="I")
                    s.add(item)
                    await s.flush()
                    s.add(RemediationEvidence(remediation_item_id=item.id, evidence_id=proof.id,
                                              workspace_id=ws.id))
                    await s.commit()

            # 3) delete the workspace, exactly as the Celery task does
            async with maker() as s:
                with tenancy.admin_bypass():
                    await perform_workspace_deletion(s, ws_id, u.id)

            # 4) rows gone -- raw SQL so a surviving row would still be visible
            async with maker() as s:
                n = await s.scalar(
                    text("SELECT count(*) FROM evidence WHERE storage_uri IN (:a, :b)"),
                    {"a": shot_uri, "b": proof_uri},
                )
                return int(n or 0)
        finally:
            await engine.dispose()

    remaining_rows = asyncio.run(_seed_and_delete())

    # 4) DB rows removed
    assert remaining_rows == 0, f"{remaining_rows} evidence row(s) survived workspace deletion"
    # 5) AND the objects removed -- the assertion the previous implementation could not pass
    assert not _exists(shot_key), "screenshot OBJECT survived workspace deletion"
    assert not _exists(proof_key), "remediation proof OBJECT survived workspace deletion"


def test_deletion_cannot_remove_another_workspaces_objects(client) -> None:
    """Requirement 6: cleanup is workspace-scoped. Deleting workspace A must leave workspace
    B's objects untouched."""
    import asyncio

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.modules.users.models import User
    from apps.api.modules.workspaces.models import Workspace
    from apps.api.modules.workspaces.tenant_service import perform_workspace_deletion

    ws_a = uuid.uuid4()
    ws_b = uuid.uuid4()
    key_b = f"workspaces/{ws_b}/remediation/{uuid.uuid4()}/proof-{uuid.uuid4().hex[:8]}.txt"
    _put(key_b, b"workspace B's private artifact")
    assert _exists(key_b)

    async def _run():
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                with tenancy.admin_bypass():
                    u = User(email=f"x-{uuid.uuid4()}@t.local", password_hash="x", full_name="X")
                    s.add(u)
                    await s.flush()
                    s.add_all([
                        Workspace(id=ws_a, name=f"a-{uuid.uuid4().hex[:8]}", owner_user_id=u.id),
                        Workspace(id=ws_b, name=f"b-{uuid.uuid4().hex[:8]}", owner_user_id=u.id),
                    ])
                    await s.commit()
                    uid = u.id
            async with maker() as s:
                with tenancy.admin_bypass():
                    await perform_workspace_deletion(s, ws_a, uid)
        finally:
            await engine.dispose()

    asyncio.run(_run())
    assert _exists(key_b), "deleting workspace A destroyed workspace B's evidence object"

    _evidence_store().delete(key_b)  # tidy up


# =============================================================================================
# RETENTION (requirements 7-8)
# =============================================================================================

def test_retention_captures_evidence_uris_before_the_cascade() -> None:
    """Requirement 7's mechanism: `capture_evidence_uris` must return the object URIs while
    the rows still exist -- including a SCREENSHOT, whose key is per-vulnerability and so is
    NOT under any `tool-runs/{id}/` prefix."""
    import asyncio

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.modules.projects.models import Project, Target
    from apps.api.modules.scans.models import Scan
    from apps.api.modules.users.models import User
    from apps.api.modules.workspaces.models import Workspace
    from apps.api.retention import repo
    from apps.api.scanner_engine.models import Evidence, ToolRun

    vuln_id = uuid.uuid4()
    shot_uri = f"s3://{get_settings().s3_bucket_evidence}/vulnerabilities/{vuln_id}/screenshot-x.png"

    async def _run():
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                with tenancy.admin_bypass():
                    u = User(email=f"r-{uuid.uuid4()}@t.local", password_hash="x", full_name="R")
                    s.add(u)
                    await s.flush()
                    ws = Workspace(name=f"r-{uuid.uuid4().hex[:8]}", owner_user_id=u.id)
                    s.add(ws)
                    await s.flush()
                    proj = Project(workspace_id=ws.id, name="p", created_by=u.id)
                    s.add(proj)
                    await s.flush()
                    tgt = Target(project_id=proj.id, type="domain", value=f"{uuid.uuid4()}.test",
                                 criticality="low", added_by=u.id)
                    s.add(tgt)
                    await s.flush()
                    scan = Scan(workspace_id=ws.id, project_id=proj.id, target_id=tgt.id,
                                initiated_by=u.id, scan_type="vuln", status="completed", config={})
                    s.add(scan)
                    await s.flush()
                    run = ToolRun(scan_id=scan.id, tool_name="nuclei", tool_version="3",
                                  status="completed", command_hash="h")
                    s.add(run)
                    await s.flush()
                    s.add(Evidence(tool_run_id=run.id, evidence_type="screenshot",
                                   storage_uri=shot_uri, checksum="c" * 64))
                    await s.commit()
                    return await repo.capture_evidence_uris(s, [run.id])
        finally:
            await engine.dispose()

    uris = asyncio.run(_run())
    assert shot_uri in uris, (
        "retention would lose the screenshot object: its URI was not captured before the "
        f"cascade (got {uris})"
    )


def test_retention_cleanup_deletes_captured_objects_and_spares_others() -> None:
    """Requirements 7 + 8 on the cleanup itself: an object named in the targets is deleted; an
    unrelated (non-expired) object is untouched."""
    from apps.api.retention.service import _StorageTargets, _cleanup_storage

    expired_key = f"vulnerabilities/{uuid.uuid4()}/screenshot-{uuid.uuid4().hex[:8]}.png"
    kept_key = f"vulnerabilities/{uuid.uuid4()}/screenshot-{uuid.uuid4().hex[:8]}.png"
    expired_uri = _put(expired_key, b"old")
    _put(kept_key, b"current")
    assert _exists(expired_key) and _exists(kept_key)

    targets = _StorageTargets()
    targets.evidence_uris.append(expired_uri)   # only the expired one is a target
    _cleanup_storage(get_settings(), targets)

    assert not _exists(expired_key), "retention did not delete the expired evidence object"
    assert _exists(kept_key), "retention deleted a NON-expired evidence object"

    _evidence_store().delete(kept_key)  # tidy up


def test_cleanup_ignores_non_s3_uris_without_raising() -> None:
    """Rows can carry `unavailable://...` or NULL. Those never became objects, so cleanup must
    skip them silently rather than sending a bogus key to the provider."""
    from apps.api.retention.service import _StorageTargets, _cleanup_storage

    targets = _StorageTargets()
    targets.evidence_uris.extend(["unavailable://nope", "", "file:///tmp/x"])
    _cleanup_storage(get_settings(), targets)  # must not raise
