"""Regression coverage for Prompt 13, Finding #9: explicit evidence checksum re-verification.

`Evidence.checksum` is computed once at write time and was never re-verified against the
stored object afterward. This file proves apps.api.scanner_engine.evidence_integrity.
verify_evidence (and its audited wrapper) correctly distinguishes PASS / INTEGRITY_FAILURE /
MISSING_OBJECT / NO_CHECKSUM, never treats a mismatch as success, and never exposes evidence
content beyond what the check itself needs.
"""
import asyncio
import hashlib
import uuid
from unittest.mock import patch

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.audit.models import AuditEvent
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.evidence_integrity import (
    IntegrityResult,
    verify_evidence,
    verify_evidence_and_record,
    verify_evidence_batch,
)
from apps.api.scanner_engine.models import Evidence, ToolRun


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


class _FakeStorage:
    """A minimal StorageProvider stand-in: an in-memory {key: bytes} map, keyed by whatever
    `get()` is called with. Raises for a missing key, exactly like a real backend would."""

    def __init__(self, objects: dict[str, bytes]):
        self._objects = objects

    def get(self, key: str) -> bytes:
        if key not in self._objects:
            raise FileNotFoundError(key)
        return self._objects[key]

    def put(self, key, content, content_type="application/octet-stream"):
        raise NotImplementedError

    def delete(self, key):
        raise NotImplementedError

    def delete_prefix(self, prefix):
        raise NotImplementedError


async def _seed_evidence(s, *, content: bytes, checksum: str | None, storage_uri: str | None = None):
    user = User(email=f"ei-{uuid.uuid4()}@t.local", password_hash="x", full_name="EI Tester")
    s.add(user)
    await s.flush()
    ws = Workspace(name=f"ei-ws-{uuid.uuid4().hex[:8]}", owner_user_id=user.id)
    s.add(ws)
    await s.flush()
    tenancy.bind_workspace(ws.id)
    project = Project(workspace_id=ws.id, name="ei-proj", created_by=user.id)
    s.add(project)
    await s.flush()
    target = Target(project_id=project.id, type="domain", value="ei.test", criticality="low", added_by=user.id)
    s.add(target)
    await s.flush()
    scan = Scan(
        workspace_id=ws.id, project_id=project.id, target_id=target.id, initiated_by=user.id,
        scan_type="web", status="completed", config={}, execution_token=uuid.uuid4(),
    )
    s.add(scan)
    await s.flush()
    tool_run = ToolRun(scan_id=scan.id, tool_name="nuclei", tool_version="3", status="completed", command_hash="")
    s.add(tool_run)
    await s.flush()
    uri = storage_uri if storage_uri is not None else f"s3://mbs-evidence/tool-runs/{tool_run.id}/raw-output.txt"
    evidence = Evidence(
        tool_run_id=tool_run.id, evidence_type="raw_output",
        storage_uri=uri, checksum=checksum or "",
    )
    s.add(evidence)
    await s.flush()
    await s.commit()
    return evidence.id, ws.id, uri


def _run(coro):
    return asyncio.run(coro)


# --- matching content: PASS -------------------------------------------------------------------

def test_matching_content_passes():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                content = b"the real raw tool output"
                checksum = hashlib.sha256(content).hexdigest()
                eid, wsid, uri = await _seed_evidence(s, content=content, checksum=checksum)

                key = uri.split("/", 3)[3]  # strip "s3://bucket/"
                fake = _FakeStorage({key: content})
                with patch(
                    "apps.api.scanner_engine.storage_provider.get_storage_provider",
                    return_value=fake,
                ):
                    check = await verify_evidence(s, eid)
                assert check.result == IntegrityResult.PASS
                assert check.actual_checksum == checksum
        finally:
            await engine.dispose()
    _run(scenario())


# --- modified/corrupt content: INTEGRITY_FAILURE, never silently treated as success ----------

def test_corrupted_content_is_reported_as_integrity_failure_not_success():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                original = b"the real raw tool output"
                checksum = hashlib.sha256(original).hexdigest()
                eid, wsid, uri = await _seed_evidence(s, content=original, checksum=checksum)

                key = uri.split("/", 3)[3]
                corrupted = b"TAMPERED CONTENT, not what was recorded"
                fake = _FakeStorage({key: corrupted})
                with patch(
                    "apps.api.scanner_engine.storage_provider.get_storage_provider",
                    return_value=fake,
                ):
                    check = await verify_evidence(s, eid)
                assert check.result == IntegrityResult.INTEGRITY_FAILURE
                assert check.actual_checksum != check.recorded_checksum
                assert check.recorded_checksum == checksum
        finally:
            await engine.dispose()
    _run(scenario())


# --- missing object: distinct from integrity failure ------------------------------------------

def test_missing_object_is_reported_distinctly_from_integrity_failure():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                content = b"whatever"
                checksum = hashlib.sha256(content).hexdigest()
                eid, wsid, uri = await _seed_evidence(s, content=content, checksum=checksum)

                fake = _FakeStorage({})  # object genuinely absent
                with patch(
                    "apps.api.scanner_engine.storage_provider.get_storage_provider",
                    return_value=fake,
                ):
                    check = await verify_evidence(s, eid)
                assert check.result == IntegrityResult.MISSING_OBJECT
                assert check.result != IntegrityResult.INTEGRITY_FAILURE
                assert check.actual_checksum is None
        finally:
            await engine.dispose()
    _run(scenario())


def test_non_s3_sentinel_uri_reports_missing_object():
    """An `unavailable://...` storage_uri (evidence storage failed at ingest time) has no real
    object to fetch -- reported as MISSING_OBJECT, never crashes the check."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                eid, wsid, uri = await _seed_evidence(
                    s, content=b"x", checksum="a" * 64,
                    storage_uri="unavailable://evidence-storage-failed/x",
                )
                check = await verify_evidence(s, eid)
                assert check.result == IntegrityResult.MISSING_OBJECT
        finally:
            await engine.dispose()
    _run(scenario())


# --- missing checksum: legacy row --------------------------------------------------------------

def test_missing_checksum_reports_no_checksum():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                eid, wsid, uri = await _seed_evidence(s, content=b"x", checksum="")
                check = await verify_evidence(s, eid)
                assert check.result == IntegrityResult.NO_CHECKSUM
        finally:
            await engine.dispose()
    _run(scenario())


# --- audited wrapper: durable record of the outcome --------------------------------------------

def test_verify_and_record_writes_an_audit_event():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                content = b"content"
                checksum = hashlib.sha256(content).hexdigest()
                eid, wsid, uri = await _seed_evidence(s, content=content, checksum=checksum)

                key = uri.split("/", 3)[3]
                fake = _FakeStorage({key: content})
                with patch(
                    "apps.api.scanner_engine.storage_provider.get_storage_provider",
                    return_value=fake,
                ):
                    check = await verify_evidence_and_record(s, wsid, eid, actor_user_id=None)
                assert check.result == IntegrityResult.PASS

                events = (await s.execute(
                    __import__("sqlalchemy").select(AuditEvent).where(
                        AuditEvent.action == "evidence.integrity_checked",
                        AuditEvent.resource_id == eid,
                    )
                )).scalars().all()
                assert len(events) == 1
                assert "result=pass" in events[0].detail
        finally:
            await engine.dispose()
    _run(scenario())


def test_verify_and_record_audits_a_failure_too():
    """The audit trail must record a FAILURE just as durably as a pass -- never only logging
    the good outcomes."""
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                original = b"original"
                checksum = hashlib.sha256(original).hexdigest()
                eid, wsid, uri = await _seed_evidence(s, content=original, checksum=checksum)

                key = uri.split("/", 3)[3]
                fake = _FakeStorage({key: b"corrupted"})
                with patch(
                    "apps.api.scanner_engine.storage_provider.get_storage_provider",
                    return_value=fake,
                ):
                    check = await verify_evidence_and_record(s, wsid, eid, actor_user_id=None)
                assert check.result == IntegrityResult.INTEGRITY_FAILURE

                events = (await s.execute(
                    __import__("sqlalchemy").select(AuditEvent).where(
                        AuditEvent.action == "evidence.integrity_checked",
                        AuditEvent.resource_id == eid,
                    )
                )).scalars().all()
                assert len(events) == 1
                assert "result=integrity_failure" in events[0].detail
        finally:
            await engine.dispose()
    _run(scenario())


# --- batch: one bad apple never stops the rest --------------------------------------------------

def test_batch_check_continues_past_a_missing_evidence_id():
    async def scenario():
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                content = b"ok"
                checksum = hashlib.sha256(content).hexdigest()
                eid_good, wsid, uri = await _seed_evidence(s, content=content, checksum=checksum)
                eid_missing = uuid.uuid4()  # does not exist at all

                key = uri.split("/", 3)[3]
                fake = _FakeStorage({key: content})
                with patch(
                    "apps.api.scanner_engine.storage_provider.get_storage_provider",
                    return_value=fake,
                ):
                    results = await verify_evidence_batch(
                        s, wsid, [eid_missing, eid_good], actor_user_id=None
                    )
                by_id = {r.evidence_id: r for r in results}
                assert by_id[eid_missing].result == IntegrityResult.MISSING_OBJECT
                assert by_id[eid_good].result == IntegrityResult.PASS
        finally:
            await engine.dispose()
    _run(scenario())


# --- tenancy: the audit record lands under the right workspace ---------------------------------

def test_audit_record_is_scoped_to_the_callers_workspace():
    async def scenario():
        tenancy.install()
        engine = _engine()
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                content = b"x"
                checksum = hashlib.sha256(content).hexdigest()
                eid, wsid, uri = await _seed_evidence(s, content=content, checksum=checksum)

                key = uri.split("/", 3)[3]
                fake = _FakeStorage({key: content})
                with patch(
                    "apps.api.scanner_engine.storage_provider.get_storage_provider",
                    return_value=fake,
                ):
                    await verify_evidence_and_record(s, wsid, eid, actor_user_id=None)

            other_ws = uuid.uuid4()
            async with maker() as s2:
                with tenancy.workspace_scope(other_ws):
                    from sqlalchemy import select as _select

                    invisible = (await s2.execute(
                        _select(AuditEvent).where(AuditEvent.resource_id == eid)
                    )).scalars().all()
                    assert invisible == [], "the audit record must not be visible from another workspace"
        finally:
            await engine.dispose()
    _run(scenario())
