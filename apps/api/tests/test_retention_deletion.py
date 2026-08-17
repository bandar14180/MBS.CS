"""Phase 5.3.2 -- retention LIVE deletion tests (real Postgres).

Each test seeds its own workspace(s) with backdated rows across the RLS + non-RLS tables, then
runs a live purge that is confined to those workspaces by monkeypatching
`repo.list_workspace_ids` (so a days=0 run can't touch other tests' data). A fake storage
provider records object deletions. Covers: two-workspace RLS isolation, capture-before-cascade,
non-s3 skip, min_keep, batch_size, audit-event creation, and audit_events-processed-last.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.ai_agent.models import AIUsageRow
from apps.api.core.config import get_settings
from apps.api.modules.audit.models import AuditEvent
from apps.api.modules.notifications.models import Notification
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.reports.models import Report
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.retention import repo, service
from apps.api.scanner_engine.models import Evidence, ToolRun

OLD = datetime(2023, 1, 1, tzinfo=timezone.utc)           # older than every default window
RECENT = datetime.now(timezone.utc) - timedelta(days=1)   # inside every window (never eligible)


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _set_ws(session, wid):
    await session.execute(
        text("SELECT set_config('app.current_workspace_id', :w, false)"), {"w": str(wid)}
    )


async def _seed(session, *, ts, n_scans=1, n_reports=1, with_evidence=False,
                report_uri_tmpl="s3://mbs-reports/reports/{rid}.pdf", ai_usage=False,
                notification=False, audit=False) -> dict:
    """Seed one workspace's data at timestamp `ts`. Returns created ids."""
    user = User(email=f"ret-{uuid.uuid4()}@t.local", password_hash="x", full_name="Ret Tester")
    session.add(user)
    await session.flush()
    ws = Workspace(name="ret-ws", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    await _set_ws(session, ws.id)  # RLS bootstrap for every insert below

    project = Project(workspace_id=ws.id, name="p", created_by=user.id)
    session.add(project)
    await session.flush()
    target = Target(project_id=project.id, type="ip_range", value="203.0.113.5",
                    criticality="low", added_by=user.id)
    session.add(target)
    await session.flush()

    ids: dict = {"ws": ws.id, "user": user.id, "project": project.id, "scans": [], "tool_runs": [], "reports": []}

    for i in range(n_scans):
        scan = Scan(workspace_id=ws.id, project_id=project.id, target_id=target.id,
                    initiated_by=user.id, scan_type="network", status="completed", config={},
                    created_at=ts, completed_at=ts + timedelta(minutes=i))  # distinct ts for min_keep
        session.add(scan)
        await session.flush()
        ids["scans"].append(scan.id)
        if with_evidence:
            tr = ToolRun(scan_id=scan.id, tool_name="nmap", tool_version="7", status="completed",
                         command_hash="h", raw_output_ref=f"s3://mbs-evidence/tool-runs/{uuid.uuid4()}/raw-output.txt")
            session.add(tr)
            await session.flush()
            ids["tool_runs"].append(tr.id)
            session.add(Evidence(tool_run_id=tr.id, evidence_type="log_excerpt",
                                 storage_uri=f"s3://mbs-evidence/tool-runs/{tr.id}/raw-output.txt", checksum="c"))

    for i in range(n_reports):
        rep = Report(project_id=project.id, type="executive", format="pdf", scan_ids=[],
                     generated_by=user.id, generated_at=ts + timedelta(minutes=i))
        session.add(rep)
        await session.flush()
        rep.storage_uri = report_uri_tmpl.format(rid=rep.id)
        ids["reports"].append(rep.id)

    if ai_usage:
        session.add(AIUsageRow(workspace_id=ws.id, provider="openrouter", model="m",
                               prompt_tokens=1, completion_tokens=1, estimated_cost_usd=0, created_at=ts))
    if notification:
        session.add(Notification(workspace_id=ws.id, type="scan_completed", title="t", created_at=ts))
    if audit:
        session.add(AuditEvent(workspace_id=ws.id, actor_user_id=user.id, actor_email="a@t.local",
                               action="scan.created", resource_type="scan", created_at=ts))
    await session.commit()
    return ids


class _FakeProvider:
    calls: list[tuple] = []

    def __init__(self, bucket=None):
        self.bucket = bucket

    def delete(self, key):
        _FakeProvider.calls.append(("delete", self.bucket, key))

    def delete_prefix(self, prefix):
        _FakeProvider.calls.append(("delete_prefix", self.bucket, prefix))
        return 1


def _live(monkeypatch, workspace_ids, **overrides):
    """Configure a confined LIVE run + fake storage."""
    s = get_settings()
    monkeypatch.setattr(s, "retention_enabled", True)
    monkeypatch.setattr(s, "retention_dry_run", False)
    monkeypatch.setattr(s, "retention_min_keep", overrides.get("min_keep", 0))
    monkeypatch.setattr(s, "retention_batch_size", overrides.get("batch_size", 500))
    for k, v in overrides.items():
        if k.startswith("retention_"):
            monkeypatch.setattr(s, k, v)

    async def _fake_list(_session):
        return list(workspace_ids)

    monkeypatch.setattr(repo, "list_workspace_ids", _fake_list)
    _FakeProvider.calls = []
    monkeypatch.setattr(service, "get_storage_provider", lambda bucket=None: _FakeProvider(bucket))
    return s


async def _count(session, wid, table, col="workspace_id") -> int:
    await _set_ws(session, wid)
    if table == "scans":
        return int(await session.scalar(
            text("SELECT count(*) FROM scans WHERE workspace_id = :w"), {"w": str(wid)}) or 0)
    if table == "reports":
        return int(await session.scalar(
            text("SELECT count(*) FROM reports r JOIN projects p ON p.id = r.project_id "
                 "WHERE p.workspace_id = :w"), {"w": str(wid)}) or 0)
    return int(await session.scalar(
        text(f"SELECT count(*) FROM {table} WHERE {col} = :w"), {"w": str(wid)}) or 0)


# --- core: rows + objects removed ----------------------------------------------------------

def test_live_purge_removes_rows_and_objects(monkeypatch):
    async def seed():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                return await _seed(s, ts=OLD, with_evidence=True, ai_usage=True, notification=True)
        finally:
            await eng.dispose()

    ids = asyncio.run(seed())
    _live(monkeypatch, [ids["ws"]])
    result = service.run_purge()

    assert result.mode == "live"
    assert result.total_deleted >= 3  # scan + report + ai_usage + notification

    async def check():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                return (await _count(s, ids["ws"], "scans"),
                        await _count(s, ids["ws"], "reports"),
                        await _count(s, ids["ws"], "ai_usage"),
                        await _count(s, ids["ws"], "notifications"))
        finally:
            await eng.dispose()

    scans, reports, ai_usage, notifs = asyncio.run(check())
    # scans is NON-RLS -> an authoritative 0 proves the scan (and its FK cascade subtree) is gone
    assert scans == 0 and reports == 0 and ai_usage == 0 and notifs == 0

    # object cleanup happened for evidence prefix + report key
    ops = _FakeProvider.calls
    assert any(op == "delete_prefix" and bucket == "mbs-evidence" for op, bucket, _ in ops)
    assert any(op == "delete" and bucket == "mbs-reports" for op, bucket, _ in ops)


# --- two-workspace RLS isolation -----------------------------------------------------------

def test_two_workspace_rls_isolation(monkeypatch):
    async def seed():
        eng = _engine()
        try:
            mk = async_sessionmaker(eng, expire_on_commit=False)
            async with mk() as s:
                a = await _seed(s, ts=OLD)       # old -> eligible
            async with mk() as s:
                b = await _seed(s, ts=RECENT)    # recent -> NOT eligible
            return a, b
        finally:
            await eng.dispose()

    a, b = asyncio.run(seed())
    _live(monkeypatch, [a["ws"], b["ws"]])  # both tenants processed
    service.run_purge()

    async def check():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                return (await _count(s, a["ws"], "scans"), await _count(s, a["ws"], "reports"),
                        await _count(s, b["ws"], "scans"), await _count(s, b["ws"], "reports"))
        finally:
            await eng.dispose()

    a_scans, a_reports, b_scans, b_reports = asyncio.run(check())
    assert a_scans == 0 and a_reports == 0      # old workspace purged
    assert b_scans == 1 and b_reports == 1      # recent workspace untouched (isolation holds)


# --- capture-before-cascade ----------------------------------------------------------------

def test_capture_tool_run_ids_before_scan_cascade(monkeypatch):
    async def seed():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                return await _seed(s, ts=OLD, n_reports=0, with_evidence=True)
        finally:
            await eng.dispose()

    ids = asyncio.run(seed())
    _live(monkeypatch, [ids["ws"]])
    service.run_purge()

    trid = ids["tool_runs"][0]
    prefixes = [arg for op, bucket, arg in _FakeProvider.calls if op == "delete_prefix"]
    assert f"tool-runs/{trid}/" in prefixes  # id was captured BEFORE the scan cascade destroyed it


# --- non-s3 URI skipped --------------------------------------------------------------------

def test_non_s3_report_uri_is_skipped(monkeypatch):
    async def seed():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                return await _seed(s, ts=OLD, n_scans=0, n_reports=1,
                                   report_uri_tmpl="unavailable://evidence-storage-failed/{rid}")
        finally:
            await eng.dispose()

    ids = asyncio.run(seed())
    _live(monkeypatch, [ids["ws"]])
    service.run_purge()

    # row deleted, but the non-s3 URI was never sent to the storage provider
    assert not any(op == "delete" for op, _, _ in _FakeProvider.calls)

    async def check():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                return await _count(s, ids["ws"], "reports")
        finally:
            await eng.dispose()

    assert asyncio.run(check()) == 0


# --- min_keep respected --------------------------------------------------------------------

def test_min_keep_spares_newest(monkeypatch):
    async def seed():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                return await _seed(s, ts=OLD, n_scans=3, n_reports=0)
        finally:
            await eng.dispose()

    ids = asyncio.run(seed())
    _live(monkeypatch, [ids["ws"]], min_keep=1)  # keep the single newest scan
    service.run_purge()

    async def check():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                return await _count(s, ids["ws"], "scans")
        finally:
            await eng.dispose()

    assert asyncio.run(check()) == 1  # 3 seeded - 2 deleted (newest 1 kept)


# --- batch_size respected ------------------------------------------------------------------

def test_batch_size_caps_deletions_per_run(monkeypatch):
    async def seed():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                return await _seed(s, ts=OLD, n_scans=0, n_reports=3)
        finally:
            await eng.dispose()

    ids = asyncio.run(seed())
    _live(monkeypatch, [ids["ws"]], batch_size=2)
    service.run_purge()

    async def check():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                return await _count(s, ids["ws"], "reports")
        finally:
            await eng.dispose()

    assert asyncio.run(check()) == 1  # 3 seeded - 2 (batch cap) = 1 remains


# --- audit event created -------------------------------------------------------------------

def test_purge_writes_audit_event(monkeypatch):
    async def seed():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                return await _seed(s, ts=OLD, n_scans=1, n_reports=1)
        finally:
            await eng.dispose()

    ids = asyncio.run(seed())
    # keep audit window long so the fresh retention.purged events survive the audit prune
    _live(monkeypatch, [ids["ws"]], retention_audit_days=3650)
    service.run_purge()

    async def check():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                await _set_ws(s, ids["ws"])
                return int(await s.scalar(
                    text("SELECT count(*) FROM audit_events WHERE action = 'retention.purged'")) or 0)
        finally:
            await eng.dispose()

    assert asyncio.run(check()) >= 2  # one for report, one for scan


# --- audit_events processed LAST -----------------------------------------------------------

def test_audit_events_deleted_last(monkeypatch):
    async def seed():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                return await _seed(s, ts=OLD, n_scans=1, n_reports=1, with_evidence=True,
                                   ai_usage=True, notification=True, audit=True)
        finally:
            await eng.dispose()

    ids = asyncio.run(seed())
    _live(monkeypatch, [ids["ws"]])

    order: list[str] = []
    real_by_ids, real_scans = repo.delete_by_ids, repo.delete_scans

    async def spy_by_ids(session, table, id_list):
        order.append(table)
        return await real_by_ids(session, table, id_list)

    async def spy_scans(session, id_list):
        order.append("scans")
        return await real_scans(session, id_list)

    monkeypatch.setattr(repo, "delete_by_ids", spy_by_ids)
    monkeypatch.setattr(repo, "delete_scans", spy_scans)
    service.run_purge()

    assert order == ["reports", "scans", "ai_usage", "notifications", "audit_events"]
    assert order[-1] == "audit_events"  # explicitly last
