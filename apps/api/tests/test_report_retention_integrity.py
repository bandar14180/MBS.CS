"""Regression coverage for Prompt 13, Finding #8: report / retention integrity.

`Report.scan_ids` is a JSON list, validated against `scans` only at CREATE time
(reports/service.create_report). It is NOT a relational FK, and scans/reports have
INDEPENDENT retention windows (retention_scan_days defaults to 180, retention_report_days to
365) -- so under normal operation a report's cited scan can be purged while the report itself
survives. This file proves `Report.scans_purged` becomes True, atomically with the scan
deletion, exactly when that happens -- and stays False when it should.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.reports.models import Report
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.retention import repo, service

OLD = datetime(2023, 1, 1, tzinfo=timezone.utc)          # older than every default window
RECENT = datetime.now(timezone.utc) - timedelta(days=1)  # inside every window


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _seed(*, scan_ts, report_ts, report_cites_scan: bool, n_scans: int = 1) -> dict:
    """One workspace with `n_scans` scans (timestamped `scan_ts`) and one report (timestamped
    `report_ts`) whose scan_ids cites the first scan iff `report_cites_scan`."""
    eng = _engine()
    try:
        async with async_sessionmaker(eng, expire_on_commit=False)() as s:
            user = User(email=f"rr-{uuid.uuid4()}@t.local", password_hash="x", full_name="RR Tester")
            s.add(user)
            await s.flush()
            ws = Workspace(name="rr-ws", owner_user_id=user.id)
            s.add(ws)
            await s.flush()
            tenancy.bind_workspace(ws.id)
            project = Project(workspace_id=ws.id, name="p", created_by=user.id)
            s.add(project)
            await s.flush()
            target = Target(project_id=project.id, type="ip_range", value="203.0.113.9",
                             criticality="low", added_by=user.id)
            s.add(target)
            await s.flush()

            scan_ids = []
            for i in range(n_scans):
                scan = Scan(
                    workspace_id=ws.id, project_id=project.id, target_id=target.id,
                    initiated_by=user.id, scan_type="network", status="completed", config={},
                    created_at=scan_ts, completed_at=scan_ts + timedelta(minutes=i),
                )
                s.add(scan)
                await s.flush()
                scan_ids.append(scan.id)

            report = Report(
                project_id=project.id, type="executive", format="pdf",
                scan_ids=[str(scan_ids[0])] if report_cites_scan else [],
                generated_by=user.id, generated_at=report_ts,
            )
            s.add(report)
            await s.flush()
            report.storage_uri = f"unavailable://test/{report.id}"  # non-s3: no storage cleanup needed
            await s.commit()

            return {
                "ws": ws.id, "project": project.id, "scans": scan_ids, "report": report.id,
            }
    finally:
        await eng.dispose()


def _live(monkeypatch, workspace_ids, **overrides):
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

    class _FakeProvider:
        def __init__(self, bucket=None):
            self.bucket = bucket

        def delete(self, key):
            pass

        def delete_prefix(self, prefix):
            return 0

    monkeypatch.setattr(service, "get_storage_provider", lambda bucket=None: _FakeProvider(bucket))


async def _report_row(ids) -> Report | None:
    eng = _engine()
    try:
        async with async_sessionmaker(eng, expire_on_commit=False)() as s:
            tenancy.bind_workspace(ids["ws"])
            return await s.scalar(select(Report).where(Report.id == ids["report"]))
    finally:
        await eng.dispose()


async def _scan_count(ids) -> int:
    eng = _engine()
    try:
        async with async_sessionmaker(eng, expire_on_commit=False)() as s:
            return int(await s.scalar(
                text("SELECT count(*) FROM scans WHERE workspace_id = :w"), {"w": str(ids["ws"])}
            ) or 0)
    finally:
        await eng.dispose()


# --- 1: report creation still works, scan_ids validated (existing behavior, sanity) ----------

def test_new_report_defaults_scans_purged_false():
    ids = asyncio.run(_seed(scan_ts=RECENT, report_ts=RECENT, report_cites_scan=True))
    report = asyncio.run(_report_row(ids))
    assert report.scans_purged is False


# --- 2/3/4: retention flags the report when (and only when) its cited scan is purged ---------

def test_referenced_scan_purge_flags_the_surviving_report(monkeypatch):
    """THE central scenario: scan retention window shorter than report retention window (the
    documented default: 180 vs 365 days) -- the scan is purged, the report survives, and it
    must now show scans_purged=True."""
    ids = asyncio.run(_seed(scan_ts=OLD, report_ts=RECENT, report_cites_scan=True))
    # retention_report_days left at its default (report is RECENT -> never eligible); only the
    # scan's window is exercised.
    _live(monkeypatch, [ids["ws"]])
    service.run_purge()

    assert asyncio.run(_scan_count(ids)) == 0, "the scan must actually have been purged"
    report = asyncio.run(_report_row(ids))
    assert report is not None, "the report itself must survive -- it has its own, longer window"
    assert report.scans_purged is True
    # scan_ids itself is NEVER rewritten -- historical accuracy of what was cited at generation.
    assert len(report.scan_ids) == 1


def test_purge_of_an_unrelated_scan_does_not_flag_the_report(monkeypatch):
    """A different, unrelated scan being purged in the same workspace must never flag a report
    that never cited it."""
    ids = asyncio.run(_seed(scan_ts=OLD, report_ts=RECENT, report_cites_scan=False, n_scans=1))
    _live(monkeypatch, [ids["ws"]])
    service.run_purge()

    assert asyncio.run(_scan_count(ids)) == 0
    report = asyncio.run(_report_row(ids))
    assert report.scans_purged is False


def test_report_with_no_purged_scans_stays_unflagged(monkeypatch):
    """A report whose cited scan is still within its retention window must not be flagged."""
    ids = asyncio.run(_seed(scan_ts=RECENT, report_ts=RECENT, report_cites_scan=True))
    _live(monkeypatch, [ids["ws"]])
    service.run_purge()

    assert asyncio.run(_scan_count(ids)) == 1, "recent scan must not have been purged"
    report = asyncio.run(_report_row(ids))
    assert report.scans_purged is False


def test_flag_and_scan_deletion_are_atomic_same_transaction(monkeypatch):
    """mark_reports_with_purged_scans runs BEFORE delete_scans, in the SAME per-workspace
    transaction service.py already commits atomically -- confirmed indirectly: after a single
    run_purge() call, the scan is gone AND the flag is set, never one without the other."""
    ids = asyncio.run(_seed(scan_ts=OLD, report_ts=RECENT, report_cites_scan=True))
    _live(monkeypatch, [ids["ws"]])
    service.run_purge()

    scan_count = asyncio.run(_scan_count(ids))
    report = asyncio.run(_report_row(ids))
    assert (scan_count == 0) and (report.scans_purged is True), (
        "scan deletion and the purged-report flag must land together, never independently"
    )


# --- 5: historical report remains interpretable -----------------------------------------------

def test_historical_report_remains_readable_and_downloadable_after_scan_purge(monkeypatch):
    """The report row (and its stored PDF pointer) must remain fully readable after its scan is
    purged -- retention never silently breaks a historical, already-issued report."""
    ids = asyncio.run(_seed(scan_ts=OLD, report_ts=RECENT, report_cites_scan=True))
    _live(monkeypatch, [ids["ws"]])
    service.run_purge()

    report = asyncio.run(_report_row(ids))
    assert report.storage_uri is not None
    assert report.type == "executive"
    assert report.scans_purged is True


# --- 6: tenant isolation -----------------------------------------------------------------------

def test_flagging_is_scoped_to_the_purging_workspace_only(monkeypatch):
    """A report in workspace B must never be flagged by a scan purge happening in workspace A,
    even if (hypothetically) a UUID were to collide -- the JOIN through projects.workspace_id
    is the isolation boundary, not the scan_ids content alone."""
    a = asyncio.run(_seed(scan_ts=OLD, report_ts=RECENT, report_cites_scan=True))
    b = asyncio.run(_seed(scan_ts=RECENT, report_ts=RECENT, report_cites_scan=True))

    _live(monkeypatch, [a["ws"]])  # only workspace A is processed by this run
    service.run_purge()

    report_a = asyncio.run(_report_row(a))
    report_b = asyncio.run(_report_row(b))
    assert report_a.scans_purged is True
    assert report_b.scans_purged is False, "workspace B must be completely untouched"
