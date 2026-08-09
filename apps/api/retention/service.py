"""Phase 5.2/5.3.2 -- retention purge orchestration.

Double-gated OFF: a run does nothing unless settings.retention_enabled is true, and even then
defaults to dry-run (plan only, read-only counts) unless retention_dry_run is set false. Live
mode deletes, per the Phase 5.3.1 safety audit:

  * iterate tenants from the NON-RLS `workspaces` anchor; set the workspace GUC per tenant.
  * order: reports -> scans (cascade) -> ai_usage -> notifications -> audit_events LAST.
  * capture evidence tool_run_ids + report object URIs BEFORE deleting rows.
  * DB delete + audit are one transaction per workspace; object cleanup is best-effort AFTER
    commit (never send a non-s3 / `unavailable://` URI to the storage provider).

All raw SQL lives in repo.py; this module is orchestration only. Import-safe without Celery.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core.config import Settings, get_settings
from apps.api.retention import repo
from apps.api.scanner_engine.storage_provider import get_storage_provider

# Structured retention logger. Events (secret-free, low-cardinality): retention.skipped,
# retention.run, retention.plan, retention.deleted, retention.storage_cleanup.
logger = logging.getLogger("mbs.retention")

# Optional-at-import metrics (same guard as core/observability.py & dr/metrics.py). Labels are
# strictly low-cardinality -- resource name / run mode only, NEVER a workspace_id/scan_id/key.
try:
    from prometheus_client import Counter

    _PROM = True
    RETENTION_RUNS = Counter("mbs_retention_runs_total", "Retention purge runs", ["mode"])
    RETENTION_PLANNED = Counter(
        "mbs_retention_planned_total", "Records a retention run identified as eligible", ["resource"]
    )
    RETENTION_DELETED = Counter(
        "mbs_retention_deleted_total", "Records a retention run actually deleted", ["resource"]
    )
except Exception:  # noqa: BLE001
    _PROM = False


@dataclass(frozen=True)
class RetentionPolicy:
    resource: str
    days_attr: str
    description: str


# Full policy set (informational; the `plan` CLI lists all of these). `evidence` is purged via
# the scan cascade + object cleanup, and `refresh_token` is deferred, so neither is a directly
# processed resource in run_purge -- see PROCESSED below.
POLICIES: list[RetentionPolicy] = [
    RetentionPolicy("evidence", "retention_evidence_days", "raw scan evidence (via scan cascade + object cleanup)"),
    RetentionPolicy("scan", "retention_scan_days", "scan records + non-finding subtree"),
    RetentionPolicy("ai_usage", "retention_ai_usage_days", "AI cost/usage log"),
    RetentionPolicy("report", "retention_report_days", "generated reports (rows + PDFs)"),
    RetentionPolicy("refresh_token", "retention_refresh_token_grace_days", "expired refresh tokens (deferred)"),
    RetentionPolicy("notification", "retention_notification_days", "in-app notifications"),
    RetentionPolicy("audit", "retention_audit_days", "audit events (compliance window)"),
]

# Resources run_purge actually processes, in the mandated delete order (audit LAST).
PROCESSED: list[str] = ["report", "scan", "ai_usage", "notification", "audit"]
_DAYS_ATTR = {p.resource: p.days_attr for p in POLICIES}
_DESC = {p.resource: p.description for p in POLICIES}


@dataclass
class ResourcePlan:
    resource: str
    retention_days: int
    cutoff: datetime
    eligible: int
    description: str
    deleted: int = 0


@dataclass
class RetentionRunResult:
    mode: str  # "disabled" | "dry_run" | "live"
    dry_run: bool
    plans: list[ResourcePlan]

    @property
    def total_eligible(self) -> int:
        return sum(p.eligible for p in self.plans)

    @property
    def total_deleted(self) -> int:
        return sum(p.deleted for p in self.plans)


@dataclass
class _StorageTargets:
    tool_run_ids: list = field(default_factory=list)  # -> tool-runs/{id}/ prefixes (mbs-evidence)
    report_uris: list = field(default_factory=list)   # raw storage_uri strings (filtered at cleanup)


def _cutoff(now: datetime, days: int) -> datetime:
    return now - timedelta(days=max(0, int(days)))


def _count_eligible(policy: RetentionPolicy, cutoff: datetime) -> int:
    """Pure planning stub for build_plan -- NO DB access (used by the `plan` CLI). Real,
    read-only counts happen inside run_purge (repo.count_eligible_*)."""
    return 0


def build_plan(settings: Settings | None = None, *, now: datetime | None = None) -> list[ResourcePlan]:
    """Compute the retention plan (per-resource window + cutoff). Pure and read-free."""
    settings = settings or get_settings()
    now = now or datetime.now(timezone.utc)
    return [
        ResourcePlan(pol.resource, int(getattr(settings, pol.days_attr)),
                     _cutoff(now, int(getattr(settings, pol.days_attr))),
                     _count_eligible(pol, now), pol.description)
        for pol in POLICIES
    ]


def _parse_s3(uri: str | None) -> tuple[str, str] | None:
    """s3://bucket/key -> (bucket, key); anything else (None / `unavailable://...`) -> None."""
    if not uri or not uri.startswith("s3://"):
        return None
    bucket, _, key = uri[len("s3://"):].partition("/")
    if not bucket or not key:
        return None
    return bucket, key


def run_purge(
    settings: Settings | None = None, *, dry_run: bool | None = None, now: datetime | None = None
) -> RetentionRunResult:
    """Entry point shared by the Celery task and the CLI.

    Contract:
      * retention_enabled=False -> return immediately (mode="disabled"), delete nothing.
      * dry_run defaults to settings.retention_dry_run; when true, COUNT (read-only) but never
        delete and never touch object storage.
      * live (enabled + not dry_run) -> per-workspace capture -> delete -> audit -> object cleanup.
    """
    settings = settings or get_settings()

    if not settings.retention_enabled:
        logger.info("retention.skipped disabled", extra={"event": "retention.skipped", "reason": "disabled"})
        if _PROM:
            RETENTION_RUNS.labels("disabled").inc()
        return RetentionRunResult(mode="disabled", dry_run=True, plans=[])

    effective_dry_run = settings.retention_dry_run if dry_run is None else dry_run
    now = now or datetime.now(timezone.utc)
    mode = "dry_run" if effective_dry_run else "live"
    cutoffs = {res: _cutoff(now, int(getattr(settings, _DAYS_ATTR[res]))) for res in PROCESSED}

    logger.info(
        "retention.run mode=%s resources=%d",
        mode, len(PROCESSED),
        extra={"event": "retention.run", "mode": mode, "dry_run": effective_dry_run,
               "batch_size": settings.retention_batch_size, "min_keep": settings.retention_min_keep},
    )

    agg = asyncio.run(_run_async(settings, effective_dry_run, cutoffs))

    plans: list[ResourcePlan] = []
    for res in PROCESSED:
        eligible, deleted = agg[res]
        plans.append(ResourcePlan(res, int(getattr(settings, _DAYS_ATTR[res])), cutoffs[res],
                                  eligible, _DESC[res], deleted))
        logger.info(
            "retention.plan resource=%s retention_days=%d cutoff=%s eligible=%d deleted=%d",
            res, int(getattr(settings, _DAYS_ATTR[res])), cutoffs[res].isoformat(), eligible, deleted,
            extra={"event": "retention.plan", "resource": res, "eligible": eligible, "deleted": deleted},
        )
        if _PROM:
            if eligible:
                RETENTION_PLANNED.labels(res).inc(eligible)
            if deleted:
                RETENTION_DELETED.labels(res).inc(deleted)

    if _PROM:
        RETENTION_RUNS.labels(mode).inc()

    return RetentionRunResult(mode=mode, dry_run=effective_dry_run, plans=plans)


async def _run_async(settings: Settings, dry_run: bool, cutoffs: dict[str, datetime]) -> dict[str, list[int]]:
    """Per-workspace purge. Returns {resource: [eligible, deleted]} aggregated across tenants."""
    agg: dict[str, list[int]] = {res: [0, 0] for res in PROCESSED}
    engine = create_async_engine(settings.database_url, poolclass=StaticPool)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as session:
            workspace_ids = await repo.list_workspace_ids(session)
            for wid in workspace_ids:
                await repo.set_workspace(session, wid)  # RLS bootstrap for this tenant
                targets = await _purge_workspace(session, wid, cutoffs, settings, dry_run, agg)
                if dry_run:
                    await session.rollback()  # read-only pass -- discard any tx state
                    continue
                await session.commit()  # DB deletes + audit are atomic per workspace
                _cleanup_storage(settings, targets)  # best-effort, AFTER commit
    finally:
        await engine.dispose()
    return agg


async def _purge_workspace(session, wid, cutoffs, settings, dry_run, agg) -> _StorageTargets:
    mk, bs = settings.retention_min_keep, settings.retention_batch_size
    targets = _StorageTargets()

    async def _generic(resource: str, table: str, ts: str) -> None:
        eligible = await repo.count_eligible_generic(session, table, ts, cutoffs[resource], mk)
        agg[resource][0] += eligible
        if dry_run or not eligible:
            return
        ids = await repo.select_eligible_generic(session, table, ts, cutoffs[resource], mk, bs)
        if resource == "report":
            targets.report_uris.extend(await repo.capture_report_uris(session, ids))  # before delete
        deleted = await repo.delete_by_ids(session, table, ids)
        agg[resource][1] += deleted
        await _audit(session, wid, resource, deleted)

    # 1) reports (rows now; objects after commit)
    await _generic("report", "reports", "generated_at")

    # 2) scans -- cascade clears the subtree; capture tool_run_ids BEFORE deleting
    eligible = await repo.count_eligible_scans(session, wid, cutoffs["scan"], mk)
    agg["scan"][0] += eligible
    if not dry_run and eligible:
        scan_ids = await repo.select_eligible_scans(session, wid, cutoffs["scan"], mk, bs)
        targets.tool_run_ids.extend(await repo.capture_tool_run_ids(session, scan_ids))
        deleted = await repo.delete_scans(session, scan_ids)
        agg["scan"][1] += deleted
        await _audit(session, wid, "scan", deleted)

    # 3) residual ai_usage, 4) notifications
    await _generic("ai_usage", "ai_usage", "created_at")
    await _generic("notification", "notifications", "created_at")

    # 5) audit_events LAST (its own prune never removes the just-written retention events)
    await _generic("audit", "audit_events", "created_at")

    return targets


async def _audit(session, wid, resource_type: str, count: int) -> None:
    """Append a system audit event (actor=None) for a resource purge, within the workspace GUC
    so the FORCE-RLS insert on audit_events passes. Flushes (commits with the workspace tx)."""
    from apps.api.modules.audit import service as audit

    await audit.record(
        session, wid, None, "retention.purged", resource_type, detail=f"purged {count}"
    )


def _cleanup_storage(settings: Settings, targets: _StorageTargets) -> None:
    """Best-effort object deletion AFTER the DB commit. A storage failure is logged and never
    re-raised (a stranded object is preferable to a failed/partial purge). Non-s3 URIs are
    skipped -- they never became real objects."""
    if targets.tool_run_ids:
        evidence = get_storage_provider(settings.s3_bucket_evidence)
        for tool_run_id in targets.tool_run_ids:
            try:
                evidence.delete_prefix(f"tool-runs/{tool_run_id}/")
            except Exception:  # noqa: BLE001 -- storage outage must not fail an otherwise-done purge
                logger.warning(
                    "retention.storage_cleanup_failed kind=evidence tool_run=%s", tool_run_id,
                    exc_info=True, extra={"event": "retention.storage_cleanup", "kind": "evidence"},
                )
    for uri in targets.report_uris:
        parsed = _parse_s3(uri)
        if parsed is None:  # skip NULL / unavailable:// -- never send a non-s3 key to storage
            continue
        bucket, key = parsed
        try:
            get_storage_provider(bucket).delete(key)
        except Exception:  # noqa: BLE001
            logger.warning(
                "retention.storage_cleanup_failed kind=report key=%s", key,
                exc_info=True, extra={"event": "retention.storage_cleanup", "kind": "report"},
            )
