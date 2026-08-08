"""Phase 5.2 -- retention purge FOUNDATION (skeleton).

Double-gated OFF: a run does nothing unless settings.retention_enabled is true, and even then
defaults to dry-run (plan only) unless retention_dry_run is set false. Import-safe without
Celery/DB so the CLI and unit tests can drive it directly (this is dr/service.py vs
backup_tasks.py again). It defines the retention POLICY set and produces a PLAN; the actual,
RLS-safe DB eligibility query + batched deletion is deliberately deferred to Phase 5.3 --
see `_count_eligible`, which performs NO database access here on purpose.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from apps.api.core.config import Settings, get_settings

# Structured retention logger. Events (all secret-free, low-cardinality):
# retention.skipped, retention.run, retention.plan.
logger = logging.getLogger("mbs.retention")

# Optional-at-import metrics (same guard as core/observability.py & dr/metrics.py): absent
# prometheus -> recorders are no-ops. Labels are strictly low-cardinality -- the resource
# name and the run mode only, NEVER a workspace_id/scan_id/object key.
try:
    from prometheus_client import Counter

    _PROM = True
    RETENTION_RUNS = Counter("mbs_retention_runs_total", "Retention purge runs", ["mode"])
    RETENTION_PLANNED = Counter(
        "mbs_retention_planned_total", "Records a retention run identified as eligible", ["resource"]
    )
except Exception:  # noqa: BLE001
    _PROM = False


@dataclass(frozen=True)
class RetentionPolicy:
    """One retention rule: a low-cardinality resource name + the Settings attribute holding
    its window (in days). The eligibility/deletion mechanics for each land in Phase 5.3."""

    resource: str
    days_attr: str
    description: str


# The policy set (informational ordering). Each maps a resource -> its configurable window.
POLICIES: list[RetentionPolicy] = [
    RetentionPolicy("evidence", "retention_evidence_days", "raw scan evidence objects + rows"),
    RetentionPolicy("scan", "retention_scan_days", "scan records + non-finding subtree"),
    RetentionPolicy("ai_usage", "retention_ai_usage_days", "AI cost/usage log"),
    RetentionPolicy("report", "retention_report_days", "generated reports (rows + PDFs)"),
    RetentionPolicy("refresh_token", "retention_refresh_token_grace_days", "expired refresh tokens"),
    RetentionPolicy("notification", "retention_notification_days", "in-app notifications"),
    RetentionPolicy("audit", "retention_audit_days", "audit events (compliance window)"),
]


@dataclass
class ResourcePlan:
    resource: str
    retention_days: int
    cutoff: datetime  # records older than this become eligible (once 5.3 wires the query)
    eligible: int     # count a real run WOULD delete; always 0 until 5.3
    description: str


@dataclass
class RetentionRunResult:
    mode: str  # "disabled" | "dry_run" | "live"
    dry_run: bool
    plans: list[ResourcePlan]

    @property
    def total_eligible(self) -> int:
        return sum(p.eligible for p in self.plans)


def _cutoff(now: datetime, days: int) -> datetime:
    return now - timedelta(days=max(0, int(days)))


def _count_eligible(policy: RetentionPolicy, cutoff: datetime) -> int:
    """Phase 5.3 will implement the read-only, RLS-safe eligibility count (and the batched,
    audited deletion that follows). The 5.2 foundation performs NO database access, so this
    returns 0 -- guaranteeing the skeleton can never read or delete production data."""
    return 0


def build_plan(settings: Settings | None = None, *, now: datetime | None = None) -> list[ResourcePlan]:
    """Compute the retention plan (per-resource window + cutoff). Pure and read-free."""
    settings = settings or get_settings()
    now = now or datetime.now(timezone.utc)
    plans: list[ResourcePlan] = []
    for pol in POLICIES:
        days = int(getattr(settings, pol.days_attr))
        cutoff = _cutoff(now, days)
        plans.append(
            ResourcePlan(pol.resource, days, cutoff, _count_eligible(pol, cutoff), pol.description)
        )
    return plans


def run_purge(
    settings: Settings | None = None, *, dry_run: bool | None = None, now: datetime | None = None
) -> RetentionRunResult:
    """Foundation entry point shared by the Celery task AND the CLI.

    Safety contract (5.2):
      * retention_enabled=False -> return immediately (mode="disabled"), delete nothing.
      * dry_run defaults to settings.retention_dry_run; when true, only PLAN (no deletion).
      * actual deletion is NOT implemented yet (5.3); reaching the live branch raises
        NotImplementedError so a misconfigured live run fails LOUD instead of silently.
    """
    settings = settings or get_settings()

    if not settings.retention_enabled:
        logger.info(
            "retention.skipped disabled",
            extra={"event": "retention.skipped", "reason": "disabled"},
        )
        if _PROM:
            RETENTION_RUNS.labels("disabled").inc()
        return RetentionRunResult(mode="disabled", dry_run=True, plans=[])

    effective_dry_run = settings.retention_dry_run if dry_run is None else dry_run
    plans = build_plan(settings, now=now)
    mode = "dry_run" if effective_dry_run else "live"

    logger.info(
        "retention.run mode=%s resources=%d total_eligible=%d",
        mode, len(plans), sum(p.eligible for p in plans),
        extra={
            "event": "retention.run", "mode": mode, "dry_run": effective_dry_run,
            "batch_size": settings.retention_batch_size, "min_keep": settings.retention_min_keep,
        },
    )
    for p in plans:
        logger.info(
            "retention.plan resource=%s retention_days=%d cutoff=%s would_delete=%d",
            p.resource, p.retention_days, p.cutoff.isoformat(), p.eligible,
            extra={
                "event": "retention.plan", "resource": p.resource,
                "retention_days": p.retention_days, "would_delete": p.eligible,
            },
        )
        if _PROM and p.eligible:
            RETENTION_PLANNED.labels(p.resource).inc(p.eligible)

    if _PROM:
        RETENTION_RUNS.labels(mode).inc()

    if not effective_dry_run:
        # Phase 5.3 wires the real RLS-safe, batched, audited deletion here. Until then a live
        # run must fail LOUD rather than pretend to purge (or silently no-op).
        raise NotImplementedError(
            "Retention deletion is not implemented yet (Phase 5.3). Keep retention_dry_run=true."
        )

    return RetentionRunResult(mode=mode, dry_run=True, plans=plans)
