"""Phase 5.2 -- retention purge task (skeleton).

Beat-UNscheduled by design: it's registered so the worker knows the task, but nothing triggers
it automatically (no beat_schedule entry), so it runs ONLY when invoked manually (.delay / CLI).
Thin shim over retention.service (mirrors backup_tasks.py over dr.service). Double-gated OFF:
a no-op unless settings.retention_enabled, and dry-run unless retention_dry_run is false.

Phase F5: bounded by its OWN soft/hard time limits (not the scan-tuned global). A soft timeout
is handled gracefully (mode='timeout'); retention commits per workspace, so completed workspaces
stay purged and the next run resumes.
"""
import logging

from celery.exceptions import SoftTimeLimitExceeded

from apps.api.celery_app.worker import celery_app
from apps.api.core.config import get_settings

logger = logging.getLogger("mbs.retention")

# F5: per-task time limits. Enforce soft < hard (mirrors worker.py); the hard limit is the
# SIGKILL backstop.
_rs = get_settings()
_retention_soft = _rs.retention_task_soft_time_limit_seconds
_retention_hard = _rs.retention_task_time_limit_seconds
if _retention_soft and _retention_hard <= _retention_soft:
    _retention_hard = _retention_soft + 300


@celery_app.task(
    name="retention.purge",
    soft_time_limit=_retention_soft or None,
    time_limit=_retention_hard or None,
)
def retention_purge_task(dry_run: bool | None = None) -> dict:
    """Run one retention pass and return a structured summary:
    {"mode": disabled|dry_run|live|timeout, "dry_run": bool|None, "total_eligible": int,
    "resources": [...]}. A per-task soft timeout returns mode='timeout' -- run_purge already
    recorded the F4 retention-failure metric (its own except), and per-workspace commits mean
    partial progress is kept and the next run resumes."""
    from apps.api.retention.service import run_purge

    try:
        result = run_purge(dry_run=dry_run)
    except SoftTimeLimitExceeded:
        logger.warning(
            "retention.soft_timeout soft_limit=%ss -- purge exceeded its time budget (partial "
            "progress committed per-workspace; next run resumes)",
            _retention_soft,
            extra={"event": "retention.soft_timeout", "soft_limit_s": _retention_soft},
        )
        return {"mode": "timeout", "dry_run": None, "total_eligible": 0, "resources": []}

    logger.info(
        "retention.task.completed mode=%s total_eligible=%d",
        result.mode, result.total_eligible,
        extra={"event": "retention.task.completed", "mode": result.mode},
    )
    return {
        "mode": result.mode,
        "dry_run": result.dry_run,
        "total_eligible": result.total_eligible,
        "resources": [
            {
                "resource": p.resource,
                "retention_days": p.retention_days,
                "cutoff": p.cutoff.isoformat(),
                "would_delete": p.eligible,
            }
            for p in result.plans
        ],
    }
