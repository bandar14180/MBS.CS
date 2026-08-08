"""Phase 5.2 -- retention purge task (skeleton).

Beat-UNscheduled by design: it's registered so the worker knows the task, but nothing triggers
it automatically (no beat_schedule entry), so it runs ONLY when invoked manually (.delay / CLI).
Thin shim over retention.service (mirrors backup_tasks.py over dr.service). Double-gated OFF:
a no-op unless settings.retention_enabled, and dry-run unless retention_dry_run is false. Safe
to run manually -- it deletes nothing in Phase 5.2 (a live run raises until 5.3 wires deletion).
"""
import logging

from apps.api.celery_app.worker import celery_app

logger = logging.getLogger("mbs.retention")


@celery_app.task(name="retention.purge")
def retention_purge_task(dry_run: bool | None = None) -> dict:
    """Run one retention pass and return a structured summary:
    {"mode": disabled|dry_run|live, "dry_run": bool, "total_eligible": int, "resources": [...]}.
    Deletes nothing in 5.2 (disabled or dry-run); live deletion arrives in Phase 5.3."""
    from apps.api.retention.service import run_purge

    result = run_purge(dry_run=dry_run)
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
