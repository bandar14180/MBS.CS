"""Phase 1.6 -- scheduled backup task.

Beat-scheduled (see worker.py); runs on the DEFAULT queue, NOT the `scans` queue, so it
never competes with or interferes with scan execution. Opt-in: a no-op unless
settings.backup_enabled is true. Idempotent per tick and safe to skip -- each run creates
its own timestamped set and applies retention.

Phase F5: bounded by its OWN soft/hard time limits (not the scan-tuned global) so a large
backup gets adequate headroom; a soft timeout is handled gracefully (log + F4 metric).
"""
import logging

from celery.exceptions import SoftTimeLimitExceeded

from apps.api.celery_app.worker import celery_app
from apps.api.core.config import get_settings

logger = logging.getLogger("mbs.backup")

# F5: per-task time limits. Enforce soft < hard (mirrors worker.py) so a misconfig can't invert
# them; the hard limit is the SIGKILL backstop.
_bs = get_settings()
_backup_soft = _bs.backup_task_soft_time_limit_seconds
_backup_hard = _bs.backup_task_time_limit_seconds
if _backup_soft and _backup_hard <= _backup_soft:
    _backup_hard = _backup_soft + 300


@celery_app.task(
    name="backup.run",
    soft_time_limit=_backup_soft or None,
    time_limit=_backup_hard or None,
)
def scheduled_backup_task() -> str:
    """Create one backup set on schedule. Returns the set name on success, 'disabled' when the
    switch is off, 'failed' when a component failed (already logged + metered), or 'timeout' if
    the per-task soft limit fired -- logged + metered via the F4 reliability signal; beat re-runs
    next cadence (sets are timestamped/idempotent)."""
    settings = get_settings()
    if not settings.backup_enabled:
        return "disabled"

    from apps.api.dr.service import run_backup

    try:
        result = run_backup(settings)
    except SoftTimeLimitExceeded:
        # A soft timeout propagating out of run_backup never set result.ok, so the F4 metric
        # was NOT recorded downstream -- record it here and return gracefully.
        from apps.api.core.observability import record_backup_failure

        record_backup_failure()
        logger.warning(
            "backup.soft_timeout soft_limit=%ss -- backup exceeded its time budget",
            _backup_soft,
            extra={"event": "backup.soft_timeout", "soft_limit_s": _backup_soft},
        )
        return "timeout"

    return result.set_dir.name if result.ok else "failed"
