"""Phase 1.6 -- scheduled backup task.

Beat-scheduled (see worker.py); runs on the DEFAULT queue, NOT the `scans` queue, so it
never competes with or interferes with scan execution. Opt-in: a no-op unless
settings.backup_enabled is true. Idempotent per tick and safe to skip -- each run creates
its own timestamped set and applies retention.
"""
import logging

from apps.api.celery_app.worker import celery_app
from apps.api.core.config import get_settings

logger = logging.getLogger("mbs.backup")


@celery_app.task(name="backup.run")
def scheduled_backup_task() -> str:
    """Create one backup set on schedule. Returns the set name on success, 'disabled' when
    the switch is off, or 'failed' when a component failed (already logged + metered)."""
    settings = get_settings()
    if not settings.backup_enabled:
        return "disabled"

    from apps.api.dr.service import run_backup

    result = run_backup(settings)
    return result.set_dir.name if result.ok else "failed"
