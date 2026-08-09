"""Phase 1.6 -- backup/restore/verification metrics + the DR structured logger.

Deliberately kept in the DR package (NOT core/observability.py) so the observability
subsystem stays untouched. Prometheus is optional-at-import: absent -> every recorder is a
no-op. ALL labels are strictly low-cardinality -- only `component` in {postgres, objects,
full}. NEVER hostname / filename / workspace_id / scan_id.
"""
import logging

try:
    from prometheus_client import Counter, Histogram

    _PROM = True
except Exception:  # noqa: BLE001
    _PROM = False

# Structured DR logger. Emitted events (all secret-free): backup.started, backup.completed,
# backup.failed, restore.started, restore.completed, restore.failed, verification.completed,
# cleanup.completed.
logger = logging.getLogger("mbs.backup")

if _PROM:
    BACKUP_SUCCESS = Counter("mbs_backup_success_total", "Backups that completed successfully", ["component"])
    BACKUP_FAILED = Counter("mbs_backup_failed_total", "Backups that failed", ["component"])
    BACKUP_DURATION = Histogram("mbs_backup_duration_seconds", "Backup duration in seconds", ["component"])
    RESTORE_SUCCESS = Counter("mbs_restore_success_total", "Restores that completed successfully", ["component"])
    RESTORE_FAILED = Counter("mbs_restore_failed_total", "Restores that failed", ["component"])
    VERIFICATION_SUCCESS = Counter("mbs_verification_success_total", "Verifications that passed", ["component"])
    VERIFICATION_FAILED = Counter("mbs_verification_failed_total", "Verifications that failed", ["component"])

_ALLOWED = {"postgres", "objects", "full"}


def _comp(component: str) -> str:
    """Clamp to the allowed low-cardinality label set (defensive; callers pass constants)."""
    return component if component in _ALLOWED else "full"


def record_backup(component: str, *, success: bool, duration_s: float = 0.0) -> None:
    if not _PROM:
        return
    c = _comp(component)
    (BACKUP_SUCCESS if success else BACKUP_FAILED).labels(c).inc()
    BACKUP_DURATION.labels(c).observe(max(0.0, duration_s))


def record_restore(component: str, *, success: bool) -> None:
    if not _PROM:
        return
    (RESTORE_SUCCESS if success else RESTORE_FAILED).labels(_comp(component)).inc()


def record_verification(component: str, *, success: bool) -> None:
    if not _PROM:
        return
    (VERIFICATION_SUCCESS if success else VERIFICATION_FAILED).labels(_comp(component)).inc()
