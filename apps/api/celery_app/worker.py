from celery import Celery

from apps.api.celery_app.startup_security import (
    TenancyInstalledSecurityStep,
    enforce_execution_plane_credentials,
    enforce_production_config,
)
from apps.api.core.config import get_settings
import apps.api.core.models_all  # noqa: F401  -- register all ORM models on Base.metadata
from apps.api.core import tenancy

settings = get_settings()

# Phase 0 MySQL cutover: install the app-layer workspace-isolation filter as early as
# possible in every worker process, right after models_all has registered every mapped
# class. TenancyInstalledSecurityStep (below) verifies this actually happened before the
# worker blueprint accepts work; beat has no engine and skips that check, but importing
# this module still installs the filter for it too (cheap, and correct if beat ever
# executes a task inline).
tenancy.install()

# Prompt 34: enforce the audit tables' append-only property in worker processes too -- a
# Celery task holds an ORM session just like a request does, so the guard must be installed
# on both paths or the invariant only holds for HTTP traffic.
from apps.api.modules.audit import immutability as _audit_immutability  # noqa: E402

_audit_immutability.install()

# Production configuration is validated HERE, at import, because this module is what every
# Celery entrypoint loads (`-A apps.api.celery_app.worker.celery_app`) and it is the only
# hook that aborts BOTH `celery worker` and `celery beat`. Celery signals cannot be used:
# an exception raised in a signal receiver is swallowed and the worker keeps serving (see
# startup_security.py). Outside production this is a no-op, so importing the app in tests
# or from the API is unaffected.
enforce_production_config(settings)

# MBS.SC Property B: a scanner EXECUTION worker must not hold control-plane credentials.
# Checked at import for the same reason as the line above -- it is the one hook that
# aborts every Celery entrypoint, and a signal receiver's exception would be swallowed.
# No-op unless SCANNER_EXECUTION_PLANE=true, so the control-plane workers (which
# legitimately hold these credentials) are unaffected.
enforce_execution_plane_credentials()

celery_app = Celery(
    "mbs_sc",
    broker=settings.redis_url,
    backend=settings.redis_url,
    # Explicit include: task modules aren't named literally "tasks" (they're
    # tasks/scan_tasks.py etc.), so autodiscover_tasks alone won't find them.
    include=[
        "apps.api.celery_app.tasks.scan_tasks",
        "apps.api.celery_app.tasks.schedule_tasks",
        "apps.api.celery_app.tasks.backup_tasks",
        # Phase 5.2: registered so the worker knows the task. NOT beat-scheduled -- it runs
        # only when invoked manually, and is double-gated OFF (retention_enabled + dry_run).
        "apps.api.celery_app.tasks.retention_tasks",
        # P1: async tenant/workspace deletion (default queue). Invoked on demand from the
        # DELETE /workspaces/{id} endpoint; idempotent + retry-safe.
        "apps.api.celery_app.tasks.tenant_tasks",
        # E2: async email delivery (default queue). Gated OFF unless email_enabled.
        "apps.api.celery_app.tasks.notification_tasks",
        # P1.1: beat-liveness heartbeat (default queue). Always scheduled; stamps a Redis timestamp.
        "apps.api.celery_app.tasks.reliability_tasks",
        # Risk-acceptance expiry (default queue). Beat-scheduled unconditionally below:
        # unlike retention it deletes nothing, and an acceptance that never lapses would
        # break the guarantee its mandatory expiry date makes.
        "apps.api.celery_app.tasks.risk_tasks",
    ],
)
celery_app.conf.broker_connection_retry_on_startup = True

# --- Reliability (P1-6) -------------------------------------------------------
# acks_late + reject_on_worker_lost: a task is only acknowledged AFTER it finishes,
# so if a worker is killed mid-scan the broker re-delivers it (graceful recovery).
# Scans are idempotent (orchestrator skips already-finished scans), so redelivery
# is safe. prefetch=1 stops a worker hoarding long scans. Named queues let the
# heavy scan work scale/isolate separately from everything else.
# Phase 1.5: BOUND every task with a soft+hard time limit so a hung/very-long scan
# cannot block warm shutdown forever. The soft limit MUST fire before the hard limit
# (invariant enforced here): the soft one raises SoftTimeLimitExceeded inside the task
# so the orchestrator marks the scan 'failed' cleanly (reclaimable); the hard one is the
# force-kill backstop. A misconfiguration (soft >= hard) is auto-corrected so the soft
# path can never be pre-empted by the hard kill.
_soft_limit = settings.celery_task_soft_time_limit_seconds
_hard_limit = settings.celery_task_time_limit_seconds
if _soft_limit and (_hard_limit <= _soft_limit):
    _hard_limit = _soft_limit + 300  # keep a margin for clean in-task teardown

# Redis broker visibility timeout. kombu's default is 3600s, which is BELOW how long a scan
# may legitimately run: under acks_late the in-flight message sits in the unacked set, and
# once this elapses Redis restores and redelivers it WHILE the original worker is still
# scanning. The atomic claim stops the redelivery executing, but it acks away the one
# message that gave the scan its acks_late safety net.
#
# DECOUPLED from the hard task limit (it used to be `max(4200, hard + 300)`): scans no
# longer HAVE a hard limit to derive from, and deriving it would silently collapse this to
# the 4200s floor -- i.e. redelivery of every scan past ~70 minutes, exactly the bug the
# derivation was introduced to prevent. It is now an explicit, independently-reasoned
# setting; see config.celery_broker_visibility_timeout_seconds for how 6h was chosen. The
# floor keeps it above any per-task limit that IS configured.
_visibility_timeout = max(
    settings.celery_broker_visibility_timeout_seconds,
    (_hard_limit or 0) + 300,
)

celery_app.conf.update(
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    broker_transport_options={"visibility_timeout": _visibility_timeout},
    task_default_queue="default",
    task_routes={
        # MBS.SC Phase 5: the DEFAULT route for a scan is the public queue (renamed from
        # the old catch-all `scans`). A private scan never relies on this default -- its
        # dispatcher passes an explicit per-site queue (see scanner_engine/scan_routing.py),
        # which takes precedence over task_routes. Keeping the default PUBLIC means a
        # dispatch that somehow lost its routing information lands on the queue with the
        # least authority, rather than on a private site's queue.
        "scans.run_scan": {"queue": "scans.public"},
        # schedules.enqueue_due stays on the default queue (cheap, frequent).
    },
    # Task-level retry defaults; the scan task overrides max_retries/backoff.
    task_acks_on_failure_or_timeout=True,
    # Phase 1.5 time limits + child recycling (see config.py for rationale).
    task_soft_time_limit=_soft_limit or None,
    task_time_limit=_hard_limit or None,
    worker_max_tasks_per_child=settings.celery_worker_max_tasks_per_child or None,
    # SCAN EXEMPTION. The limits above are right for every other task (email, retention,
    # relay -- all bounded work), but applying them to `scans.run_scan` killed any scan
    # past 1h and marked it 'failed' purely for elapsed time, even while it was healthy and
    # producing results. A scan's legitimate duration depends on the target, not the clock.
    #
    # `task_annotations` overrides the global limits for this ONE task name; None means
    # "no limit" in Celery, and per-task annotations take precedence over the global conf.
    # Every other resource protection stays exactly as it was: prefetch=1, the per-child
    # recycle below, the runners' own per-tool/per-target and per-request timeouts, and the
    # scanner's concurrency semaphores. What replaces the wall-clock kill is liveness-based
    # reaping (scans.last_heartbeat_at + scan_stale_heartbeat_seconds), which recovers a
    # genuinely dead executor FASTER than the old limits did while never touching a healthy
    # long-running one.
    task_annotations={
        "scans.run_scan": {
            "soft_time_limit": settings.celery_scan_task_soft_time_limit_seconds or None,
            "time_limit": settings.celery_scan_task_time_limit_seconds or None,
        }
    },
)

# Continuous security: a beat tick every 60s launches any due recurring scans.
# Runs in the dedicated `beat` service (see docker-compose); the worker executes
# the scans it enqueues.
celery_app.conf.beat_schedule = {
    "enqueue-due-schedules": {
        "task": "schedules.enqueue_due",
        "schedule": 60.0,
    },
    # Phase 1.2: periodically recover scans stuck in 'running' after a worker crash
    # (worker claimed then died; acks_late redelivery would otherwise just skip it).
    "reap-orphaned-scans": {
        "task": "scans.reap_orphans",
        "schedule": float(settings.scan_orphan_reaper_interval_seconds),
    },
    # MBS.SC Phase 8 (P8-F): WORKER-level liveness. The scan reaper above recovers a dead
    # scan; this stops handing NEW work to a worker that has gone silent. Before it existed
    # `last_seen_at` was written by every heartbeat and read by nothing, so a worker silent
    # for 42 minutes still leased successfully. ALWAYS scheduled -- worker liveness matters
    # in every deployment, and the transition it makes ('active' -> 'suspended') is
    # reversible and fail-closed. Default queue, never `scans`.
    "reap-stale-workers": {
        "task": "workers.reap_stale",
        "schedule": float(settings.worker_stale_reaper_interval_seconds),
    },
    # P1.1: beat-liveness heartbeat. A tiny task stamped every tick so a stalled scheduler is
    # alertable (mbs_beat_age_seconds -> MbsBeatStalled). Always scheduled -- beat liveness matters
    # in every deployment. Runs on the default queue, never `scans`; purely additive observability.
    "beat-heartbeat": {
        "task": "reliability.beat_heartbeat",
        "schedule": float(settings.beat_heartbeat_interval_seconds),
    },
    # Risk-acceptance expiry. ALWAYS scheduled (not feature-gated like backup/retention): it
    # only flips a status a human already scheduled, and skipping it would leave every
    # "expiring" acceptance in force forever. Hourly is ample -- expiries are set in days or
    # months, so a sub-hour lag is immaterial while an hourly sweep is negligible load.
    "expire-risk-acceptances": {
        "task": "risk.expire_acceptances",
        "schedule": float(settings.risk_acceptance_expiry_interval_seconds),
    },
}

# Phase 1.6: scheduled backups. Only registered when enabled, so a disabled deployment
# doesn't tick a no-op. Runs on the default queue (never the `scans` queue) so it cannot
# interfere with scan execution.
if settings.backup_enabled:
    celery_app.conf.beat_schedule["scheduled-backup"] = {
        "task": "backup.run",
        "schedule": float(settings.backup_interval_seconds),
    }


# Phase 5.3.3: scheduled retention purge. Mirrors the backup gating -- the beat entry is added
# ONLY when retention_enabled, so a disabled deployment never ticks it. The existing 5.2/5.3.2
# `retention.purge` task ALSO self-gates (retention_enabled + retention_dry_run), so even a
# stray tick can never delete unexpectedly. Runs on the default queue (never `scans`). Extracted
# into a helper purely so the enabled/disabled branch is unit-testable without reloading here.
def register_retention_schedule(app, cfg) -> None:
    if cfg.retention_enabled:
        app.conf.beat_schedule["retention-purge"] = {
            "task": "retention.purge",
            "schedule": float(cfg.retention_interval_seconds),
        }


register_retention_schedule(celery_app, settings)

celery_app.conf.timezone = "UTC"

# The tenancy-installed invariant (see apps/api/core/tenancy.py -- an uninstalled filter
# means every workspace-scoped table is queried unfiltered) needs a live connection, so it
# runs as a WORKER BOOTSTEP rather than at import: bootsteps abort worker startup when they
# raise, they execute only in a real worker process -- so `beat`, which opens no engine, is
# untouched -- and they keep the DB call out of the API's import path, where the lifespan
# already performs the same check.
celery_app.steps["worker"].add(TenancyInstalledSecurityStep)


# Phase 4.1: start the worker's Prometheus metrics endpoint once the worker is up. Registered
# unconditionally (the handler no-ops in the API process -- the signal only fires in a worker)
# and is fully best-effort, so it can never block worker startup.
from celery.signals import worker_ready, worker_shutting_down  # noqa: E402


@worker_ready.connect
def _start_worker_metrics(**_kwargs) -> None:
    from apps.api.celery_app.metrics import start_worker_metrics_server

    start_worker_metrics_server()


# A missing scanner binary is only visible today as a per-ToolRun FileNotFoundError
# buried in the tool_runs table -- from a finished report it is indistinguishable
# from "the tool ran and found nothing". Resolve every registered tool's binary on
# PATH once, here, so the worker log states up front exactly which tools this
# process can actually execute. Diagnostics only: log_preflight never raises.
@worker_ready.connect
def _log_scanner_preflight(**_kwargs) -> None:
    from apps.api.scanner_engine.tool_preflight import log_preflight

    log_preflight()


# P1-1: on a deliberate (warm) shutdown, return a still-executing scan to the queue so the
# redelivery that acks_late ALREADY performs is actually claimable -- without this the
# redelivered task hits `_claim_scan` on a 'running' row, skips, and ACKs away the only
# message that could restart the scan (leaving it stranded until the orphan reaper fails it).
# The handler writes nothing up front; see apps/api/celery_app/shutdown.py for why it waits
# out the drain first. Best-effort: it must never block or fail the worker's exit.
@worker_shutting_down.connect
def _requeue_inflight_scans(**_kwargs) -> None:
    try:
        from apps.api.celery_app.shutdown import on_worker_shutting_down

        on_worker_shutting_down()
    except Exception:  # noqa: BLE001 -- shutdown hygiene must never prevent shutdown
        import logging

        logging.getLogger("mbs.shutdown").warning("shutdown.hook_failed", exc_info=True)
