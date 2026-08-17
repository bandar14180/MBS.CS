"""P1.1 -- beat-liveness heartbeat task.

A tiny beat-scheduled task whose ONLY job is to stamp a Redis timestamp each tick
(observability.record_beat_tick). The API-side ReliabilityCollector exposes it as
mbs_beat_age_seconds, so a stalled beat scheduler -- or a down worker-default that would run the
task -- is alertable via MbsBeatStalled, even though beat itself emits no explicit failure.

Additive + best-effort: the task does no I/O beyond a single Redis SET (which itself never raises),
changes no existing behavior, and runs on the default queue (never `scans`).
"""
import logging

from apps.api.celery_app.worker import celery_app

logger = logging.getLogger("mbs.reliability")


@celery_app.task(name="reliability.beat_heartbeat")
def beat_heartbeat_task() -> dict:
    """Stamp the beat-liveness timestamp and return a tiny structured result."""
    from apps.api.core.observability import record_beat_tick

    record_beat_tick()
    logger.debug("reliability.beat_heartbeat", extra={"event": "reliability.beat_heartbeat"})
    return {"ok": True}
