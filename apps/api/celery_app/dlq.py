"""Dead-letter queue operations for scan tasks.

Failed scan tasks that exhaust their retries are recorded on the Redis list
`dlq:scans.run_scan` (see scan_tasks._record_dlq) with a structured entry:
`{task_name, task_id, scan_id, retries, error, ts}`. This module is the operator
tooling to inspect, replay, and remove them.

Replay is IDEMPOTENT-safe: re-enqueuing `scans.run_scan` for a scan that already
reached a terminal-success state is a no-op (the orchestrator skips it), and a
failed scan is simply re-run. Replay does not auto-loop; it re-enqueues once and
removes the entry from the DLQ.

CLI:
    python -m apps.api.celery_app.dlq list
    python -m apps.api.celery_app.dlq replay <scan_id>
    python -m apps.api.celery_app.dlq remove <scan_id>
    python -m apps.api.celery_app.dlq purge
"""
import uuid
import json

from apps.api.celery_app.tasks.scan_tasks import DLQ_KEY
from apps.api.core.config import get_settings


def _redis():
    import redis

    return redis.from_url(get_settings().redis_url)


def inspect() -> list[dict]:
    """Return all DLQ entries (oldest first) as decoded dicts."""
    out: list[dict] = []
    for raw in _redis().lrange(DLQ_KEY, 0, -1):
        try:
            out.append(json.loads(raw))
        except (ValueError, TypeError):
            out.append({"raw": raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)})
    return out


def remove(scan_id: str) -> int:
    """Remove all DLQ entries for a scan_id. Returns how many were removed."""
    client = _redis()
    removed = 0
    for raw in client.lrange(DLQ_KEY, 0, -1):
        try:
            entry = json.loads(raw)
        except (ValueError, TypeError):
            continue
        if entry.get("scan_id") == scan_id:
            removed += client.lrem(DLQ_KEY, 0, raw)
    return removed


def replay(scan_id: str) -> bool:
    """Re-enqueue the scan once, then drop it from the DLQ. Idempotent: a scan that
    already finished successfully is skipped by the orchestrator. Returns True if a
    matching DLQ entry was found and re-enqueued.

    DISPATCH MODEL. Under the LEASE model (`celery_scan_dispatch_enabled` False, the
    deployed default) there is no consumer for the scan queues, so enqueueing here would
    put the replayed scan onto a queue nothing reads -- the operator would be told the
    replay succeeded while nothing ever ran. A scan is instead replayed by making it
    LEASABLE again, which is what `_claim_scan` already understands: it claims from
    `queued` and from reaper-recovered `failed`. This is deliberately NOT done by writing
    the scan row from here -- that would need a DB session in a Redis-only module -- so the
    caller is told plainly what to do rather than being given a false success.
    """
    entries = [e for e in inspect() if e.get("scan_id") == scan_id]
    if not entries:
        return False

    from apps.api.core.config import get_settings

    if not get_settings().celery_scan_dispatch_enabled:
        # Refuse rather than enqueue into a queue with no consumer. The DLQ entry is
        # deliberately LEFT IN PLACE: dropping it would destroy the record of the failure
        # without anything having been replayed.
        raise RuntimeError(
            f"scan {scan_id}: Celery scan dispatch is disabled (lease model), so a replay "
            "cannot be enqueued -- nothing consumes the scan queues. Re-run the scan "
            "through the API instead; the DLQ entry has been left in place."
        )

    from apps.api.celery_app.tasks.scan_tasks import run_scan_task

    # MBS.SC Phase 5: replay MUST re-route, not just re-enqueue. `.delay()` would use the
    # task's default route (`scans.public`), so replaying a failed PRIVATE scan would drop
    # it onto the public queue -- where a public worker with internet egress and no tunnel
    # would pick it up. Re-derive the queue from the scan's own persisted zone/site.
    queue = _queue_for_scan_id(scan_id)
    run_scan_task.apply_async(args=[scan_id], queue=queue)
    remove(scan_id)
    return True


def _queue_for_scan_id(scan_id: str) -> str:
    """The queue this scan must be replayed to, read from the scan row.

    Falls back to the PUBLIC queue only when the scan row genuinely says public (or has
    vanished). A private scan whose site cannot be determined is not replayed to a
    lesser-authority queue -- queue_for_scan raises instead, which surfaces the problem
    rather than silently misrouting an internal engagement.
    """
    import asyncio

    from apps.api.scanner_engine.scan_routing import queue_for_scan

    async def _load() -> tuple[str, str | None]:
        from apps.api.core.db import make_worker_engine
        from apps.api.modules.scans.models import Scan
        from sqlalchemy.ext.asyncio import async_sessionmaker

        engine = make_worker_engine()
        try:
            maker = async_sessionmaker(engine, expire_on_commit=False)
            async with maker() as session:
                scan = await session.get(Scan, uuid.UUID(scan_id))
                if scan is None:
                    return "public", None
                cfg = scan.config or {}
                return (cfg.get("network_zone") or "public"), cfg.get("site_id")
        finally:
            await engine.dispose()

    zone, site_id = asyncio.run(_load())
    return queue_for_scan(network_zone=zone, site_id=site_id)


def purge() -> int:
    client = _redis()
    n = client.llen(DLQ_KEY)
    client.delete(DLQ_KEY)
    return int(n or 0)


def _main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    cmd, *rest = argv
    if cmd == "list":
        for e in inspect():
            print(json.dumps(e))
        return 0
    if cmd == "replay" and rest:
        print("re-enqueued" if replay(rest[0]) else "no DLQ entry for that scan_id")
        return 0
    if cmd == "remove" and rest:
        print(f"removed {remove(rest[0])} entrie(s)")
        return 0
    if cmd == "purge":
        print(f"purged {purge()} entrie(s)")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    import sys

    raise SystemExit(_main(sys.argv[1:]))
