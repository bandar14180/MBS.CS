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
    matching DLQ entry was found and re-enqueued."""
    entries = [e for e in inspect() if e.get("scan_id") == scan_id]
    if not entries:
        return False
    from apps.api.celery_app.tasks.scan_tasks import run_scan_task

    run_scan_task.delay(scan_id)
    remove(scan_id)
    return True


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
