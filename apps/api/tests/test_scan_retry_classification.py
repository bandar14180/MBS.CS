"""F2 -- retry classification for scans.run_scan.

Only TRANSIENT infra faults (DB/broker/network) are retried; PERMANENT/deterministic failures
are dead-lettered immediately without retry (retrying would just repeat the failure + side
effects). Tasks run via .apply() (eager) with _run/_record_dlq monkeypatched, so no DB/Redis is
touched; time.sleep is neutralized so backoff never actually waits.
"""
import uuid

from apps.api.celery_app.tasks import scan_tasks
from apps.api.celery_app.tasks.scan_tasks import TRANSIENT_ERRORS, run_scan_task


def test_transient_error_classification():
    from sqlalchemy.exc import InterfaceError, OperationalError

    # transient infra faults -> retryable
    assert issubclass(OperationalError, TRANSIENT_ERRORS)
    assert issubclass(InterfaceError, TRANSIENT_ERRORS)
    assert issubclass(ConnectionError, TRANSIENT_ERRORS)
    assert issubclass(TimeoutError, TRANSIENT_ERRORS)
    from redis.exceptions import ConnectionError as RedisConnectionError

    assert issubclass(RedisConnectionError, TRANSIENT_ERRORS)

    # permanent / deterministic errors -> NOT retryable
    assert not issubclass(ValueError, TRANSIENT_ERRORS)
    assert not issubclass(RuntimeError, TRANSIENT_ERRORS)
    assert not issubclass(KeyError, TRANSIENT_ERRORS)


def _wire(monkeypatch, boom_exc, *, succeed_after: int | None = None):
    """Monkeypatch _run to raise `boom_exc` (optionally succeeding after N calls) and _record_dlq
    to a counter; neutralize backoff sleeps. Returns the shared call counters."""
    calls = {"run": 0, "dlq": 0}

    async def _boom(_scan_id):
        calls["run"] += 1
        if succeed_after is not None and calls["run"] > succeed_after:
            return None
        raise boom_exc

    monkeypatch.setattr(scan_tasks, "_run", _boom)
    monkeypatch.setattr(scan_tasks, "_record_dlq", lambda *a, **k: calls.__setitem__("dlq", calls["dlq"] + 1))

    import time as _time

    monkeypatch.setattr(_time, "sleep", lambda *a, **k: None)  # never actually wait on backoff
    return calls


def test_transient_error_retries_then_dead_letters(monkeypatch):
    from sqlalchemy.exc import OperationalError

    calls = _wire(monkeypatch, OperationalError("SELECT 1", {}, Exception("connection reset")))
    result = run_scan_task.apply(args=[str(uuid.uuid4())], throw=False)

    # initial attempt + max_retries retries, then dead-lettered exactly once on exhaustion
    assert calls["run"] == run_scan_task.max_retries + 1
    assert calls["dlq"] == 1
    assert result.failed()


def test_transient_error_recovers_without_dead_letter(monkeypatch):
    from redis.exceptions import ConnectionError as RedisConnectionError

    calls = _wire(monkeypatch, RedisConnectionError("broker blip"), succeed_after=1)
    result = run_scan_task.apply(args=[str(uuid.uuid4())], throw=False)

    assert calls["run"] == 2          # failed once, retried, then succeeded
    assert calls["dlq"] == 0          # a recovered transient fault is never dead-lettered
    assert result.successful()


def test_permanent_error_does_not_retry_and_dead_letters(monkeypatch):
    calls = _wire(monkeypatch, ValueError("disallowed target -- permanent"))
    result = run_scan_task.apply(args=[str(uuid.uuid4())], throw=False)

    assert calls["run"] == 1          # NO retry for a permanent failure
    assert calls["dlq"] == 1          # dead-lettered immediately
    assert result.failed()


def test_retry_config_preserved():
    # F2 must not change these reliability knobs.
    assert run_scan_task.max_retries == 3
    assert run_scan_task.acks_late is True
    assert TRANSIENT_ERRORS != (Exception,)  # the broad catch-all is gone
