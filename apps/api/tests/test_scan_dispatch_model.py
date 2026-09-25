"""Scan DISPATCH MODEL -- one mechanism per scan, and it must have a consumer.

THE INCIDENT THESE PIN
----------------------
`create_scan` enqueued every scan to Celery (`scans.public`, or a per-site private queue)
unconditionally. Under the deployed MBS.SC lease architecture NOTHING consumes those queues:
the scan worker is deliberately off `mbs-core`, cannot reach Redis, and runs
`scanner_worker.main` (an HTTP lease loop) rather than `celery worker`.

Two distinct failures followed, and the second is the one that made scans unrecoverable:

  1. every scan produced a message no process would ever read -- measured live as 110
     undelivered messages sitting in `scans.public`;
  2. `celery_task_id` was set from that enqueue's result, and `_relay_queued()` rescues only
     scans with `celery_task_id IS NULL`. A SUCCESSFUL-but-unconsumable enqueue therefore
     disqualified the scan from the very safety net meant to catch an undispatched scan.

Scan 35706539-… (created 2026-09-17 11:32:30, target www.lincoln.edu.my) sat `queued` with
0 tool runs and was structurally unrecoverable: not leased (no eligible worker), not relayed
(non-NULL task id), and not consumed (no consumer).

WHAT THESE TESTS GUARD
----------------------
  * the lease model leaves `celery_task_id` NULL, so a never-leased scan stays relay-visible;
  * the Celery model is still available and still works, for a deployment that runs a
    control-plane executor;
  * the relay never enqueues onto a queue its own dispatch model does not own;
  * the compose topology and the dispatch default agree -- the assertion that would have
    caught this at build time.
"""
import asyncio
import uuid
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE = REPO_ROOT / "infra" / "docker-compose.yml"


# --- Test 7: queue topology --------------------------------------------------------------

def _services() -> dict:
    if not COMPOSE.is_file():
        pytest.skip("infra/ not bind-mounted in this environment")
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]


def _celery_worker_queues(services: dict) -> set[str]:
    """Every queue consumed by a `celery worker -Q ...` service in the compose topology."""
    queues: set[str] = set()
    for svc in services.values():
        command = svc.get("command")
        if not command:
            continue
        parts = command if isinstance(command, list) else command.split()
        if "worker" in parts and "-Q" in parts:
            queues |= set(parts[parts.index("-Q") + 1].split(","))
    return queues


def test_no_celery_service_consumes_the_scan_queues():
    """THE TOPOLOGY FACT the dispatch default has to match.

    This is not a complaint about the topology -- it is correct for the lease model. It is
    pinned so that the default asserted in the next test cannot drift away from it silently.
    """
    queues = _celery_worker_queues(_services())
    assert "scans.public" not in queues, (
        "a Celery worker now consumes scans.public -- if that is intentional, "
        "celery_scan_dispatch_enabled must be flipped to match"
    )
    assert not any(q.startswith("scans.private.") for q in queues)


def test_celery_scan_dispatch_is_off_because_nothing_consumes_those_queues():
    """PRODUCER AND CONSUMER MUST AGREE. This is the invariant whose absence caused the
    incident: a producer targeting a queue with no consumer.

    If someone adds a scan-queue consumer, this test fails and tells them to enable the
    setting. If someone enables the setting without adding a consumer, it fails too. Either
    way the two halves cannot silently diverge again.
    """
    from apps.api.core.config import get_settings

    consumed = _celery_worker_queues(_services())
    has_scan_consumer = "scans.public" in consumed or any(
        q.startswith("scans.private.") for q in consumed
    )
    assert get_settings().celery_scan_dispatch_enabled == has_scan_consumer, (
        "celery_scan_dispatch_enabled must be True if and only if a Celery worker actually "
        f"consumes a scan queue (consumers found: {sorted(consumed)})"
    )


# --- Test 8: relay recovery --------------------------------------------------------------

def test_the_relay_declines_to_act_when_celery_does_not_dispatch(monkeypatch):
    """Under the lease model EVERY queued scan has `celery_task_id IS NULL`, so the relay's
    predicate matches all of them. Relaying them would enqueue onto `scans.public`, which
    nothing consumes -- recreating the exact undelivered backlog this split removes, and
    stamping a task id that would disqualify them from any FUTURE relay.

    So the relay must decline. Returning 0 here is the relay correctly refusing to act on a
    queue it does not own, not the relay being broken.
    """
    from apps.api.celery_app.tasks import scan_tasks
    from apps.api.core.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "celery_scan_dispatch_enabled", False, raising=False)
    monkeypatch.setattr(settings, "scan_queued_relay_enabled", True, raising=False)

    dispatched: list = []

    def _boom(*a, **kw):
        dispatched.append(a)
        raise AssertionError("the relay must not enqueue under the lease model")

    monkeypatch.setattr(scan_tasks.run_scan_task, "apply_async", _boom)

    assert asyncio.run(scan_tasks._relay_queued()) == 0
    assert dispatched == []


def test_a_lease_dispatched_scan_keeps_a_null_task_id_so_it_stays_relay_visible():
    """THE FIELD THAT STRANDED THE SCAN. A lease-dispatched scan must leave
    `celery_task_id` NULL.

    That is not merely tidy: `celery_task_id IS NULL` is what `_relay_queued()` reads as
    "never dispatched". A scan carrying a task id from an enqueue nothing consumed looked
    dispatched to every recovery mechanism while no execution existed anywhere.
    """
    import inspect

    from apps.api.modules.scans import service as scans_service

    src = inspect.getsource(scans_service.create_scan)
    # The assignment must be reachable ONLY under the Celery branch.
    assert "celery_scan_dispatch_enabled" in src, (
        "create_scan must choose a dispatch model rather than always enqueueing"
    )
    before, _, after = src.partition("celery_scan_dispatch_enabled")
    assert "scan.celery_task_id = async_result.id" not in before, (
        "celery_task_id must not be set before/regardless of the dispatch-model check"
    )
    assert "scan.celery_task_id = async_result.id" in after


def test_the_celery_dispatch_path_is_still_intact_when_enabled():
    """The Celery model is DISABLED, not deleted. A deployment running a control-plane
    executor must still be able to use it, so the task and its routing stay live."""
    from apps.api.celery_app.tasks.scan_tasks import run_scan_task
    from apps.api.scanner_engine.scan_routing import queue_for_scan

    assert run_scan_task.name == "scans.run_scan"
    assert queue_for_scan(network_zone="public", site_id=None) == "scans.public"
    sid = uuid.uuid4()
    assert queue_for_scan(network_zone="private", site_id=sid) == f"scans.private.{sid}"
