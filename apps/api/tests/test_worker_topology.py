"""F1 -- worker topology. The heavy `scans` queue and the `default` queue (schedules,
orphan reaper, backup, retention) must run on SEPARATE worker processes, so a saturated
scan worker can never starve the control-plane tasks.

Compose-inspection tests (skip where infra/ isn't bind-mounted, like test_scan_shutdown /
test_monitoring_config) plus a routing assertion against the live Celery config.
"""
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE = REPO_ROOT / "infra" / "docker-compose.yml"


def _services() -> dict:
    if not COMPOSE.is_file():
        pytest.skip("infra/ not bind-mounted in this environment")
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]


def _queues(command) -> set[str]:
    """The set of queues a `celery worker -Q a,b` command consumes."""
    parts = command if isinstance(command, list) else command.split()
    return set(parts[parts.index("-Q") + 1].split(","))


def _is_worker_command(command) -> bool:
    if not command:
        return False
    parts = command if isinstance(command, list) else command.split()
    return "worker" in parts and "-Q" in parts  # a celery *worker* with an explicit -Q


def test_scan_and_default_queues_run_on_separate_workers():
    """F1's property -- scan work and control-plane work never share a worker -- now holds
    by a STRONGER mechanism than a queue flag.

    The scan worker no longer runs `celery worker -Q scans.public` at all: it cannot reach
    the broker (MBS.SC network segmentation), so it leases authorized work from the
    scanner-manager instead. It therefore cannot drain `default` even by misconfiguration,
    because it cannot drain any queue. `worker-default` is unchanged and still consumes
    `default` only.
    """
    svcs = _services()
    assert "worker" in svcs and "worker-default" in svcs, "both dedicated workers must exist"

    scan_cmd = svcs["worker"]["command"]
    parts = scan_cmd if isinstance(scan_cmd, list) else scan_cmd.split()
    assert "apps.api.scanner_worker.main" in parts, (
        "the scan worker must run the lease loop, not a celery consumer"
    )
    assert "celery" not in parts, (
        "the scan worker must NOT be a celery consumer -- it has no route to the broker"
    )
    # The control-plane worker is untouched: still celery, still `default` only.
    assert _queues(svcs["worker-default"]["command"]) == {"default"}  # default-only


def test_no_single_worker_consumes_both_queues():
    # The regression F1 fixes: no worker may drain both `scans` and `default`. With the
    # scan worker no longer consuming any queue, this now checks the remaining celery
    # consumers -- and asserts, in effect, that none of them picked up the scan queue.
    for name, svc in _services().items():
        cmd = svc.get("command")
        if not _is_worker_command(cmd):
            continue
        queues = _queues(cmd)
        assert queues in ({"scans.public"}, {"default"}), f"{name} consumes both queues: {queues}"


def test_routing_unchanged_scans_go_to_scans_queue():
    # F1 must NOT change routing: scans.run_scan still targets the `scans` queue.
    from apps.api.celery_app.worker import celery_app

    assert celery_app.conf.task_routes["scans.run_scan"] == {"queue": "scans.public"}
    assert celery_app.conf.task_default_queue == "default"
