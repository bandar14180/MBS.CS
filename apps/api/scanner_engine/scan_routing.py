"""Scan queue routing + worker/job matching -- MBS.SC Phase 5.

LIVES IN scanner_engine, NOT celery_app, and that placement is load-bearing. Both planes
use this module: the CONTROL plane to decide which queue a scan is dispatched to, and the
EXECUTION plane (scanner_worker.lease_loop) to re-validate a leased job against its own
identity. Keeping it under `celery_app` made the isolated worker import from the Celery
package -- harmless in practice (this module imports neither celery nor redis) but exactly
the coupling the execution plane must not have, and a lint/import-graph test correctly
flagged it. It contains no broker code and never did.

Previously every scan went to a single `scans` queue, so any worker holding the broker
credentials could pop any tenant's job. Queue membership was, in effect, the authorization
model -- and it had exactly one level.

Routing is now:

    public target            ->  scans.public
    private target (site S)  ->  scans.private.<site-id>

The per-site queue matters because of overlapping RFC1918 space: tenant A and tenant B may
both legitimately use 10.0.0.0/8, and a worker that could take either tenant's job would
have to disambiguate two identical address ranges at runtime. Giving each site its own
queue AND its own worker (Phase 10) means the routing question is answered before any
packet is sent.

ROUTING IS NOT AUTHORIZATION. A queue name is a hint, not a permission: anything with
broker access could still consume the wrong queue. `assert_job_matches_worker` below is
the enforcing half -- the worker re-checks every job it receives against its OWN
configured identity and refuses a mismatch, and the manager re-checks again server-side.
Three independent layers, because a queue name is not a security boundary.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

PUBLIC_SCAN_QUEUE = "scans.public"
PRIVATE_QUEUE_PREFIX = "scans.private."


class JobNotForThisWorker(PermissionError):
    """This worker is not authorized for the job it was handed."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


def queue_for_scan(*, network_zone: str | None, site_id=None) -> str:
    """The queue a scan must be dispatched to.

    A private zone with no site cannot be routed anywhere: there is no queue that means
    "some private network", and inventing one would be a queue any private worker might
    consume. Falling back to the public queue would be worse still -- it would send an
    internal engagement to a worker with public internet egress -- so this raises.
    """
    if (network_zone or "public") != "private":
        return PUBLIC_SCAN_QUEUE
    if not site_id:
        raise ValueError(
            "a private scan must name a site to be routed; refusing to fall back to the "
            "public queue"
        )
    return f"{PRIVATE_QUEUE_PREFIX}{site_id}"


def site_id_from_queue(queue: str) -> str | None:
    if queue and queue.startswith(PRIVATE_QUEUE_PREFIX):
        return queue[len(PRIVATE_QUEUE_PREFIX):] or None
    return None


def is_private_queue(queue: str) -> bool:
    return bool(queue) and queue.startswith(PRIVATE_QUEUE_PREFIX)


def assert_job_matches_worker(
    *,
    job_network_zone: str | None,
    job_site_id=None,
    worker_site_id=None,
    worker_pool_id: str | None = None,
    job_pool_id: str | None = None,
) -> None:
    """The WORKER-side check: refuse a job that does not match this worker's identity.

    Runs before the scan starts, on the execution side, using the worker's own configured
    identity (from its environment) rather than anything in the message. It exists because
    a misrouted or maliciously-injected message must not be executed just because it
    arrived -- "it was on my queue" is not authorization.

    Both directions are enforced, for the same reasons as the manager-side equivalent: a
    public worker has no tunnel and must not attempt private work, and a private worker
    holding a customer's tunnel must not be reaching arbitrary internet hosts.
    """
    zone = (job_network_zone or "public")
    job_site = str(job_site_id) if job_site_id else None
    own_site = str(worker_site_id) if worker_site_id else None

    if zone == "private":
        if not job_site:
            raise JobNotForThisWorker(
                "JOB_PRIVATE_WITHOUT_SITE", "private job carries no site id; refusing."
            )
        if not own_site:
            raise JobNotForThisWorker(
                "PUBLIC_WORKER_CANNOT_TAKE_PRIVATE_JOB",
                "this worker is not bound to a private site and cannot run private jobs.",
            )
        if own_site != job_site:
            logger.warning(
                "scan_routing.wrong_site worker_site=%s job_site=%s", own_site, job_site,
                extra={"event": "scan_routing.wrong_site", "reason": "WORKER_WRONG_SITE"},
            )
            raise JobNotForThisWorker(
                "WORKER_WRONG_SITE",
                "this worker is bound to a different private site; refusing the job.",
            )
    else:
        if own_site:
            raise JobNotForThisWorker(
                "PRIVATE_WORKER_CANNOT_TAKE_PUBLIC_JOB",
                "a site-bound worker must not run public jobs.",
            )

    if job_pool_id and worker_pool_id and job_pool_id != worker_pool_id:
        raise JobNotForThisWorker(
            "WORKER_WRONG_POOL",
            f"job targets pool {job_pool_id!r}, this worker is in {worker_pool_id!r}.",
        )
