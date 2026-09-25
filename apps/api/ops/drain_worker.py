"""Drain a scanner worker -- MBS.SC PHASE 8 (queue draining).

    python -m apps.api.ops.drain_worker --worker-id <id> --reason "<why>"

WHY THIS EXISTS
---------------
`draining` has been in `WORKER_STATUSES` since Phase 3, documented as "finish in-flight
work, lease nothing new", and `LEASE_ELIGIBLE_STATUSES` has always excluded it. What it
never had was anything that could SET it: an audit of every `.py`, `.md`, `.yml`, `.sql`
and `.sh` in the repository found zero assignments of the value. The state was enforced
and unreachable -- the same shape of gap `ops/revoke_worker.py` closed for revocation.

The documented alternative (`docker compose stop worker-site-<slug>`, runbook 4.4) is a
real drain and is UNCHANGED by this tool. But it is process-level: it needs access to the
worker's host, and it stops the container rather than letting the control plane record
that a worker is being retired. This is the declarative half -- drain from the control
plane, with an audit record, without touching the host.

WHY DRAINING IS NOT REVOCATION
------------------------------
Revocation is an emergency and is terminal: it destroys both stored credentials and cuts
the worker off at AUTHENTICATION, so it cannot even report the scan it was running. That
is correct for a suspected compromise -- you do not let a compromised worker finish.

Draining is planned maintenance. The worker keeps its credential, stays authenticated, and
its in-flight scan runs to completion and reports normally through /v1/tool-results,
/v1/evidence, /v1/heartbeat and /v1/lease/complete. It is refused at /v1/lease and nowhere
else. That asymmetry is implemented as two separate authorities in
`scanner_workers.service`: `assert_worker_active` (may it act at all) and
`assert_worker_may_lease` (may it take NEW work).

WHY A CLI AND NOT AN ENDPOINT
-----------------------------
The same reasoning `ops/revoke_worker.py` documents, and it applies unchanged here.
`require_permission` is WORKSPACE-scoped, and a shared public worker has
`workspace_id = NULL` -- so existing RBAC cannot express "may drain this worker" for
precisely the workers most likely to need draining. A drain endpoint is also a
denial-of-service lever: whoever can call it can stop scanning capacity. This keeps the
authority bar exactly where it already is: "can exec into a control-plane container".

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
  * It does not stop, kill or signal anything. Draining is COOPERATIVE: the worker's
    current tool is left strictly alone, and the running scan finishes on its own. This
    tool changes one column; it is not a process control.
  * It does not requeue or move queued scans. A drained worker simply stops being offered
    them; the existing lease architecture continues to govern the queue.
  * It does not tear down WireGuard, and it does not touch credentials. A drained worker is
    still a trusted worker -- that is what lets it finish. If the worker is COMPROMISED,
    this is the wrong tool: use `ops/revoke_worker.py`.
  * It offers no un-drain. Returning a worker to `active` is a re-approval decision, and
    the reaper's one-directional rule ("there is no path that sets active") is deliberate.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

logger = logging.getLogger(__name__)


async def _drain(worker_id: str, reason: str, actor: str | None = None) -> int:
    """Drain one worker. Returns a process exit code; never raises to the caller.

    Builds its own session for the same reason the revoke tool does: an operator running
    this may have nothing else conveniently alive, and a maintenance action should not
    depend on the API process being up.
    """
    # Imported inside the function so `--help` works without a database or app config.
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from apps.api.core import models_all  # noqa: F401  -- resolve every mapper before querying
    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.core.db import make_worker_engine
    from apps.api.modules.audit import scanner_ops
    from apps.api.modules.scanner_workers import service as workers_service

    engine = make_worker_engine(get_settings().database_url)
    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_maker() as db:
            # admin_bypass: `scanner_workers` is infrastructure, not tenant-scoped data, and
            # a shared public worker has no workspace to scope to at all. The operator is
            # acting platform-wide by construction.
            with tenancy.admin_bypass():
                try:
                    worker = await workers_service.drain_worker(db, worker_id, reason=reason)
                except workers_service.WorkerNotAuthorized as exc:
                    # Unknown worker id. Nothing was written.
                    print(f"ERROR: {exc.message}", file=sys.stderr)
                    return 2
                except workers_service.WorkerNotDrainable as exc:
                    # Wrong state -- already draining, suspended, pending, or revoked by a
                    # concurrent operator. Nothing was written, and in particular a revoked
                    # worker was NOT resurrected into a drained one.
                    print(f"ERROR: {exc.message}", file=sys.stderr)
                    return 3

                # Audit written BEFORE the commit so the record and the transition land in
                # ONE transaction. Best-effort by construction (`record_worker_drained`
                # swallows and logs its own failure): a broken audit path must not leave an
                # operator unable to retire a worker.
                try:
                    audited = await scanner_ops.record_worker_drained(
                        db,
                        worker_id=worker.worker_id,
                        reason=reason,
                        actor=actor,
                        workspace_id=worker.workspace_id,
                        site_id=worker.site_id,
                    )
                except Exception:  # noqa: BLE001 -- see above: auditing is best-effort
                    logger.warning(
                        "drain_worker.audit_failed worker=%s -- drain still applied",
                        worker.worker_id, exc_info=True,
                    )
                    audited = False

                # COMMIT BEFORE REPORTING SUCCESS, for the same reason the revoke tool
                # does: otherwise the transition rolls back when the session closes and the
                # operator is told a worker is draining when it is still taking work.
                await db.commit()

            print(f"DRAINING worker_id={worker.worker_id}")
            print(f"  status            = {worker.status}")
            print(f"  pool_id           = {worker.pool_id}")
            if worker.site_id:
                print(f"  site_id           = {worker.site_id} (private worker)")
            else:
                print("  site_id           = - (shared public worker)")
            print("  credentials       = UNCHANGED (a draining worker must still report)")
            print(f"  actor             = {scanner_ops.normalise_actor(actor)} (operator-supplied, NOT authenticated)")
            print(f"  audit record      = {'written' if audited else 'FAILED -- see logs (drain still applied)'}")
            print()
            print("The worker will be refused at /v1/lease from its next poll onward, and is")
            print("still accepted everywhere else so the scan it currently holds can finish and")
            print("report normally. Its running tool was NOT stopped.")
            print()
            print("This state PERSISTS across a restart. There is no un-drain: returning the")
            print("worker to service is a re-approval decision, made deliberately.")
            print()
            print("If this worker is COMPROMISED, draining is the wrong tool -- it stays")
            print("authenticated. Use: python -m apps.api.ops.revoke_worker")
            return 0
    finally:
        await engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m apps.api.ops.drain_worker",
        description=(
            "Gracefully decommission a scanner worker: active -> draining. It takes no new "
            "leases and finishes the scan it already holds. Not an emergency control -- for "
            "a suspected compromise use revoke_worker instead."
        ),
    )
    # BOTH required, for the same reason revocation requires them: a drain with no recorded
    # reason leaves an unexplained non-leasing worker for whoever investigates next.
    parser.add_argument("--worker-id", required=True, help="the scanner_workers.worker_id to drain")
    parser.add_argument(
        "--reason", required=True,
        help="why it is being drained; recorded in the audit event and logged",
    )
    # OPTIONAL and optional on purpose -- see revoke_worker: a CLI has no authenticated
    # principal, so this is a recorded CLAIM, never a verified identity.
    parser.add_argument(
        "--actor", default=None,
        help=("who is performing this drain (e.g. an on-call handle). "
              "OPERATOR-SUPPLIED ATTRIBUTION, NOT authenticated identity. "
              "Omitted -> recorded as 'unattributed'."),
    )
    args = parser.parse_args(argv)

    worker_id = (args.worker_id or "").strip()
    reason = (args.reason or "").strip()
    # All-whitespace satisfies argparse but records nothing, so it is refused here.
    if not worker_id:
        parser.error("--worker-id must not be empty")
    if not reason:
        parser.error("--reason must not be empty")

    return asyncio.run(_drain(worker_id, reason, args.actor))


if __name__ == "__main__":
    raise SystemExit(main())
