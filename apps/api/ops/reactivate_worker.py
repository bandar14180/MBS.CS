"""Reactivate a suspended scanner worker -- MBS.SC PHASE 8 (P8-F recovery).

    python -m apps.api.ops.reactivate_worker --worker-id <id> --reason "<why>"

WHY THIS EXISTS
---------------
`reap_stale_workers` moves a silent worker `active` -> `suspended` and deliberately never
moves it back. Its docstring says the state is "REVERSIBLE (an operator reactivates)" --
but nothing that could perform that reactivation was ever written. An audit of the
repository found ZERO code paths assigning `status = 'active'`: the state was documented as
reversible and was, in practice, terminal.

That gap is what turned a routine outage into an unrecoverable one. Because a suspended
worker is refused at AUTHENTICATION, it cannot call `/v1/heartbeat`, so `last_seen_at` can
never be refreshed, so it remains stale and remains suspended -- a self-sealing deadlock:

    suspended -> 403 at auth -> cannot heartbeat -> last_seen_at frozen
              -> still stale -> still suspended  (forever)

Verified live: a host restart on 2026-09-13 suspended the entire fleet (both workers) in two
sweeps at 04:35:06 and 04:59:22. Four days later both were still `suspended`, the public
worker container was crash-looping against a 403 `WORKER_SUSPENDED`, zero scans had been
dispatched, and a scan created 2026-09-17 11:32:30 was still `queued` with 0 tool runs.

This is the smallest safe mechanism that ends that deadlock: ONE state transition,
`suspended` -> `active`, performed deliberately by an operator.

WHY THIS DOES NOT WEAKEN P8-F
-----------------------------
The reaper's one-directional rule is about what the SYSTEM may do to itself, and it is
untouched here:

  * The reaper still only ever writes `active` -> `suspended`. Stale detection is unchanged.
  * NOTHING automatic reactivates anything. A resumed heartbeat still grants no authority --
    it cannot, because authentication refuses a suspended worker before the handler runs.
  * There is no self-service path. A worker cannot reactivate itself; it has no way to reach
    this code, which runs in a control-plane container and not over any worker-facing API.

What changes is only that a HUMAN can now do deliberately what the system must never do
silently. "Fail-closed" means the system does not readmit a worker on its own; it does not
mean a worker can never be readmitted. Without this the only recovery was a manual UPDATE
against production -- unaudited, unreviewed, and far more dangerous than this tool.

STALE DETECTION vs WORKER RECOVERY -- deliberately separate:

    detection (automatic, system)  reap_stale_workers()   active    -> suspended
    recovery  (deliberate, human)  this tool              suspended -> active

WHY A CLI AND NOT AN ENDPOINT
-----------------------------
The same reasoning `ops/revoke_worker.py` and `ops/drain_worker.py` document, and it applies
here with one addition. `require_permission` is WORKSPACE-scoped and a shared public worker
has `workspace_id = NULL`, so existing RBAC cannot express "may reactivate this worker" for
exactly the workers most likely to need it. And where a drain endpoint would be a
denial-of-service lever, a REACTIVATION endpoint is the more dangerous shape: it GRANTS
authority, so it is the last thing that should be reachable over the network. This keeps the
authority bar where it already is: "can exec into a control-plane container".

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
  * It does not reactivate a REVOKED worker. Revocation is terminal and is excluded twice
    over in the SQL guard. Register a replacement worker instead.
  * It does not approve a PENDING worker. That is an approval decision, not a recovery one,
    and routing it through here would bypass approval entirely.
  * It does not un-drain. `drain_worker` explicitly offers no un-drain; reactivation must
    not become one by the back door.
  * It does not write `last_seen_at`. The worker proves its own liveness by heartbeating
    once it can authenticate again -- backdating that here would fabricate an observation
    no worker ever made, and would re-arm the same staleness from the wrong side.
  * It does not start, restart or signal anything. If the worker process is genuinely dead
    it will simply be re-suspended at the next sweep, which is correct: this readmits a
    worker to the fleet, it does not vouch for it.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

logger = logging.getLogger(__name__)


def _observed_status(exc) -> str | None:
    """The status the row was ACTUALLY in, from the refusal message.

    `reactivate_worker` re-reads the row before refusing and formats
    `Worker '<id>' is '<status>', not 'suspended'`, so the state is already in the message --
    this lifts it for the audit row rather than issuing a second query, which could observe
    a DIFFERENT state than the one that caused the refusal and record a misleading value.

    Returns None when the shape does not match, which the audit layer records as `unknown`.
    Never raises: a provenance helper must not turn a refusal into a crash.
    """
    try:
        import re

        m = re.search(r"is '([a-z_]+)'", getattr(exc, "message", "") or "")
        return m.group(1) if m else None
    except Exception:  # noqa: BLE001 -- best-effort provenance only
        return None


async def _audit_failure(
    db, scanner_ops, *, worker_id: str, reason: str, actor: str | None,
    failure: str, observed_status: str | None,
) -> None:
    """Record a refused reactivation, then COMMIT it. Never raises.

    ITS OWN COMMIT, unlike the success path. A successful reactivation shares one transaction
    with the UPDATE it describes; a refusal has no such write to ride along with, and the
    session is about to be discarded, so the row must be committed here or it is lost.

    BEST EFFORT, like every other write in `scanner_ops`: an audit failure must never change
    the exit code the operator sees or mask the real refusal reason. A refused operation that
    also failed to audit is still a refused operation.
    """
    try:
        await scanner_ops.record_worker_reactivation_failed(
            db, worker_id=worker_id, reason=reason, actor=actor,
            failure=failure, observed_status=observed_status,
        )
        await db.commit()
    except Exception:  # noqa: BLE001 -- auditing must never break the audited operation
        logger.warning(
            "reactivate_worker.failure_audit_failed worker=%s -- refusal still stands",
            worker_id, exc_info=True,
        )


async def _reactivate(worker_id: str, reason: str, actor: str | None = None) -> int:
    """Reactivate one worker. Returns a process exit code; never raises to the caller.

    Builds its own session for the same reason the revoke and drain tools do: an operator
    running this during an incident may have nothing else conveniently alive, and a
    recovery action must not depend on the API process being up.
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
                    worker = await workers_service.reactivate_worker(
                        db, worker_id, reason=reason
                    )
                except workers_service.WorkerNotAuthorized as exc:
                    # Unknown worker id. Nothing was written to `scanner_workers`.
                    #
                    # AUDITED ANYWAY. A refused attempt is exactly what an auditor needs to
                    # see -- repeated refusals against unknown ids are what probing looks
                    # like -- and recording only successes cannot distinguish "nobody tried"
                    # from "the guard held". Its own commit, because the failing statement
                    # left nothing else to commit alongside.
                    await _audit_failure(
                        db, scanner_ops, worker_id=worker_id, reason=reason, actor=actor,
                        failure=exc.reason, observed_status=None,
                    )
                    print(f"ERROR: {exc.message}", file=sys.stderr)
                    return 2
                except workers_service.WorkerNotReactivatable as exc:
                    # Wrong state -- active, draining, pending, or revoked by a concurrent
                    # operator. Nothing was written, and in particular a REVOKED worker was
                    # NOT resurrected into an active one. The refusal is recorded with the
                    # status the row was ACTUALLY in, so the trail shows which guard held.
                    await _audit_failure(
                        db, scanner_ops, worker_id=worker_id, reason=reason, actor=actor,
                        failure=exc.reason, observed_status=_observed_status(exc),
                    )
                    print(f"ERROR: {exc.message}", file=sys.stderr)
                    return 3

                # Audit written BEFORE the commit so the record and the transition land in
                # ONE transaction. Best-effort by construction (`record_worker_reactivated`
                # swallows and logs its own failure): a broken audit path must not leave an
                # operator unable to recover the fleet during an incident.
                try:
                    audited = await scanner_ops.record_worker_reactivated(
                        db,
                        worker_id=worker.worker_id,
                        reason=reason,
                        actor=actor,
                        workspace_id=worker.workspace_id,
                        site_id=worker.site_id,
                    )
                except Exception:  # noqa: BLE001 -- see above: auditing is best-effort
                    logger.warning(
                        "reactivate_worker.audit_failed worker=%s -- reactivation still applied",
                        worker.worker_id, exc_info=True,
                    )
                    audited = False

                # COMMIT BEFORE REPORTING SUCCESS, for the same reason the revoke and drain
                # tools do: otherwise the transition rolls back when the session closes and
                # the operator is told a worker is active when it is still refused at auth.
                await db.commit()

            print(f"REACTIVATED worker_id={worker.worker_id}")
            print(f"  status            = {worker.status}")
            print(f"  pool_id           = {worker.pool_id}")
            if worker.site_id:
                print(f"  site_id           = {worker.site_id} (private worker)")
            else:
                print("  site_id           = - (shared public worker)")
            print(f"  last_seen_at      = {worker.last_seen_at} (NOT backdated -- the worker "
                  "proves its own liveness)")
            print("  credentials       = UNCHANGED (reactivation is a state change, not a reissue)")
            print(f"  actor             = {scanner_ops.normalise_actor(actor)} (operator-supplied, NOT authenticated)")
            _os_user, _src_host, _src_pid = scanner_ops._source_identity()
            print(f"  source            = {_os_user}@{_src_host} pid={_src_pid} (observed, recorded in the audit row)")
            print(f"  audit record      = {'written' if audited else 'FAILED -- see logs (reactivation still applied)'}")
            print()
            print("The worker will be accepted at /v1/heartbeat and /v1/lease from its next")
            print("poll onward. Every other control is UNCHANGED: it must still authenticate,")
            print("and pool / site / workspace binding is still enforced per request.")
            print()
            print("If the worker process is genuinely dead it will be re-suspended by the next")
            print("stale sweep. That is correct -- this readmits a worker, it does not vouch")
            print("for one. Confirm it is actually running before reactivating.")
            return 0
    finally:
        await engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m apps.api.ops.reactivate_worker",
        description=(
            "Recover a suspended scanner worker: suspended -> active. The operator half of "
            "P8-F -- the reaper suspends a silent worker and never restores it, so this is "
            "the only path back. Cannot reactivate a revoked worker (terminal), approve a "
            "pending one, or un-drain a draining one."
        ),
    )
    # BOTH required, matching revoke/drain: a reactivation with no recorded reason leaves an
    # unexplained authority GRANT for whoever investigates next -- the one direction where an
    # unexplained change matters most.
    parser.add_argument(
        "--worker-id", required=True, help="the scanner_workers.worker_id to reactivate"
    )
    parser.add_argument(
        "--reason", required=True,
        help="why it is being reactivated; recorded in the audit event and logged",
    )
    # OPTIONAL and optional on purpose -- see revoke_worker: a CLI has no authenticated
    # principal, so this is a recorded CLAIM, never a verified identity.
    parser.add_argument(
        "--actor", default=None,
        help=("who is performing this reactivation (e.g. an on-call handle). "
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

    return asyncio.run(_reactivate(worker_id, reason, args.actor))


if __name__ == "__main__":
    raise SystemExit(main())
