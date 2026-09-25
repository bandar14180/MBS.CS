"""Revoke a scanner worker -- MBS.SC PHASE 8 (P8-E).

    python -m apps.api.ops.revoke_worker --worker-id <id> --reason "<why>"

WHY THIS EXISTS
---------------
`scanner_workers.service.revoke_worker()` has always been complete and correct -- it sets the
terminal status, stamps the reason, destroys BOTH stored credentials, emits the metric and
logs the event. What it never had was a caller: before this module, `grep` found it only in
test files. The documented emergency procedure was a Python snippet that could not actually
be run as written, because it referenced a `db` session it never constructed:

    await workers.revoke_worker(db, "worker-site-acme-dc1", reason="suspected compromise")
    await db.commit()

So an operator responding to a suspected compromise had to shell into a container, hand-build
an engine and sessionmaker, enter the tenancy bypass, call the function, and remember to
commit -- under time pressure. A control that exists but cannot be reached in an incident is
an operational gap, and that gap is what this closes.

WHY A CLI AND NOT AN ENDPOINT
-----------------------------
An HTTP endpoint would need an authorization model the platform does not have.
`require_permission` is WORKSPACE-scoped, and a shared public worker has `workspace_id =
NULL` -- so existing RBAC cannot express "may revoke this worker" for precisely the workers
most likely to need revoking. Adding a platform-admin role is a materially larger change than
the gap warrants, and a revocation endpoint is also a denial-of-service lever: whoever can
call it can halt scanning.

This CLI keeps the authority bar exactly where it already is -- "can exec into a control-plane
container" -- while making the procedure one correct command instead of a hand-assembled
session.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
  * It does not reimplement revocation. Every invariant (terminal status, reason, credential
    destruction, metric, audit log) comes from `revoke_worker()`, which is unchanged. A bare
    `UPDATE scanner_workers SET status='revoked'` would "work" in the sense that the gate
    checks `status` -- and would leave a live `token_hash` in the row. This never does that.
  * It does not tear down WireGuard. Revocation is control-plane side: it stops the worker
    leasing work and submitting results, but a compromised HOST keeps its tunnel until the
    container is stopped. That containment step is the runbook's, not this tool's, and
    pretending otherwise here would give a false sense of completion.
  * It offers no un-revoke. Revocation is terminal by design; recovery is registering a
    replacement worker with fresh credentials.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

logger = logging.getLogger(__name__)


async def _revoke(worker_id: str, reason: str, actor: str | None = None) -> int:
    """Revoke one worker. Returns a process exit code; never raises to the caller.

    The session is built here rather than injected: this tool must run with nothing else
    alive -- no API process, no worker, no Celery -- because an incident is exactly when
    those may be the things you are cutting off. Same short-lived-engine pattern the beat
    tasks and provisioning scripts use.
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
                    worker = await workers_service.revoke_worker(
                        db, worker_id, reason=reason
                    )
                except workers_service.WorkerNotAuthorized as exc:
                    # Raised for an unknown worker id. Nothing was written.
                    print(f"ERROR: {exc.message}", file=sys.stderr)
                    return 2

                # P8-G: durable audit, written BEFORE the commit so the record and the
                # revocation land in ONE transaction -- an audited revocation that rolled
                # back, or a revocation with no record, would both be worse than either
                # alone. Best-effort by construction: `record_worker_revoked` swallows and
                # logs its own failure, so a broken audit path can never leave a compromised
                # worker active. `audited` only drives the message printed below.
                #
                # workspace_id comes from the worker's OWN row: NULL for a shared public
                # worker, which is a platform-scoped event (see modules/audit/scanner_ops).
                try:
                    audited = await scanner_ops.record_worker_revoked(
                        db,
                        worker_id=worker.worker_id,
                        reason=reason,
                        actor=actor,
                        workspace_id=worker.workspace_id,
                        site_id=worker.site_id,
                    )
                except Exception:  # noqa: BLE001 -- see above: auditing is best-effort
                    # `record_worker_revoked` already swallows its own failures, so reaching
                    # here means the audit path itself is broken in a way it did not expect.
                    # The revocation must still stand: cutting off a compromised worker is
                    # the operation, and the record is the evidence of it -- losing the
                    # evidence is bad, failing to cut it off is worse.
                    logger.warning(
                        "revoke_worker.audit_failed worker=%s -- revocation still applied",
                        worker.worker_id, exc_info=True,
                    )
                    audited = False

                # COMMIT BEFORE REPORTING SUCCESS. `revoke_worker` only flushes; without
                # this the whole revocation would roll back when the session closed and the
                # operator would be told a compromised worker was cut off when it was not.
                await db.commit()

            print(f"REVOKED worker_id={worker.worker_id}")
            print(f"  status            = {worker.status}")
            print(f"  revoked_at        = {worker.revoked_at}")
            print(f"  revoked_reason    = {worker.revoked_reason}")
            # Reported as a statement about the row, not the secret -- there is nothing left
            # to print, which is the point.
            print(f"  token_hash        = {'CLEARED' if worker.token_hash is None else '*** STILL SET ***'}")
            print(f"  cert_fingerprint  = {'CLEARED' if worker.cert_fingerprint is None else '*** STILL SET ***'}")
            print(f"  actor             = {scanner_ops.normalise_actor(actor)} (operator-supplied, NOT authenticated)")
            print(f"  audit record      = {'written' if audited else 'FAILED -- see logs (revocation still applied)'}")
            print()
            print("This is TERMINAL. The worker is refused at authentication and at every")
            print("authorization gate from its next manager call onward, and it will never be")
            print("reactivated -- register a REPLACEMENT worker with fresh credentials.")
            print()
            print("WireGuard is NOT torn down by revocation. If the host is compromised, stop")
            print("its container to remove its network reach (runbook 4.4).")
            return 0
    finally:
        await engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m apps.api.ops.revoke_worker",
        description=(
            "Terminally revoke a scanner worker. Clears its stored credentials and refuses "
            "it at every gate from its next manager call. Cannot be undone."
        ),
    )
    # BOTH are required, deliberately. A reason that could be omitted or silently defaulted
    # would make the audit trail useless exactly where it matters most: `revoked_reason` is
    # the only record of WHY a worker was cut off.
    parser.add_argument("--worker-id", required=True, help="the scanner_workers.worker_id to revoke")
    parser.add_argument(
        "--reason", required=True,
        help="why it is being revoked; persisted to revoked_reason and logged",
    )
    # OPTIONAL, and optional on purpose. A CLI has no authenticated principal, so this is
    # OPERATOR-SUPPLIED ATTRIBUTION, never a verified identity -- it is recorded as a claim
    # and never written to `actor_user_id`. Omitting it records an explicit `unattributed`
    # rather than an invented name; requiring it would only encourage a junk value.
    parser.add_argument(
        "--actor", default=None,
        help=("who is performing this revocation (e.g. an on-call handle). "
              "OPERATOR-SUPPLIED ATTRIBUTION, NOT authenticated identity. "
              "Omitted -> recorded as 'unattributed'."),
    )
    args = parser.parse_args(argv)

    worker_id = (args.worker_id or "").strip()
    reason = (args.reason or "").strip()
    # An all-whitespace reason satisfies argparse but records nothing, so it is refused here.
    if not worker_id:
        parser.error("--worker-id must not be empty")
    if not reason:
        parser.error("--reason must not be empty")

    return asyncio.run(_revoke(worker_id, reason, args.actor))


if __name__ == "__main__":
    raise SystemExit(main())
