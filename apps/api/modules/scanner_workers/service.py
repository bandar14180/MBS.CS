"""Scanner worker authentication and authorization -- MBS.SC Phases 3/4/13.

Everything a worker is allowed to do is decided HERE, from the worker's own persisted
row, never from anything the worker sends. That single rule is what makes the manager a
narrow boundary rather than a proxy: a request can say "I am worker-7, give me work", and
the server answers using worker-7's row -- it cannot say "give me work for site X" and be
believed.

The checks compose in a fixed order, each fail-closed:

    authenticate_worker()          who is this, really?  (constant-time credential match)
    assert_worker_active()         is it allowed to act at all?  (revoked/suspended/pending)
    assert_worker_may_lease()      may it take NEW work?  (adds: not draining)
    assert_worker_may_serve_site() is it bound to THIS customer's network?
    assert_worker_may_take_scan()  is this specific scan within that binding?

`assert_worker_active` and `assert_worker_may_lease` are deliberately two questions, not
one. The first gates authentication and therefore every endpoint; the second gates only
`/v1/lease`. That is what lets a `draining` worker finish and report the scan it already
holds while never being handed another.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

# P8-F: MODULE SCOPE, NOT INSIDE THE REAPER. `platform_uptime` starts its monotonic anchor at
# import, so importing it lazily inside `reap_stale_workers()` made each forked Celery child
# start its OWN anchor on its first sweep -- every sweep then reported `uptime=0.0s` and the
# startup grace never expired (observed live: ForkPoolWorker-1 and -8, 300s apart, both 0.0s).
# At module scope the anchor is established when this module is first imported, which for the
# worker is MainProcess boot, before prefork. Keep this import here.
from apps.api.core.platform_uptime import process_uptime_seconds, within_startup_grace
from apps.api.modules.scanner_workers.models import (
    LEASE_ELIGIBLE_STATUSES,
    WORKING_STATUSES,
    ScannerWorker,
)

logger = logging.getLogger(__name__)


class WorkerNotAuthorized(PermissionError):
    """A worker was refused. `reason` is a stable machine-readable code."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        # Same rationale as PrivateSiteNotAuthorized: count at construction so no refusal
        # path can be added without also being observable. Bounded reason code only.
        try:
            from apps.api.core.observability import record_scanner_authz_denied

            record_scanner_authz_denied(reason)
        except Exception:  # noqa: BLE001 -- metrics must never break an authz decision
            pass


REASON_UNKNOWN_WORKER = "WORKER_UNKNOWN"
REASON_BAD_CREDENTIAL = "WORKER_BAD_CREDENTIAL"
REASON_WORKER_REVOKED = "WORKER_REVOKED"
REASON_WORKER_SUSPENDED = "WORKER_SUSPENDED"
REASON_WORKER_NOT_ACTIVE = "WORKER_NOT_ACTIVE"
# Refused a NEW lease only: the worker is mid-decommission and may still finish what it
# already holds. Distinct from WORKER_NOT_ACTIVE so an operator reading a refusal can tell
# "deliberately draining" from "never approved".
REASON_WORKER_DRAINING = "WORKER_DRAINING"
REASON_WORKER_UNAUTHORIZED = "WORKER_UNAUTHORIZED"
REASON_WRONG_POOL = "WORKER_WRONG_POOL"
REASON_WRONG_SITE = "WORKER_WRONG_SITE"
REASON_WRONG_WORKSPACE = "WORKER_WRONG_WORKSPACE"
REASON_PUBLIC_WORKER_PRIVATE_JOB = "PUBLIC_WORKER_CANNOT_TAKE_PRIVATE_JOB"
REASON_PRIVATE_WORKER_PUBLIC_JOB = "PRIVATE_WORKER_CANNOT_TAKE_PUBLIC_JOB"
REASON_EGRESS_MODE_MISMATCH = "WORKER_EGRESS_MODE_MISMATCH"


def hash_worker_token(token: str) -> str:
    """Hash a worker bootstrap token for storage.

    SHA-256 rather than a password KDF on purpose: these are high-entropy machine-generated
    tokens (`secrets.token_urlsafe(32)`), not human passwords, so there is no dictionary to
    slow down -- brute force is infeasible against 256 bits of entropy regardless of KDF.
    What matters is that the DATABASE never holds a replayable credential, which this
    achieves. (A human-chosen secret would need Argon2/bcrypt instead.)
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_worker_token() -> str:
    """A fresh worker bootstrap credential. Returned to the operator ONCE; only its hash
    is persisted, so it cannot be recovered from the database later."""
    return secrets.token_urlsafe(32)


async def authenticate_worker(
    db: AsyncSession,
    *,
    worker_id: str,
    token: str | None = None,
    cert_fingerprint: str | None = None,
) -> ScannerWorker:
    """Resolve a presented credential to exactly one worker row.

    Accepts either a bootstrap token or an mTLS client-certificate fingerprint. BOTH are
    compared with `hmac.compare_digest` against the stored value: a plain `==` on a secret
    leaks its prefix through timing, and a worker credential is a long-lived one.

    The credential must match the row for `worker_id` -- presenting worker A's valid token
    while claiming to be worker B fails, because the row is looked up by the claimed id and
    the secret is then checked against THAT row.
    """
    row = await db.execute(select(ScannerWorker).where(ScannerWorker.worker_id == worker_id))
    worker = row.scalar_one_or_none()
    if worker is None:
        # Same generic message as a bad credential: distinguishing "no such worker" from
        # "wrong secret" would let an unauthenticated caller enumerate valid worker ids.
        logger.warning(
            "scanner_worker.auth_unknown worker=%s", worker_id,
            extra={"event": "scanner_worker.auth_failed", "worker_id": worker_id,
                   "reason": REASON_UNKNOWN_WORKER},
        )
        raise WorkerNotAuthorized(REASON_UNKNOWN_WORKER, "Worker authentication failed.")

    ok = False
    if cert_fingerprint and worker.cert_fingerprint:
        ok = hmac.compare_digest(worker.cert_fingerprint, cert_fingerprint)
        if ok and worker.cert_not_after is not None:
            not_after = worker.cert_not_after
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=timezone.utc)
            if not_after < datetime.now(timezone.utc):
                ok = False  # expired certificate is not a credential
    if not ok and token and worker.token_hash:
        ok = hmac.compare_digest(worker.token_hash, hash_worker_token(token))

    if not ok:
        logger.warning(
            "scanner_worker.auth_failed worker=%s", worker_id,
            extra={"event": "scanner_worker.auth_failed", "worker_id": worker_id,
                   "reason": REASON_BAD_CREDENTIAL},
        )
        raise WorkerNotAuthorized(REASON_BAD_CREDENTIAL, "Worker authentication failed.")
    return worker


def assert_worker_active(worker: ScannerWorker) -> None:
    """Refuse unless the worker may ACT AS A WORKER AT ALL.

    TWO SEPARATE AUTHORITIES, and conflating them is what made `draining` unusable.

    This answers "may this worker speak to the manager?" -- it gates authentication and
    therefore EVERY endpoint, so a status refused here cannot submit a tool result, post
    evidence, heartbeat, or complete a lease it already holds.

    "May this worker be handed NEW work?" is a different question, and it is asked
    separately by `assert_worker_may_lease()` at the lease boundary alone.

    That split is the whole point of `draining`. Its contract is "finish in-flight work,
    take nothing new", which is unreachable if the decommissioning worker is cut off from
    the very endpoints its running scan needs to report through: it would lose every
    result of the scan it was supposed to be allowed to finish. So `draining` passes here
    and is refused only at `/v1/lease`.

    `revoked` and `suspended` are UNCHANGED -- both are still refused here, at
    authentication, and so remain refused everywhere at once. Revocation in particular is
    enforced control-plane side precisely so it does not depend on reaching the scanner
    host: a compromised or unreachable worker is cut off by a row update, and its very next
    manager call fails.
    """
    if worker.revoked_at is not None or worker.status == "revoked":
        raise WorkerNotAuthorized(
            REASON_WORKER_REVOKED,
            f"Worker '{worker.worker_id}' has been revoked; it may not take work.",
        )
    if worker.status == "suspended":
        raise WorkerNotAuthorized(
            REASON_WORKER_SUSPENDED, f"Worker '{worker.worker_id}' is suspended."
        )
    if worker.status not in WORKING_STATUSES:
        # 'pending' (registered but not yet approved) lands here: it has never been
        # cleared to do anything, so it may not act at all.
        raise WorkerNotAuthorized(
            REASON_WORKER_NOT_ACTIVE,
            f"Worker '{worker.worker_id}' is '{worker.status}', not 'active'.",
        )


def assert_worker_may_lease(worker: ScannerWorker) -> None:
    """Refuse unless the worker may be handed NEW work. The lease boundary only.

    Strictly narrower than `assert_worker_active`: every status that cannot act at all is
    also refused here (the call below is not redundant -- it keeps this a superset, so a
    future status can never become leasable by being forgotten in one of the two places),
    and `draining` is additionally refused.

    Kept as an allow-list against `LEASE_ELIGIBLE_STATUSES` rather than a deny-list of
    `draining`: a new status added to the model is then non-leasable until someone
    deliberately says otherwise, which is the fail-closed direction.
    """
    assert_worker_active(worker)
    if worker.status not in LEASE_ELIGIBLE_STATUSES:
        # 'draining' is the case this exists for: it may finish what it holds, and may
        # never be given more.
        raise WorkerNotAuthorized(
            REASON_WORKER_DRAINING if worker.status == "draining" else REASON_WORKER_NOT_ACTIVE,
            f"Worker '{worker.worker_id}' is '{worker.status}' and may not take new work.",
        )


def assert_worker_may_serve_site(worker: ScannerWorker, site_id: uuid.UUID | None) -> None:
    """Enforce the worker<->site binding in BOTH directions.

    * A PUBLIC worker (site_id NULL) must never take a private job. It has no tunnel and
      no per-customer isolation, so letting it try would be an unrouted scan at best and
      a cross-customer leak at worst.
    * A PRIVATE worker must never take a job for a DIFFERENT site -- this is the check
      that keeps tenant A's worker out of tenant B's network -- and must never take a
      public job either, so that a machine holding a customer's tunnel is not also
      reaching arbitrary internet hosts.
    """
    if site_id is None:
        if worker.site_id is not None:
            raise WorkerNotAuthorized(
                REASON_PRIVATE_WORKER_PUBLIC_JOB,
                f"Worker '{worker.worker_id}' is bound to a private site and may not take "
                f"public jobs.",
            )
        return
    if worker.site_id is None:
        raise WorkerNotAuthorized(
            REASON_PUBLIC_WORKER_PRIVATE_JOB,
            f"Worker '{worker.worker_id}' is a public worker and may not take private jobs.",
        )
    if worker.site_id != site_id:
        logger.warning(
            "scanner_worker.wrong_site worker=%s bound_site=%s requested_site=%s",
            worker.worker_id, worker.site_id, site_id,
            extra={"event": "scanner_worker.wrong_site", "worker_id": worker.worker_id,
                   "reason": REASON_WRONG_SITE},
        )
        raise WorkerNotAuthorized(
            REASON_WRONG_SITE,
            f"Worker '{worker.worker_id}' is not authorized for the requested private site.",
        )


def assert_worker_in_pool(worker: ScannerWorker, pool_id: str | None) -> None:
    if pool_id and worker.pool_id != pool_id:
        raise WorkerNotAuthorized(
            REASON_WRONG_POOL,
            f"Worker '{worker.worker_id}' is not a member of pool '{pool_id}'.",
        )


def worker_egress_mode(worker: ScannerWorker, *, settings=None) -> str:
    """This worker's egress mode, derived from its PERSISTED pool membership.

    WHY POOL MEMBERSHIP AND NOT A NEW COLUMN. `pool_id` is already a persisted,
    operator-controlled, non-nullable column that every authorization boundary in this
    module already enforces (`assert_worker_in_pool`), and a worker cannot choose or change
    its own pool -- the manager reads it from the row. It therefore already carries exactly
    the properties an egress-mode field would need, and adding a parallel column would
    create a second source of truth that could disagree with the first.

    The alternative -- trusting a mode the WORKER declares about itself -- was rejected
    outright: a worker's self-description is exactly what must not decide what it may be
    handed. The worker's own `SCANNER_EGRESS_MODE` is a separate, independent check on the
    worker side (see lease_loop.validate_leased_job); the two must agree, and neither is
    authoritative for the other. That is the point: a mismatch fails closed on both ends.
    """
    from apps.api.core.config import get_settings

    s = settings or get_settings()
    vpn_pools = {
        p.strip() for p in (s.vpn_egress_pool_list or []) if p and p.strip()
    }
    return "vpn" if (worker.pool_id or "").strip() in vpn_pools else "direct"


def assert_worker_egress_mode(
    worker: ScannerWorker, required_mode: str | None, *, settings=None
) -> None:
    """Refuse unless this worker's egress mode matches what the scan REQUIRES.

    The failure this prevents: a scan the customer was told would run from the dedicated
    VPN exit IP instead runs from the platform's own address, because it was leased to an
    ordinary direct worker. The scan would succeed and report normally, so nothing
    downstream would ever reveal it.

    Fails closed in both directions. A vpn-required scan is refused to a direct worker
    (the leak), and a direct-required scan is refused to a VPN worker (which would
    misattribute traffic to the shared exit IP and consume its reputation).
    """
    required = (required_mode or "").strip().lower()
    if not required:
        return  # the scan expresses no requirement; any public worker may take it
    actual = worker_egress_mode(worker, settings=settings)
    if required != actual:
        raise WorkerNotAuthorized(
            REASON_EGRESS_MODE_MISMATCH,
            f"Worker '{worker.worker_id}' has egress mode '{actual}' but this scan "
            f"requires '{required}'.",
        )


def assert_worker_may_take_scan(
    worker: ScannerWorker,
    *,
    workspace_id: uuid.UUID,
    site_id: uuid.UUID | None,
    pool_id: str | None = None,
    required_egress_mode: str | None = None,
) -> None:
    """The composite gate applied to every job lease and every result submission.

    Ordering matters: liveness/revocation first (cheapest and most urgent), then the
    tenant binding, then pool membership, then the egress requirement.
    """
    assert_worker_active(worker)
    assert_worker_may_serve_site(worker, site_id)
    assert_worker_egress_mode(worker, required_egress_mode)
    # A tenant-bound worker may only ever act for its own workspace. A shared public
    # worker has workspace_id NULL and is legitimately multi-tenant for PUBLIC targets.
    if worker.workspace_id is not None and worker.workspace_id != workspace_id:
        logger.warning(
            "scanner_worker.wrong_workspace worker=%s bound_ws=%s requested_ws=%s",
            worker.worker_id, worker.workspace_id, workspace_id,
            extra={"event": "scanner_worker.wrong_workspace",
                   "worker_id": worker.worker_id, "reason": REASON_WRONG_WORKSPACE},
        )
        raise WorkerNotAuthorized(
            REASON_WRONG_WORKSPACE,
            f"Worker '{worker.worker_id}' is not authorized for this workspace.",
        )
    assert_worker_in_pool(worker, pool_id)


async def revoke_worker(
    db: AsyncSession, worker_id: str, *, reason: str
) -> ScannerWorker:
    """Emergency control (Phase 13): permanently cut a worker off.

    Terminal by design -- a revoked worker is never reactivated, a replacement is
    registered instead. Enforced entirely control-plane side, so it works even if the
    worker host is compromised, unreachable, or actively hostile.
    """
    row = await db.execute(select(ScannerWorker).where(ScannerWorker.worker_id == worker_id))
    worker = row.scalar_one_or_none()
    if worker is None:
        raise WorkerNotAuthorized(REASON_UNKNOWN_WORKER, f"No such worker '{worker_id}'.")
    worker.status = "revoked"
    worker.revoked_at = datetime.now(timezone.utc)
    worker.revoked_reason = reason
    # Destroy the stored credential material too: revocation should not leave a hash that
    # a future bug could re-accept.
    worker.token_hash = None
    worker.cert_fingerprint = None
    worker.updated_at = datetime.now(timezone.utc)
    await db.flush()
    try:
        from apps.api.core.observability import record_worker_revoked

        record_worker_revoked()
    except Exception:  # noqa: BLE001
        pass
    logger.warning(
        "scanner_worker.revoked worker=%s reason=%s", worker_id, reason,
        extra={"event": "scanner_worker.revoked", "worker_id": worker_id},
    )
    return worker


async def record_heartbeat(
    db: AsyncSession,
    worker: ScannerWorker,
    *,
    health_state: str = "healthy",
    detail: str | None = None,
    handshake_age_s: int | None = None,
) -> None:
    """Liveness + tunnel health, as reported by the worker.

    Self-reported and therefore ADVISORY: a compromised worker can claim to be healthy.
    It is used for operator visibility and staleness alerting, never as the authority for
    "may this scan run" -- that decision comes from a live preflight probe (Phase 12).
    """
    worker.last_seen_at = datetime.now(timezone.utc)
    worker.health_state = health_state
    worker.last_health_detail = detail
    if handshake_age_s is not None:
        worker.last_handshake_age_s = handshake_age_s
    await db.flush()


class WorkerNotDrainable(Exception):
    """A drain was refused because the worker is not in a drainable state.

    Distinct from `WorkerNotAuthorized`, which means "this worker may not do something".
    This means "this OPERATOR request does not apply to this row" -- nothing was written,
    and nothing about the worker's own authority changed.
    """

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


REASON_NOT_DRAINABLE = "WORKER_NOT_DRAINABLE"
REASON_NOT_REACTIVATABLE = "WORKER_NOT_REACTIVATABLE"


class WorkerNotReactivatable(Exception):
    """A reactivation was refused because the worker is not in a reactivatable state.

    Distinct from `WorkerNotAuthorized` for the same reason `WorkerNotDrainable` is: this
    means "this OPERATOR request does not apply to this row" -- nothing was written, and in
    particular nothing about the worker's own authority changed.
    """

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


async def reactivate_worker(
    db: AsyncSession, worker_id: str, *, reason: str
) -> ScannerWorker:
    """Operator recovery (P8-F): `suspended` -> `active`. The ONLY path back.

    THE DEADLOCK THIS ENDS. `reap_stale_workers` moves a silent worker `active` ->
    `suspended` and deliberately never moves it back, documenting that "an operator
    reactivates". No such path existed: an audit of the repository found zero code that
    could ever write `active`, so `suspended` was terminal in practice while being
    documented as reversible. That gap is what made the P8-F incident unrecoverable --
    a suspended worker is refused at AUTHENTICATION, so it can never heartbeat, so
    `last_seen_at` can never be refreshed, so it stays stale and stays suspended. Verified
    live: both workers suspended 2026-09-13, still suspended four days later, 0 scans
    dispatched, a worker container restarting on a loop against a 403.

    WHY THIS IS NOT A WEAKENING OF THE FAIL-CLOSED MODEL. The reaper's one-directional rule
    is about what the SYSTEM may do to itself, and that rule is untouched: nothing
    automatic reactivates anything, a resumed heartbeat still grants nothing (it cannot --
    authentication refuses it first), and there is no self-service path a worker can reach.
    Reactivation is an explicit, out-of-band OPERATOR decision with the same authority bar
    as revoke/drain ("can exec into a control-plane container"), and it is audited. The
    difference between "the system must not readmit a worker silently" and "an operator
    must be able to readmit a worker deliberately" is exactly the difference between
    fail-closed and unrecoverable.

    CONDITIONAL AND ATOMIC, mirroring `drain_worker` / `_claim_scan`: a single
    `UPDATE ... WHERE status = 'suspended' AND revoked_at IS NULL`, so the transition can
    only ever be taken from the one state it is defined for. Three properties follow, and
    each is load-bearing:

      * `revoked` CANNOT be resurrected. Revocation is terminal, and the guard excludes it
        twice over (`status = 'suspended'` cannot match a revoked row, and `revoked_at IS
        NULL` is asserted anyway). Reactivating a revoked worker would weaken a terminal
        state -- the one direction this must never move.
      * `pending` is NOT reachable. A worker registered but never approved has never been
        cleared to do anything; readmitting it here would bypass approval entirely.
      * `draining` is NOT reachable. A drain is a deliberate retirement decision, and
        `ops/drain_worker` explicitly documents that it offers no un-drain. Reactivation
        must not become one by the back door.

    Deliberately does NOT touch credentials, pool, site, workspace, or any health field.
    In particular it does NOT write `last_seen_at`: the worker proves its own liveness by
    heartbeating once it can authenticate again. Backdating liveness here would fabricate
    an observation no worker ever made -- and would re-arm the very staleness the operator
    is trying to clear, only from the wrong side.

    NOTE the worker may be immediately re-suspended if it is genuinely dead: reactivation
    grants it the ABILITY to heartbeat, not a guarantee that it will. That is correct --
    this readmits a worker to the fleet, it does not vouch for it.
    """
    from sqlalchemy import text  # local import, matching drain_worker / reap_stale_workers

    row = await db.execute(select(ScannerWorker).where(ScannerWorker.worker_id == worker_id))
    worker = row.scalar_one_or_none()
    if worker is None:
        raise WorkerNotAuthorized(REASON_UNKNOWN_WORKER, f"No such worker '{worker_id}'.")

    # The atomic transition. `rowcount == 1` iff THIS caller moved the row out of
    # 'suspended'. `last_health_detail` records WHY it was readmitted, replacing the
    # reaper's "stale: no worker heartbeat for 600s" note so the row explains its own
    # current state rather than its previous one.
    result = await db.execute(
        text(
            "UPDATE scanner_workers SET status = 'active', last_health_detail = :detail, "
            "updated_at = now(6) "
            "WHERE worker_id = :wid AND status = 'suspended' AND revoked_at IS NULL"
        ),
        {"wid": worker_id, "detail": f"reactivated by operator: {reason}"[:1000]},
    )
    # `rowcount` via getattr for the same reason drain_worker does it -- see that function.
    # Default 0 == "did not win", so a driver that failed to report cannot be mistaken for
    # a successful transition.
    if (getattr(result, "rowcount", 0) or 0) != 1:
        # Report what the row ACTUALLY says, re-read rather than assumed: the operator needs
        # to know whether they lost a race with a revoke or simply reactivated twice.
        await db.refresh(worker)
        raise WorkerNotReactivatable(
            REASON_NOT_REACTIVATABLE,
            f"Worker '{worker_id}' is '{worker.status}', not 'suspended'; "
            "only a suspended worker can be reactivated.",
        )

    await db.refresh(worker)
    logger.warning(
        "scanner_worker.reactivated worker=%s reason=%s", worker_id, reason,
        extra={"event": "scanner_worker.reactivated", "worker_id": worker_id,
               "pool_id": worker.pool_id, "reason": reason},
    )
    return worker


async def drain_worker(
    db: AsyncSession, worker_id: str, *, reason: str
) -> ScannerWorker:
    """Graceful decommission (Phase 8): `active` -> `draining`. Takes nothing new; finishes
    what it holds.

    NOT REVOCATION, and the difference is the entire point. Revocation is an emergency: it
    is terminal, destroys both stored credentials, and cuts the worker off at
    authentication so it cannot even report the scan it was running. Draining is planned
    maintenance: the credential is untouched, the worker stays authenticated, and its
    in-flight scan runs to completion and reports normally. It is simply never handed
    another job.

    CONDITIONAL AND ATOMIC, mirroring `_claim_scan` / `_finalize_status`: a single
    `UPDATE ... WHERE status = 'active'`, so the transition can only ever be taken from the
    one state it is defined for. That is what makes a concurrent revoke win -- revocation
    sets `revoked`, this statement then matches zero rows, and a drain can never resurrect
    a revoked worker into a leasable-looking state. The same guard refuses `suspended`,
    `pending` and an already-`draining` row.

    Deliberately does NOT touch: credentials, pool, site, workspace, health fields, or any
    running process. It signals a state, it does not stop anything -- the worker's current
    tool is left alone, exactly as cooperative cancellation leaves it alone.
    """
    from sqlalchemy import text  # local import, matching reap_stale_workers below

    row = await db.execute(select(ScannerWorker).where(ScannerWorker.worker_id == worker_id))
    worker = row.scalar_one_or_none()
    if worker is None:
        raise WorkerNotAuthorized(REASON_UNKNOWN_WORKER, f"No such worker '{worker_id}'.")

    # The atomic transition. `rowcount == 1` iff THIS caller moved the row out of 'active'.
    result = await db.execute(
        text(
            "UPDATE scanner_workers SET status = 'draining', updated_at = now(6) "
            "WHERE worker_id = :wid AND status = 'active' AND revoked_at IS NULL"
        ),
        {"wid": worker_id},
    )
    # `rowcount` via getattr for the same reason `reap_stale_workers` does it: SQLAlchemy
    # types the generic `Result` without the attribute, though the CursorResult an UPDATE
    # actually returns carries it, and CLIENT_FOUND_ROWS makes it exact (see core/db.py).
    # The default is 0 -- i.e. "did not win" -- so a driver that failed to report cannot be
    # mistaken for a successful transition.
    if (getattr(result, "rowcount", 0) or 0) != 1:
        # Report what the row ACTUALLY says, re-read rather than assumed: the operator
        # needs to know whether they lost a race with a revoke or simply drained twice.
        await db.refresh(worker)
        raise WorkerNotDrainable(
            REASON_NOT_DRAINABLE,
            f"Worker '{worker_id}' is '{worker.status}', not 'active'; "
            "only an active worker can be drained.",
        )

    await db.refresh(worker)
    logger.warning(
        "scanner_worker.draining worker=%s reason=%s", worker_id, reason,
        extra={"event": "scanner_worker.draining", "worker_id": worker_id,
               "pool_id": worker.pool_id, "reason": reason},
    )
    return worker


# ---------------------------------------------------------------------------------------
# Stale-worker reaper (MBS.SC PHASE 8 -- P8-F)
# ---------------------------------------------------------------------------------------

async def reap_stale_workers(
    db: AsyncSession, stale_after_seconds: int, *, startup_grace_seconds: float = 0.0
) -> int:
    """Suspend workers that have stopped reporting. Returns how many were suspended.

    THE GAP THIS CLOSES. `last_seen_at` and `health_state` were WRITTEN by every heartbeat
    (Phase 8 Tier 1) but never ACTED ON: `assert_worker_active` gates on `revoked_at` and
    `status` only, so silence changed nothing. Verified live before this landed -- a worker
    silent for 2544s was still `status='active'`, still reported `health_state='healthy'`
    (a value last true 42 minutes earlier), and still leased successfully:

        POST /v1/lease -> HTTP 200   (accepted despite 42 minutes of silence)

    The manager was therefore handing jobs to a worker that may be dead, hung or
    network-partitioned. The scan-level orphan reaper eventually recovers such a scan, but
    only AFTER work was dispatched into a void. This makes silence itself actionable.

    FAIL-CLOSED BY CONSTRUCTION. The statement can only ever REMOVE lease eligibility:
      * the only transition is 'active' -> 'suspended'. There is no branch that writes
        'active', so the reaper cannot restore authority to anything;
      * `suspended` is REVERSIBLE (an operator reactivates); the reaper deliberately does
        not, because auto-reactivation on a resumed heartbeat is not a fail-closed act --
        a worker that went silent for an unknown reason should be looked at, not silently
        readmitted;
      * `revoked` is TERMINAL and is excluded twice over (`status = 'active'` cannot match a
         revoked row, and `revoked_at IS NULL` is asserted anyway). "Reaping" a revoked
         worker into `suspended` would WEAKEN a terminal state, which is the one direction
         this must never move;
      * `pending` and `draining` are untouched: neither is lease-eligible already, so
         suspending them would add nothing and would lose the operator's intent.

    `assert_worker_active` is deliberately NOT modified. `suspended` is already refused
    there, so the existing gate does the enforcing and this function only supplies the
    state -- one authorization path, not two.

    WHAT IT MAY TOUCH. `status` and `last_health_detail` (the audit reason) only. Never
    `site_id`, `workspace_id` or `pool_id` -- a reaper that could move a worker between
    tenants would be a tenancy bug, not a liveness feature. Never `health_state` either:
    that field is the worker's own last self-report and is what P8-C projects into
    `mbs_tunnel_up`, so overwriting it here would make the manager's metric export state
    something no worker ever said.

    NULL `last_seen_at` -- a worker registered but never heard from -- falls back to
    `created_at` via COALESCE, so a row that never reported cannot become immortal simply by
    having no heartbeat to be stale. Same discipline as the scan reaper's
    COALESCE(last_heartbeat_at, started_at).

    ONE ATOMIC CONDITIONAL UPDATE, so it is idempotent and safe to run concurrently: a
    second sweep matches nothing because the rows are no longer 'active', and two beats
    racing cannot double-suspend or interleave badly.

    COLD-START PROTECTION (`startup_grace_seconds`). The predicate above is correct but
    measures "time since the last successful worker -> manager round-trip", not "time since
    the worker was last alive". Those diverge by exactly the platform's own downtime,
    because `last_seen_at` is written only by an AUTHENTICATED heartbeat -- so while this
    platform is down, a healthy worker cannot refresh it and accrues apparent silence it had
    no way to prevent. Beat then dispatches this sweep ~163ms after it restarts (its
    persisted `last_run_at` predates the outage, so the task is immediately due), and an
    outage longer than `stale_after_seconds` suspends the entire active fleet before any
    worker can beat -- a state that is self-sealing, because a suspended worker is refused at
    authentication and can therefore never refresh `last_seen_at` again.

    So the sweep is SKIPPED WHOLESALE while this process has been up for less than
    `startup_grace_seconds`: a worker must not be judged silent for time during which the
    platform judging it was itself unavailable. Nothing about the predicate, the statement or
    the transition changes -- the gate only decides WHETHER this sweep runs at all, never
    which rows it may touch, so the fail-closed direction is untouched: a skipped sweep
    grants no authority to anyone and leaves every status exactly as it found it.

    The default is 0.0 -- NO gate -- so this stays a pure addition: every existing caller and
    test behaves exactly as before unless it opts in. The Celery task opts in, because it is
    the one caller whose process lifetime actually tracks the platform's.
    """
    from sqlalchemy import text

    # NOTE: `process_uptime_seconds` / `within_startup_grace` are imported at MODULE scope
    # (see the top of this file). Do NOT move them back in here -- a lazy import re-runs in
    # each forked child and restarts the anchor, which is the defect this fix removes.
    stale = int(stale_after_seconds)

    # THE COLD-START GATE. Checked before any statement runs, so a gated sweep touches
    # nothing at all -- no UPDATE, no audit row, no commit.
    if within_startup_grace(startup_grace_seconds):
        logger.info(
            "scanner_worker.reap_skipped_startup_grace uptime=%.1fs grace=%.1fs",
            process_uptime_seconds(), float(startup_grace_seconds),
            extra={"event": "scanner_worker.reap_skipped_startup_grace",
                   "uptime_seconds": round(process_uptime_seconds(), 1),
                   "startup_grace_seconds": float(startup_grace_seconds)},
        )
        return 0

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=stale)
    reason = (
        f"stale: no worker heartbeat for {stale}s; suspended by the worker reaper "
        f"(reversible -- reactivate once the worker is known good)"
    )
    # P8-G: capture WHICH workers this sweep will suspend, before the UPDATE changes them.
    # The UPDATE's `rowcount` gives a COUNT, not identities, and MySQL has no RETURNING -- so
    # a per-worker audit row needs this read. It uses the IDENTICAL predicate as the UPDATE
    # below, and the UPDATE remains the single atomic authority: a row that slips out of the
    # set between the two statements simply is not updated, and its audit row is dropped by
    # the `suspended`-count guard further down. Read-only, so it cannot affect the outcome.
    doomed: list[tuple[str, uuid.UUID | None, uuid.UUID | None]] = []
    try:
        rows = await db.execute(
            text(
                "SELECT worker_id, workspace_id, site_id FROM scanner_workers "
                "WHERE status = 'active' AND revoked_at IS NULL "
                "AND COALESCE(last_seen_at, created_at) < :cutoff"
            ),
            {"cutoff": cutoff},
        )
        # The GUID TypeDecorator returns uuid.UUID (or None) for these columns.
        doomed = [(str(r[0]), r[1], r[2]) for r in rows.fetchall()]
    except Exception:  # noqa: BLE001 -- auditing must never break the reaper
        logger.warning("scanner_worker.reap_audit_preselect_failed", exc_info=True)

    result = await db.execute(
        text(
            "UPDATE scanner_workers "
            "SET status = 'suspended', last_health_detail = :reason, updated_at = now(6) "
            # 'active' is the ONLY source state -- this is what keeps the transition
            # one-directional and leaves pending/draining/suspended/revoked alone.
            "WHERE status = 'active' "
            # Belt and braces: a revoked row cannot be 'active', but revocation is terminal
            # and must never be reachable from here even if a status were ever mis-set.
            "AND revoked_at IS NULL "
            # Silence is measured from the last heartbeat, or from registration for a worker
            # that has never sent one.
            "AND COALESCE(last_seen_at, created_at) < :cutoff"
        ),
        {"reason": reason, "cutoff": cutoff},
    )
    # `rowcount` is exact here (CLIENT_FOUND_ROWS; see core/db.py's _mysql_connect_args) and is
    # the MySQL replacement for RETURNING, exactly as the scan reaper uses it. Fetched via
    # getattr because SQLAlchemy types the generic `Result` without it -- the attribute exists
    # on the CursorResult an UPDATE actually returns, so this is a typing accommodation, not a
    # behavioural fallback (the `or 0` only covers a driver reporting -1/None).
    suspended = getattr(result, "rowcount", 0) or 0

    # P8-G: one durable audit row per ACTUALLY-suspended worker, written before the commit so
    # the records and the suspensions land together. A sweep that suspended nothing writes
    # nothing -- an audit trail of non-events is noise that hides the real ones.
    #
    # BEST EFFORT, and structurally so: `record_worker_reaped_stale` swallows and logs its own
    # failure, and this block is additionally wrapped, so no audit problem can stop a stale
    # worker being suspended. The reaper's semantics are unchanged -- same predicate, same
    # atomic UPDATE, same return value.
    if suspended and doomed:
        try:
            from apps.api.modules.audit import scanner_ops

            for worker_id, ws_id, site_id in doomed:
                await scanner_ops.record_worker_reaped_stale(
                    db, worker_id=worker_id, stale_after_seconds=stale,
                    workspace_id=ws_id, site_id=site_id,
                )
        except Exception:  # noqa: BLE001 -- never let auditing break the sweep
            logger.warning("scanner_worker.reap_audit_failed", exc_info=True)

    await db.commit()
    if suspended:
        logger.warning(
            "scanner_worker.reaped_stale count=%d stale_after_seconds=%d",
            suspended, stale,
            extra={"event": "scanner_worker.reaped_stale", "count": suspended,
                   "stale_after_seconds": stale},
        )
    return suspended
