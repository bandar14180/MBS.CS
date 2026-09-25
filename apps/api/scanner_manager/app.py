"""Scanner manager -- the control-plane boundary for the execution plane (MBS.SC Phase 4).

DESIGN CONSTRAINT, stated first because it is the one that is easy to get wrong: this is
NOT a proxy to the control plane. It exposes a fixed, small set of operations, and every
one of them re-derives authorization SERVER-SIDE from the worker's own persisted row:

    lease   -> which scans may THIS worker run?      (never "the scan you asked for")
    result  -> may THIS worker write to THIS scan?
    evidence-> may THIS worker attach evidence to THIS scan, and is the content valid?

The rule that makes this hold: a request may identify WHICH scan it is talking about, but
it may never supply the workspace, the site, or the pool that authorizes it. Those come
from the database rows for the authenticated worker and the named scan, and the two must
agree. A compromised worker can therefore replay, lie about its health, or send garbage --
and still cannot reach another tenant's data, because nothing it sends is trusted as
authorization input.

WHY IT IS A SEPARATE SERVICE: it runs on both `mbs-core` (to persist) and `mbs-dispatch`
(reachable by workers), and it is the ONLY service on both. That is what allows the
scanner worker to be removed from `mbs-core` entirely, which is the structural half of
scanner isolation -- the application checks here are the other half.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core import runtime_flags, tenancy
from apps.api.core.config import get_settings
from apps.api.core.logging import configure_logging
from apps.api.core.db import get_db
from apps.api.modules.assets.service import upsert_asset
from apps.api.modules.private_sites import service as sites_service
from apps.api.modules.scanner_workers import service as workers_service
from apps.api.modules.scanner_workers.models import (
    LEASE_ELIGIBLE_STATUSES,
    WORKER_HEALTH_STATES,
    ScannerWorker,
)
from apps.api.modules.scans import service as _scans_service
from apps.api.modules.scans.models import Scan
from apps.api.scanner_engine import result_sink
from apps.api.scanner_engine.models import Evidence
# REGISTERS `users` IN THE MAPPER REGISTRY -- imported for its side effect, not its name.
#
# Evidence.uploaded_by carries ForeignKey("users.id"), and SQLAlchemy resolves a STRING
# foreign key lazily, at flush time, against Base.metadata. This process imports a narrow
# slice of the models (9 tables) rather than the whole app, so `users` was absent and the
# first INSERT of an Evidence row died with:
#     NoReferencedTableError: Foreign key associated with column 'evidence.uploaded_by'
#     could not find table 'users'
# -> POST /v1/evidence returned 500, and because the vulnerability ingestion runs AFTER
# that flush in the same handler, no finding was ever ingested either.
#
# The column itself is nullable and scanner evidence leaves it NULL (the tool run is the
# provenance), so nothing here needs the User CLASS -- only its table has to be present in
# the registry for the FK to resolve. The database already has the constraint
# (`fk_evidence_uploaded_by_users`), so this is purely a mapper-registration fix and needs
# no migration.
from apps.api.modules.users.models import User  # noqa: F401

logger = logging.getLogger(__name__)

# OBSERVABILITY (small, deliberate): this app never configured logging, so it inherited
# uvicorn's root configuration and every `logger.info` in this module was DROPPED. Measured
# on the running manager: 311 successful POST /v1/tool-results and not one
# `manager.tool_result` line, while `logger.warning` events came through normally. That is
# why a boundary silently persisting nothing produced no diagnostic signal for two days.
#
# Uses the SAME configure_logging() the API and workers use, so format (JSON or text) and
# level come from the same settings rather than a second convention. Scope is deliberately
# limited to turning existing log statements back on; no new telemetry is added here.
configure_logging(get_settings().log_level, get_settings().log_json)

app = FastAPI(
    title="MBS Scanner Manager",
    description="Narrow, explicitly-authorized boundary between the scanner execution "
                "plane and the control plane.",
    docs_url=None,      # no interactive docs on an internal security boundary
    redoc_url=None,
    openapi_url=None,
)


# ---------------------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------------------

async def authenticated_worker(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_worker_id: str | None = Header(default=None, alias="X-Worker-Id"),
    authorization: str | None = Header(default=None),
) -> ScannerWorker:
    """Resolve the caller to exactly one ScannerWorker row, or refuse.

    Both the claimed worker id AND a matching secret are required -- the id alone names a
    row, it does not prove ownership of it. An mTLS fingerprint, when the deployment
    terminates client certificates at this service, is preferred over the bearer token.
    """
    if not x_worker_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "worker identity required")
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    # Populated by the TLS-terminating proxy when mTLS is in use.
    fingerprint = request.headers.get("X-Client-Cert-Fingerprint")
    if not token and not fingerprint:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "worker credential required")
    try:
        worker = await workers_service.authenticate_worker(
            db, worker_id=x_worker_id, token=token, cert_fingerprint=fingerprint
        )
        # Revocation/suspension is checked at AUTHENTICATION time, so a revoked worker
        # is refused by every endpoint at once rather than per-endpoint.
        workers_service.assert_worker_active(worker)
    except workers_service.WorkerNotAuthorized as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, exc.reason) from exc
    return worker


# ---------------------------------------------------------------------------------------
# Shared authorization for a scan the worker names
# ---------------------------------------------------------------------------------------

# ---------------------------------------------------------------------------------------
# Emergency-flag transition audit (MBS.SC P8-G)
# ---------------------------------------------------------------------------------------
# P8-D made the private-scanning kill switch runtime-mutable via a filesystem sentinel, which
# means it can now change WITHOUT any code path running -- so nothing recorded that it had.
# This records the transition the manager OBSERVES.
#
# WHY HERE AND NOT IN runtime_flags. That module is the low-level, fail-closed filesystem
# read on the hot lease path; it holds no database session and must stay lightweight. Giving
# it one would put a DB write inside the emergency check itself, which is the last place that
# should be able to block or slow down. The manager consumes the effective flag and already
# has a session, so the observation is recorded here instead.
#
# TRANSITIONS ONLY, NOT POLLS. The flag is re-read at most every 5s (P8-D's TTL); auditing
# each read would write ~17k rows a day saying nothing changed. `_EMERGENCY_STATE` holds this
# PROCESS's last observation: the first observation sets the baseline silently, an unchanged
# observation writes nothing, and only a genuine False->True or True->False writes one row.
#
# PER-PROCESS BY DESIGN. With several manager replicas each observes the same filesystem
# change independently, so each may record its own transition row. That is accepted for P8-G
# rather than introducing distributed locking or a coordination table to deduplicate it --
# the duplicates are honest observations, and the cure would be worse than the symptom.
_EMERGENCY_STATE: dict[str, bool] = {}


async def _audit_emergency_transition(db: AsyncSession, current: bool) -> None:
    """Record a change in the observed effective emergency state. Never raises.

    BEST EFFORT AND NON-BLOCKING: enforcement has already been decided by the caller before
    this runs, so an audit failure cannot leave private scanning enabled. The state is
    updated regardless of whether the write succeeded -- otherwise a transient database
    problem would make every subsequent request retry the same audit row forever.
    """
    previous = _EMERGENCY_STATE.get("effective")
    if previous is None:
        _EMERGENCY_STATE["effective"] = current   # baseline only: no audit row
        return
    if previous == current:
        return
    _EMERGENCY_STATE["effective"] = current
    try:
        from apps.api.modules.audit import scanner_ops

        await scanner_ops.record_emergency_transition(db, previous=previous, current=current)
        await db.commit()
    except Exception:  # noqa: BLE001 -- auditing must never affect enforcement
        logger.warning(
            "manager.emergency_audit_failed previous=%s current=%s", previous, current,
            exc_info=True,
            extra={"event": "manager.emergency_audit_failed"},
        )


async def _authorize_scan_for_worker(
    db: AsyncSession, worker: ScannerWorker, scan_id: uuid.UUID
) -> Scan:
    """The single gate every scan-scoped operation goes through.

    Loads the scan by its trusted internal id (scans is tenancy-EXEMPT precisely so a
    worker-facing path can bootstrap from it), then requires the worker's OWN row to be
    authorized for that scan's workspace, site and pool. The worker supplies only the
    scan id; every authorization input comes from persisted state.
    """
    scan = await db.get(Scan, scan_id)
    if scan is None:
        # Same 403 as an unauthorized scan: a 404 here would let a worker probe which
        # scan ids exist across the whole platform.
        raise HTTPException(status.HTTP_403_FORBIDDEN, "SCAN_NOT_AUTHORIZED")

    site_id = (scan.config or {}).get("site_id")
    site_uuid = uuid.UUID(str(site_id)) if site_id else None
    try:
        workers_service.assert_worker_may_take_scan(
            worker, workspace_id=scan.workspace_id, site_id=site_uuid,
        )
    except workers_service.WorkerNotAuthorized as exc:
        logger.warning(
            "manager.scan_authz_denied worker=%s scan=%s reason=%s",
            worker.worker_id, scan_id, exc.reason,
            extra={"event": "manager.scan_authz_denied", "worker_id": worker.worker_id,
                   "scan_id": str(scan_id), "reason": exc.reason},
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, exc.reason) from exc

    # A private scan additionally requires its site to still be scannable RIGHT NOW --
    # suspension must take effect for in-flight work, not just at dispatch.
    if site_uuid is not None:
        # PHASE 8 (emergency disconnect). The global kill switch was previously honoured
        # only in /v1/lease, i.e. it stopped NEW private work but let an already-leased
        # scan keep submitting tool results and evidence for as long as it ran. An
        # emergency control that cannot stop work already in flight is not an emergency
        # control -- the operator flips it precisely because something is wrong NOW.
        # Checked here, in the gate every scan-scoped request passes through, so it covers
        # /v1/tool-results, /v1/evidence and /v1/lease/complete as well as leasing.
        #
        # PUBLIC scanning is deliberately untouched: the condition is inside the
        # `site_uuid is not None` branch, so flipping the switch never interrupts a public
        # engagement.
        #
        # P8-D: the value now comes from `private_scanning_emergency_disabled()` -- the
        # logical OR of the environment setting and the operator's runtime sentinel file --
        # rather than from the `@lru_cache`d settings object alone, which froze the flag for
        # the life of the process and made activation require a manager restart. The
        # environment half is unchanged, so this can only ever ADD a way to switch it on.
        _emergency = runtime_flags.private_scanning_emergency_disabled()
        # P8-G: record the transition AFTER the value is decided, so auditing can never
        # influence the enforcement decision below.
        await _audit_emergency_transition(db, _emergency)
        if _emergency:
            logger.warning(
                "manager.emergency_disconnect_block worker=%s scan=%s",
                worker.worker_id, scan_id,
                extra={"event": "manager.emergency_disconnect_block",
                       "worker_id": worker.worker_id, "scan_id": str(scan_id),
                       "reason": "PRIVATE_SCANNING_EMERGENCY_DISABLED"},
            )
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "PRIVATE_SCANNING_EMERGENCY_DISABLED"
            )
        try:
            site = await sites_service.get_site_for_workspace(db, site_uuid, scan.workspace_id)
            sites_service.assert_site_scannable(site)
        except sites_service.PrivateSiteNotAuthorized as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, exc.reason) from exc
    return scan


# ---------------------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------------------

class HeartbeatIn(BaseModel):
    # F-9-01. These two fields were `str` (length-capped only) and an unbounded `int`, so an
    # authenticated worker could POST `health_state="super-healthy"` with
    # `handshake_age_s=-99999` and have both persisted verbatim -- confirmed in the Phase 9
    # adversarial audit by reading the row back.
    #
    # REJECT, DO NOT COERCE. `Literal` + `ge=0` fail the request with 422 at the validation
    # boundary, so an invalid value never reaches `record_heartbeat()` and is never stored.
    # Silently mapping "super-healthy" -> "unknown" or -99999 -> 0 was deliberately NOT
    # chosen: it would hide malformed or hostile telemetry behind a plausible-looking row,
    # which is the failure mode this fix exists to remove.
    #
    # The vocabulary lives in `scanner_workers.models.WORKER_HEALTH_STATES`, beside the
    # column that stores it, so the boundary and the schema cannot drift. `Literal` (not a
    # bare constraint) also publishes the allowed set in the OpenAPI schema.
    #
    # STILL ADVISORY: no authorization gate reads either field. A negative handshake age was
    # the more interesting half -- it is exported as `mbs_tunnel_handshake_age_seconds`, so a
    # worker could have suppressed `MbsTunnelHandshakeStale` (`> 600`) for its own pool by
    # reporting a negative age. `ge=0` closes that without touching any security decision.
    health_state: Literal["healthy", "degraded", "unhealthy", "unknown"] = "healthy"
    detail: str | None = Field(default=None, max_length=2000)
    handshake_age_s: int | None = Field(default=None, ge=0)
    # OPTIONAL scan liveness. When a lease worker is mid-execution it names the scan it is
    # running plus the token it was issued, and the manager refreshes that scan's
    # `last_heartbeat_at` -- the signal the orphan reaper keys on. Both are required
    # together: a scan_id without its token cannot be trusted to mean "I own this".
    scan_id: uuid.UUID | None = None
    execution_token: uuid.UUID | None = None


# `Literal` needs literal members at class-definition time, so it cannot be spelled from
# WORKER_HEALTH_STATES directly. This asserts the two agree at IMPORT, so adding a state to
# the model without widening the boundary (or the reverse) fails fast and loudly here rather
# than silently accepting or refusing a value at runtime.
assert set(
    HeartbeatIn.model_fields["health_state"].annotation.__args__  # type: ignore[union-attr]
) == set(WORKER_HEALTH_STATES), (
    "HeartbeatIn.health_state and WORKER_HEALTH_STATES have drifted; the API boundary and "
    "the stored column must accept exactly the same vocabulary"
)


class LeaseIn(BaseModel):
    # Advisory only: the SERVER decides what this worker may have. Sending a bigger
    # number cannot widen authorization, only the batch size.
    max_jobs: int = Field(default=1, ge=1, le=10)


class LeaseCompleteIn(BaseModel):
    scan_id: uuid.UUID
    # The token the LEASE issued. Not optional: an unfenced terminal write is exactly what
    # the execution-token mechanism exists to prevent.
    execution_token: uuid.UUID
    # completed | completed_with_errors | failed. Constrained server-side (see the
    # endpoint) so a worker cannot invent a status.
    status: str = Field(max_length=32)
    reason: str | None = Field(default=None, max_length=500)


class ToolStartedIn(BaseModel):
    """A tool is ABOUT to run. Progress, not outcome.

    Carries no findings, no exit code and no status: the status is `running` by definition
    -- letting the worker name it here would just be one more untrusted string to
    validate, and `running` is the only state this endpoint can mean.
    """

    scan_id: uuid.UUID
    # The SAME id the eventual /v1/tool-results submission uses, so the result updates this
    # row rather than creating a second one for the same execution.
    tool_run_id: uuid.UUID
    # Constrained server-side to this scan's authorized module list AND the tool registry,
    # exactly as ToolResultIn.tool_name is -- see _authorized_tool_name.
    tool_name: str = Field(max_length=64)
    # Same lease fencing as every other write on this boundary.
    execution_token: uuid.UUID
    # When the tool actually started, as observed by the worker. Optional and validated the
    # same way the result path validates it (see _resolve_tool_started_at).
    started_at: datetime | None = None


class ToolResultIn(BaseModel):
    scan_id: uuid.UUID
    # Chosen by the worker and used as the ToolRun PRIMARY KEY, which is what makes a
    # resubmission idempotent rather than duplicating the row (acks_late / lease
    # redelivery / a retried POST all re-send the same id).
    tool_run_id: uuid.UUID
    # REQUIRED. `tool_runs.tool_name` is NOT NULL and the value is shown in the UI and in
    # customer reports, so it can neither be omitted nor taken on trust: the endpoint
    # constrains it to this scan's own authorized module list AND to the tool registry.
    # It is NOT derivable server-side -- a lease covers a whole scan, not one tool, and the
    # executor SKIPS modules that do not apply to the target type, so position in
    # `requested_modules` does not identify the tool. Deriving it by order would mislabel
    # results silently, which is worse than the gap it would close.
    tool_name: str = Field(max_length=64)
    # The lease fencing token, exactly as /v1/lease/complete and /v1/heartbeat require it.
    # Without it a worker whose lease was superseded (graceful-shutdown requeue, orphan
    # reap, cancellation) could still write results into a scan another executor now owns.
    execution_token: uuid.UUID
    # completed | partial | failed | skipped_unauthorized. Constrained server-side (see the
    # endpoint) so a worker cannot invent a lifecycle state -- same rule as the terminal
    # status on /v1/lease/complete.
    status: str = Field(max_length=32)
    findings: list = Field(default_factory=list)
    exit_code: int | None = None
    error_message: str | None = Field(default=None, max_length=2000)
    # When the tool actually STARTED, as observed by the worker that ran it.
    #
    # Optional, and it must stay optional: a worker running an older image submits without
    # it, and rejecting those results would lose a whole scan's tool history to fix a
    # cosmetic duration. When absent the row falls back to `completed_at` (see the
    # endpoint), which is exactly the previous behaviour minus the negative duration.
    started_at: datetime | None = None
    # PROMPT 10 (execution determinism & reproducible trace). The exact command line the
    # tool ran with -- see ToolRun.effective_command. Optional for the same reason every
    # other progress-only field here is: an older worker submits without it, and the row
    # simply keeps command_hash="" / effective_command=NULL exactly as before, rather than
    # having its whole result rejected. Length-bounded generously (a katana/ffuf command can
    # legitimately join many resolved targets) but still far short of being usable to smuggle
    # a large or adversarial payload through a field that is meant to be one shell command.
    effective_command: str | None = Field(default=None, max_length=8000)
    # Whether the tool's own wall-clock budget was exceeded (base.run_with_timeout's
    # TimedRun.timed_out, threaded through RawToolOutput.timed_out). Optional/None for the
    # same backward-compatibility reason as above; None is stored as "unknown", never
    # coerced to False, so an older worker's silence is never misrepresented as "did not
    # time out" -- see the endpoint.
    timed_out: bool | None = None


class EvidenceIn(BaseModel):
    scan_id: uuid.UUID
    tool_run_id: uuid.UUID | None = None
    finding_id: uuid.UUID | None = None
    content_type: str = Field(default="text/plain", max_length=128)
    content_b64: str
    # The worker's claimed digest. Verified against the bytes; never trusted as given.
    sha256: str | None = None
    # Same fencing as ToolResultIn -- a superseded execution must not be able to attach
    # evidence to the new owner's run.
    execution_token: uuid.UUID
    # The raw stdout of a tool run is re-parsed server-side into vulnerability findings
    # (see the endpoint). The worker names the tool; the manager owns the PARSER, so a
    # compromised worker cannot inject a finding that no tool actually produced.
    tool_name: str | None = Field(default=None, max_length=64)
    # SCREENSHOT ASSOCIATION. The finding this evidence depicts, by the stable fingerprint
    # the parser produces -- never a vulnerability id, which the execution plane has no
    # database to look up and therefore must not be trusted to supply.
    #
    # It is matched against vulnerabilities that already exist for THIS scan's project, so
    # a fingerprint the manager's own parse never produced resolves to nothing and the
    # image is stored unattached rather than being filed against an invented finding.
    # Length-bounded like every other worker-supplied string, to the column's own width
    # (vulnerabilities.fingerprint is String(512)).
    fingerprint: str | None = Field(default=None, max_length=512)


# ---------------------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict:
    """Unauthenticated liveness only. Deliberately reveals nothing about workers,
    tenants or scans."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------------------
# Metrics (MBS.SC PHASE 8 -- P8-C)
# ---------------------------------------------------------------------------------------
# WHY THE METRICS COME FROM HERE AND NOT FROM THE WORKER.
#
# Phase 8 Tier 1 made every private worker EMIT tunnel health (`record_tunnel_state`), but a
# private worker sits on its own `mbs-site-<slug>` network plus `mbs-dispatch` and binds no
# metrics port. The only way Prometheus could scrape it directly would be to join the
# execution plane -- exactly the boundary Phases 1/2 exist to enforce, and a single
# Prometheus bridging every customer's site network would defeat the per-site isolation
# Phase 7 proved.
#
# So nothing is scraped from the execution plane at all. The worker already REPORTS its
# health to this manager over the existing authenticated `/v1/heartbeat` call, and
# `record_heartbeat` persists it on `scanner_workers`. This endpoint projects those
# already-persisted rows. Prometheus therefore talks only to a control-plane service on
# `mbs-core`, and the private workers remain entirely unaware that it exists: no new port,
# no new credential, no new capability, no new network attachment.
#
# The cost is freshness -- a value here is at most one heartbeat interval (30s) old. That is
# deliberate and safe against alert thresholds of 300s/600s.
#
# LABEL DISCIPLINE. `pool_id` ONLY. `site_id` and `workspace_id` are tenant identifiers, and
# a metrics endpoint is the one surface an operator is most likely to forward to a
# third-party dashboard -- labelling by them would publish how many private customers exist
# and how busy each one is. `record_tunnel_state` already documents this rule; it is enforced
# here and asserted by test_p8c_manager_metrics.py.

_HEALTHY = "healthy"


def _worker_metric_lines(rows, *, now: datetime) -> list[str]:
    """Render `scanner_workers` rows as Prometheus exposition text.

    Pure and separately testable -- no database, no clock of its own -- so the label
    discipline and the fail-closed rules below can be asserted without standing up the app.

    THREE FAIL-CLOSED RULES, each of which exists because the alternative is an alert that
    stays silent while something is wrong:

      1. A worker that has NEVER reported (`last_seen_at IS NULL`) is emitted as
         `mbs_tunnel_up 0`, never 1 and never omitted. Omitting it would leave
         `mbs_tunnel_up == 0` with nothing to match, so a worker that never came up at all
         would look identical to a healthy fleet.
      2. Any `health_state` other than exactly 'healthy' -- including 'unknown' -- is 0.
      3. `handshake_age_s` is emitted ONLY when the worker actually reported one. A missing
         age must not be rendered as 0, which would read as "handshake just happened".

    PUBLIC workers (site_id IS NULL) produce NO tunnel metric at all: they have no tunnel,
    and emitting `up=1` for them would dilute `mbs_tunnel_up == 0` across pools that can
    never have a tunnel, making the alert progressively less meaningful as the public fleet
    grows. They DO get a heartbeat-age metric, which is meaningful for any worker.
    """
    out: list[str] = [
        "# HELP mbs_tunnel_up Private scanner tunnel health (1=healthy, 0=unhealthy/unknown).",
        "# TYPE mbs_tunnel_up gauge",
        "# HELP mbs_tunnel_handshake_age_seconds Seconds since the last WireGuard handshake.",
        "# TYPE mbs_tunnel_handshake_age_seconds gauge",
        "# HELP mbs_scanner_worker_heartbeat_age_seconds Seconds since the worker last reported.",
        "# TYPE mbs_scanner_worker_heartbeat_age_seconds gauge",
        "# HELP mbs_scanner_workers_lease_eligible Workers in this pool that may be handed new work.",
        "# TYPE mbs_scanner_workers_lease_eligible gauge",
        "# HELP mbs_scanner_workers_registered Workers registered in this pool, any status.",
        "# TYPE mbs_scanner_workers_registered gauge",
    ]
    # WHY A COUNT PER POOL, AND WHY IT IS NOT DERIVABLE FROM THE METRICS ABOVE.
    #
    # `mbs_scanner_worker_heartbeat_age_seconds` is emitted only for a worker with a
    # non-NULL `last_seen_at` -- and a SUSPENDED worker is refused at authentication, so it
    # can never refresh that column. The moment the reaper suspends the fleet, the staleness
    # metric therefore stops ageing and (for a worker that never reported) is absent
    # entirely. `MbsScannerWorkerHeartbeatStale` goes QUIET exactly when scanning is most
    # broken, which is how a fully-suspended fleet stayed invisible for four days while the
    # API kept accepting scans.
    #
    # This gauge is derived from `status` instead of from liveness, so it is unaffected by
    # that feedback loop: a suspended, revoked or draining worker simply is not counted as
    # eligible, and the value falls to 0 whether or not anything is still heartbeating.
    # `mbs_scanner_workers_registered` is emitted alongside it so an alert can tell a pool
    # that has been EMPTIED (fleet suspended: registered > 0, eligible == 0) from one that
    # was never populated or has been decommissioned (registered == 0) -- two situations
    # with different operator responses.
    eligible_by_pool: dict[str, int] = {}
    registered_by_pool: dict[str, int] = {}
    for row in rows:
        pool = _escape_label(getattr(row, "pool_id", None) or "unknown")
        is_private = getattr(row, "site_id", None) is not None
        last_seen = getattr(row, "last_seen_at", None)

        registered_by_pool[pool] = registered_by_pool.get(pool, 0) + 1
        # Reuses the SAME predicate the lease boundary enforces rather than restating it:
        # a status that stops being leasable must not keep being counted as eligible.
        is_eligible = (
            getattr(row, "revoked_at", None) is None
            and getattr(row, "status", None) in LEASE_ELIGIBLE_STATUSES
        )
        eligible_by_pool[pool] = eligible_by_pool.get(pool, 0) + (1 if is_eligible else 0)

        if is_private:
            healthy = (
                last_seen is not None
                and (getattr(row, "health_state", None) or "").strip().lower() == _HEALTHY
            )
            out.append(f'mbs_tunnel_up{{pool_id="{pool}"}} {1 if healthy else 0}')
            age = getattr(row, "last_handshake_age_s", None)
            if age is not None:
                out.append(
                    f'mbs_tunnel_handshake_age_seconds{{pool_id="{pool}"}} {float(age)}'
                )

        if last_seen is not None:
            seen = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=timezone.utc)
            seconds = max(0.0, (now - seen).total_seconds())
            out.append(
                f'mbs_scanner_worker_heartbeat_age_seconds{{pool_id="{pool}"}} {seconds:.1f}'
            )

    # Emitted for every pool that has ANY registered worker, including pools whose eligible
    # count is 0 -- that zero IS the signal, and omitting the series would leave the alert
    # with nothing to match, repeating the exact failure mode described above.
    for pool in sorted(registered_by_pool):
        out.append(
            f'mbs_scanner_workers_lease_eligible{{pool_id="{pool}"}} '
            f'{eligible_by_pool.get(pool, 0)}'
        )
        out.append(
            f'mbs_scanner_workers_registered{{pool_id="{pool}"}} {registered_by_pool[pool]}'
        )
    return out


def _escape_label(value: str) -> str:
    """Prometheus label-value escaping. A pool id is operator-chosen, but a metrics endpoint
    must not be able to emit malformed exposition text (or inject a second label) because
    somebody named a pool with a quote in it."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "")


@app.get("/metrics")
async def metrics(request: Request, db: AsyncSession = Depends(get_db)):
    """Prometheus scrape endpoint for private-worker VPN health.

    Access is governed by the SAME `METRICS_MODE` contract the API's own `/metrics` uses
    (core/config.py): disabled | token | authenticated | public, fail-closed by default --
    in `token` mode with no `METRICS_TOKEN` set, access is denied. No new credential model is
    introduced; Prometheus already sends this header from its mounted secret.
    """
    from fastapi.responses import Response

    settings = get_settings()
    mode = (settings.metrics_mode or "token").strip().lower()
    if mode == "disabled":
        return Response(status_code=404)
    if mode != "public":
        # `authenticated` is deliberately NOT offered here: this service has no user session
        # and issues no JWTs, so accepting one would mean importing user-auth into the
        # worker-facing plane. Anything that is not `public` therefore requires the token,
        # which is the mode Prometheus is already configured for.
        import hmac

        supplied = request.headers.get("x-metrics-token", "")
        if not settings.metrics_token or not hmac.compare_digest(
            supplied, settings.metrics_token
        ):
            return Response("Forbidden", status_code=403)

    try:
        with tenancy.admin_bypass():
            # admin_bypass, and it is not a hole: `scanner_workers` is infrastructure, not
            # tenant data, and the projection below emits `pool_id` only -- no site,
            # workspace, worker id or scan ever reaches the output.
            rows = list(await db.scalars(select(ScannerWorker)))
        body = "\n".join(_worker_metric_lines(rows, now=datetime.now(timezone.utc))) + "\n"
    except Exception:  # noqa: BLE001 -- observability must never take the manager down
        # A failed scrape is a monitoring outage; a 500 loop or a crashed manager would be a
        # SCANNING outage. 503 tells Prometheus "target down" without touching the lease path.
        logger.warning("manager.metrics_failed", exc_info=True,
                       extra={"event": "manager.metrics_failed"})
        return Response("metrics unavailable", status_code=503)
    return Response(body, media_type="text/plain; version=0.0.4; charset=utf-8")


@app.post("/v1/heartbeat")
async def heartbeat(
    payload: HeartbeatIn,
    worker: ScannerWorker = Depends(authenticated_worker),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Liveness + self-reported tunnel health, and (optionally) SCAN liveness.

    Self-reported HEALTH values are ADVISORY: they drive operator alerting, never the
    decision to run a scan (a compromised worker would simply claim to be healthy).

    SCAN liveness is different, and is the reason this endpoint takes a scan_id at all.
    `scans.last_heartbeat_at` is what the orphan reaper keys on to tell a healthy long scan
    from a dead executor. On the Celery path the executor stamps it directly
    (orchestrator._stamp_heartbeat); a LEASE worker has no database, so without this it
    could never stamp at all -- every leased scan would look heartbeat-less, and the reaper
    would fall back to its much cruder "runtime exceeded" rule. That is a real regression
    in both directions: healthy long leased scans reaped early, dead ones recovered late.

    It is NOT a trust hole. The stamp goes through the SAME fenced statement the Celery
    executor uses -- `WHERE id = :id AND status = 'running' AND execution_token = :tok` --
    so a worker can only refresh a scan it currently, verifiably owns. A worker whose lease
    was already revoked by the reaper (token cleared) matches zero rows and silently stamps
    nothing, which is exactly right: it must not be able to keep a scan looking alive on
    behalf of the executor that replaced it.
    """
    await workers_service.record_heartbeat(
        db, worker, health_state=payload.health_state,
        detail=payload.detail, handshake_age_s=payload.handshake_age_s,
    )

    scan_stamped = False
    if payload.scan_id is not None and payload.execution_token is not None:
        # Authorize the scan for THIS worker first (workspace/site/pool), so a worker
        # cannot even name another tenant's scan here.
        scan = await _authorize_scan_for_worker(db, worker, payload.scan_id)
        from apps.api.scanner_engine.orchestrator import _stamp_heartbeat

        with tenancy.admin_bypass():
            await _stamp_heartbeat(db, scan.id, payload.execution_token)
        scan_stamped = True

    await db.commit()
    return {
        "ok": True, "worker_id": worker.worker_id, "status": worker.status,
        "scan_heartbeat": scan_stamped,
    }


# Statuses a worker may report for one tool run. Mirrors classify_run() plus the
# authorization skip the orchestrator records; anything else is a worker inventing a
# lifecycle state, which is refused exactly as an invented terminal scan status is.
_ALLOWED_TOOL_STATUSES = frozenset(
    {"completed", "partial", "failed", "skipped_unauthorized"}
)


async def _link_screenshot_to_finding(
    db: AsyncSession, *, scan, evidence_row, fingerprint: str, tool_run_id,
) -> bool:
    """Attach a stored screenshot to the vulnerability it depicts. Returns True if linked.

    Resolution is by `(project_id, fingerprint)` -- the SAME unique identity the ingestion
    pipeline dedupes on (`uq_vulnerabilities_project_fingerprint`), so this attaches to the
    row that ingest just created or refreshed rather than to a second copy of it.

    `project_id` is read from the already-authorized SCAN row, never from the payload, so
    the lookup is confined to the tenant that owns the scan.

    BEST EFFORT. A screenshot that cannot be associated is not worth failing an evidence
    submission whose bytes are already stored -- the same rule the raw-output path follows.
    """
    from apps.api.modules.vulnerabilities.models import Vulnerability, VulnerabilityEvidence

    try:
        vuln = await db.scalar(
            select(Vulnerability).where(
                Vulnerability.project_id == scan.project_id,
                Vulnerability.fingerprint == fingerprint,
            )
        )
        if vuln is None:
            # Normal and safe: the finding may have been filtered out server-side, or the
            # fingerprint was never one this manager derived. Store, do not attach.
            logger.info(
                "manager.screenshot_unmatched scan=%s", scan.id,
                extra={"event": "manager.screenshot_unmatched", "scan_id": str(scan.id)},
            )
            return False

        # IDEMPOTENT, exactly as vulnerabilities/service.py does it: the PK is
        # (vulnerability_id, evidence_id), and a re-scan that recaptures the same page
        # yields the same checksum -> the same Evidence row -> the same pair. INSERT ...
        # ON DUPLICATE KEY is atomic and race-free, where a plain INSERT would raise 1062
        # and poison the session for the rest of the request.
        from sqlalchemy.dialects.mysql import insert as mysql_insert

        # The arg-type ignore below: `Model.__table__` is typed FromClause in the SQLAlchemy
        # stubs while insert() wants TableClause; a known stub imprecision, already
        # documented in pyproject's mypy overrides for the modules that use this idiom.
        # Ignored on the line rather than by adding this whole security-boundary module to
        # that suppression list, which would stop checking arg-type everywhere else in it.
        stmt = mysql_insert(VulnerabilityEvidence.__table__).values(  # type: ignore[arg-type]
            vulnerability_id=vuln.id, evidence_id=evidence_row.id, tool_run_id=tool_run_id,
        )
        stmt = stmt.on_duplicate_key_update(tool_run_id=VulnerabilityEvidence.tool_run_id)
        await db.execute(stmt)
        logger.info(
            "manager.screenshot_linked scan=%s vuln=%s", scan.id, vuln.id,
            extra={"event": "manager.screenshot_linked", "scan_id": str(scan.id),
                   "vulnerability_id": str(vuln.id)},
        )
        return True
    except Exception:  # noqa: BLE001 -- association loss must not reject stored evidence
        logger.warning(
            "manager.screenshot_link_failed scan=%s", scan.id,
            extra={"event": "manager.screenshot_link_failed", "scan_id": str(scan.id)},
            exc_info=True,
        )
        return False


async def _ingest_from_raw_output(
    db: AsyncSession, *, scan, tool_run, evidence_id: uuid.UUID,
    tool_name: str, content: bytes, content_type: str,
) -> int:
    """Re-derive vulnerability findings from stored raw output and run THE security pipeline.

    Deliberately reconstructs a `RawToolOutput` and calls the registry runner's own
    `parse_vulnerabilities()` -- the same parser the in-process path uses -- rather than
    accepting parsed findings over the wire. The worker sends bytes; the control plane
    decides what they mean.

    Everything here is best-effort with respect to the EVIDENCE: a parser that raises must
    not reject an otherwise valid evidence submission, because the raw output is already
    stored and is itself the customer-visible artifact. A parse failure costs findings from
    one tool run, never the run's evidence.
    """
    from apps.api.scanner_engine.orchestrator import ingest_vulnerability_findings
    from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY
    from apps.api.scanner_engine.tool_runners.base import RawToolOutput

    # Only textual tool output can be parsed; a screenshot or binary blob is evidence only.
    if not (content_type or "").startswith("text/"):
        return 0
    runner_cls = TOOL_REGISTRY.get(tool_name)
    if runner_cls is None:
        return 0

    # A FAILED run's output is not trusted to yield findings -- the same rule the in-process
    # path applies ("Don't trust output from a failed run -- record the error, ingest
    # nothing"). Keeping the rule identical is the point of sharing the pipeline at all.
    if getattr(tool_run, "status", None) == "failed":
        return 0

    try:
        runner = runner_cls()
        raw = RawToolOutput(
            command="", stdout=content.decode("utf-8", errors="replace"),
            stderr="", exit_code=tool_run.exit_code if tool_run.exit_code is not None else 0,
        )
        vuln_findings = list(runner.parse_vulnerabilities(raw))
    except Exception:  # noqa: BLE001 -- a broken parse costs findings, never the evidence
        logger.warning(
            "manager.vuln_parse_failed scan=%s tool=%s", scan.id, tool_name,
            extra={"event": "manager.vuln_parse_failed", "scan_id": str(scan.id),
                   "tool": tool_name},
            exc_info=True,
        )
        return 0

    if not vuln_findings:
        return 0

    from apps.api.modules.projects.models import Target

    with tenancy.admin_bypass():
        # `targets` is VIA-scoped; the scan row was already authorized for this worker and
        # only its OWN target is read, for the criticality that weights the risk score.
        target = await db.get(Target, scan.target_id)

    return await ingest_vulnerability_findings(
        db,
        scan=scan,
        vuln_findings=vuln_findings,
        tool_run_id=tool_run.id,
        evidence_id=evidence_id,
        criticality=getattr(target, "criticality", "medium") or "medium",
        target_type=getattr(target, "type", "") or "",
        target_value=getattr(target, "value", "") or "",
        extra_scope_hosts=None,
        # The control plane must not open connections to customer targets: scanner-manager
        # is deliberately NOT on mbs-scan-egress. Screenshots are execution-plane work.
        capture_screenshots=False,
    )


def _authorized_tool_name(scan, tool_name: str) -> str:
    """Constrain a worker-supplied tool name to what THIS scan is authorized to run.

    Two independent gates, both from state the worker cannot influence:
      1. the scan's OWN `requested_modules` (persisted on the scan row at creation), so a
         worker cannot file a result for a tool this scan never asked for;
      2. TOOL_REGISTRY, so the name is a real registered tool and not free text that would
         land verbatim in the UI and in customer reports.
    """
    from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY

    requested = set((scan.config or {}).get("requested_modules") or [])
    if tool_name not in requested:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "TOOL_NOT_REQUESTED_FOR_SCAN")
    if tool_name not in TOOL_REGISTRY:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "UNKNOWN_TOOL_NAME")
    return tool_name


def _assert_execution_token(scan, execution_token: uuid.UUID) -> None:
    """Fence a result write against the scan's CURRENT execution token.

    The same guarantee `_finalize_status` gives the terminal write, applied to the
    per-tool writes: a worker whose lease was superseded -- requeued on graceful
    shutdown, reclaimed by the orphan reaper, or cancelled -- holds a stale token and
    must not be able to append results to the execution that replaced it. Without this
    the two executions' tool runs interleave in one scan and the timeline becomes a
    fiction. 409 (not 403): the credential is fine, the LEASE is not.
    """
    current = getattr(scan, "execution_token", None)
    if current is None or str(current) != str(execution_token):
        raise HTTPException(status.HTTP_409_CONFLICT, "EXECUTION_SUPERSEDED")


# How far a worker's clock may run ahead of the manager's before its reported start time is
# discarded. These are SEPARATE HOSTS by design (the worker sits on the dispatch network,
# often on customer premises), so their clocks are close but never identical, and a tool
# that legitimately finishes in milliseconds can report a start a hair after the manager's
# "now". A few seconds absorbs ordinary NTP drift without accepting a start time that is
# meaningfully in the future.
_TOOL_START_FUTURE_TOLERANCE_SECONDS = 5.0


def _as_utc(value: datetime) -> datetime:
    """A tz-aware UTC datetime, whatever the source.

    Values read back through `UTCDateTime` are aware, but a value that came off the wire
    through Pydantic may be naive if the worker serialized it without an offset. This
    codebase's storage convention is "naive == UTC" (see core/db_types.py), so applying it
    here keeps the comparisons below from raising TypeError on mixed awareness.
    """
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _resolve_tool_started_at(
    reported: datetime | None, completed_at: datetime, worker_id: str
) -> datetime:
    """The start time to persist for a tool run, from an UNTRUSTED worker-reported value.

    Two rules, and deliberately only two:

      * a start time in the FUTURE (beyond clock-skew tolerance) is discarded -- it would
        store a negative duration, the exact defect this field exists to fix;
      * a start time AFTER `completed_at` is clamped to it, so the row can never be
        inverted even if the two values straddle the tolerance window.

    What is deliberately NOT enforced is a lower bound against `scan.started_at`. It looks
    like the obvious companion check and it would reject correct results: `scans.started_at`
    is REWRITTEN when a scan is re-run, so a scan row can legitimately carry a start time
    later than tool runs already attached to it (observed in this deployment: scan
    f1f82a1e started 2026-09-08 with tool runs from 2026-08-27), and it is stored truncated
    to whole seconds while tool runs carry microseconds, so a tool starting in the same
    second as its scan can compare as earlier. An old start time is also harmless: it makes
    a duration look too long, it cannot invert the row.

    Covered by test_remote_result_persistence.py::test_a_future_started_at_is_discarded_*
    and ::test_a_started_at_within_clock_skew_tolerance_is_clamped_not_inverted.
    """
    if reported is None:
        # Backward compatibility with a worker that does not send the field. Using
        # `completed_at` yields a 0s duration -- honest ("not measured") rather than the
        # negative one the CURRENT_TIMESTAMP default produced.
        return completed_at

    reported = _as_utc(reported)
    if (reported - completed_at).total_seconds() > _TOOL_START_FUTURE_TOLERANCE_SECONDS:
        logger.warning(
            "manager.tool_started_at_in_future worker=%s reported=%s completed=%s",
            worker_id, reported.isoformat(), completed_at.isoformat(),
            extra={"event": "manager.tool_started_at_in_future", "worker_id": worker_id},
        )
        return completed_at
    # Within tolerance but still ahead: clamp rather than drop, so a sub-millisecond tool
    # reports 0s instead of a negative duration.
    return min(reported, completed_at)


def _command_hash(effective_command: str | None) -> str:
    """SHA-256 of the worker-reported command text, or "" when none was sent.

    PROMPT 10. `command_hash` is derived HERE, server-side, from the same text that is
    stored as `effective_command` -- never accepted as a separate worker-supplied field --
    so the digest can never disagree with the text it is supposed to attest to. This is
    also the fix for this path's command_hash being hardcoded "" unconditionally: an older
    worker that does not send `effective_command` still gets "" (unchanged behaviour), but
    a current worker's submission now produces both a readable command and its digest,
    matching what the in-process orchestrator has always recorded.
    """
    if not effective_command:
        return ""
    return hashlib.sha256(effective_command.encode()).hexdigest()


def required_scan_egress_mode(scan) -> str | None:
    """The egress mode THIS scan requires, or None when it expresses no requirement.

    Read from the scan's own config, which `scans/service.create_scan` populated at
    creation time from the workspace/target policy. Returned as None rather than "direct"
    when unset, because None means "any public worker will do" -- the existing behaviour
    for every scan created before this feature, which must keep working unchanged.

    A PRIVATE scan never requires VPN egress: its traffic goes into the customer's tunnel,
    not out to the Internet, and pushing it through a platform VPN would be both pointless
    and a cross-plane violation. That is enforced structurally too -- a VPN-egress worker
    has no site binding, so it cannot take a private job at all.
    """
    config = scan.config or {}
    if config.get("site_id"):
        return None
    mode = (config.get("required_egress_mode") or "").strip().lower()
    return mode or None


async def _build_job_payload(
    db: AsyncSession, scan, site, execution_token: uuid.UUID
) -> dict:
    """Everything the execution worker needs to run ONE scan, and nothing else.

    This is the whole reason the worker can be credential-free: rather than reading
    `targets`/`projects`/`private_sites` itself (which needs a database), it is HANDED the
    already-authorized execution plan. The manager derived every field from persisted rows
    it just authorized, so the worker has no input into what it is allowed to scan.

    Deliberately absent: any credential, any connection string, any other tenant's data,
    and any field the worker could use to widen its own authority. `authorized_cidrs` and
    `dns_servers` are included because the worker must ENFORCE them locally (net_policy +
    egress_guard); they are this tenant's own configuration, and the worker is already
    bound to this tenant.
    """
    from apps.api.modules.projects.models import Target

    with tenancy.admin_bypass():
        # admin_bypass: `targets` is a VIA-scoped table and the ambient context is not
        # bound to this workspace yet. The read is safe because the scan row was just
        # authorized for THIS worker, and we read only that scan's own target by id.
        target = await db.get(Target, scan.target_id)

    config = scan.config or {}
    return {
        "scan_id": str(scan.id),
        "workspace_id": str(scan.workspace_id),
        "project_id": str(scan.project_id),
        # The fencing token. The worker must present this on every write for this scan.
        "execution_token": str(execution_token),
        "network_zone": "private" if site is not None else "public",
        "site_id": str(site.id) if site is not None else None,
        "target": {
            "id": str(scan.target_id),
            "type": target.type if target else None,
            "value": target.value if target else None,
        },
        "requested_modules": list(config.get("requested_modules") or []),
        # Tool-runner tuning knobs ONLY (e.g. timeout_seconds, nuclei_tags, ffuf_rate) --
        # filtered through the SAME allowlist scans/service.create_scan already enforced at
        # scan-creation time (ALLOWED_TOOL_CONFIG_KEYS), so this can only ever re-forward a
        # key that was already validated as a runner knob. `scan.config` also carries
        # orchestration/safety keys (requested_modules, use_agent, exploitation_enabled,
        # network_zone, ...) at its top level; those must never reach the worker as tool
        # config, which is exactly what filtering through the allowlist prevents -- an
        # untrusted worker gains no new authority by receiving this dict.
        "config": {
            k: v for k, v in config.items() if k in _scans_service.ALLOWED_TOOL_CONFIG_KEYS
        },
        # The worker enforces these locally; they are the same values the policy is built
        # from server-side, not a second source of truth.
        "authorized_cidrs": list(site.authorized_cidrs or []) if site is not None else [],
        "dns_servers": list(site.dns_servers or []) if site is not None else [],
        "pool_id": site.scanner_pool_id if site is not None else None,
        # DEDICATED VPN EGRESS. The worker re-checks this against its OWN configured mode
        # and refuses a mismatch -- the same "handed to me is not authorized for me"
        # discipline the rest of this payload is validated under. It is included for that
        # local enforcement only; the authoritative decision was already made server-side
        # by `assert_worker_egress_mode` before this payload was built, so a worker that
        # ignored the field would still never have been leased the job.
        "required_egress_mode": required_scan_egress_mode(scan),
    }


@app.post("/v1/lease")
async def lease_jobs(
    payload: LeaseIn,
    worker: ScannerWorker = Depends(authenticated_worker),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Hand this worker the scans IT is authorized for -- and only those.

    The query is constrained by the worker's OWN pool/site/workspace columns, so a worker
    cannot express interest in another tenant's queue at all. This is why leasing is a
    manager operation rather than a broker subscription: a Redis queue cannot enforce
    "only rows whose workspace matches this worker's binding".
    """
    # LEASE ELIGIBILITY -- the narrower of the two worker authorities, asked HERE and
    # nowhere else. `authenticated_worker` has already refused revoked/suspended/pending,
    # so the status this adds is `draining`: a decommissioning worker keeps every endpoint
    # it needs to finish and report the scan it already holds, and is refused only new work.
    #
    # Checked ONCE up front rather than relying on the per-row gate below, which `continue`s
    # silently -- a draining worker would otherwise get an indistinguishable empty list, and
    # "you are draining" is exactly what an operator needs to see in the log.
    try:
        workers_service.assert_worker_may_lease(worker)
    except workers_service.WorkerNotAuthorized as exc:
        logger.info(
            "manager.lease_refused worker=%s pool=%s reason=%s",
            worker.worker_id, worker.pool_id, exc.reason,
            extra={"event": "manager.lease_refused", "worker_id": worker.worker_id,
                   "pool_id": worker.pool_id, "reason": exc.reason},
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, exc.reason) from exc

    settings = get_settings()

    # WHICH ROWS ARE LEASABLE.
    #
    # `queued` is the normal case. `failed` is included ONLY for scans the ORPHAN REAPER
    # recovered -- it marks an abandoned execution `failed` and stamps
    # config.recovery.reason, and `_claim_scan` already treats `failed` as claimable (that
    # is its retry path). Without this, a lease-executed scan whose worker died would be
    # recovered by the reaper and then never picked up again: the work would be silently
    # lost. Caught by test_a_recovered_scan_can_be_leased_again.
    #
    # It is deliberately NOT "any failed scan". A scan that failed for its OWN reasons (bad
    # target, tool crash, exhausted retries, dead-lettered) must not be re-leased forever --
    # on the Celery path that case is handled by a bounded autoretry chain plus the DLQ, and
    # an unconditional re-lease here would be an unbounded retry loop that bypasses both.
    # The `recovery` key is what distinguishes "the executor died" from "the scan failed".
    reaper_recovered = Scan.config["recovery"].isnot(None)
    leasable = or_(Scan.status == "queued",
                   and_(Scan.status == "failed", reaper_recovered))

    if worker.site_id is not None:
        # PRIVATE worker: only its own site's scans, in its own workspace.
        stmt = (
            select(Scan)
            .where(leasable)
            .where(Scan.workspace_id == worker.workspace_id)
            .limit(payload.max_jobs)
        )
    else:
        # PUBLIC worker: private scans are filtered out below by the per-row site check,
        # which is authoritative.
        stmt = select(Scan).where(leasable).limit(payload.max_jobs * 4)

    # Emergency global disable (Phase 13) -- enforced control-plane side so it does not
    # depend on reaching any scanner host.
    #
    # P8-D: environment OR runtime sentinel (see core/runtime_flags). Read ONCE per lease
    # request rather than per candidate row: a single lease must not be able to see the
    # switch flip halfway through and hand out some jobs but not others.
    private_disabled = runtime_flags.private_scanning_emergency_disabled(settings)
    # P8-G: same observed-transition audit on the lease path. Enforcement is already
    # decided above; this only records what was seen.
    await _audit_emergency_transition(db, private_disabled)

    with tenancy.admin_bypass():
        # admin_bypass is required and is NOT a hole: `scans` is tenancy-EXEMPT anyway,
        # and every row returned is individually authorized against this worker's binding
        # immediately below. The bypass buys the ability to SEE candidate rows; it grants
        # no ability to hand them to an unauthorized worker.
        rows = (await db.execute(stmt)).scalars().all()

    leased = []
    for scan in rows:
        site_id = (scan.config or {}).get("site_id")
        site_uuid = uuid.UUID(str(site_id)) if site_id else None
        if site_uuid is not None and private_disabled:
            continue
        site = None
        try:
            workers_service.assert_worker_may_take_scan(
                worker, workspace_id=scan.workspace_id, site_id=site_uuid,
                # VPN-EGRESS GATE. A scan that requires the dedicated VPN exit is skipped
                # for a direct worker here, BEFORE the atomic claim -- so it stays
                # `queued` and is picked up by a VPN worker on a later poll, rather than
                # being claimed and then failed. That ordering matters: claiming first
                # would burn the scan's claim on a worker that was never allowed to run it.
                required_egress_mode=required_scan_egress_mode(scan),
            )
            if site_uuid is not None:
                site = await sites_service.get_site_for_workspace(
                    db, site_uuid, scan.workspace_id
                )
                sites_service.assert_site_scannable(site)
        except (workers_service.WorkerNotAuthorized,
                sites_service.PrivateSiteNotAuthorized):
            continue  # not for this worker; silently skip (no information disclosed)

        # ATOMIC CLAIM -- the lease is only real once this wins.
        #
        # Reuses orchestrator._claim_scan verbatim rather than reimplementing the claim:
        # it is the SAME single conditional UPDATE that has always fenced Celery
        # redelivery, so the lease path and the (control-plane) Celery path contend on one
        # mechanism instead of two that could disagree. Only one caller can observe
        # rowcount == 1 for a given row, so two workers polling concurrently cannot both
        # receive the same scan -- which the pre-claim version of this endpoint allowed,
        # because it only SELECTed.
        #
        # The token is generated HERE, server-side. A worker never chooses its own
        # execution token; it is handed one and must present it back for every fenced
        # write, exactly like the Celery executor does.
        from apps.api.scanner_engine.orchestrator import _claim_scan

        execution_token = uuid.uuid4()
        with tenancy.admin_bypass():
            won = await _claim_scan(db, scan.id, execution_token)
            await db.commit()
        if not won:
            # Another worker (or the control-plane executor) claimed it first. Not an
            # error -- just move on to the next candidate.
            continue

        job = await _build_job_payload(db, scan, site, execution_token)
        leased.append(job)
        if len(leased) >= payload.max_jobs:
            break

    logger.info(
        "manager.lease worker=%s pool=%s leased=%d",
        worker.worker_id, worker.pool_id, len(leased),
        extra={"event": "manager.lease", "worker_id": worker.worker_id,
               "pool_id": worker.pool_id, "leased": len(leased)},
    )
    return {"jobs": leased}


@app.post("/v1/lease/complete")
async def complete_lease(
    payload: LeaseCompleteIn,
    worker: ScannerWorker = Depends(authenticated_worker),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """The FENCED terminal write for a leased scan.

    Reuses orchestrator._finalize_status, which is the same conditional UPDATE the Celery
    executor has always used:

        WHERE id = :id AND status = 'running' AND execution_token = :tok

    So a worker whose lease was superseded (requeued on shutdown, reclaimed after an orphan
    reap, or cancelled) loses the race and CANNOT overwrite the new owner's outcome or a
    'cancelled' state. That is reported back as `accepted: false` with an explicit reason
    rather than an error: nothing failed, this execution simply stopped being authoritative.

    The worker is NOT trusted to name an arbitrary status -- only the terminal values below
    are accepted (the same vocabulary the Celery orchestrator's own aggregation produces:
    completed / completed_with_errors / failed), so a compromised worker cannot invent a
    lifecycle state.
    """
    if payload.status not in ("completed", "completed_with_errors", "failed"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "INVALID_TERMINAL_STATUS")

    scan = await _authorize_scan_for_worker(db, worker, payload.scan_id)

    from apps.api.scanner_engine.orchestrator import _finalize_status, _ownership_lost_reason

    with tenancy.admin_bypass():
        won = await _finalize_status(db, scan, payload.status, payload.execution_token)
        await db.commit()
        await db.refresh(scan)

    if not won:
        reason = _ownership_lost_reason(scan.status)
        logger.warning(
            "manager.lease_complete_superseded worker=%s scan=%s status=%s reason=%s",
            worker.worker_id, scan.id, scan.status, reason,
            extra={"event": "manager.lease_complete_superseded",
                   "worker_id": worker.worker_id, "scan_id": str(scan.id),
                   "reason": reason},
        )
        return {"accepted": False, "reason": reason, "status": scan.status}

    logger.info(
        "manager.lease_complete worker=%s scan=%s status=%s",
        worker.worker_id, scan.id, payload.status,
        extra={"event": "manager.lease_complete", "worker_id": worker.worker_id,
               "scan_id": str(scan.id), "status": payload.status},
    )
    return {"accepted": True, "status": payload.status}


@app.get("/v1/scan-status")
async def scan_status(
    scan_id: uuid.UUID,
    execution_token: uuid.UUID,
    worker: ScannerWorker = Depends(authenticated_worker),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Why this execution should stop right now -- the COOPERATIVE CANCELLATION probe.

    STRICTLY READ-ONLY. This endpoint exists because a lease worker has no database: on
    the Celery path the executor calls `_execution_stop_reason` directly between tools, so
    a cancelled scan stops before the next tool is launched. A lease-executed scan could
    not ask that question at all, so `cancel_scan` marked the row 'cancelled' and the
    worker kept running the remaining tools to completion -- discovering the cancellation
    only when its terminal write was refused as `already_terminal`.

    It REUSES `_execution_stop_reason` rather than reimplementing the state machine: the
    two dispatch paths must never be able to disagree about what 'cancelled' or 'revoked'
    means. `execution_token` is required for exactly the reason it is required everywhere
    else on this boundary -- 'revoked' is defined as "this token no longer owns the row",
    which is unanswerable without knowing which execution is asking.

    Deliberately NOT the heartbeat. `/v1/heartbeat` is best-effort by contract (a failed
    beat must never affect a scan) and it WRITES `last_heartbeat_at`; folding a stop signal
    into it would both invert that contract and make cancellation depend on a write path.
    This is a separate, side-effect-free read.
    """
    scan = await _authorize_scan_for_worker(db, worker, scan_id)

    from apps.api.scanner_engine.orchestrator import _execution_stop_reason

    with tenancy.admin_bypass():
        reason = await _execution_stop_reason(db, scan.id, execution_token)
    return {"stop_reason": reason}


@app.post("/v1/tool-started")
async def submit_tool_started(
    payload: ToolStartedIn,
    worker: ScannerWorker = Depends(authenticated_worker),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """OPEN a tool run as `running`, before the tool executes.

    WHY THIS EXISTS: on the remote path a ToolRun row was created only when the tool
    FINISHED, so the scan-progress UI jumped straight from "waiting" to "completed" and a
    ten-minute katana/nuclei run looked frozen throughout. The frontend already knows how
    to render a live counter from a running row's `started_at` -- it simply never received
    one. This endpoint supplies it. It is the remote-path equivalent of the in-process
    orchestrator's pre-launch insert, which is why that path has always shown the counter.

    Cosmetic by contract: the worker treats a failure here as a lost display detail and
    runs the tool anyway. Nothing downstream depends on this row existing -- the eventual
    /v1/tool-results submission creates it if it is absent, exactly as before.

    SECURITY: identical to /v1/tool-results, deliberately sharing the same three helpers
    rather than re-deriving anything. A progress endpoint is still a WRITE endpoint, and a
    weaker check here would be a way around the stricter one next door.
    """
    scan = await _authorize_scan_for_worker(db, worker, payload.scan_id)
    _assert_execution_token(scan, payload.execution_token)
    tool_name = _authorized_tool_name(scan, payload.tool_name)

    from apps.api.scanner_engine.models import ToolRun
    from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY

    # From the registry, never the worker -- same rule as the result path.
    tool_version = getattr(TOOL_REGISTRY[tool_name], "version", "") or ""

    with tenancy.workspace_scope(scan.workspace_id):
        existing = await db.get(ToolRun, payload.tool_run_id)
        if existing is not None and str(existing.scan_id) != str(scan.id):
            # A worker-chosen PRIMARY KEY could otherwise name a row belonging to another
            # scan -- including another tenant's. Refuse; a ToolRun never moves.
            logger.warning(
                "manager.tool_started_cross_scan worker=%s tool_run=%s",
                worker.worker_id, payload.tool_run_id,
                extra={"event": "manager.tool_started_cross_scan",
                       "worker_id": worker.worker_id},
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "TOOL_RUN_BELONGS_TO_ANOTHER_SCAN")

        now = datetime.now(timezone.utc)
        started_at = _resolve_tool_started_at(payload.started_at, now, worker.worker_id)

        if existing is None:
            db.add(
                ToolRun(
                    id=payload.tool_run_id,
                    scan_id=scan.id,
                    tool_name=tool_name,
                    tool_version=tool_version,
                    status="running",
                    # Filled by the evidence submission, which carries the command line.
                    command_hash="",
                    started_at=started_at,
                    # THE point of this endpoint: an open row. `duration_seconds` stays
                    # null while this is null, so the UI counts from `started_at` instead
                    # of showing a finished duration.
                    completed_at=None,
                )
            )
        else:
            # A re-announcement (lease redelivery before the tool ran) must not reopen a
            # row that has already finished: that would erase a terminal status and make a
            # completed tool look like it is running again. Only a row still `running` --
            # i.e. one this same announcement opened -- may be touched.
            if existing.status == "running" and existing.completed_at is None:
                existing.started_at = started_at

        await db.commit()

    logger.info(
        "manager.tool_started worker=%s scan=%s tool=%s",
        worker.worker_id, scan.id, tool_name,
        extra={"event": "manager.tool_started", "worker_id": worker.worker_id,
               "scan_id": str(scan.id), "tool": tool_name},
    )
    return {"ok": True, "scan_id": str(scan.id), "tool_run_id": str(payload.tool_run_id),
            "status": "running"}


@app.post("/v1/tool-results")
async def submit_tool_result(
    payload: ToolResultIn,
    worker: ScannerWorker = Depends(authenticated_worker),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """PERSIST one tool run's outcome, only for a scan this worker is authorized for.

    This endpoint used to authorize, log, `commit()` an EMPTY transaction and return
    `{"ok": true}` -- writing nothing. The isolated worker holds no database credential by
    design, so the manager is the only component that CAN write; with it a no-op, every
    remote scan silently lost its entire tool history. The symptom surfaced far away, as a
    completed scan whose UI showed 12 tools still "queued", because `tool_runs` had no rows
    to report. That is what this writes.

    Idempotent by construction: `tool_run_id` is the ToolRun PRIMARY KEY and is chosen by
    the worker, so a redelivered lease, an acks_late retry or a re-POSTed request updates
    the same row instead of creating a second one.

    STATUS IS WRITE-ONCE. Every value in `_ALLOWED_TOOL_STATUSES` is a terminal outcome (this
    endpoint has no "running" status -- that is `/v1/tool-started`), and the current worker
    computes and submits its status exactly once per `tool_run_id` (see F2-09: `status` is
    decided before the single `_submit_tool_result_resilient` call). A resubmission for a
    `tool_run_id` that ALREADY holds a terminal status must therefore be reporting the SAME
    execution's outcome a second time -- a true retry -- and a genuine retry reports the same
    status it reported before. A resubmission carrying a DIFFERENT status is not distinguishable
    from a bug or an adversarial actor overwriting an already-recorded outcome, so the first
    terminal status wins and is never silently replaced; `started_at`/`completed_at` repair
    still applies (those are idempotent by construction regardless of status).
    """
    scan = await _authorize_scan_for_worker(db, worker, payload.scan_id)
    _assert_execution_token(scan, payload.execution_token)
    tool_name = _authorized_tool_name(scan, payload.tool_name)
    if payload.status not in _ALLOWED_TOOL_STATUSES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "INVALID_TOOL_STATUS")

    from apps.api.scanner_engine.models import ToolRun
    from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY

    # The VERSION comes from the registry, never from the worker: it is a property of the
    # tool image the control plane published, and a compromised worker must not be able to
    # attribute its output to a different version than the one that ran.
    tool_version = getattr(TOOL_REGISTRY[tool_name], "version", "") or ""

    # workspace_scope(), NOT a bare bind_workspace(): this is a REQUEST HANDLER, and a bare
    # bind leaves the workspace bound in this task's context after the response is sent.
    # Under a server that reuses a context across requests, the next request could inherit
    # this tenant's binding -- a cross-tenant leak introduced by the very mechanism meant to
    # prevent one. The scope unbinds on exit, including on an exception.
    with tenancy.workspace_scope(scan.workspace_id):
        existing = await db.get(ToolRun, payload.tool_run_id)
        if existing is not None and str(existing.scan_id) != str(scan.id):
            # The id is a PRIMARY KEY the worker chooses, so a worker could otherwise name
            # an id that already belongs to a DIFFERENT scan -- including another tenant's --
            # and overwrite it. Refuse rather than re-parent: a ToolRun never moves.
            logger.warning(
                "manager.tool_result_cross_scan worker=%s tool_run=%s",
                worker.worker_id, payload.tool_run_id,
                extra={"event": "manager.tool_result_cross_scan",
                       "worker_id": worker.worker_id},
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "TOOL_RUN_BELONGS_TO_ANOTHER_SCAN")

        completed_at = datetime.now(timezone.utc)
        started_at = _resolve_tool_started_at(payload.started_at, completed_at, worker.worker_id)
        if existing is None:
            db.add(
                ToolRun(
                    id=payload.tool_run_id,
                    scan_id=scan.id,
                    tool_name=tool_name,
                    tool_version=tool_version,
                    status=payload.status,
                    # PROMPT 10: derived from payload.effective_command (see _command_hash),
                    # not a worker-supplied hash -- an older worker that omits the field
                    # still gets "" here, exactly the previous behaviour.
                    command_hash=_command_hash(payload.effective_command),
                    effective_command=payload.effective_command,
                    # None (not sent) is stored as False -- ToolRun.timed_out is NOT NULL --
                    # but that is indistinguishable from "did not time out" only for a
                    # pre-Prompt-10 worker, which recorded no timeout signal at all before
                    # this column existed either. Never coerced to True by omission.
                    timed_out=bool(payload.timed_out),
                    started_at=started_at,
                    completed_at=completed_at,
                    exit_code=payload.exit_code,
                    error_message=(payload.error_message or None),
                )
            )
        else:
            # STATUS IS WRITE-ONCE (see the docstring): once a prior submission has already
            # recorded a terminal outcome for this tool_run_id, a resubmission reporting a
            # DIFFERENT status is not applied -- the first terminal status wins. `existing.status`
            # is still "running" here if this is the first result for a row `/v1/tool-started`
            # opened, which is the normal case and must still be written.
            already_terminal = existing.status in _ALLOWED_TOOL_STATUSES
            if not already_terminal:
                existing.status = payload.status
            elif existing.status != payload.status:
                logger.warning(
                    "manager.tool_result_status_conflict_ignored worker=%s tool_run=%s "
                    "existing=%s incoming=%s -- keeping the first terminal status",
                    worker.worker_id, payload.tool_run_id, existing.status, payload.status,
                    extra={"event": "manager.tool_result_status_conflict_ignored",
                           "worker_id": worker.worker_id, "tool_run_id": str(payload.tool_run_id),
                           "existing_status": existing.status, "incoming_status": payload.status},
                )
            existing.tool_name = tool_name
            existing.tool_version = tool_version
            # A resubmission (lease redelivery / acks_late retry) must not stretch the
            # duration: keep the ORIGINAL start unless it is missing or would leave the row
            # inverted, which is precisely the pre-fix state a retry can find.
            if existing.started_at is None or _as_utc(existing.started_at) > completed_at:
                existing.started_at = started_at
            # ...and freeze the END the same way. A resubmission reports the SAME attempt,
            # which has already finished, so re-stamping `completed_at` with "now" charged
            # the redelivery gap to the tool: a 3s run re-POSTed 6s later recorded 9s.
            # `tool_run_id` is minted per execution (executor.py), so a genuine re-execution
            # writes a NEW row -- an existing row is always the same attempt reported twice.
            # Written only when missing, or when inverted (the pre-fix rows), so this still
            # REPAIRS bad data rather than cementing it.
            if existing.completed_at is None or _as_utc(existing.completed_at) < _as_utc(existing.started_at):
                existing.completed_at = completed_at
            if payload.exit_code is not None:
                existing.exit_code = payload.exit_code
            if payload.error_message:
                existing.error_message = payload.error_message
            # PROMPT 10: written only when this row does not already carry one, exactly
            # like the error_message repair above -- a retry reports the SAME execution's
            # command a second time, so the first submission's value (if any) is authoritative
            # and a resubmission must never blank it out or silently replace it with a
            # different command (a `/v1/tool-started` announcement never sets this field).
            if payload.effective_command and not existing.effective_command:
                existing.effective_command = payload.effective_command
                existing.command_hash = _command_hash(payload.effective_command)
            if payload.timed_out:
                existing.timed_out = True

        # ---- TRANSACTION 1: the TOOL RUN's terminal state, and nothing else. ------------
        #
        # COMMITTED BEFORE ANY ASSET IS TOUCHED, and that ordering is the whole point.
        # These two writes used to share one transaction, so a single unstorable finding
        # rolled back the status update as well: in incident 615d0e0b a ~700-character URL
        # raised DataError(1406) here, and katana -- which had actually run and produced
        # 30,873 URLs -- was left `running` in the database permanently, because the row
        # that would have marked it `partial` died with the asset INSERT.
        #
        # The tool's outcome is a FACT ABOUT EXECUTION that the worker observed directly.
        # It must not be contingent on whether the payload it carried happens to be
        # storable. Committing here makes that independence structural rather than a
        # matter of error-handling discipline further down.
        await db.commit()

        # ---- TRANSACTION 2: inventory ingestion, isolated PER ASSET. --------------------
        #
        # Inventory findings become ASSETS through the same upsert the in-process path uses,
        # so re-submitting a result touches existing assets rather than duplicating them.
        #
        # Each upsert runs inside its own SAVEPOINT, and each failure is caught per item.
        #
        # MEASURED, not assumed: against aiomysql a failed Core statement (DataError 1406,
        # IntegrityError) does NOT poison the surrounding transaction -- the session stays
        # usable and a later commit still persists the good rows. So on THIS path the
        # try/except alone would already keep the other findings. The savepoint is kept
        # because that property is specific to emitting Core statements one at a time: an
        # ORM flush, a deadlock/lock-timeout abort (1213/1205, which MySQL rolls back for
        # us), or any future batching here would invalidate the transaction, and then one
        # bad finding WOULD cost every good one after it. Cheap insurance at the exact
        # boundary where the blast radius is defined.
        ingested_assets = 0
        rejected_assets = 0
        for finding in payload.findings or []:
            if not isinstance(finding, dict):
                continue
            asset_type, value = finding.get("asset_type"), finding.get("value")
            if not asset_type or not value:
                continue
            try:
                async with db.begin_nested():
                    await upsert_asset(
                        db,
                        project_id=scan.project_id,
                        target_id=scan.target_id,
                        asset_type=str(asset_type),
                        value=str(value),
                        metadata=dict(finding.get("metadata") or {}),
                    )
                ingested_assets += 1
            except Exception as exc:  # noqa: BLE001 -- one asset must not cost the others
                # NOT swallowed: the rejection is counted, logged with the value's identity
                # and length, and reported back in the response body. An operator can answer
                # "which asset was dropped, and why" without reading a stack trace.
                rejected_assets += 1
                logger.warning(
                    "manager.asset_rejected worker=%s scan=%s tool=%s type=%s len=%d "
                    "error=%s value_prefix=%s",
                    worker.worker_id, scan.id, tool_name, asset_type, len(str(value)),
                    f"{type(exc).__name__}: {exc}", str(value)[:120],
                    extra={"event": "manager.asset_rejected",
                           "worker_id": worker.worker_id, "scan_id": str(scan.id),
                           "tool": tool_name, "asset_type": str(asset_type),
                           "value_length": len(str(value)),
                           "error": f"{type(exc).__name__}: {exc}"},
                )

        await db.commit()
        logger.info(
            "manager.tool_result worker=%s scan=%s tool=%s status=%s assets=%d rejected=%d",
            worker.worker_id, scan.id, tool_name, payload.status, ingested_assets,
            rejected_assets,
            extra={"event": "manager.tool_result", "worker_id": worker.worker_id,
                   "scan_id": str(scan.id), "tool": tool_name, "assets": ingested_assets,
                   "rejected": rejected_assets},
        )
    return {"ok": True, "scan_id": str(scan.id), "tool_run_id": str(payload.tool_run_id),
            "assets": ingested_assets, "rejected_assets": rejected_assets}


@app.post("/v1/evidence")
async def submit_evidence(
    payload: EvidenceIn,
    worker: ScannerWorker = Depends(authenticated_worker),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Store evidence, bound to the workspace of the scan -- not to anything the worker says.

    Three independent checks, in order:
      1. the worker is authorized for THIS scan (cross-tenant submission dies here);
      2. the content passes size/type validation;
      3. the digest is recomputed from the bytes, so a false `sha256` cannot be recorded.
    """
    scan = await _authorize_scan_for_worker(db, worker, payload.scan_id)

    try:
        content = base64.b64decode(payload.content_b64, validate=True)
    except Exception as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "EVIDENCE_NOT_BASE64") from exc

    try:
        digest = result_sink.validate_evidence(content, payload.content_type)
    except result_sink.EvidenceRejected as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    if payload.sha256 and payload.sha256.lower() != digest:
        # The submitter's claim disagrees with the bytes: refuse rather than silently
        # storing the real digest, because the mismatch itself is the signal.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "EVIDENCE_DIGEST_MISMATCH")

    # The workspace comes from the SCAN row, so evidence is always filed under the tenant
    # that owns the scan -- there is no code path in which the worker chooses it.
    # workspace_scope() rather than a bare bind: see the note in submit_tool_result about
    # a binding outliving its request.
    _assert_execution_token(scan, payload.execution_token)

    from apps.api.scanner_engine.models import ToolRun

    vulnerabilities = 0
    with tenancy.workspace_scope(scan.workspace_id):
        sink = result_sink.LocalResultSink(workspace_id=scan.workspace_id)
        # Uploads the bytes to object storage. It does NOT write the Evidence ROW -- on the
        # in-process path the orchestrator writes that itself, and making the sink do it too
        # would duplicate every local row. The row is written here instead, so exactly one
        # component owns it on each path.
        stored = await sink.submit_evidence(
            scan_id=scan.id, tool_run_id=payload.tool_run_id,
            content=content, content_type=payload.content_type, finding_id=payload.finding_id,
        )

        # THE EVIDENCE ROW. Its absence was the second half of the silent data loss: the
        # bytes reached MinIO (8000+ objects) while `evidence` stopped gaining rows
        # entirely, so nothing in the database pointed at any of them and no report could
        # cite them. Keyed by (tool_run_id, checksum) so a retried submission of the same
        # bytes updates nothing rather than accumulating duplicate rows.
        evidence_row = None
        if payload.tool_run_id is not None:
            evidence_row = await db.scalar(
                select(Evidence).where(
                    Evidence.tool_run_id == payload.tool_run_id,
                    Evidence.checksum == stored["sha256"],
                )
            )
        # An image is SCREENSHOT evidence, not a log excerpt. The report layer routes on
        # exactly this value: data.py sends `screenshot` rows to VulnRow.screenshots (which
        # the technical report embeds) and everything else to the textual artifact list
        # rendered as "Raw tool output". Typing it wrong here would store the bytes and
        # still show no image, which is the regression this restores.
        is_screenshot = (payload.content_type or "").split(";")[0].strip().lower() == "image/png"
        if evidence_row is None:
            evidence_row = Evidence(
                tool_run_id=payload.tool_run_id,
                evidence_type="screenshot" if is_screenshot else "log_excerpt",
                storage_uri=stored["uri"],
                checksum=stored["sha256"],
            )
            db.add(evidence_row)
            await db.flush()  # need evidence_row.id to link vulnerabilities to it

        # SCREENSHOT -> FINDING ASSOCIATION.
        #
        # The execution plane cannot resolve a vulnerability id (no database credential), so
        # it sends the finding's stable fingerprint and the resolution happens here, against
        # rows that already exist for THIS scan's project. A fingerprint the manager's own
        # parse never produced simply matches nothing: the image stays stored but attaches
        # to no finding, so a worker cannot file evidence against an invented vulnerability.
        #
        # The project comes from the authorized scan row, never from the payload, so this
        # lookup cannot cross a tenant boundary regardless of what was sent.
        if is_screenshot and payload.fingerprint:
            await _link_screenshot_to_finding(
                db, scan=scan, evidence_row=evidence_row,
                fingerprint=payload.fingerprint, tool_run_id=payload.tool_run_id,
            )

        tool_run = (
            await db.get(ToolRun, payload.tool_run_id)
            if payload.tool_run_id is not None else None
        )
        if tool_run is not None and not tool_run.raw_output_ref:
            tool_run.raw_output_ref = stored["uri"]

        # SERVER-SIDE VULNERABILITY PARSING.
        #
        # The remote path never produced a single vulnerability: the executor calls the
        # runner but never `parse_vulnerabilities()`, and nothing downstream did it either,
        # so `vulnerabilities` gained no rows at all after the cutover while scans kept
        # reporting success.
        #
        # The parse happens HERE, not in the worker, and that is a security property rather
        # than a convenience: `parse_vulnerabilities` is a pure function of the raw output,
        # so the control plane can re-derive findings from the same bytes it just stored and
        # checksummed. The worker therefore supplies EVIDENCE, never conclusions -- it
        # cannot fabricate a finding no tool emitted, nor suppress one by omitting it from a
        # summary, because the manager reads the output itself.
        #
        # Findings then go through ingest_vulnerability_findings(), the SAME function the
        # in-process orchestrator calls, so dedup/lifecycle, risk scoring, compliance
        # mapping and ATT&CK mapping all apply identically. No parallel pipeline exists.
        if tool_run is not None and payload.tool_name:
            vulnerabilities = await _ingest_from_raw_output(
                db, scan=scan, tool_run=tool_run, evidence_id=evidence_row.id,
                tool_name=payload.tool_name, content=content,
                content_type=payload.content_type,
            )

        await db.commit()
    logger.info(
        "manager.evidence_stored worker=%s scan=%s bytes=%d vulnerabilities=%d",
        worker.worker_id, scan.id, len(content), vulnerabilities,
        extra={"event": "manager.evidence_stored", "worker_id": worker.worker_id,
               "scan_id": str(scan.id), "workspace_id": str(scan.workspace_id),
               "vulnerabilities": vulnerabilities},
    )
    return {"ok": True, "sha256": stored["sha256"], "uri": stored["uri"],
            "vulnerabilities": vulnerabilities}


@app.get("/v1/site-config")
async def site_config(
    worker: ScannerWorker = Depends(authenticated_worker),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """The tunnel configuration for the worker's OWN site.

    Takes no site parameter, deliberately: the site is read from the worker's row, so
    there is no request in which a worker can ask for another customer's tunnel
    configuration. Returns PUBLIC key material only -- the worker generates and keeps its
    own private key, which the control plane never sees.
    """
    if worker.site_id is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "WORKER_NOT_PRIVATE")
    if worker.workspace_id is None:
        # A site-bound worker with no workspace binding is a broken registration, and it
        # matters: `get_site_for_workspace` proves ownership by comparing the site's
        # workspace to this one, and comparing against None would make that check
        # meaningless. (mypy caught exactly this -- workspace_id is nullable because a
        # SHARED PUBLIC worker legitimately has none.) Refuse rather than resolve it from
        # the site, which would be assuming the answer to the question being asked.
        logger.error(
            "manager.private_worker_without_workspace worker=%s site=%s",
            worker.worker_id, worker.site_id,
            extra={"event": "manager.worker_misconfigured", "worker_id": worker.worker_id},
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "WORKER_MISCONFIGURED")
    try:
        site = await sites_service.get_site_for_workspace(
            db, worker.site_id, worker.workspace_id
        )
    except sites_service.PrivateSiteNotAuthorized as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, exc.reason) from exc
    return {
        "site_id": str(site.id),
        "status": site.status,
        "authorized_cidrs": list(site.authorized_cidrs or []),
        "dns_servers": list(site.dns_servers or []),
        "dns_search_domains": list(site.dns_search_domains or []),
        "wg_endpoint_host": site.wg_endpoint_host,
        "wg_endpoint_port": site.wg_endpoint_port,
        "peer_public_key": site.peer_public_key,
        "wg_persistent_keepalive": site.wg_persistent_keepalive,
    }
