"""Durable audit for Phase 8 scanner/VPN operator actions -- MBS.SC P8-G.

WHY THIS EXISTS
---------------
Every Phase 8 control was enforced correctly but left NO durable record. Demonstrated
concretely during discovery: a worker revoked through the approved P8-E CLI an hour earlier
had vanished entirely -- `platform_audit_events` held 0 rows, and the log line had gone to
the operator's `docker exec` session rather than any container log. Container logs are
`json-file` with no rotation and no shipping, so they die with the container anyway.

This module is the thin, shared seam that writes those records. It is NOT a new audit
system: every call goes through the EXISTING `audit_service.record_platform_event()` into
the EXISTING `platform_audit_events` table.

THE THREE RULES EVERY CALLER RELIES ON
--------------------------------------
  1. BEST EFFORT, ALWAYS. An audit write must never break the operation it is recording.
     Revocation must still cut off a compromised worker, the reaper must still suspend, and
     emergency enforcement must still refuse work, even if the audit insert fails. Every
     helper here swallows its exception and logs it instead.
  2. SECRET-FREE. `detail` carries ids, states and reasons only -- never a token, token
     hash, certificate fingerprint, filesystem path, or environment value. A durable audit
     trail is exactly the wrong place to accumulate credentials.
  3. HONEST ATTRIBUTION. The platform cannot authenticate a person at a CLI or a filesystem
     touch, so this never claims it did. `actor` is one of:
         <operator string>  -- supplied via --actor: OPERATOR-ASSERTED, not authenticated
         unattributed       -- a CLI action where the operator supplied no actor
         system             -- no human involved (the reaper, an observed flag transition)
     `actor_user_id` stays NULL throughout: it is the column for an AUTHENTICATED user id,
     and filling it from a free-text CLI argument would misrepresent a claim as an identity.

WORKSPACE SCOPE
---------------
`workspace_id=None` means PLATFORM-SCOPED -- the emergency flag (platform-wide by
definition) or a shared public worker (whose own workspace_id is already NULL). That is the
convention this repository already uses for "not workspace-scoped"; see the column comment
on PlatformAuditEvent.
"""
from __future__ import annotations

import logging
import uuid

logger = logging.getLogger(__name__)

# --- Event names. `noun.verb` / `noun.verb.outcome`, matching tenant.delete.* ---------------
EVENT_WORKER_REVOKED = "scanner.worker.revoked"
EVENT_WORKER_DRAINED = "scanner.worker.drained"
EVENT_WORKER_REAPED_STALE = "scanner.worker.reaped_stale"
EVENT_WORKER_REACTIVATED = "scanner.worker.reactivated"
# A REFUSED reactivation. Separate event rather than an `outcome=` on the one above, so an
# auditor can find every attempt that did NOT readmit a worker with a single equality filter
# -- the same `noun.verb.outcome` shape tenant.delete.* already uses.
EVENT_WORKER_REACTIVATION_FAILED = "scanner.worker.reactivation_failed"
EVENT_EMERGENCY_TRANSITION = "scanner.private_scanning.emergency"

#: Actor recorded when no human was involved at all.
ACTOR_SYSTEM = "system"
#: Actor recorded when a CLI permits attribution and the operator supplied none.
ACTOR_UNATTRIBUTED = "unattributed"

# --- Actor TYPE: what kind of thing is claiming to have acted --------------------------
# `actor` alone cannot answer "was this a person or a machine", because an operator string
# is free text. These name the CHANNEL the action came through, which the platform DOES
# know for certain.
ACTOR_TYPE_OPERATOR_CLI = "operator_cli"   # an ops/ CLI: operator-asserted, unauthenticated
ACTOR_TYPE_SYSTEM = "system"               # the platform acting on its own (reaper, flags)

#: Recorded for any provenance field the platform cannot determine. NEVER guessed.
PROVENANCE_UNKNOWN = "unknown"


def _source_identity() -> tuple[str, str, str]:
    """MACHINE-VERIFIABLE provenance for the process performing an operator action.

    WHY THIS EXISTS. An investigation of the 2026-09-17 reactivation could not attribute it:
    the row recorded `actor=blocker-1-remediation`, a free-text `--actor` value matching
    nothing in the repository, and every source that could have identified the invoker was
    unavailable -- shell history did not cover the window, Docker exec events were not
    retained, and MySQL `general_log` is off. The audit row proved WHAT happened and WHEN,
    but not WHO or FROM WHERE.

    These three values are the identity the process actually has, as opposed to the one it
    claims. They are recorded ALONGSIDE `actor`, never instead of it:

        actor        what the operator SAYS they are   (free text, unverified)
        os_user      what the OS says the process is   (observed)
        source_host  where the process is running      (observed)

    That distinction is the whole point. `os_user=appuser source_host=<container id>` versus
    `os_user=banda source_host=MSI` immediately separates "run inside a control-plane
    container" from "run on the developer host" -- the exact question the investigation
    could not answer.

    NOT AUTHENTICATION, and this must not be read as such. A caller able to run the CLI can
    influence these (a different container user, a spoofed hostname). They raise the cost of
    an unattributed action and make an honest one self-documenting; they do not make the
    actor trustworthy. `actor_authenticated=false` therefore stays exactly as it was.

    NEVER RAISES. Provenance is strictly additive to an operator recovery path that must
    keep working during an incident, so any lookup that fails degrades to `unknown` rather
    than taking down the audit row -- or worse, the recovery itself.

    SECRET-FREE, by construction: a username, a hostname and a process id. No token, path,
    header, or environment value is read here (rule 2).
    """
    import os

    try:
        import getpass

        os_user = getpass.getuser() or PROVENANCE_UNKNOWN
    except Exception:  # noqa: BLE001 -- no password database, no controlling terminal, ...
        os_user = PROVENANCE_UNKNOWN
    try:
        import socket

        source_host = socket.gethostname() or PROVENANCE_UNKNOWN
    except Exception:  # noqa: BLE001
        source_host = PROVENANCE_UNKNOWN
    try:
        source_pid = str(os.getpid())
    except Exception:  # noqa: BLE001
        source_pid = PROVENANCE_UNKNOWN
    return os_user, source_host, source_pid


def normalise_actor(actor: str | None) -> str:
    """The actor string to record.

    An omitted or blank `--actor` becomes an EXPLICIT `unattributed` rather than being left
    empty or silently filled in: "we do not know who did this" is a fact worth recording,
    and inventing an identity would be worse than recording none.
    """
    cleaned = (actor or "").strip()
    return cleaned or ACTOR_UNATTRIBUTED


def _format_detail(pairs) -> str:
    """`k=v` pairs, stable order, skipping empties.

    Deliberately flat text rather than JSON: `detail` is a Text column read by humans during
    an incident, and the existing tenant.delete.* records are plain strings too.
    """
    return " ".join(f"{k}={v}" for k, v in pairs if v not in (None, ""))


async def _safe_record(db, *, workspace_id, event: str, detail: str) -> bool:
    """Write one platform audit row. Returns True iff it was recorded.

    NEVER raises. A failure here is logged and swallowed -- see rule 1 above. Note this
    FLUSHES but does not COMMIT: the caller owns the transaction, so the audit row lands in
    the same commit as the action it describes wherever that is possible.
    """
    try:
        from apps.api.modules.audit import service as audit_service

        await audit_service.record_platform_event(
            db,
            workspace_id,
            None,  # actor_user_id: reserved for an AUTHENTICATED user; see rule 3.
            event,
            detail=detail,
        )
        return True
    except Exception:  # noqa: BLE001 -- auditing must never break the audited operation
        logger.warning(
            "scanner_ops.audit_failed event=%s -- operation continues", event,
            exc_info=True,
            extra={"event": "scanner_ops.audit_failed", "audited_event": event},
        )
        return False


async def record_worker_revoked(
    db, *, worker_id: str, reason: str, actor: str | None,
    workspace_id: uuid.UUID | None, site_id: uuid.UUID | None = None,
) -> bool:
    """Audit a P8-E revocation. Operator-triggered, so an actor is meaningful."""
    return await _safe_record(
        db,
        workspace_id=workspace_id,
        event=EVENT_WORKER_REVOKED,
        detail=_format_detail([
            ("worker_id", worker_id),
            ("site_id", str(site_id) if site_id else None),
            ("actor", normalise_actor(actor)),
            ("actor_authenticated", "false"),  # a CLI cannot authenticate a person
            ("outcome", "revoked"),
            ("reason", reason),
        ]),
    )


async def record_worker_drained(
    db, *, worker_id: str, reason: str, actor: str | None,
    workspace_id: uuid.UUID | None, site_id: uuid.UUID | None = None,
) -> bool:
    """Audit a Phase 8 graceful decommission. Operator-triggered, like a revocation.

    Records the FROM state explicitly: `drain_worker` only ever transitions out of
    `active`, so an auditor reading this knows the worker was leasing work up to this
    point -- which is the fact that matters when reconstructing what a decommissioned
    worker could have been handed.
    """
    return await _safe_record(
        db,
        workspace_id=workspace_id,
        event=EVENT_WORKER_DRAINED,
        detail=_format_detail([
            ("worker_id", worker_id),
            ("site_id", str(site_id) if site_id else None),
            ("actor", normalise_actor(actor)),
            ("actor_authenticated", "false"),  # a CLI cannot authenticate a person
            ("previous_status", "active"),
            ("new_status", "draining"),
            ("outcome", "draining"),
            ("reason", reason),
        ]),
    )


async def record_worker_reactivated(
    db, *, worker_id: str, reason: str, actor: str | None,
    workspace_id: uuid.UUID | None, site_id: uuid.UUID | None = None,
) -> bool:
    """Audit a SUCCESSFUL P8-F operator recovery. Operator-triggered, so an actor is
    meaningful.

    This is the ONLY event in this module that records a worker GAINING authority, which is
    exactly why it is audited as carefully as the ones that remove it: an auditor
    reconstructing an incident needs to see who readmitted a worker to the fleet, when, and
    on what stated grounds. The FROM state is recorded explicitly (`suspended`) because
    `reactivate_worker` can transition from nothing else -- so this row also proves the
    worker was NOT revoked or pending at the time.

    PROVENANCE. `actor` is what the operator CLAIMS; `os_user`/`source_host`/`source_pid`
    are what the process demonstrably IS. Both are recorded, and `actor_authenticated=false`
    still says plainly that neither is an authenticated identity. See `_source_identity()`
    for why the claimed value alone proved insufficient during the 2026-09-17 investigation.
    """
    os_user, source_host, source_pid = _source_identity()
    return await _safe_record(
        db,
        workspace_id=workspace_id,
        event=EVENT_WORKER_REACTIVATED,
        detail=_format_detail([
            ("worker_id", worker_id),
            ("site_id", str(site_id) if site_id else None),
            ("actor", normalise_actor(actor)),
            ("actor_type", ACTOR_TYPE_OPERATOR_CLI),
            ("actor_authenticated", "false"),  # a CLI cannot authenticate a person
            ("os_user", os_user),
            ("source_host", source_host),
            ("source_pid", source_pid),
            ("previous_status", "suspended"),
            ("new_status", "active"),
            ("outcome", "active"),
            ("result", "success"),
            ("reason", reason),
        ]),
    )


async def record_worker_reactivation_failed(
    db, *, worker_id: str, reason: str, actor: str | None, failure: str,
    observed_status: str | None = None,
    workspace_id: uuid.UUID | None = None, site_id: uuid.UUID | None = None,
) -> bool:
    """Audit a REFUSED reactivation attempt.

    THE GAP THIS CLOSES. Only successful recoveries were recorded, so the audit trail showed
    readmissions but never ATTEMPTS. That is the wrong half to keep: a refused attempt on a
    `revoked` worker is precisely the event an auditor most wants to see, and repeated
    refusals are the signature of someone probing the recovery path. A trail that records
    only what succeeded cannot distinguish "nobody tried" from "somebody tried and the
    guard held".

    `failure` is the stable machine-readable refusal code, and `observed_status` is the state
    the row was ACTUALLY in -- together they show which guard refused, without the auditor
    needing the source to interpret the row.

    NOTHING WAS WRITTEN when this is recorded: the transition was refused before any state
    change, so `new_status` is deliberately absent rather than reported as unchanged.
    """
    os_user, source_host, source_pid = _source_identity()
    return await _safe_record(
        db,
        workspace_id=workspace_id,
        event=EVENT_WORKER_REACTIVATION_FAILED,
        detail=_format_detail([
            ("worker_id", worker_id),
            ("site_id", str(site_id) if site_id else None),
            ("actor", normalise_actor(actor)),
            ("actor_type", ACTOR_TYPE_OPERATOR_CLI),
            ("actor_authenticated", "false"),
            ("os_user", os_user),
            ("source_host", source_host),
            ("source_pid", source_pid),
            ("observed_status", observed_status or PROVENANCE_UNKNOWN),
            ("outcome", "refused"),
            ("result", "failure"),
            ("failure", failure),
            ("reason", reason),
        ]),
    )


async def record_worker_reaped_stale(
    db, *, worker_id: str, stale_after_seconds: int,
    workspace_id: uuid.UUID | None, site_id: uuid.UUID | None = None,
) -> bool:
    """Audit ONE P8-F suspension. System-generated -- no human is involved, so the actor is
    `system` and never `unattributed` (which would imply a person we failed to identify)."""
    return await _safe_record(
        db,
        workspace_id=workspace_id,
        event=EVENT_WORKER_REAPED_STALE,
        detail=_format_detail([
            ("worker_id", worker_id),
            ("site_id", str(site_id) if site_id else None),
            ("actor", ACTOR_SYSTEM),
            ("previous_status", "active"),
            ("new_status", "suspended"),
            ("reason", f"no heartbeat for {int(stale_after_seconds)}s"),
        ]),
    )


async def record_emergency_transition(db, *, previous: bool, current: bool) -> bool:
    """Audit an OBSERVED change in the effective private-scanning emergency state (P8-D).

    Platform-scoped (`workspace_id=None`) because the kill switch is platform-wide.

    `source=observed_runtime_transition` is the load-bearing word: the sentinel is a
    filesystem act the application cannot attribute to a person, so this records what the
    manager OBSERVED, not who did it. Anything stronger would be a claim the system cannot
    support.
    """
    return await _safe_record(
        db,
        workspace_id=None,
        event=EVENT_EMERGENCY_TRANSITION,
        detail=_format_detail([
            ("subject", "private_scanning_emergency_state"),
            ("previous", "true" if previous else "false"),
            ("current", "true" if current else "false"),
            ("source", "observed_runtime_transition"),
            ("actor", ACTOR_SYSTEM),
            ("actor_authenticated", "false"),
        ]),
    )
