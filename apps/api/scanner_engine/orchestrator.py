import hashlib
import logging
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.events import ScanCompleted, emit as emit_event, subscribe as subscribe_event
from apps.api.core.observability import record_ai_decision, record_scan_result, record_tool_failure
from apps.api.modules.assets.models import Asset
from apps.api.modules.assets.service import upsert_asset
from apps.api.modules.attack.service import sync_attack_mappings
from apps.api.modules.authorization_scope.service import require_verified_target
from apps.api.modules.compliance.service import sync_mappings
from apps.api.modules.risk.service import upsert_risk_score
from apps.api.modules.scans.models import Scan
from apps.api.modules.vulnerabilities.service import ingest_finding
from apps.api.scanner_engine import evidence_store
from apps.api.scanner_engine.models import Evidence, ToolRun
from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY
from apps.api.scanner_engine.tool_runners.base import CommonFinding, classify_run

logger = logging.getLogger(__name__)


class AuthorizationRevoked(Exception):
    """Raised when a scan's authorization scope is no longer valid at execution
    time (revoked/expired between queueing and running)."""


class ExecutionRevoked(Exception):
    """Raised when THIS executor no longer owns the scan it is running (P1-1 P3).

    Ownership is revoked by the graceful-shutdown hook returning an interrupted scan to the
    queue (`running` -> `queued`, `execution_token` -> NULL) so it can be redispatched. The
    revoked executor must stop cooperatively and must NOT finalize: its outcome is no longer
    authoritative, and the row now belongs to whichever executor claims it next. Deliberately
    NOT an error path -- nothing failed, this execution was superseded."""


async def _load_scan(db: AsyncSession, scan_id: uuid.UUID) -> Scan:
    # scans is intentionally not RLS-protected; we read it by trusted id first,
    # THEN set the workspace RLS var so every subsequent read/write on
    # projects/targets/assets/authorization_scopes is correctly scoped.
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise ValueError(f"Scan {scan_id} not found")
    return scan


async def _claim_scan(db: AsyncSession, scan_id: uuid.UUID, execution_token: uuid.UUID) -> bool:
    """Atomically CLAIM a scan for execution (F3). A single conditional UPDATE uses the
    `status` column as the claim token: only a `queued` scan (first run) or a `failed`
    scan (retry) is claimable; a `running` or terminal scan is not. Returns True iff
    THIS caller won the claim. Prevents duplicate concurrent execution from acks_late
    redelivery / duplicate dispatch WITHOUT any long-held lock -- the row lock is held
    only for this one statement, which commits immediately (the multi-minute scan then
    runs lock-free). Under READ COMMITTED a losing worker updates 0 rows. Does NOT
    recover orphaned `running` scans (out of scope -- see F3b follow-up).

    The claim ALSO stamps `execution_token` (P1-1 P3): the claimable-status set is
    deliberately UNCHANGED -- this only records WHICH execution won, so every later
    ownership-sensitive write can be fenced against a superseded executor. The token is
    REQUIRED: an execution that did not record who it is could never fence its own terminal
    write, which is precisely the defect this exists to prevent."""
    result = await db.execute(
        text(
            "UPDATE scans SET status = 'running', started_at = now(), execution_token = :tok "
            "WHERE id = :id AND status IN ('queued', 'failed') RETURNING id"
        ),
        {"id": str(scan_id), "tok": str(execution_token)},
    )
    claimed = result.first() is not None
    await db.commit()  # make the claim durable + visible to other workers
    return claimed


async def reap_orphaned_scans(db: AsyncSession, timeout_seconds: int) -> int:
    """Recover scans stuck in 'running' past `timeout_seconds` -- a worker that claimed
    the scan (M4.6.2) then crashed/was lost, so acks_late redelivery just skips it and
    the scan would otherwise stay 'running' forever (Phase 1.2 / F3b).

    A SINGLE atomic conditional UPDATE marks them 'failed': it touches ONLY over-threshold
    'running' scans -- never completed/failed/cancelled or recently-started ones -- with
    no per-row race. Returns how many were recovered.

    Why 'failed' and NOT re-queue: the reaper never re-dispatches a task, so it can never
    create a duplicate execution. If a marked scan is later retried, the atomic claim
    (queued/failed only) still guarantees at-most-one executor.

    The SAME statement clears `execution_token`, so the transition is `running + token X` ->
    `failed + token NULL`. That is what REVOKES a 'crashed' worker that was merely slow and
    is in fact still alive: it can no longer finalize (terminalization is fenced on
    `status='running'` AND the token), and -- because the token no longer matches -- its
    losing terminal write is correctly recognised as lost ownership, so it records no
    duplicate lifecycle metric, publishes no second ScanCompleted, and is not dead-lettered.
    Without the clear, that executor still "owned" a terminal row and fell through into
    exactly those duplicate signals. Note this is a REVOCATION, not an overwrite: the
    reaper's 'failed' stands, and the slow worker's own outcome is discarded.

    A replacement executor is never at risk: a fresh claim sets `started_at = now()`, so a
    re-claimed scan is not over the threshold and this statement cannot match it.

    A clear failure reason is persisted into config.recovery (reason/recovered_at/
    running_timeout_seconds) in the SAME atomic statement -- additive JSONB, no schema or
    API change (ScanRead already exposes config), so the orphaned outcome is queryable and
    visible without altering the lifecycle."""
    reason = (
        f"orphaned: scan remained RUNNING beyond the {int(timeout_seconds)}s recovery "
        f"threshold with no worker completion; worker/process presumed dead"
    )
    # Explicit ::text/::int casts are REQUIRED: params used only inside jsonb_build_object
    # (which accepts "any") have no inferable type for asyncpg. A distinct :timeout_val
    # (vs :secs for make_interval) avoids one param serving two type contexts.
    result = await db.execute(
        text(
            "UPDATE scans SET status = 'failed', completed_at = now(), execution_token = NULL, "
            "config = coalesce(config, '{}'::jsonb) || jsonb_build_object("
            "  'recovery', jsonb_build_object("
            "    'reason', :reason ::text, 'recovered_at', now(), "
            "    'running_timeout_seconds', :timeout_val ::int"
            "  )"
            ") "
            "WHERE status = 'running' AND started_at < now() - make_interval(secs => :secs) "
            "RETURNING id"
        ),
        {"reason": reason, "timeout_val": int(timeout_seconds), "secs": int(timeout_seconds)},
    )
    reaped = len(result.fetchall())
    await db.commit()
    return reaped


async def _finalize_status(
    db: AsyncSession, scan: Scan, new_status: str, execution_token: uuid.UUID
) -> bool:
    """Atomically move a scan from 'running' to a terminal status (Phase 1.5).

    The write is CONDITIONAL on status still being 'running' (mirrors the atomic claim),
    so it can NEVER clobber a scan that was cancelled (or otherwise moved terminal)
    concurrently by the API. Returns True iff THIS caller performed the terminal write;
    False means someone else already finalized it (e.g. a cancel) and the caller must not
    overwrite. Refreshes the ORM object so callers see the authoritative status.

    OWNERSHIP FENCE (P1-1 P3): the write additionally requires the row to still be owned by
    THIS execution. Without that, an executor whose scan had been requeued and then
    re-claimed by a NEW executor would satisfy `status='running'` and clobber the new
    owner's scan with its own stale outcome. On success the token is cleared -- a terminal
    scan is owned by nobody. The token is REQUIRED: there is deliberately no way to disable
    the fence, so a caller cannot silently perform an unowned terminal write."""
    result = await db.execute(
        text(
            "UPDATE scans SET status = :st, completed_at = now(), execution_token = NULL "
            "WHERE id = :id AND status = 'running' AND execution_token = :tok ::uuid "
            "RETURNING id"
        ),
        {"st": new_status, "id": str(scan.id), "tok": str(execution_token)},
    )
    won = result.first() is not None
    await db.commit()
    await db.refresh(scan)
    return won


_TERMINAL_STATUSES = ("completed", "completed_with_errors", "failed", "cancelled")


def _ownership_lost_reason(status: str | None) -> str:
    """WHY this execution no longer owns its scan, derived from the row's CURRENT status.

    Ownership can be lost three different ways, and reporting all of them as a shutdown
    requeue is misleading -- the orphan reaper terminalizes a scan (and revokes its token)
    with no shutdown involved at all."""
    if status == "queued":
        return "requeued_on_shutdown"      # graceful-shutdown hook returned it to the queue
    if status == "running":
        return "reclaimed_by_new_owner"    # a later executor already claimed it
    if status in _TERMINAL_STATUSES:
        return "already_terminal"          # reaper / cancellation / another finalizer won
    return "ownership_lost"


async def _execution_stop_reason(
    db: AsyncSession, scan_id: uuid.UUID, execution_token: uuid.UUID
) -> str | None:
    """Why this execution should stop right now, or None to continue (Phase 1.5 + P1-1 P3).

    One fresh single-statement read; under READ COMMITTED it sees commits made on other
    connections. Returns:
      * 'cancelled' -- the user cancelled (pre-existing cooperative cancellation), or
      * 'revoked'   -- this execution no longer owns the scan: the graceful-shutdown hook
                       returned it to the queue, or a later executor has since claimed it.
    Checked between tool runs AND once more immediately before each tool is spawned, so a
    superseded executor never deliberately starts new work against the target. It cannot
    make an already-running tool stop, so it shrinks the overlap window rather than removing
    it; what actually rules out a concurrent replacement executor is the shutdown timing
    (see `test_shutdown_timing_invariant_*`)."""
    row = (await db.execute(
        text("SELECT status, execution_token FROM scans WHERE id = :id"), {"id": str(scan_id)}
    )).first()
    if row is None:
        return "revoked"  # row vanished: we certainly no longer own it
    status, current_token = row[0], row[1]
    if status == "cancelled":
        return "cancelled"
    if status != "running" or str(current_token or "") != str(execution_token):
        return "revoked"
    return None


async def run_scan(
    db: AsyncSession, scan_id: uuid.UUID, execution_token: uuid.UUID | None = None
) -> None:
    # EXECUTION OWNERSHIP (P1-1 P3): one token identifies THIS execution for its whole life.
    # Installed by the atomic claim below and required by every terminal write, so an
    # executor that is superseded mid-run (graceful-shutdown requeue) can neither finalize
    # nor be confused with the executor that takes over. The task layer passes its own token
    # so it can fence the soft-timeout path too; direct callers get a fresh one.
    execution_token = execution_token or uuid.uuid4()
    scan = await _load_scan(db, scan_id)

    # ATOMIC CLAIM (F3): a task can be re-delivered after a worker crash (acks_late),
    # duplicated, or retried. Claim the scan with a single conditional UPDATE (status
    # is the claim token) -- only a queued (first run) or failed (retry) scan is
    # claimable; a running or terminal scan is not. This prevents duplicate concurrent
    # execution without any long-held lock. If we don't win the claim, skip cleanly.
    claimed = await _claim_scan(db, scan_id, execution_token)
    await db.refresh(scan)  # resync the ORM object after the raw claim UPDATE
    if not claimed:
        logger.info("scan.skip_not_claimable scan=%s status=%s", scan.id, scan.status)
        return

    await db.execute(
        text("SELECT set_config('app.current_workspace_id', :wid, false)"),
        {"wid": str(scan.workspace_id)},
    )
    # status='running' + started_at were set atomically by _claim_scan above.

    scan_started = time.monotonic()
    logger.info(
        "scan.start scan=%s workspace=%s project=%s target=%s requested=%s ai_planner=%s",
        scan.id, scan.workspace_id, scan.project_id, scan.target_id,
        scan.config.get("requested_modules", []), bool(scan.config.get("use_ai_planner")),
    )

    try:
        # Re-check the guardrail at execution time, not just at creation:
        # authorization can be revoked/expire between queueing and running
        # (blueprint §7 -- gate again before active tools). The scope also tells
        # us whether active-testing tools (nuclei/...) are permitted.
        scope = await require_verified_target(db, scan.workspace_id, scan.project_id, scan.target_id)

        from apps.api.modules.projects.models import Target

        target_row = await db.get(Target, scan.target_id)
        if target_row is None:
            raise ValueError("Target disappeared")

        # SSRF re-check at execution time (defense in depth): the target may
        # predate the creation-time guard, or its DNS may now resolve to a
        # forbidden address (rebinding). A forbidden target hard-aborts the scan --
        # this is a safety failure, not a fail-soft tool error.
        import socket as _socket

        from apps.api.scanner_engine.net_guard import (
            TargetNotAllowed,
            _host_from_value,
            resolve_and_validate,
        )

        if target_row.type in ("domain", "ip_range"):
            try:
                resolve_and_validate(_host_from_value(target_row.value))
            except TargetNotAllowed as exc:
                raise ValueError(f"Target blocked by SSRF policy: {exc}")
            except _socket.gaierror:
                pass  # unresolvable now; tools will fail cleanly, no scan of a bad host

        requested = scan.config.get("requested_modules", [])
        discovered: list[CommonFinding] = []
        tool_statuses: list[str] = []

        # AUTONOMOUS AGENT (opt-in `use_agent`): the RedTeamAgent chooses tools
        # dynamically by kill-chain phase + results, within the engagement's Rules
        # of Engagement (safety enforced in code). Supersedes the AI planner + the
        # fixed pipeline. Fail-soft: an AI failure ends the loop cleanly.
        if scan.config.get("use_agent"):
            tool_statuses = await _run_agent_driven(db, scan, target_row, scope, execution_token)
        else:
            # Opt-in AI planning (blueprint §7 step 2). When enabled, the AI Planner
            # proposes which of the requested tools to run and in what order; its
            # output is allowlist-enforced in code (planner._sanitize) so it can only
            # re-order/prune, never introduce a tool. Default off -> deterministic
            # phase order, unchanged behavior for every existing scan.
            #
            # FAIL-FAST: the user opted into AI planning, so if it cannot run (no key)
            # or fails (API/parse error), the scan FAILS loudly -- we do NOT silently
            # fall back and pretend AI was involved.
            if scan.config.get("use_ai_planner"):
                from apps.api.ai_agent.planner import AIPlanner
                from apps.api.ai_agent.providers.usage import collect_ai_usage
                from apps.api.ai_agent.usage_repo import persist_ai_usage

                with collect_ai_usage(
                    agent_role="planner",
                    workspace_id=str(scan.workspace_id),
                    scan_id=str(scan.id),
                ) as planner_usage:
                    plan = await AIPlanner().plan(
                        db,
                        scan_id=scan.id,
                        target_type=target_row.type,
                        target_value=target_row.value,
                        requested_modules=requested,
                        active_testing_allowed=scope.active_testing_allowed,
                    )
                requested = plan.tool_sequence
                await db.commit()
                await persist_ai_usage(planner_usage)

            runners = [TOOL_REGISTRY[m]() for m in requested if m in TOOL_REGISTRY]
            # Deterministic recon pipeline: run in phase order regardless of request
            # order (subfinder -> httpx -> naabu -> nmap -> nuclei).
            runners.sort(key=lambda r: r.phase)

            # Findings accumulate across the pipeline so later tools build on earlier
            # ones (httpx probes subfinder's subdomains; nmap deep-scans naabu ports).
            for runner in runners:
                # Cooperative stop (Phase 1.5 + P1-1 P3): stop launching further tools the
                # moment the scan is cancelled OR this execution is superseded.
                stop_reason = await _execution_stop_reason(db, scan.id, execution_token)
                if stop_reason == "cancelled":
                    # The terminal write below then loses the atomic race and leaves the
                    # 'cancelled' state intact.
                    logger.info(
                        "scan.cancelled_stop scan=%s tool=%s (skipping remaining tools)", scan.id, runner.name,
                        extra={"event": "scan.cancelled_stop", "scan_id": str(scan.id),
                               "reason": "cancelled", "tool": runner.name},
                    )
                    break
                if stop_reason == "revoked":
                    # We no longer own this scan -- abandon it BEFORE running another tool,
                    # so the executor that takes over never overlaps with this one.
                    raise ExecutionRevoked(f"execution superseded before tool {runner.name}")
                if runner.applicable_target_types is not None and target_row.type not in runner.applicable_target_types:
                    continue
                # Active-testing gate: tools that send payloads run only when the
                # scope explicitly permits it (authorization can be revoked between
                # queue and execution -- record a visible skipped run).
                if runner.requires_active_testing and not scope.active_testing_allowed:
                    db.add(
                        ToolRun(
                            scan_id=scan.id,
                            tool_name=runner.name,
                            tool_version=runner.version,
                            status="skipped_unauthorized",
                            command_hash="",
                            completed_at=datetime.now(timezone.utc),
                        )
                    )
                    await db.commit()
                    continue
                findings, status = await _run_single_tool(
                    db, scan, runner, target_row.value, discovered, target_row.criticality,
                    target_row.type, execution_token,
                )
                discovered.extend(findings)
                tool_statuses.append(status)

        # The scan's status honestly reflects its tools. RESILIENT PIPELINE: a
        # single tool's failure or partial run no longer aborts the whole scan --
        # evidence and any parseable findings from the other tools are kept, and a
        # report can still be generated. Aggregate over the tools that ACTUALLY
        # executed (skipped_unauthorized runs are intentional, not failures):
        #   failed                -> every executed tool failed
        #   completed_with_errors -> at least one tool failed or ran partial
        #   completed             -> all executed tools succeeded (or none ran)
        if tool_statuses and all(s == "failed" for s in tool_statuses):
            new_status = "failed"
        elif any(s in ("failed", "partial") for s in tool_statuses):
            new_status = "completed_with_errors"
        else:
            new_status = "completed"

        # Best-effort AI attack-path narrative over all of this scan's findings.
        # Fully fail-soft: an AI failure never changes the scan status or aborts.
        await _synthesize_attack_narrative(db, scan)
    except ExecutionRevoked as exc:
        # SUPERSEDED, not failed (P1-1 P3). Something else now owns this scan -- the
        # graceful-shutdown requeue, a later executor, or the orphan reaper terminalizing it.
        # Emit NO terminal write, NO lifecycle metric and NO ScanCompleted event: reporting a
        # result for a scan we no longer own would be a false outcome. Return normally so the
        # task acks; recovery is whatever the current owner does with the row.
        try:
            await db.refresh(scan)  # report the ACTUAL reason, not an assumed shutdown
        except Exception:  # noqa: BLE001 -- row vanished; the generic reason still applies
            pass
        _revocation_reason = _ownership_lost_reason(scan.status)
        logger.warning(
            "scan.execution_revoked scan=%s duration=%.2fs -- %s; abandoning to the current owner",
            scan.id, time.monotonic() - scan_started, exc,
            extra={"event": "scan.execution_revoked", "scan_id": str(scan.id),
                   "reason": _revocation_reason, "status": scan.status,
                   "duration_s": round(time.monotonic() - scan_started, 2),
                   **({"shutdown_reason": "worker_shutting_down"}
                      if _revocation_reason == "requeued_on_shutdown" else {})},
        )
        return
    except Exception as exc:
        _duration = time.monotonic() - scan_started
        # ROLL BACK FIRST. The exception may be a failed flush (observed: a duplicate
        # vulnerability_evidence PK during ingest), which leaves this Session in
        # PendingRollbackError state -- every subsequent statement on it, and even a lazy
        # attribute load like `scan.id`, re-raises until the transaction is rolled back.
        # Without this, `_finalize_status` below crashed instead of marking the scan failed,
        # so the task died and the scan sat 'running' until the reaper recovered it hours
        # later. Rolling back discards only the failed, uncommitted ingest work (already lost
        # anyway); the atomic terminal write is its own statement and is unaffected. Best-
        # effort: if the connection itself is gone, the terminal write below will surface
        # that, and the reaper remains the final backstop.
        try:
            await db.rollback()
            # rollback() EXPIRES every ORM object on the session, so `scan.status` /
            # `scan.execution_token` below and `_finalize_status`'s own `db.refresh(scan)`
            # would otherwise trigger a lazy reload at an awkward moment. Re-load `scan`
            # explicitly against the now-clean session so those reads (and the revocation
            # check) see current, committed state -- which for a requeue is exactly the
            # cleared token they must observe.
            scan = await _load_scan(db, scan_id)
        except Exception:  # noqa: BLE001 -- rollback/reload is recovery; never mask `exc`
            logger.debug("scan.finalize_rollback_failed scan_id=%s", scan_id, exc_info=True)
        # Atomic terminal write: only running -> failed, and only while WE still own it. If a
        # cancel landed concurrently (Phase 1.5), we lose the race and MUST NOT overwrite
        # 'cancelled'; if ownership was revoked, we lose it too and must not report anything.
        won = await _finalize_status(db, scan, "failed", execution_token)
        if not won and scan.status != "cancelled" and str(scan.execution_token or "") != str(execution_token):
            # Ownership was lost before this write (requeue, re-claim, or the orphan reaper
            # terminalizing us): the scan ran, but its outcome is not ours to record. Same
            # contract as ExecutionRevoked.
            _revocation_reason = _ownership_lost_reason(scan.status)
            logger.warning(
                "scan.execution_revoked scan=%s status=%s duration=%.2fs reason=%s -- lost the "
                "terminal write; abandoning to the current owner",
                scan.id, scan.status, _duration, _revocation_reason,
                extra={"event": "scan.execution_revoked", "scan_id": str(scan.id),
                       "status": scan.status, "reason": _revocation_reason,
                       "duration_s": round(_duration, 2),
                       **({"shutdown_reason": "worker_shutting_down"}
                          if _revocation_reason == "requeued_on_shutdown" else {})},
            )
            return
        if not won and scan.status == "cancelled":
            logger.info(
                "scan.cancelled_during_run scan=%s -- leaving cancelled, not retrying", scan.id,
                extra={"event": "scan.cancelled_during_run", "scan_id": str(scan.id),
                       "reason": "cancelled", "duration_s": round(_duration, 2)},
            )
            return  # user cancellation is terminal; do not retry a cancelled scan
        record_scan_result("failed", _duration)  # Phase 1.3 metric (real lifecycle event)
        logger.error(
            "scan.failed scan=%s duration=%.2fs error=%s",
            scan.id, _duration, exc,
            extra={"event": "scan.failed", "scan_id": str(scan.id), "status": "failed",
                   "duration_s": round(_duration, 2), "reason": type(exc).__name__},
            exc_info=True,
        )
        await _publish_scan_completed(db, scan)
        raise

    _duration = time.monotonic() - scan_started
    # Atomic terminal write: only running -> terminal, so a scan cancelled mid-run (or
    # already finalized) is never clobbered back to completed (Phase 1.5).
    won = await _finalize_status(db, scan, new_status, execution_token)
    if not won:
        if scan.status != "cancelled" and str(scan.execution_token or "") != str(execution_token):
            # P1-1 P3: requeued, already re-claimed, or reaped while we were finishing. The
            # work ran, but this executor no longer owns the row -- record nothing, publish
            # nothing.
            _revocation_reason = _ownership_lost_reason(scan.status)
            logger.warning(
                "scan.execution_revoked scan=%s status=%s reason=%s -- lost the terminal "
                "write; abandoning to the current owner",
                scan.id, scan.status, _revocation_reason,
                extra={"event": "scan.execution_revoked", "scan_id": str(scan.id),
                       "status": scan.status, "reason": _revocation_reason,
                       **({"shutdown_reason": "worker_shutting_down"}
                          if _revocation_reason == "requeued_on_shutdown" else {})},
            )
            return
        logger.info(
            "scan.finalize_skipped scan=%s status=%s -- already terminal, not overwriting",
            scan.id, scan.status,
            extra={"event": "scan.finalize_skipped", "scan_id": str(scan.id),
                   "status": scan.status, "reason": "already_terminal"},
        )
        return
    record_scan_result(scan.status, _duration)  # Phase 1.3: success/failed + duration; wires outcomes
    logger.info(
        "scan.finished scan=%s status=%s duration=%.2fs tools_run=%d",
        # tool_statuses is populated by BOTH branches (the agent path returns it,
        # the deterministic path appends to it), so it is the correct count here.
        scan.id, scan.status, _duration, len(tool_statuses),
        extra={"event": "scan.finished", "scan_id": str(scan.id), "status": scan.status,
               "duration_s": round(_duration, 2), "tools_run": len(tool_statuses)},
    )
    await _publish_scan_completed(db, scan)


async def _emit_scan_notification(db: AsyncSession, scan: Scan) -> None:
    """Best-effort in-app notification for a finished scan -- a failure here must
    never affect the scan outcome. Runs with the workspace RLS GUC already set."""
    try:
        from apps.api.modules.notifications.service import notify_scan_finished

        await notify_scan_finished(db, scan)
        await db.commit()
    except Exception:
        logger.warning("scan.notify_failed scan=%s", scan.id, exc_info=True)


async def _on_scan_completed(event: ScanCompleted) -> None:
    """Default ScanCompleted subscriber: the in-app notification. Behaviorally
    identical to the previous direct call; now routed through the event bus so
    other reactions can subscribe without touching the orchestrator."""
    if event.db is not None and event.scan is not None:
        await _emit_scan_notification(event.db, event.scan)


# Register the built-in subscriber at import time, so it is wired wherever the
# orchestrator runs (API process and Celery worker alike).
subscribe_event(ScanCompleted, _on_scan_completed)


async def _publish_scan_completed(db: AsyncSession, scan: Scan) -> None:
    await emit_event(
        ScanCompleted(scan_id=scan.id, workspace_id=scan.workspace_id, status=scan.status, db=db, scan=scan)
    )


async def _run_agent_driven(
    db: AsyncSession, scan: Scan, target_row, scope, execution_token: uuid.UUID
) -> list[str]:
    """Agent-driven engagement (M2): the single RedTeamAgent chooses tools
    dynamically by kill-chain phase + accumulated results, within the engagement's
    Rules of Engagement (safety enforced in code, not prompt). Every decision + tool
    run is recorded to agent_steps; engagement_state tracks the live phase. Reuses
    the deterministic `_run_single_tool` for execution. FAIL-SOFT: an AI failure
    ends the loop cleanly -- deterministic tools already run are kept -- and a
    per-tool safety violation blocks just that tool, never the engagement."""
    import asyncio

    from apps.api.ai_agent.agent import AgentDecision, RedTeamAgent
    from apps.api.ai_agent.prompts.agent import AGENT_PROMPT_VERSION
    from apps.api.ai_agent.providers.usage import collect_ai_usage
    from apps.api.ai_agent.usage_repo import persist_ai_usage
    from apps.api.core.config import get_settings
    from apps.api.modules.agent.models import AgentStep, EngagementState
    from apps.api.modules.agent.repo import latest_agent_decision, persist_agent_decision
    from apps.api.modules.attack.service import scan_kill_chain_steps
    from apps.api.scanner_engine import attack_graph as ag
    from apps.api.scanner_engine.attack_graph import AccessEvidence, AssetEvidence
    from apps.api.scanner_engine.safety import RulesOfEngagement, SafetyViolation, assert_action_allowed
    from apps.api.scanner_engine.state_projection import (
        ActionOutcome,
        summarize_actions,
        summarize_attack_context,
        summarize_attack_graph,
        summarize_findings,
        summarize_prior_beliefs,
    )

    settings = get_settings()
    roe = RulesOfEngagement.from_config(scan.config)
    agent = RedTeamAgent()

    # GET-OR-CREATE (F3.3): the engagement is one-per-scan (uq_engagement_state_scan). On a
    # re-run (F2 transient retry / reaper reclaim / DLQ replay) one already exists -- REUSE it and
    # SKIP the expensive AI agent loop entirely (skip-on-retry: no re-spend, no LLM calls). This
    # also removes the IntegrityError a second INSERT would otherwise raise on retry. Finalize
    # safely from the tool_runs the prior run already persisted, so run_scan's status aggregation
    # reflects the real work without restarting the agent.
    existing = await db.scalar(
        select(EngagementState).where(EngagementState.scan_id == scan.id)
    )
    if existing is not None:
        logger.info(
            "scan.agent_engagement_reused scan=%s engagement_status=%s -- skipping AI agent loop on re-run",
            scan.id, existing.status,
            extra={"event": "scan.agent_engagement_reused", "scan_id": str(scan.id),
                   "engagement_status": existing.status},
        )
        prior_statuses = list(
            await db.scalars(select(ToolRun.status).where(ToolRun.scan_id == scan.id))
        )
        return [s for s in prior_statuses if s != "skipped_unauthorized"]

    state = EngagementState(
        workspace_id=scan.workspace_id,
        scan_id=scan.id,
        status="running",
        current_phase="reconnaissance",
        objective=f"Safe autonomous red-team assessment of {target_row.value}",
    )
    db.add(state)
    await db.flush()
    await db.commit()  # F3.3: persist immediately so a retry reliably finds it and skips the loop

    discovered: list[CommonFinding] = []
    tool_statuses: list[str] = []
    outcomes: list[ActionOutcome] = []  # the memory of what has been tried (blueprint §14)
    asset_evidence: list[AssetEvidence] = []  # assets w/ originating tool, for the attack graph
    access_evidence: list[AccessEvidence] = []  # confirmed access, accumulated across rounds
    already_run: set[str] = set()
    step_no = 0
    # M4.4.3 deterministic budget counters (agent_max_steps stays the HARD ceiling).
    loop_started = time.monotonic()
    ai_calls = 0
    stall = 0  # consecutive tool runs that produced no new findings

    def _budget_snapshot() -> dict:
        return {
            "step_no": step_no,
            "max_steps": settings.agent_max_steps,
            "ai_calls": ai_calls,
            "elapsed_seconds": round(time.monotonic() - loop_started, 2),
            "min_confidence": settings.agent_min_confidence,
            "stall": stall,
        }

    def _budget_stop_reason() -> str | None:
        """Deterministic termination precedence (checked BEFORE each AI call). None
        means continue. Never extends past agent_max_steps (the while guard)."""
        if settings.agent_max_ai_calls and ai_calls >= settings.agent_max_ai_calls:
            return "ai_call_budget_exhausted"
        if settings.agent_time_budget_seconds and (time.monotonic() - loop_started) >= settings.agent_time_budget_seconds:
            return "time_budget_exhausted"
        if settings.agent_stall_limit and stall >= settings.agent_stall_limit:
            return "no_progress"
        return None

    async def _rebuild_graph(new_access: list[AccessEvidence] | None = None) -> dict:
        """Deterministically (re)build the evidence-driven attack graph from all
        accumulated evidence and persist it to engagement_state. Idempotent -- the
        LLM never writes here (blueprint §7/§18). Confirmed access ACCUMULATES so a
        rebuild never drops access nodes across reasoning rounds (M4.4.4)."""
        if new_access:
            access_evidence.extend(new_access)
        graph_findings = await _graph_findings(db, scan)
        state.attack_graph = ag.update_graph(
            state.attack_graph or {},
            assets=asset_evidence,
            findings=graph_findings,
            access=access_evidence or None,
            now=datetime.now(timezone.utc).isoformat(),
        )
        return state.attack_graph

    def _record(phase, action_type, tool, tier, rationale, result, status):
        step = AgentStep(
            workspace_id=scan.workspace_id,
            scan_id=scan.id,
            step_no=step_no,
            phase=phase,
            action_type=action_type,
            tool_or_module=tool,
            safety_tier=tier,
            rationale=(rationale or None) and rationale[:2000],
            result_summary=(result or None) and result[:2000],
            status=status,
        )
        db.add(step)
        return step

    async def _persist_decision(decision, step, budget_state=None) -> None:
        """Persist the STRUCTURED reasoning audit (agent_decisions) for this cycle,
        hard-linked to its AgentStep. AgentStep is unchanged -- this is complementary
        (blueprint M4.4). Flush first so the step has an id to reference."""
        await db.flush()
        await persist_agent_decision(
            db,
            workspace_id=scan.workspace_id,
            scan_id=scan.id,
            step_no=step_no,
            decision=decision,
            agent_step_id=step.id,
            budget_state=budget_state or {"step_no": step_no, "max_steps": settings.agent_max_steps},
        )

    async def _decision_loop() -> None:
        """One reasoning round: the agent proposes candidates, the CODE selects +
        validates + executes DETECTION tools from the allowlist, until it finishes or
        a deterministic budget stops it. Continues across rounds from the same
        step/budget counters and accumulated `already_run`. The agent NEVER selects
        exploitation -- that stays deterministic and gated in the outer round."""
        nonlocal step_no, ai_calls, stall
        while step_no < settings.agent_max_steps:
            # Cooperative stop (Phase 1.5 + P1-1 P3): break out of the reasoning loop as soon
            # as the scan is cancelled, before spending another AI call or tool run. The
            # outer atomic terminal write then leaves the 'cancelled' state intact.
            agent_stop = await _execution_stop_reason(db, scan.id, execution_token)
            if agent_stop == "cancelled":
                logger.info(
                    "scan.cancelled_stop scan=%s (agent loop, step=%d)", scan.id, step_no,
                    extra={"event": "scan.cancelled_stop", "scan_id": str(scan.id),
                           "reason": "cancelled", "step_no": step_no},
                )
                break
            if agent_stop == "revoked":
                # Superseded mid-engagement: stop before another AI call or tool run.
                raise ExecutionRevoked(f"execution superseded at agent step {step_no}")
            # Deterministic budget stop (checked before spending an AI call). Recorded as
            # a finish decision so the termination reason is auditable in agent_decisions.
            budget_stop = _budget_stop_reason()
            if budget_stop:
                fin = AgentDecision(
                    "finish", None, state.current_phase, f"budget stop: {budget_stop}",
                    agent._client.model_version, AGENT_PROMPT_VERSION, stop_reason=budget_stop,
                )
                step = _record(state.current_phase, "decision", None, None, fin.summary(), "engagement stopped (budget)", "executed")
                await _persist_decision(fin, step, budget_state=_budget_snapshot())
                step_no += 1  # every persisted decision consumes a unique step_no (across rounds)
                await db.commit()
                break

            available = agent.available_tools(
                target_type=target_row.type,
                active_testing_allowed=scope.active_testing_allowed,
                roe=roe,
                already_run=already_run,
            )
            # Live ATT&CK / kill-chain context from the findings so far, so the agent
            # reasons over which phases are already evidenced (not just which tools
            # ran) -- makes ATT&CK a decision input, not a report section (§16/§17).
            attack_summary = summarize_attack_context(await scan_kill_chain_steps(db, scan.id))
            # Evidence-driven attack graph (asset->service->finding->technique + access),
            # rebuilt from accumulated evidence and fed back into reasoning (blueprint §7).
            graph = await _rebuild_graph()
            # Belief continuity (M4.4.2): carry the PREVIOUS cycle's structured reasoning
            # forward from the persisted agent_decisions row -- hypotheses stay UNVERIFIED.
            prior = await latest_agent_decision(db, scan.id)
            prior_beliefs = (
                summarize_prior_beliefs(prior.observations, prior.inferences, prior.hypotheses)
                if prior else "(none yet)"
            )
            with collect_ai_usage(
                agent_role="agent", workspace_id=str(scan.workspace_id), scan_id=str(scan.id)
            ) as usage:
                decision = await asyncio.to_thread(
                    agent.decide,
                    target_type=target_row.type,
                    target_value=target_row.value,
                    current_phase=state.current_phase,
                    findings_summary=summarize_findings(discovered),
                    attack_summary=attack_summary,
                    actions_summary=summarize_actions(outcomes),
                    graph_summary=summarize_attack_graph(graph),
                    objective=state.objective or "",
                    prior_beliefs=prior_beliefs,
                    min_confidence=settings.agent_min_confidence,
                    available=available,
                )
            ai_calls += 1
            record_ai_decision(decision.action)  # Phase 1.3: agent decisions by action
            await persist_ai_usage(usage)

            if decision.action != "run_tool" or not decision.tool:
                step = _record(decision.phase, "decision", None, None, decision.summary(), "engagement finished", "executed")
                await _persist_decision(decision, step, budget_state=_budget_snapshot())
                step_no += 1  # every persisted decision consumes a unique step_no (across rounds)
                await db.commit()
                break

            runner = TOOL_REGISTRY[decision.tool]()
            # Safety gate (belt and suspenders -- available_tools already filtered).
            try:
                assert_action_allowed(safety_tier=runner.safety_tier, roe=roe)
            except SafetyViolation as exc:
                step = _record(decision.phase, "tool_run", decision.tool, runner.safety_tier, decision.summary(), f"BLOCKED: {exc}", "blocked")
                await _persist_decision(decision, step, budget_state=_budget_snapshot())
                outcomes.append(ActionOutcome(decision.tool, "blocked", str(exc)[:120]))
                already_run.add(decision.tool)
                await db.commit()
                step_no += 1
                continue

            findings, status = await _run_single_tool(
                db, scan, runner, target_row.value, discovered, target_row.criticality,
                target_row.type, execution_token,
            )
            discovered.extend(findings)
            # Tag each discovered asset with the tool that found it, for graph provenance.
            asset_evidence.extend(
                AssetEvidence(asset_type=f.asset_type, value=f.value, tool=runner.name, metadata=f.metadata)
                for f in findings
            )
            tool_statuses.append(status)
            outcomes.append(ActionOutcome(decision.tool, status, f"{len(findings)} finding(s)"))
            already_run.add(decision.tool)
            state.current_phase = decision.phase
            # Stall detection (M4.4.3): a tool run that yields no new findings advances the
            # no-progress counter; any new evidence resets it.
            stall = stall + 1 if not findings else 0
            step = _record(decision.phase, "tool_run", decision.tool, runner.safety_tier, decision.summary(), f"{status}: {len(findings)} finding(s)", status)
            await _persist_decision(decision, step, budget_state=_budget_snapshot())
            await db.commit()
            step_no += 1

    # OUTER ROUNDS (M4.4.4): recon/detection reasoning, then deterministic gated
    # exploitation, then -- if exploitation produced NEW confirmed access and a round
    # remains -- RE-ENTER so the next reasoning cycle sees that access (feedback only;
    # the agent never selects exploitation). Default agent_max_rounds=1 == prior behavior.
    round_no = 0
    while round_no < settings.agent_max_rounds:
        await _decision_loop()

        # EXPLOITATION PHASE -- gated, deterministic, SAFE. Runs only when the RoE
        # enables it (deployment + engagement); never driven by the model, so a
        # misbehaving model can't trigger it. Each attempt additionally requires host
        # approval + passes the safety gate.
        new_access: list = []
        if roe.exploitation_enabled:
            state.current_phase = "exploitation"
            confirmed = await _run_exploitation_phase(db, scan, target_row, roe, step_no)
            if confirmed:
                # Keep the M2 confirmed_access key (back-compat) AND fold the confirmed
                # access into the evidence-driven graph as access nodes on their hosts.
                state.attack_graph = {
                    **(state.attack_graph or {}),
                    "confirmed_access": [
                        {"target": r.target, "access_type": r.access_type, "module": r.module, "proof": r.proof}
                        for r in confirmed
                    ],
                }
                new_access = [
                    AccessEvidence(target=r.target, access_type=r.access_type, module=r.module, proof=r.proof)
                    for r in confirmed
                    if r.exploitable
                ]
                await _rebuild_graph(new_access=new_access)

        round_no += 1
        # Re-enter only if exploitation produced new access AND a round remains, so the
        # NEXT reasoning cycle consumes the confirmed access (feedback only).
        if not new_access or round_no >= settings.agent_max_rounds:
            break

    state.status = "completed"
    await db.commit()
    return tool_statuses


async def _graph_findings(db: AsyncSession, scan: Scan) -> list:
    """Collect this scan's ingested vulnerabilities as FindingEvidence for the attack
    graph: each finding's deterministic ATT&CK techniques (from attack_mappings) and
    the value of the asset it was resolved to (vuln.asset_id -> asset), so the graph
    can link Finding -> Service without inventing a location. Pure read; the graph
    construction itself is deterministic and evidence-only."""
    from collections import defaultdict

    from apps.api.modules.attack.models import AttackMapping
    from apps.api.modules.vulnerabilities.models import Vulnerability
    from apps.api.scanner_engine.attack_graph import FindingEvidence

    vulns = list(await db.scalars(select(Vulnerability).where(Vulnerability.last_seen_scan_id == scan.id)))
    if not vulns:
        return []

    vuln_ids = [v.id for v in vulns]
    techniques: dict = defaultdict(list)
    for m in await db.scalars(select(AttackMapping).where(AttackMapping.vulnerability_id.in_(vuln_ids))):
        techniques[m.vulnerability_id].append((m.tactic_id, m.technique_id, m.technique_name, m.kill_chain_phase))

    asset_value: dict = {}
    asset_ids = {v.asset_id for v in vulns if v.asset_id}
    if asset_ids:
        for a in await db.scalars(select(Asset).where(Asset.id.in_(asset_ids))):
            asset_value[a.id] = a.value

    return [
        FindingEvidence(
            fingerprint=v.fingerprint,
            title=v.title,
            severity=v.severity,
            techniques=techniques.get(v.id, []),
            service_value=asset_value.get(v.asset_id),
            category=v.category,
        )
        for v in vulns
    ]


async def _maybe_capture_screenshot(
    db: AsyncSession,
    *,
    vuln,
    matched_at: str | None,
    tool_run_id,
    target_type: str,
    target_value: str,
    extra_authorized_hosts,
) -> None:
    """Capture and persist a screenshot of a finding's affected URL. BEST EFFORT.

    Uses the EXISTING evidence model -- one Evidence row with evidence_type='screenshot'
    (a free-form varchar; no schema change) linked to this vulnerability through the
    EXISTING VulnerabilityEvidence M:N table. That gives the report a per-FINDING image
    rather than the per-tool-run log excerpt every finding currently shares.

    Every failure mode -- feature off, ineligible URL, blocked scope/SSRF, browser missing,
    timeout, oversize image, storage outage -- leaves the finding, its existing evidence and
    the scan completely untouched. Nothing is written unless a real image was captured and
    stored, so no empty or placeholder screenshot evidence can ever exist."""
    from sqlalchemy.dialects.mysql import insert as mysql_insert

    from apps.api.modules.vulnerabilities.models import VulnerabilityEvidence
    from apps.api.scanner_engine import screenshot as screenshot_mod

    if not screenshot_mod.is_enabled():
        return

    eligibility = screenshot_mod.check_eligibility(
        matched_at,
        vuln.severity,
        target_type,
        target_value,
        extra_authorized_hosts=extra_authorized_hosts,
    )
    if not eligibility.eligible:
        logger.debug(
            "screenshot.skipped vuln=%s reason=%s", vuln.id, eligibility.reason
        )
        return

    try:
        image = await screenshot_mod.capture_screenshot(
            eligibility.url,
            target_type,
            target_value,
            extra_authorized_hosts=extra_authorized_hosts,
        )
    except Exception:  # noqa: BLE001 -- capture_screenshot already swallows, belt and braces
        logger.warning("screenshot.capture_raised vuln=%s", vuln.id, exc_info=True)
        return
    if not image:
        return  # failure already logged; never fabricate evidence

    try:
        # Storage is blocking boto3 -> off the event loop, like the raw-output path.
        storage_uri, checksum = await asyncio.to_thread(
            evidence_store.store_screenshot, vuln.id, image
        )
    except Exception:  # noqa: BLE001 -- a storage outage must not fail the scan
        logger.warning("screenshot.store_failed vuln=%s", vuln.id, exc_info=True)
        return

    shot = Evidence(
        tool_run_id=tool_run_id,
        evidence_type="screenshot",
        storage_uri=storage_uri,
        checksum=checksum,
    )
    db.add(shot)
    await db.flush()  # need shot.id for the link row

    # Idempotent link, mirroring ingest_finding: a re-scan that recaptures the same page
    # writes the same (vulnerability, evidence) pair rather than raising a duplicate key.
    stmt = mysql_insert(VulnerabilityEvidence.__table__).values(
        vulnerability_id=vuln.id, evidence_id=shot.id, tool_run_id=tool_run_id
    )
    stmt = stmt.on_duplicate_key_update(tool_run_id=VulnerabilityEvidence.tool_run_id)
    await db.execute(stmt)
    logger.info("screenshot.captured vuln=%s bytes=%d uri=%s", vuln.id, len(image), storage_uri)


async def _run_exploitation_phase(db: AsyncSession, scan: Scan, target_row, roe, base_step_no: int) -> list:
    """Deterministic, gated exploitation of this scan's confirmed findings using
    curated modules. Non-destructive by construction. Every attempt is triple-gated:
    (1) roe.exploitation_enabled, (2) the target host is human-approved (approved_hosts
    in the engagement config; '*' = all), (3) safety.assert_action_allowed. A blocked
    or unapproved finding is recorded (modeled), never executed. Returns the confirmed
    ExploitResults for the attack graph."""
    from apps.api.modules.agent.models import AgentStep
    from apps.api.modules.vulnerabilities.models import Vulnerability
    from apps.api.scanner_engine.exploits import EXPLOIT_REGISTRY
    from apps.api.scanner_engine.safety import SafetyViolation, assert_action_allowed

    vulns = list(await db.scalars(select(Vulnerability).where(Vulnerability.last_seen_scan_id == scan.id)))
    approved = set(scan.config.get("approved_hosts", []))
    host = target_row.value
    host_ok = "*" in approved or host in approved
    results: list = []
    step_no = base_step_no

    def _rec(module_name, tier, action_type, status, detail):
        db.add(
            AgentStep(
                workspace_id=scan.workspace_id, scan_id=scan.id, step_no=step_no,
                phase="exploitation", action_type=action_type, tool_or_module=module_name,
                safety_tier=tier, rationale=None, result_summary=(detail or None) and detail[:2000], status=status,
            )
        )

    for v in vulns:
        finding = {"category": v.category, "fingerprint": v.fingerprint, "title": v.title, "severity": v.severity}
        for module_cls in EXPLOIT_REGISTRY.values():
            module = module_cls()
            if not module.can_attempt(finding):
                continue
            # Gate 2: human pre-approval per host (Rules of Engagement).
            if roe.require_approval and not host_ok:
                _rec(module.name, module.safety_tier, "approval_wait", "skipped",
                     f"host '{host}' not approved -- modeled only: {v.title[:60]}")
                step_no += 1
                await db.commit()
                continue
            # Gate 3: the non-bypassable safety check (intrusive + non-destructive).
            try:
                assert_action_allowed(safety_tier=module.safety_tier, roe=roe, operation=module.proof_action)
            except SafetyViolation as exc:
                _rec(module.name, module.safety_tier, "exploit", "blocked", str(exc))
                step_no += 1
                await db.commit()
                continue
            res = await module.attempt(host, finding)
            results.append(res)
            _rec(module.name, module.safety_tier, "exploit", "executed" if res.exploitable else "skipped",
                 f"{res.access_type}: {res.proof}")
            step_no += 1
            await db.commit()
    return results


async def _synthesize_attack_narrative(db: AsyncSession, scan: Scan) -> None:
    """Best-effort AI attack-path narrative for the whole scan. Wires the AI
    Correlator (grouping) together with the deterministic attack_mappings (phase
    ordering) into one kill-chain story, persisted to attack_narratives.

    FAIL-SOFT: any failure (no AI key, provider down, parse/rate-limit error)
    logs a warning and leaves the deterministic mappings intact -- it must never
    change the scan status or abort. Runs with the workspace RLS GUC already set."""
    try:
        import asyncio

        from apps.api.ai_agent.correlator import AICorrelator
        from apps.api.ai_agent.providers.factory import get_ai_client
        from apps.api.ai_agent.providers.usage import collect_ai_usage
        from apps.api.ai_agent.usage_repo import persist_ai_usage
        from apps.api.core.config import get_settings
        from apps.api.core.observability import get_correlation_id
        from apps.api.modules.attack.models import AttackMapping, AttackNarrative
        from apps.api.modules.attack.service import kill_chain_steps, save_attack_narrative
        from apps.api.modules.vulnerabilities.models import Vulnerability

        # IDEMPOTENCY (F3.2): a re-run (F2 transient retry / reaper reclaim / DLQ replay) must not
        # re-invoke the AI correlator. The narrative is one-per-scan (uq_attack_narrative_scan); if
        # it already exists, skip -- no duplicate AI charge, no duplicate ai_usage row. The
        # deterministic ATT&CK mapping + kill-chain fallback are unchanged, so coverage is unaffected.
        if await db.scalar(select(AttackNarrative.id).where(AttackNarrative.scan_id == scan.id)) is not None:
            logger.info(
                "scan.attack_narrative_reused scan=%s (already synthesized; skipping AI correlator)",
                scan.id,
                extra={"event": "scan.attack_narrative_reused", "scan_id": str(scan.id)},
            )
            return

        settings = get_settings()
        vulns = list(
            await db.scalars(select(Vulnerability).where(Vulnerability.last_seen_scan_id == scan.id))
        )
        if not vulns:
            return  # nothing to narrate

        # LATENCY BOUND: beyond the cap, skip the AI narrative entirely. The
        # deterministic ATT&CK mapping is already persisted and the kill-chain
        # endpoint falls back to it, so coverage is unchanged -- only the generated
        # story is bounded. Never blocks a large scan on unbounded AI work.
        if len(vulns) > settings.ai_correlator_max_findings:
            logger.info(
                "scan.attack_narrative_skipped scan=%s findings=%d > cap=%d",
                scan.id, len(vulns), settings.ai_correlator_max_findings,
            )
            return

        vuln_ids = [v.id for v in vulns]
        mappings = list(
            await db.scalars(select(AttackMapping).where(AttackMapping.vulnerability_id.in_(vuln_ids)))
        )

        findings = [
            {"id": str(v.id), "title": v.title, "severity": v.severity, "category": v.category}
            for v in vulns
        ]
        client = get_ai_client(settings.ai_correlator_model or None)
        with collect_ai_usage(
            agent_role="correlator",
            workspace_id=str(scan.workspace_id),
            scan_id=str(scan.id),
            correlation_id=get_correlation_id(),
        ) as usage_records:
            # Wall-clock bound the (blocking) correlator off the loop; a timeout is
            # fail-soft -> deterministic fallback, scan unaffected.
            correlation = await asyncio.wait_for(
                asyncio.to_thread(AICorrelator(client=client).correlate, findings),
                timeout=settings.ai_correlator_timeout_seconds,
            )

        # Deterministic-backed kill-chain steps (from persisted mappings) plus a
        # short summary that reflects the AI Correlator's grouping.
        steps = kill_chain_steps({v.id: v.title for v in vulns}, mappings)
        phases = [s["phase_name"] for s in steps]
        summary = (
            f"{len(vulns)} finding(s) correlated into {len(correlation.groups)} attack group(s). "
            f"Kill-chain coverage: {', '.join(phases) if phases else 'no techniques mapped'}."
        )
        await save_attack_narrative(
            db,
            workspace_id=scan.workspace_id,
            scan_id=scan.id,
            summary=summary,
            steps=steps,
            model_version=correlation.model_version,
            prompt_version=correlation.prompt_version,
        )
        await db.commit()
        await persist_ai_usage(usage_records)
    except TimeoutError:
        logger.warning("scan.attack_narrative_timeout scan=%s", scan.id)
    except Exception:  # noqa: BLE001 -- narrative is strictly best-effort
        logger.warning("scan.attack_narrative_failed scan=%s", scan.id, exc_info=True)


async def _run_single_tool(
    db: AsyncSession,
    scan: Scan,
    runner,
    target_value: str,
    prior_findings: list[CommonFinding],
    criticality: str,
    target_type: str,
    execution_token: uuid.UUID | None = None,
) -> tuple[list[CommonFinding], str]:
    """Run one tool resiliently and return (findings, status) where status is
    completed | partial | failed. A tool NEVER aborts the scan: a crash/timeout or
    a non-zero exit with no usable output is recorded as `failed` and the pipeline
    moves on; a non-zero exit that still produced parseable output is `partial`
    (its findings are kept). The overall scan status is aggregated by the caller."""
    from apps.api.core.config import get_settings
    from apps.api.scanner_engine import scope_guard

    config = scan.config or {}

    # M4.5 (G9): authorization-scope enforcement on DERIVED hosts. A discovered asset
    # is handed to this active tool only if its host is within the target's authorized
    # scope; out-of-scope or indeterminable-host findings are recorded as observations
    # (see the in_scope tagging below) but NEVER actively probed -- FAIL CLOSED. The
    # primary target is always probed: it is passed as target_value, not a finding.
    scoped_prior = prior_findings
    if get_settings().scan_enforce_derived_scope:
        scoped_prior, out_of_scope = scope_guard.partition_in_scope(target_type, target_value, prior_findings)
        if out_of_scope:
            logger.info(
                "scan.out_of_scope_skipped scan=%s tool=%s blocked=%d hosts=%s",
                scan.id, runner.name, len(out_of_scope),
                ",".join(sorted({scope_guard.extract_host(f) or "?" for f in out_of_scope}))[:500],
            )

    tool_run = ToolRun(
        scan_id=scan.id,
        tool_name=runner.name,
        tool_version=runner.version,
        status="running",
        command_hash="",  # filled after we know the command
    )
    db.add(tool_run)
    await db.commit()
    await db.refresh(tool_run)

    started = time.monotonic()
    logger.info(
        "tool.start scan=%s tool=%s version=%s target=%s prior_findings=%d",
        scan.id, runner.name, runner.version, target_value, len(prior_findings),
    )

    # LAST-MOMENT OWNERSHIP GATE (P1-1 P3). The between-tools check happens before this
    # function is entered, so a revocation committed in between would otherwise let a
    # superseded executor spawn one more tool against the target. Re-check immediately
    # before the process is spawned, so the window shrinks to this statement and no tool is
    # ever launched with a revocation already visible. The half-written ToolRun row is
    # marked so the abandoned attempt is auditable rather than left 'running'.
    if execution_token is not None:
        if await _execution_stop_reason(db, scan.id, execution_token) == "revoked":
            tool_run.status = "abandoned_revoked"
            tool_run.completed_at = datetime.now(timezone.utc)
            tool_run.error_message = "execution superseded before launch (graceful-shutdown requeue)"
            await db.commit()
            raise ExecutionRevoked(f"execution superseded before launching {runner.name}")

    # A crash/timeout in the runner is a failed tool run, NOT a failed scan: record
    # it (with evidence of the exception) and let the pipeline continue.
    try:
        raw = await runner.run(target_value, config, scoped_prior)
    except Exception as exc:
        tool_run.status = "failed"
        tool_run.completed_at = datetime.now(timezone.utc)
        tool_run.error_message = f"{type(exc).__name__}: {exc}"[:2000]
        await db.commit()
        record_tool_failure(runner.name)  # Phase 1.3 metric
        logger.error(
            "tool.failed scan=%s tool=%s duration=%.2fs error=%s",
            scan.id, runner.name, time.monotonic() - started, exc,
            extra={"event": "tool.failed", "scan_id": str(scan.id), "tool": runner.name,
                   "status": "failed", "duration_s": round(time.monotonic() - started, 2),
                   "reason": type(exc).__name__},
            exc_info=True,
        )
        return [], "failed"

    tool_run.command_hash = hashlib.sha256(raw.command.encode()).hexdigest()
    tool_run.exit_code = raw.exit_code

    # Every finding must trace to raw evidence (blueprint §1) -- store the raw
    # stdout/stderr blob in object storage and record an evidence row BEFORE
    # turning any of it into assets. Stored even for failed runs (debuggability).
    #
    # FAIL-SOFT (evidence storage): object storage (MinIO/S3) being down must NOT
    # fail an otherwise-successful scan. On a storage error we record a sentinel
    # evidence row (so vulnerability -> evidence linkage still holds) and mark the
    # tool run so the scan honestly aggregates to completed_with_errors.
    blob = (
        f"$ {raw.command}\n\n=== STDOUT ===\n{raw.stdout}\n\n=== STDERR ===\n{raw.stderr}\n"
    ).encode()
    storage_failed = False
    try:
        storage_uri, checksum = evidence_store.store_raw_output(tool_run.id, blob)
    except Exception as exc:  # noqa: BLE001 -- storage outage must not fail the scan
        storage_failed = True
        storage_uri, checksum = f"unavailable://evidence-storage-failed/{tool_run.id}", ""
        logger.warning(
            "tool.evidence_store_failed scan=%s tool=%s error=%s",
            scan.id, runner.name, exc, exc_info=True,
        )
    tool_run.raw_output_ref = storage_uri
    evidence = Evidence(
        tool_run_id=tool_run.id,
        evidence_type="log_excerpt",
        storage_uri=storage_uri,
        checksum=checksum,
    )
    db.add(evidence)
    await db.flush()  # need evidence.id to link vulnerabilities to it

    # PARSE-FIRST: attempt to parse regardless of exit code (a parser bug must not
    # crash the pipeline). Then classify the run. A non-zero exit is only benign if
    # the tool declares it so; otherwise output-bearing => partial, else failed.
    try:
        findings = runner.parse(raw)
    except Exception:  # noqa: BLE001 -- a broken parse yields no assets, not a crash
        logger.warning("tool.parse_failed scan=%s tool=%s", scan.id, runner.name, exc_info=True)
        findings = []
    try:
        vuln_findings = list(runner.parse_vulnerabilities(raw))
    except Exception:  # noqa: BLE001
        logger.warning("tool.parse_vuln_failed scan=%s tool=%s", scan.id, runner.name, exc_info=True)
        vuln_findings = []

    stderr_tail = (raw.stderr or "").strip()[-1000:]
    status = classify_run(runner, raw, produced_findings=bool(findings or vuln_findings))
    # Evidence storage failed: the tool ran, but its raw output couldn't be
    # persisted -- never a clean success, so downgrade completed -> partial so the
    # scan honestly aggregates to completed_with_errors (fail-soft).
    if storage_failed and status == "completed":
        status = "partial"

    if status == "failed":
        # Don't trust output from a failed run -- record the error, ingest nothing.
        findings, vuln_findings = [], []
        tool_run.error_message = f"exit code {raw.exit_code}" + (f": {stderr_tail}" if stderr_tail else "")
    elif status == "partial":
        tool_run.error_message = (
            f"non-zero exit {raw.exit_code}; partial results kept"
            + (f": {stderr_tail}" if stderr_tail else "")
        )
    if storage_failed:
        note = "evidence storage unavailable (raw output not persisted)"
        tool_run.error_message = f"{tool_run.error_message}; {note}" if tool_run.error_message else note

    # M4.5: record each discovered asset's scope decision as an observation (metadata
    # in_scope) so the stored asset + graph reflect what was in/out of scope. Tagging
    # happens regardless of the kill-switch; only the active-probing FILTER above is
    # gated. Fail closed: an indeterminable host is tagged out of scope.
    for finding in findings:
        finding.metadata = {
            **(finding.metadata or {}),
            "in_scope": scope_guard.finding_in_scope(target_type, target_value, finding),
        }

    for finding in findings:
        await upsert_asset(
            db,
            project_id=scan.project_id,
            target_id=scan.target_id,
            asset_type=finding.asset_type,
            value=finding.value,
            metadata=finding.metadata,
        )

    # Vulnerability findings go through the Vulnerability Engine (dedup +
    # lifecycle), each linked to this run's evidence. Then the Risk Engine weights
    # CVSS by asset criticality, the Compliance Engine maps the finding's category
    # to framework controls, and the Attack Engine maps it to MITRE ATT&CK
    # techniques + Cyber Kill Chain phases (blueprint §7 steps 7 & later).
    for vuln_finding in vuln_findings:
        asset_id = await _resolve_asset_id(db, scan, vuln_finding.matched_at)
        vuln = await ingest_finding(
            db,
            project_id=scan.project_id,
            scan_id=scan.id,
            finding=vuln_finding,
            tool_run_id=tool_run.id,
            evidence_id=evidence.id,
            asset_id=asset_id,
        )
        await upsert_risk_score(db, vuln.id, vuln.cvss_score, criticality)
        await sync_mappings(db, vuln.id, vuln.category)
        await sync_attack_mappings(db, vuln.id, vuln.category, vuln_finding.metadata)
        # Visual evidence for non-info web findings (best effort -- never fails the scan).
        await _maybe_capture_screenshot(
            db,
            vuln=vuln,
            matched_at=vuln_finding.matched_at,
            tool_run_id=tool_run.id,
            target_type=target_type,
            target_value=target_value,
            extra_authorized_hosts=extra_scope_hosts,
        )

    tool_run.status = status
    tool_run.completed_at = datetime.now(timezone.utc)
    await db.commit()

    if status == "failed":
        record_tool_failure(runner.name)  # Phase 1.3: non-zero exit with no usable output
    logger.info(
        "tool.done scan=%s tool=%s status=%s exit=%s duration=%.2fs "
        "assets=%d vulnerabilities=%d evidence=%s",
        scan.id, runner.name, status, raw.exit_code, time.monotonic() - started,
        len(findings), len(vuln_findings), storage_uri,
    )
    return findings, status


async def _resolve_asset_id(db: AsyncSession, scan: Scan, matched_at: str | None) -> uuid.UUID | None:
    """Best-effort: tie a vulnerability to the asset it was observed at, by
    matching the finding's location against an http_service asset for this
    target. Returns None if no clean match (asset_id is nullable)."""
    if not matched_at:
        return None
    asset = await db.scalar(
        select(Asset).where(
            Asset.target_id == scan.target_id,
            Asset.asset_type == "http_service",
            Asset.value == matched_at.rstrip("/"),
        )
    )
    return asset.id if asset else None
