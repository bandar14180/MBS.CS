"""Execution-plane scan executor -- runs tools, submits results through the manager.

THE SEAM, AND WHY IT IS HERE
----------------------------
`orchestrator.run_scan` cannot run on the isolated worker: it takes an `AsyncSession` and
touches the database at 58 call sites (claim, tool_runs, findings, assets, risk, compliance,
evidence, terminal write). All of that is legitimate CONTROL-PLANE work.

The TOOL RUNNERS, by contrast, are completely database-free -- `grep 'db\\.' ` over
`tool_runners/` returns nothing. Their contract is pure:

    run(target_value, config, prior_findings) -> RawToolOutput

That is the seam. The execution plane runs the runners; the control plane keeps the
orchestration. Everything the runners depend on -- `run_with_timeout` (partial output,
no pipe deadlock, bounded cleanup), `classify_run`, `net_guard`, `net_policy`,
`egress_guard`, `site_dns` -- is process-local and works unchanged here.

WHAT IS PRESERVED VERBATIM
--------------------------
  * per-tool timeouts and the partial-output rule (`run_with_timeout` is used by the
    runners themselves; this module does not re-implement or bypass it);
  * process cleanup (`terminate_and_reap`, inside the runners);
  * phase ordering (runners sorted by `.phase`, as the orchestrator does);
  * findings accumulating across the pipeline so later tools build on earlier ones;
  * `classify_run`'s completed/partial/failed semantics.

WHAT IS DELIBERATELY NOT DONE HERE
----------------------------------
Findings ingestion, asset upsert, risk scoring, compliance/ATT&CK mapping and the AI
planner all require the database and stay control-plane side. The worker submits raw tool
results and evidence through the manager, which performs the validated persistence. A
worker that did the ingestion itself would need a database session, which is the thing this
whole architecture removes.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from apps.api.core.config import get_settings
from apps.api.scanner_engine import scope_guard
from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY
from apps.api.scanner_engine.tool_runners.base import classify_run
from apps.api.scanner_worker.lease_loop import REASON_AUTH_FAILED, LeaseError

logger = logging.getLogger(__name__)


class ManagerResultReporter:
    """Submits tool results and evidence through the manager boundary.

    Wraps `result_sink.ManagerResultSink` so the executor has one place to talk to, and so
    a submission failure is logged with the scan context rather than surfacing as a bare
    transport error.
    """

    def __init__(self, sink) -> None:
        self._sink = sink

    async def submit_tool_started(
        self, *, scan_id, tool_run_id, tool_name, execution_token=None, started_at=None,
    ) -> None:
        await self._sink.submit_tool_started(
            scan_id=scan_id, tool_run_id=tool_run_id, tool_name=tool_name,
            execution_token=execution_token, started_at=started_at,
        )

    async def submit_tool_result(
        self, *, scan_id, tool_run_id, status, findings,
        tool_name=None, execution_token=None, exit_code=None, error_message=None,
        started_at=None, effective_command=None, timed_out=None,
    ) -> None:
        await self._sink.submit_tool_result(
            scan_id=scan_id, tool_run_id=tool_run_id, status=status, findings=findings,
            tool_name=tool_name, execution_token=execution_token,
            exit_code=exit_code, error_message=error_message, started_at=started_at,
            effective_command=effective_command, timed_out=timed_out,
        )

    async def submit_evidence(
        self, *, scan_id, tool_run_id, content, content_type,
        execution_token=None, tool_name=None, fingerprint=None,
    ) -> None:
        await self._sink.submit_evidence(
            scan_id=scan_id, tool_run_id=tool_run_id,
            content=content, content_type=content_type,
            execution_token=execution_token, tool_name=tool_name,
            fingerprint=fingerprint,
        )


def _finding_to_dict(finding) -> dict:
    """A CommonFinding as plain JSON for the manager.

    Explicit field mapping rather than `__dict__`: the wire format between the execution
    plane and the control plane should be a deliberate contract, not whatever attributes a
    dataclass happens to carry today.
    """
    return {
        "asset_type": getattr(finding, "asset_type", None),
        "value": getattr(finding, "value", None),
        "metadata": dict(getattr(finding, "metadata", {}) or {}),
    }


async def _capture_and_submit_screenshots(
    runner, raw, *, status, reporter, scan_id, tool_run_id, execution_token,
    target_type, target_value,
) -> int:
    """Capture screenshots for this tool run's findings and submit the PNG bytes.

    Returns how many were submitted (0 is the normal case for most tools). NEVER raises:
    the caller has already recorded the tool's status, findings and raw evidence, and none
    of that may be put at risk by a browser.

    The local `parse_vulnerabilities` call here decides only WHICH URLs are photographed.
    The manager re-parses the same bytes itself to decide which findings are persisted, so
    the worker still supplies evidence rather than conclusions.
    """
    if reporter is None:
        return 0
    if status == "failed":
        # Don't trust output from a failed run -- mirrors F2-07's discard of `findings` for
        # this same case. This function re-parses `raw` independently of the caller's
        # already-zeroed `findings`/`vuln_findings`, so without this check a hard_failure()
        # run could still have screenshot evidence generated for vulnerabilities the
        # pipeline has already decided not to trust.
        return 0

    try:
        from apps.api.scanner_worker import screenshot_capture

        parse_vulns = getattr(runner, "parse_vulnerabilities", None)
        if parse_vulns is None:
            return 0  # inventory-only tool (subfinder, httpx...): nothing to photograph
        vuln_findings = list(parse_vulns(raw) or [])
        if not vuln_findings:
            return 0

        shots = await screenshot_capture.capture_for_findings(
            vuln_findings,
            target_type=target_type or "",
            target_value=target_value or "",
        )
    except Exception as exc:  # noqa: BLE001 -- images are never worth a scan
        logger.warning(
            "executor.screenshot_capture_failed scan=%s tool=%s error=%s",
            scan_id, runner.name, exc,
            extra={"event": "executor.screenshot_capture_failed", "scan_id": str(scan_id),
                   "tool": runner.name},
        )
        return 0

    submitted = 0
    for fingerprint, image in shots:
        try:
            await reporter.submit_evidence(
                scan_id=scan_id, tool_run_id=tool_run_id,
                content=image, content_type="image/png",
                execution_token=execution_token,
                # NO tool_name: that field names the PARSER the manager applies to derive
                # findings, and a PNG is not parseable output. Sending it would push image
                # bytes through the text parser on every screenshot.
                tool_name=None,
                # The finding this image belongs to. The manager resolves it against the
                # vulnerabilities IT parsed; an unknown fingerprint attaches to nothing.
                fingerprint=fingerprint,
            )
            submitted += 1
        except Exception as exc:  # noqa: BLE001 -- same rule as raw-output evidence
            logger.warning(
                "executor.screenshot_submit_failed scan=%s tool=%s error=%s",
                scan_id, runner.name, exc,
                extra={"event": "executor.screenshot_submit_failed",
                       "scan_id": str(scan_id), "tool": runner.name},
            )
    if submitted:
        logger.info(
            "executor.screenshots_submitted scan=%s tool=%s count=%d",
            scan_id, runner.name, submitted,
            extra={"event": "executor.screenshots_submitted", "scan_id": str(scan_id),
                   "tool": runner.name, "count": submitted},
        )
    return submitted


async def _submit_tool_result_resilient(
    reporter, *, scan_id, tool_run_id, tool_name, status: str, refusal=None, **kwargs
) -> bool:
    """Submit one tool's result. Returns True if it persisted, False if it was lost.

    NEVER RAISES. This is the single most important property in this module, and it is the
    direct fix for incident 615d0e0b: a `DataError` while storing one over-long URL became
    HTTP 500 from the manager, that 500 escaped this call as an `HTTPStatusError`, and the
    exception unwound the whole tool loop -- so ffuf, arjun, nuclei and nuclei-dast never
    ran, and the scan was recorded `failed`, even though seven tools had succeeded and
    katana had produced 30,873 URLs.

    SCANNER EXECUTION FAILURE AND RESULT PERSISTENCE FAILURE ARE DIFFERENT EVENTS.
    The first is a fact about the target and belongs in the scan's outcome. The second is a
    fact about our own storage layer, and the tools that have not run yet are entirely
    capable of running. Conflating them let an infrastructure problem masquerade as a
    security finding ("the scan failed"), which is the more dangerous of the two errors.

    This is NOT `except Exception: pass`. The loss is counted by the caller, recorded in the
    returned status list, logged at ERROR with the scan, the tool and the underlying cause,
    and surfaced in `executor.finished`. An operator can still answer "did persistence fail,
    for which tool, and why" -- they simply do not lose the rest of the scan to it.
    """
    if reporter is None:
        return False
    try:
        await reporter.submit_tool_result(
            scan_id=scan_id, tool_run_id=tool_run_id, status=status,
            tool_name=tool_name, **kwargs,
        )
        return True
    except Exception as exc:  # noqa: BLE001 -- persistence loss must not end the scan
        if _is_authoritative_refusal(exc):
            # NOT a persistence failure. The control plane refused this execution, so the
            # result was never "lost" -- it was declined. Recorded on the stop latch and
            # STILL NOT RAISED: this function's never-raises property is what keeps one
            # bad submission from unwinding the loop, and the caller stops at the next
            # tool boundary instead. The tool that just ran keeps its recorded status.
            _note_refusal(refusal, exc, scan_id=scan_id, tool=tool_name,
                          event="executor.tool_result_submit_refused")
            return False
        logger.error(
            "executor.tool_result_submit_failed scan=%s tool=%s tool_run=%s status=%s "
            "error=%s -- the tool RAN; only its result submission failed, so the pipeline "
            "continues with the remaining tools",
            scan_id, tool_name, tool_run_id, status, f"{type(exc).__name__}: {exc}",
            extra={"event": "executor.tool_result_submit_failed",
                   "scan_id": str(scan_id), "tool": tool_name,
                   "tool_run_id": str(tool_run_id), "tool_status": status,
                   "error": f"{type(exc).__name__}: {exc}"},
        )
        return False


# Reasons the manager can give for stopping. Anything else -- including a value a future
# manager invents -- is treated as "keep going": this loop must never stop a scan on a
# response it does not understand.
_STOP_REASONS = frozenset({"cancelled", "revoked"})


def _is_authoritative_refusal(exc: BaseException) -> bool:
    """Is this exception a control-plane VERDICT rather than an outage?

    THE DISTINCTION THIS FUNCTION EXISTS TO DRAW, and the reason incident 615d0e0b is
    not re-opened by it:

      * 401/403 -- the manager has DECIDED this worker may no longer act on this scan: its
        credential was revoked, its site suspended, or private scanning was
        emergency-disabled. Retrying re-sends the same bytes and earns the same refusal.
      * 409 -- `_assert_execution_token` has DECIDED this execution is no longer the
        scan's owner (EXECUTION_SUPERSEDED: requeued on graceful shutdown, reclaimed by
        the orphan reaper, or cancelled -- see scanner_manager/app.py). This is every bit
        as authoritative as a 401/403: the fenced DB write behind it can never be won by a
        stale token, so treating a 409 as a mere outage (Lifecycle Integrity audit,
        Prompt 9) does not corrupt persisted state, but it DOES leave a superseded
        executor running further tools against the target -- unbounded, since every
        subsequent write keeps losing the same fenced race and getting reclassified as
        another "outage". Recognising it here makes the executor stop at the next tool
        boundary instead, matching the Celery path's `_execution_stop_reason` -> "revoked"
        -> `ExecutionRevoked` cooperative-stop contract.
      * 5xx, timeouts, connection resets, DNS failures -- the manager never reached a
        decision. These are the persistence outages that must stay fail-open, because
        615d0e0b proved that unwinding the tool loop over one of them loses the work of
        every tool that already succeeded.

    Both shapes a refusal can arrive in are recognised, because the two submission
    transports differ and neither is being redesigned here:
      * `ManagerClient._request` (the lease/probe path) already converts 401/403 into
        `LeaseError(REASON_AUTH_FAILED, ...)`;
      * `result_sink._post` (the submission path) raises the underlying
        `httpx.HTTPStatusError`, which `_is_retryable` already declines to retry for any
        4xx -- this reads the same status code to decide it is a verdict, not merely
        unretryable.

    Anything unrecognised is NOT a verdict. The default must stay "this was an outage", so
    a new exception type can only ever cost a delayed stop, never a falsely aborted scan.
    """
    if isinstance(exc, LeaseError):
        return exc.reason == REASON_AUTH_FAILED
    response = getattr(exc, "response", None)
    status_code = getattr(response, "status_code", None)
    return status_code in (401, 403, 409)


def _note_refusal(refusal, exc: BaseException, *, scan_id, tool, event: str) -> None:
    """Record that the control plane refused this execution, and log it as a REFUSAL.

    `refusal` is a one-slot mutable latch owned by `execute_leased_job`; a submission
    helper cannot stop the loop by itself (raising is exactly what incident 615d0e0b
    forbade), so it records the verdict here and the loop reads it at the tool boundary it
    already checks. Once set it is never cleared: a later successful submission does not
    un-refuse an execution the control plane has already declined.

    Logged at WARNING under its own event name rather than reusing the
    `*_submit_failed` events, because an operator triaging a refusal is looking at an
    authorization/emergency action, not at a storage incident.
    """
    if refusal is not None and refusal.get("reason") is None:
        refusal["reason"] = "revoked"
    logger.warning(
        "%s scan=%s tool=%s error=%s -- the control plane REFUSED this execution; "
        "stopping before the next tool",
        event, scan_id, tool, f"{type(exc).__name__}: {exc}",
        extra={"event": event, "scan_id": str(scan_id), "tool": tool,
               "reason": "revoked", "error": f"{type(exc).__name__}: {exc}"},
    )


async def _stop_reason(stop_probe, *, scan_id) -> str | None:
    """Ask whether this execution should stop. Returns a reason, or None to continue.

    TWO DIFFERENT FAILURES, TWO DIFFERENT ANSWERS. This is the distinction
    `result_sink._is_retryable` already draws for submissions, applied to the probe:

      * A TRANSPORT failure -- DNS, timeout, connection reset, a 5xx -- means the manager
        never gave us an answer. FAIL-OPEN: continue. Cancellation detection shortens a
        cancelled scan; it must never become a way for a manager outage to kill healthy
        ones, which would be a strictly worse failure than the one it fixes.

      * A 401/403 is not an outage, it is a VERDICT: the manager has decided this worker
        may no longer act on this scan (its credential was revoked, its site suspended, or
        private scanning was emergency-disabled). Retrying earns the same refusal, and
        every 403 this probe can receive has the same correct response -- stop. Treating it
        as an outage would mean continuing to run tools against a customer network after
        the control plane has explicitly refused this execution.

    The refusal is recognised through the EXISTING worker-side contract:
    `ManagerClient._request` already converts 401/403 into
    `LeaseError(REASON_AUTH_FAILED, ...)`, so nothing new is invented here and the two
    sides cannot drift apart.

    It is reported as 'revoked' -- the vocabulary `_execution_stop_reason` already uses for
    "this execution no longer owns its scan" -- rather than as a new fourth state, so the
    caller has exactly the two stop reasons it had before.
    """
    if stop_probe is None:
        return None
    try:
        reason = await stop_probe()
    except LeaseError as exc:
        if exc.reason == REASON_AUTH_FAILED:
            logger.warning(
                "executor.stop_probe_refused scan=%s reason=%s -- the manager refused this "
                "execution; stopping before the next tool", scan_id, exc.reason,
                extra={"event": "executor.stop_probe_refused", "scan_id": str(scan_id),
                       "reason": exc.reason},
            )
            return "revoked"
        # Any other lease-level error is not a verdict about this execution: fail open.
        logger.warning(
            "executor.stop_probe_failed scan=%s error=%s -- continuing (fail-open)",
            scan_id, f"{type(exc).__name__}: {exc}",
            extra={"event": "executor.stop_probe_failed", "scan_id": str(scan_id),
                   "error": f"{type(exc).__name__}: {exc}"},
        )
        return None
    except Exception as exc:  # noqa: BLE001 -- a transport failure must never stop a scan
        logger.warning(
            "executor.stop_probe_failed scan=%s error=%s -- continuing (fail-open)",
            scan_id, f"{type(exc).__name__}: {exc}",
            extra={"event": "executor.stop_probe_failed", "scan_id": str(scan_id),
                   "error": f"{type(exc).__name__}: {exc}"},
        )
        return None
    return reason if reason in _STOP_REASONS else None


async def execute_leased_job(
    job: dict, policy, *, reporter=None, registry=None, stop_probe=None
) -> str:
    """Run one leased scan's tool pipeline. Returns 'completed', 'completed_with_errors'
    or 'failed' -- the same three-way outcome orchestrator.run_scan aggregates on the
    Celery path (see its `new_status` derivation), so a scan's status carries the same
    fidelity regardless of which execution plane ran it.

    `policy` is already bound by the lease loop (contextvar), so every resolution and every
    connection this pipeline makes is checked against THIS scan's authorized set. It is
    also passed explicitly where a callee accepts it, so the decision does not depend on
    ambient state alone.
    """
    scan_id = uuid.UUID(str(job["scan_id"]))
    # The fencing token the manager issued with this lease. Every result/evidence write
    # carries it so a SUPERSEDED execution (graceful-shutdown requeue, orphan reap,
    # cancellation) cannot append to the run that replaced it. Read from the job rather
    # than plumbed through a new parameter: the lease loop already hands the whole job in.
    _token = job.get("execution_token")
    execution_token = uuid.UUID(str(_token)) if _token else None
    target = job.get("target") or {}
    target_value = target.get("value")
    target_type = target.get("type")
    requested = list(job.get("requested_modules") or [])
    registry = registry if registry is not None else TOOL_REGISTRY

    # Allowlist-enforced, exactly as the orchestrator does: a module name that is not a
    # registered tool is dropped, never executed. A compromised manager therefore cannot
    # get an arbitrary command run by naming it as a "module".
    runners = [registry[m]() for m in requested if m in registry]
    # Deterministic phase order (subfinder -> httpx -> naabu -> nmap -> nuclei), regardless
    # of the order the modules were requested in.
    runners.sort(key=lambda r: r.phase)

    if not runners:
        logger.warning(
            "executor.no_runnable_modules scan=%s requested=%s", scan_id, requested,
            extra={"event": "executor.no_runnable_modules", "scan_id": str(scan_id)},
        )
        return "failed"

    discovered: list = []
    statuses: list[str] = []
    # How many tools RAN but whose outcome could not be recorded. Counted separately from
    # `statuses` because it describes our storage layer, not the target -- see
    # `_submit_tool_result_resilient`. Reported in `executor.finished` so a scan whose
    # results were partly lost is visibly different from one that simply found nothing.
    persistence_failures = 0
    # STOP LATCH for an authoritative refusal observed on a SUBMISSION path (Phase 8
    # emergency disconnect). The scan-status probe is the primary signal; this catches the
    # same verdict when it arrives on a write instead -- e.g. the operator flips the
    # emergency switch between two probes, and the tool-result POST is the first call to
    # see the 403. One-slot and write-once (see `_note_refusal`).
    refusal: dict = {"reason": None}

    for runner in runners:
        # COOPERATIVE STOP (Phase 1), mirroring the Celery path's between-tools probe in
        # orchestrator.run_scan. BEFORE the tool_run_id, the started_at and the
        # submit_tool_started below -- a cancelled scan must not open a ToolRun row for a
        # tool that will never run.
        #
        # FAIL-OPEN, and that is the whole safety argument for putting a network call in
        # this loop: an unreachable or misbehaving manager leaves `stop_reason` None and
        # the pipeline continues exactly as it did before this check existed. A transient
        # outage can therefore never cancel a healthy scan; the worst it can do is delay
        # a real cancellation to the next tool boundary.
        #
        # It does NOT touch the tool already running -- there is none at this point in the
        # loop. A tool in flight always finishes and reports its result, preserving the
        # partial output `run_with_timeout` exists to keep.
        # A refusal already latched by a previous tool's submission wins WITHOUT another
        # probe: the control plane has refused this execution once, and asking again could
        # only produce an outage that would be read as "keep going".
        stop_reason = refusal["reason"] or await _stop_reason(stop_probe, scan_id=scan_id)
        if stop_reason is not None:
            logger.info(
                "executor.cooperative_stop scan=%s reason=%s tool=%s "
                "(skipping this and all remaining tools)",
                scan_id, stop_reason, runner.name,
                extra={"event": "executor.cooperative_stop", "scan_id": str(scan_id),
                       "reason": stop_reason, "tool": runner.name},
            )
            break
        if (runner.applicable_target_types is not None
                and target_type not in runner.applicable_target_types):
            continue
        tool_run_id = uuid.uuid4()
        # The ONLY accurate record of when this tool began. The manager creates the
        # ToolRun row when the RESULT arrives, so without this it would fall back to the
        # column default (CURRENT_TIMESTAMP at insert) and every remote run would report a
        # ~0s duration -- in fact a slightly NEGATIVE one, since `completed_at` is computed
        # in Python microseconds before MySQL evaluates the default. Captured here, outside
        # the try, so the failure path below reports the same instant.
        started_at = datetime.now(timezone.utc)

        # ANNOUNCE THE START, before the tool runs. Without this the ToolRun row does not
        # exist until the tool FINISHES, so the UI jumps straight from 'waiting' to
        # 'completed' and a katana/nuclei run that takes ten minutes looks frozen the whole
        # time. Opening the row here is what lets the existing frontend counter tick from
        # the server's own `started_at` rather than a fabricated client-side origin.
        #
        # FAIL-SOFT, deliberately: this is PROGRESS reporting, and losing it costs a
        # cosmetic counter. Aborting a scan because a status announcement did not land
        # would trade a real result for a display detail -- the same rule evidence
        # submission already follows below.
        if reporter is not None:
            try:
                await reporter.submit_tool_started(
                    scan_id=scan_id, tool_run_id=tool_run_id, tool_name=runner.name,
                    execution_token=execution_token, started_at=started_at,
                )
            except Exception as exc:  # noqa: BLE001 -- progress loss must not fail a scan
                if _is_authoritative_refusal(exc):
                    # A refusal here is not lost progress, it is a verdict. Latched for
                    # the boundary check; this tool still runs, because it has already
                    # been decided on and killing it would lose partial output for no
                    # security gain -- the scan stops before the NEXT one.
                    _note_refusal(refusal, exc, scan_id=scan_id, tool=runner.name,
                                  event="executor.tool_started_submit_refused")
                else:
                    logger.warning(
                        "executor.tool_started_submit_failed scan=%s tool=%s error=%s",
                        scan_id, runner.name, exc,
                        extra={"event": "executor.tool_started_submit_failed",
                               "scan_id": str(scan_id), "tool": runner.name},
                    )

        # M4.5 (G9): authorization-scope enforcement on DERIVED hosts, mirroring
        # orchestrator._run_single_tool exactly. A discovered asset is handed to this
        # active tool only if its host is within the target's authorized scope;
        # out-of-scope/unresolvable/deny-listed findings are still kept in `discovered`
        # (see the F2-06/F2-07 aggregation and asset-ingest contract below) but are never
        # actively probed -- FAIL CLOSED. This does not mutate `discovered` itself: only
        # the list handed to THIS runner.run() call is narrowed.
        #
        # `derived_scope_roots` stays a direct call: it inspects only NAMED (non-IP) hosts,
        # and for those `host_in_scope` either matches by suffix or is rejected by
        # `_hostname_resolves_to`'s `_is_ip` guard before any lookup -- so it never reaches
        # the resolver and never blocks. (Verified against the real implementation; do not
        # "fix" this by symmetry with the offload below.)
        extra_scope_hosts = scope_guard.derived_scope_roots(
            target_type or "", target_value or "", discovered
        )
        scoped_prior = discovered
        if get_settings().scan_enforce_derived_scope:
            # OFF THE EVENT LOOP. `partition_in_scope` IS synchronous and DOES resolve DNS:
            # host_in_scope -> _hostname_resolves_to / _ip_host_in_range ->
            # net_guard.resolve_hostname -> socket.getaddrinfo, which additionally
            # time.sleep()s between its retry attempts. Every IP-valued finding under a
            # domain target, and every hostname finding under an ip_range target, takes that
            # path -- and those are the common shapes (naabu/nmap resolve before invoking
            # their binary, so their findings are bare IPs).
            #
            # Called inline it blocked the worker's ONLY event loop -- the same loop
            # carrying `_heartbeat_while_running` and the lease tasks. Observed starving the
            # heartbeat for 13m46s on a run with many unresolvable derived hosts, after
            # which the manager suspended the worker and the stale-scan reaper cascaded.
            #
            # `asyncio.to_thread` copies the current contextvars.Context into the thread, so
            # the scan's bound `net_policy` -- and therefore split-horizon site-DNS routing
            # for private scans -- still applies. The resolution performed is exactly the one
            # performed before; only the thread it runs on differs. No scope rule, no retry
            # policy and no fail-closed verdict is touched here.
            scoped_prior, out_of_scope = await asyncio.to_thread(
                scope_guard.partition_in_scope,
                target_type or "", target_value or "", discovered,
                extra_authorized_hosts=extra_scope_hosts,
            )
            if out_of_scope:
                logger.info(
                    "executor.out_of_scope_skipped scan=%s tool=%s blocked=%d hosts=%s",
                    scan_id, runner.name, len(out_of_scope),
                    ",".join(sorted({scope_guard.extract_host(f) or "?" for f in out_of_scope}))[:500],
                    extra={"event": "executor.out_of_scope_skipped", "scan_id": str(scan_id),
                           "tool": runner.name, "blocked": len(out_of_scope)},
                )

        try:
            # The runner enforces its own timeout via run_with_timeout, which KEEPS
            # partial output on timeout -- not re-implemented here.
            raw = await runner.run(target_value, dict(job.get("config") or {}), list(scoped_prior))
        except Exception as exc:  # noqa: BLE001 -- one tool failing must not end the scan
            statuses.append("failed")
            logger.warning(
                "executor.tool_failed scan=%s tool=%s error=%s", scan_id, runner.name, exc,
                extra={"event": "executor.tool_failed", "scan_id": str(scan_id),
                       "tool": runner.name},
            )
            if not await _submit_tool_result_resilient(
                reporter, scan_id=scan_id, tool_run_id=tool_run_id, status="failed",
                tool_name=runner.name, findings=[], execution_token=execution_token,
                error_message=f"{type(exc).__name__}: {exc}"[:2000],
                started_at=started_at, refusal=refusal,
            ):
                persistence_failures += 1
            continue

        # PARSE the raw output into inventory findings, exactly as the in-process path does.
        #
        # This previously read `getattr(raw, "findings", None)`, but RawToolOutput has no
        # such attribute -- its fields are command/stdout/stderr/exit_code -- so the
        # expression was unconditionally None and `findings` was ALWAYS empty. Three things
        # broke silently as a result: no asset was ever discovered on this path, later tools
        # in the pipeline received an empty `discovered` list instead of the earlier tools'
        # output (httpx got no subdomains, nmap got no ports), and classify_run() was always
        # told produced_findings=False, which downgrades a non-zero-exit run that did yield
        # output from `partial` to `failed`.
        try:
            findings = list(runner.parse(raw) or [])
        except Exception:  # noqa: BLE001 -- a broken parse yields no assets, not a crash
            logger.warning(
                "executor.parse_failed scan=%s tool=%s", scan_id, runner.name,
                extra={"event": "executor.parse_failed", "scan_id": str(scan_id),
                       "tool": runner.name},
                exc_info=True,
            )
            findings = []
        # classify_run must see the same signal the orchestrator gives it: a tool that
        # produced only vulnerability output (no inventory findings) is not empty-handed.
        # Without this, `partial` (output-bearing, non-zero exit) silently downgraded to
        # `failed` for any vuln-only tool -- the worker never submits these findings (see
        # `_capture_and_submit_screenshots`'s docstring), but classification must still
        # reflect that the run produced something.
        try:
            parse_vulns = getattr(runner, "parse_vulnerabilities", None)
            vuln_findings = list(parse_vulns(raw) or []) if parse_vulns is not None else []
        except Exception:  # noqa: BLE001 -- a broken parse yields no vulns, not a crash
            logger.warning(
                "executor.parse_vuln_failed scan=%s tool=%s", scan_id, runner.name,
                extra={"event": "executor.parse_vuln_failed", "scan_id": str(scan_id),
                       "tool": runner.name},
                exc_info=True,
            )
            vuln_findings = []
        status = classify_run(runner, raw, produced_findings=bool(findings or vuln_findings))
        statuses.append(status)
        if status == "failed":
            # Don't trust output from a failed run -- mirrors orchestrator.run_scan's own
            # guard (orchestrator.py). A hard_failure()-flagged run can still have a
            # non-empty parse() (e.g. an auth/usage error signature in stderr alongside
            # parseable stdout), and that output must not reach later tools or the manager.
            findings = []
        discovered.extend(findings)

        # A tool that RAN but did not succeed must carry its reason across the manager
        # boundary. Only the exception path above sent error_message, so a `partial`/`failed`
        # run that exited non-zero arrived with error_message NULL: the DB, the report and the
        # UI all showed e.g. "Katana failed" with no stated cause, and the runner's own stderr
        # diagnosis (the katana SIGKILL/OOM note) was discarded here. A clean exit still sends
        # nothing, so this adds no noise to successful runs.
        tool_error: str | None = None
        if status != "completed":
            tool_error = (getattr(raw, "stderr", None) or "").strip()[:2000] or None

        if reporter is not None:
            # Raw output is EVIDENCE and goes through the validated path (digest, size and
            # type checked on both sides, tenancy bound to the scan row server-side).
            #
            # SUBMITTED BEFORE THE TOOL RESULT, mirroring orchestrator._run_single_tool's own
            # ordering (evidence store, then classify/commit status). A storage failure here
            # is folded into `status` below via the same `storage_failed` downgrade rule the
            # orchestrator applies, so a tool run is never reported `completed` with no
            # evidence behind it -- see F2-09. Fail-soft in full: a storage problem costs at
            # most a downgrade to `partial`, never the scan.
            raw_text = getattr(raw, "stdout", None) or ""
            storage_failed = False
            if raw_text:
                try:
                    await reporter.submit_evidence(
                        scan_id=scan_id, tool_run_id=tool_run_id,
                        content=raw_text.encode("utf-8", errors="replace"),
                        content_type="text/plain",
                        execution_token=execution_token,
                        # Names the parser the CONTROL PLANE applies to these bytes to
                        # derive vulnerability findings. The worker sends no findings of
                        # its own -- see the manager endpoint for why that is a security
                        # property and not just a division of labour.
                        tool_name=runner.name,
                    )
                except Exception as exc:  # noqa: BLE001 -- evidence loss must not fail a scan
                    if _is_authoritative_refusal(exc):
                        _note_refusal(refusal, exc, scan_id=scan_id, tool=runner.name,
                                      event="executor.evidence_submit_refused")
                    else:
                        storage_failed = True
                        logger.warning(
                            "executor.evidence_submit_failed scan=%s tool=%s error=%s",
                            scan_id, runner.name, exc,
                            extra={"event": "executor.evidence_submit_failed",
                                   "scan_id": str(scan_id)},
                        )
            if storage_failed and status == "completed":
                status = "partial"
                statuses[-1] = status
                tool_error = (getattr(raw, "stderr", None) or "").strip()[:2000] or None

            # THE INCIDENT LINE. This call used to be bare: the manager's 500 (raised while
            # storing one over-long katana URL) propagated out of the tool loop and ended
            # the scan. It is now the only thing that can be lost when persistence fails --
            # the tools that follow still run.
            if not await _submit_tool_result_resilient(
                reporter, scan_id=scan_id, tool_run_id=tool_run_id, status=status,
                tool_name=runner.name,
                findings=[_finding_to_dict(f) for f in findings],
                execution_token=execution_token,
                exit_code=getattr(raw, "exit_code", None),
                error_message=tool_error, refusal=refusal,
                started_at=started_at,
                # PROMPT 10: the exact command this tool ran with, and whether it hit its
                # own wall-clock budget -- see ToolRun.effective_command/.timed_out. This is
                # the fix for the lease/manager path's command_hash never being set at all
                # (scanner_manager/app.py hardcoded ""): the worker now sends the real
                # command text and the manager derives and stores BOTH the text and its
                # digest from it, server-side.
                effective_command=getattr(raw, "command", None),
                timed_out=bool(getattr(raw, "timed_out", False)),
            ):
                persistence_failures += 1

            # SCREENSHOT EVIDENCE -- execution plane only.
            #
            # STRICTLY AFTER the raw-output submission above, and that ordering is
            # load-bearing: the manager derives the vulnerabilities from those bytes, so
            # the rows a screenshot's fingerprint resolves against do not exist until that
            # call has returned. Submitting earlier would attach nothing.
            #
            # This is the ONLY plane that may do it. The worker sits on mbs-scan-egress and
            # already carries Chromium; the manager is on the control plane and calls
            # ingest_vulnerability_findings(capture_screenshots=False) precisely so it never
            # opens a connection to a customer target.
            #
            # Fail-soft in full: a capture problem, a submission problem, or a parser that
            # raises must cost at most the images. The tool's status, its findings and its
            # raw evidence are all already recorded by this point.
            await _capture_and_submit_screenshots(
                runner, raw, status=status,
                reporter=reporter, scan_id=scan_id, tool_run_id=tool_run_id,
                execution_token=execution_token,
                target_type=target_type, target_value=target_value,
            )

    if persistence_failures:
        logger.error(
            "executor.result_persistence_degraded scan=%s lost=%d of %d tool result(s) -- "
            "every tool still executed; the scan's outcome reflects EXECUTION, not storage",
            scan_id, persistence_failures, len(statuses),
            extra={"event": "executor.result_persistence_degraded",
                   "scan_id": str(scan_id), "lost": persistence_failures,
                   "tools": len(statuses)},
        )
    logger.info(
        "executor.finished scan=%s tools=%d statuses=%s findings=%d persistence_failures=%d",
        scan_id, len(statuses), statuses, len(discovered), persistence_failures,
        extra={"event": "executor.finished", "scan_id": str(scan_id),
               "persistence_failures": persistence_failures},
    )
    # Three-way aggregation, matching orchestrator.run_scan's own derivation of `new_status`
    # exactly: all tools failed -> failed; some tool failed or was partial -> completed_with_
    # errors; otherwise -> completed. Previously this collapsed to a binary completed/failed,
    # so a scan where one tool timed out (partial) or errored while others succeeded was
    # misreported as a clean 'completed' -- indistinguishable from a scan with no issues.
    #
    # `statuses` records what the TOOLS did, and is appended before any submission is
    # attempted, so a scan whose results failed to persist still reports the execution that
    # actually happened. That is deliberate: marking such a scan 'failed' would tell the
    # operator the target was not scanned, which is false and is exactly the misreport that
    # made incident 615d0e0b look like a katana bug.
    if statuses and all(s == "failed" for s in statuses):
        return "failed"
    if any(s in ("failed", "partial") for s in statuses):
        return "completed_with_errors"
    if statuses:
        # LIFECYCLE INTEGRITY (Prompt 9, Invariant 7/8): `statuses` is this executor's own
        # in-memory record of what the tools DID, but the scan's terminal status is what
        # `/v1/lease/complete` persists as authoritative -- and the manager never re-derives
        # it from `tool_runs`, it trusts this return value verbatim (scanner_manager/app.py
        # `complete_lease`). If a `/v1/tool-results` submission was lost
        # (`persistence_failures`), the corresponding row is either MISSING entirely or
        # stuck `running` (later swept to `failed` by `reconcile_orphaned_tool_runs`, well
        # after this scan has already gone terminal) -- so a scan whose every *executed*
        # tool succeeded can still finalize `completed` while `tool_runs` itself tells a
        # different story. That is the same shape of defect F2-09 fixed for a single tool's
        # evidence-storage failure (completed -> partial); this is its scan-level analogue.
        # Downgrading to `completed_with_errors` keeps the scan honestly distinguishable
        # from a truly clean run without ever claiming `failed` -- the tools DID execute.
        if persistence_failures:
            return "completed_with_errors"
        return "completed"
    return "failed"


def build_executor(reporter=None, registry=None):
    """An executor callable for LeaseLoop(executor=...)."""

    async def _executor(job: dict, policy, *, stop_probe=None) -> str:
        return await execute_leased_job(
            job, policy, reporter=reporter, registry=registry, stop_probe=stop_probe,
        )

    return _executor
