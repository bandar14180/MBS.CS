import logging
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.projects.service import get_project
from apps.api.core.pagination import MAX_LIMIT, Pagination, paginate
from apps.api.modules.authorization_scope.service import require_verified_target
from apps.api.modules.projects.service import get_target
from apps.api.modules.scans.models import Scan
from apps.api.scanner_engine.models import Evidence, ToolRun
from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY

logger = logging.getLogger(__name__)

# Every runtime knob a tool runner actually reads via config.get(...) (scanner_engine/
# tool_runners/*.py). This is the ONLY surface ScanCreate.tool_config may touch -- an
# unknown key is rejected at creation rather than silently ignored at scan time, so a
# caller finds out immediately if they mistyped a knob. Never includes an orchestration/
# safety key (requested_modules, use_agent, exploitation_enabled, ...); those have their
# own typed ScanCreate fields and cannot be overridden this way.
ALLOWED_TOOL_CONFIG_KEYS = frozenset({
    "timeout_seconds",          # shared wall-clock timeout most runners honor
    "top_ports",                # naabu, nmap fallback
    "rate",                     # naabu packet rate
    "crawl_depth", "crawl_rate",  # katana
    "param_discovery_max", "param_discovery_timeout_seconds",  # arjun
    "arjun_wordlist", "arjun_threads", "arjun_request_timeout",  # arjun tuning
    "nuclei_tags",               # nuclei template tag set
    # nuclei's OWN wall-clock timeout, independent of the shared `timeout_seconds` above.
    # Nuclei is routinely the longest tool in the pipeline (a full template set against a
    # real site legitimately outruns the 600s default -- three production runs are recorded
    # in tool_runs as `failed / exit -1 / timed out` at exactly 600s). Raising the SHARED
    # key to fix that would also raise it for subfinder/dnsx/httpx/whatweb/amass/naabu/
    # nmap/katana and, most consequentially, ffuf -- whose timeout is PER TARGET, so the
    # scan's worst case would grow by that factor times the target count. This key lets
    # nuclei be tuned alone, mirroring how nuclei-dast already has `dast_timeout_seconds`.
    "nuclei_timeout_seconds",    # nuclei only (falls back to timeout_seconds, then 600)
    "dast_timeout_seconds",      # nuclei-dast
    "ffuf_wordlist_path", "ffuf_rate",  # ffuf
})


async def create_scan(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    initiated_by: uuid.UUID,
    target_id: uuid.UUID,
    scan_type: str,
    requested_modules: list[str],
    use_ai_planner: bool = False,
    use_agent: bool = False,
    exploitation_enabled: bool = False,
    approved_hosts: list[str] | None = None,
    tool_config: dict | None = None,
) -> Scan:
    target = await get_target(db, workspace_id, project_id, target_id)  # 404s if not in this project/workspace

    from apps.api.scanner_engine import capabilities

    # Refuse target types with no scanner engine -- otherwise the scan would
    # "complete" having run nothing. The capability registry is the source of truth.
    if not capabilities.is_supported(target.type):
        supported = sorted(capabilities.supported_target_types())
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Target type '{target.type}' is not supported for scanning yet "
            f"(supported: {', '.join(supported) or 'none'}). Refusing to start a scan "
            f"that would assess nothing.",
        )

    from apps.api.modules.billing import service as billing

    await billing.enforce_scan_quota(db, workspace_id)

    unknown = [m for m in requested_modules if m not in TOOL_REGISTRY]
    if unknown:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown tool module(s): {', '.join(unknown)}")

    unknown_tool_config = [k for k in (tool_config or {}) if k not in ALLOWED_TOOL_CONFIG_KEYS]
    if unknown_tool_config:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Unknown tool_config key(s): {', '.join(sorted(unknown_tool_config))}. "
            f"Allowed: {', '.join(sorted(ALLOWED_TOOL_CONFIG_KEYS))}",
        )

    # AI planning needs a configured key. Reject at creation time with a clear
    # message rather than letting the scan fail-fast at runtime with a confusing
    # "all stages skipped" result. (Fail-fast, but at the right layer.)
    if use_ai_planner:
        from apps.api.core.config import get_settings

        settings = get_settings()
        if not settings.ai_enabled:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"AI planner requires an API key for the configured AI provider "
                f"('{settings.ai_provider}'). Turn off 'Use AI planner' to run the scan "
                f"without AI, or set the provider's API key.",
            )

    # The guardrail: no verified authorization scope, no scan. See
    # authorization_scope.service.require_verified_target.
    scope = await require_verified_target(db, workspace_id, project_id, target_id)

    # Active-testing tools (nuclei/...) may only be requested when the scope
    # explicitly permits active testing -- block at the API layer, not just at
    # execution (blueprint §7). The orchestrator re-checks in case authorization
    # is revoked before the scan runs.
    if not scope.active_testing_allowed:
        active = [m for m in requested_modules if TOOL_REGISTRY[m].requires_active_testing]
        if active:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Active testing not authorized for this target; requested active module(s): {', '.join(active)}",
            )

    # MBS.SC: resolve the target's NETWORK ZONE from the persisted target row, and (for a
    # private target) validate the whole authorization chain BEFORE the scan row is created.
    # Doing it here means an unauthorized private request is rejected at the API with a
    # clear reason instead of being queued and failing minutes later inside a worker.
    #
    # The zone is read from the TARGET, never from caller-supplied config: a client must not
    # be able to declare a target private (or public) at scan time.
    from apps.api.modules.private_sites import service as private_sites_service
    from apps.api.modules.projects.models import Target as _Target

    target_row = await db.get(_Target, target_id)
    target_zone = (getattr(target_row, "network_zone", None) or "public") if target_row else "public"
    target_site_id = getattr(target_row, "site_id", None) if target_row else None

    if target_zone == "private":
        try:
            # Builds (and therefore fully validates) the site chain: ownership by THIS
            # workspace, active lifecycle state, and a non-empty CIDR set.
            await private_sites_service.build_scan_network_policy(
                db, workspace_id=workspace_id, scan_id=None,
                network_zone="private", site_id=target_site_id,
            )
        except private_sites_service.PrivateSiteNotAuthorized as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"{exc.reason}: {exc.message}")

    scan = Scan(
        workspace_id=workspace_id,
        project_id=project_id,
        target_id=target_id,
        initiated_by=initiated_by,
        scan_type=scan_type,
        status="queued",
        config={
            # tool_config first: an allowlisted knob is real, caller-supplied tuning, but
            # it must never be able to shadow an orchestration/safety key -- the explicit
            # keys below always win the merge regardless of dict order.
            **(tool_config or {}),
            "requested_modules": requested_modules,
            "use_ai_planner": use_ai_planner,
            "use_agent": use_agent,
            "exploitation_enabled": exploitation_enabled,
            "approved_hosts": approved_hosts or [],
            # MBS.SC: recorded so the worker and the manager can both see which zone/site
            # this scan belongs to without re-reading the target. AUTHORITY still lives on
            # the target row -- the orchestrator re-derives its policy from the target, so
            # a tampered config value cannot widen access, only misroute (which the
            # worker-side and manager-side checks then refuse).
            "network_zone": target_zone,
            "site_id": str(target_site_id) if target_site_id else None,
        },
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # DISPATCH. Which mechanism actually executes this scan depends on the deployed
    # execution model, and getting this wrong is what stranded 110 scans.
    #
    # THE INCIDENT THIS CLOSES. This function used to ALWAYS `apply_async` to
    # `scans.public` (or a per-site queue). Under the MBS.SC lease model nothing consumes
    # those queues: the scan worker is deliberately off `mbs-core`, cannot reach Redis, and
    # runs `scanner_worker.main` (an HTTP lease loop) instead of `celery worker`. So every
    # scan wrote a Celery message that no process would ever read -- verified live as 110
    # undelivered messages in `scans.public`.
    #
    # The message being useless was not the damage. `celery_task_id` was set from its
    # result, and `_relay_queued()` only rescues scans with `celery_task_id IS NULL`, so a
    # SUCCESSFUL-but-unconsumable enqueue permanently disqualified the scan from the very
    # safety net meant to catch an undispatched scan. A scan created 2026-09-17 11:32:30 sat
    # `queued` with 0 tool runs and was structurally unrecoverable.
    #
    # UNDER THE LEASE MODEL THERE IS NOTHING TO ENQUEUE. The scan ROW is the queue: a
    # worker calls POST /v1/lease, the manager selects `status='queued'` rows the worker is
    # authorized for, and `_claim_scan` performs the atomic queued -> running transition.
    # Committing the row (above) IS the dispatch. Leaving `celery_task_id` NULL is therefore
    # correct AND load-bearing: it keeps the scan visible to the relay, so a scan that is
    # never leased stays recoverable instead of silently stranded.
    #
    # The Celery path is kept for a deployment that still runs a control-plane executor
    # consuming the scan queue (it needs DB access, which the isolated worker does not
    # have). `celery_scan_dispatch_enabled` selects between them; it defaults to OFF,
    # matching the deployed architecture, and the two models are never both used for one
    # scan -- one dispatch mechanism per scan, never two competing ones.
    from apps.api.core.config import get_settings as _get_settings

    if _get_settings().celery_scan_dispatch_enabled:
        # Imported here, not at module load: celery_app.worker importing back
        # through apps.api.main at import time is a needless coupling risk, and
        # this keeps the API process from needing a live Celery/Redis connection
        # just to import the scans module.
        from apps.api.celery_app.tasks.scan_tasks import run_scan_task
        from apps.api.core.observability import get_correlation_id

        # Propagate the request correlation id (Phase 4.1) so the worker's scan logs can be
        # joined to the API request that created the scan. For a scheduled dispatch
        # (worker/beat context, no request) this is the ambient "-", which the task replaces
        # with a fresh id. MBS.SC Phase 5: route by zone/site -- a public scan goes to
        # `scans.public`; a private scan goes to its own per-site queue so no generic worker
        # can consume it.
        from apps.api.scanner_engine.scan_routing import queue_for_scan

        scan_queue = queue_for_scan(network_zone=target_zone, site_id=target_site_id)
        async_result = run_scan_task.apply_async(
            args=[str(scan.id)],
            kwargs={"correlation_id": get_correlation_id()},
            queue=scan_queue,
        )
        scan.celery_task_id = async_result.id
    else:
        logger.info(
            "scan.dispatch_lease scan=%s zone=%s -- awaiting worker lease (no Celery enqueue)",
            scan.id, target_zone,
            extra={"event": "scan.dispatch_lease", "scan_id": str(scan.id),
                   "network_zone": target_zone, "dispatch": "lease"},
        )

    from apps.api.modules.audit import service as audit

    await audit.record(
        db, workspace_id, initiated_by, "scan.created", "scan",
        resource_id=scan.id, detail=f"{scan_type}: {', '.join(requested_modules)}",
        outcome=audit.OUTCOME_SUCCESS,  # Prompt 34: the scan record was created.
    )
    await db.commit()
    await db.refresh(scan)

    return scan


async def list_scans(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, page: Pagination | None = None
) -> tuple[list[Scan], int]:
    # AUDIT-010: verify the project EXISTS IN THIS WORKSPACE before listing.
    #
    # The query below is correctly scoped, so a cross-tenant project id never leaked data --
    # it returned `200 []`. But `200 []` and `404` are different answers to the same
    # question, and this API already answers it with 404 everywhere else (the single-resource
    # getters, and the reports/targets list endpoints, which call get_project for exactly
    # this reason). An empty 200 says "this project is yours and has nothing"; the truth is
    # "this project is not yours". Beyond the inconsistency, it is a weak existence oracle:
    # a caller could tell a real foreign project id from a random UUID if the two ever
    # diverged, and it hides genuine client bugs behind a success response.
    await get_project(db, workspace_id, project_id)
    query = (
        select(Scan)
        .where(Scan.workspace_id == workspace_id, Scan.project_id == project_id)
        .order_by(Scan.created_at.desc(), Scan.id)
    )
    return await paginate(db, query, page or Pagination(limit=MAX_LIMIT, offset=0))


async def get_scan(db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, scan_id: uuid.UUID) -> Scan:
    scan = await db.scalar(
        select(Scan).where(
            Scan.id == scan_id, Scan.workspace_id == workspace_id, Scan.project_id == project_id
        )
    )
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return scan


async def cancel_scan(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, scan_id: uuid.UUID
) -> Scan:
    """Cancel a scan, atomically.

    F2-03/F2-04: this used to be read-then-write -- an unconditional `scan.status =
    'cancelled'` ORM assignment, committed with no WHERE clause tying the write to the
    status this function had just read. A concurrent terminal write (the lease worker's
    fenced `_finalize_status`, or the Celery path finishing at the same instant) could land
    between the read and this commit and be silently clobbered back to 'cancelled' -- the
    scan would report cancelled even though it had already completed/failed. The terminal
    check was also missing `completed_with_errors`, so a scan in that state was treated as
    still cancellable.

    The fix reuses the SAME fencing idiom `orchestrator._finalize_status` already uses for
    the lease/Celery terminal write: one conditional `UPDATE ... WHERE status NOT IN
    (<canonical terminal statuses>)`, whose rowcount tells us whether THIS call actually won
    the race. The database condition -- not a prior Python-side read -- is what enforces the
    invariant, so a scan that reaches a terminal state after this function's own SELECT but
    before its UPDATE is still protected.
    """
    from apps.api.scanner_engine.orchestrator import _TERMINAL_STATUSES

    scan = await get_scan(db, workspace_id, project_id, scan_id)

    if scan.status in _TERMINAL_STATUSES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Scan already {scan.status}, cannot cancel")

    placeholders = ", ".join(f":st{i}" for i in range(len(_TERMINAL_STATUSES)))
    params: dict = {"id": str(scan.id), "now": datetime.now(timezone.utc)}
    params.update({f"st{i}": s for i, s in enumerate(_TERMINAL_STATUSES)})
    result = await db.execute(
        text(
            "UPDATE scans SET status = 'cancelled', completed_at = :now, execution_token = NULL "
            f"WHERE id = :id AND status NOT IN ({placeholders})"
        ),
        params,
    )
    won = result.rowcount == 1
    await db.commit()
    await db.refresh(scan)

    if not won:
        # Lost the race: some other write (a lease worker finishing, a Celery task
        # completing) reached a terminal state first. `scan` now reflects that authoritative
        # outcome -- report it rather than pretending the cancellation succeeded.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Scan already {scan.status}, cannot cancel")

    if scan.celery_task_id:
        from apps.api.celery_app.worker import celery_app

        celery_app.control.revoke(scan.celery_task_id, terminate=True)

    return scan


async def list_tool_runs(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, scan_id: uuid.UUID
) -> list[ToolRun]:
    await get_scan(db, workspace_id, project_id, scan_id)
    result = await db.scalars(select(ToolRun).where(ToolRun.scan_id == scan_id).order_by(ToolRun.started_at))
    return list(result)


async def get_scan_timeline(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, scan_id: uuid.UUID, page: Pagination
) -> tuple[list[dict], int]:
    """Chronological scan event stream (Phase 1.3): scan started, tool executions,
    findings, agent decisions/actions, scan completed. Ownership is enforced by
    get_scan (404 out-of-scope); the underlying tool_runs / agent_steps /
    vulnerabilities is a VIA table in tenancy.py, so the bound workspace scopes it too.
    Bounded per scan; paginated in memory over the merged, time-ordered events."""
    from apps.api.modules.agent.models import AgentStep
    from apps.api.modules.vulnerabilities.models import Vulnerability

    scan = await get_scan(db, workspace_id, project_id, scan_id)
    events: list[dict] = []
    if scan.started_at:
        events.append({"ts": scan.started_at, "event": "scan.started", "tool": None, "status": "running", "detail": None})
    for tr in await db.scalars(select(ToolRun).where(ToolRun.scan_id == scan_id)):
        events.append({"ts": tr.started_at, "event": "tool.executed", "tool": tr.tool_name,
                       "status": tr.status, "detail": (tr.error_message or None) and tr.error_message[:300]})
    for st in await db.scalars(select(AgentStep).where(AgentStep.scan_id == scan_id)):
        events.append({"ts": st.created_at, "event": f"agent.{st.action_type}", "tool": st.tool_or_module,
                       "status": st.status, "detail": (st.result_summary or None) and st.result_summary[:300]})
    for v in await db.scalars(select(Vulnerability).where(Vulnerability.last_seen_scan_id == scan_id)):
        events.append({"ts": v.created_at, "event": "finding.generated", "tool": None,
                       "status": v.severity, "detail": (v.title or "")[:300]})
    if scan.completed_at:
        events.append({"ts": scan.completed_at, "event": "scan.completed", "tool": None,
                       "status": scan.status, "detail": None})

    _epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    events.sort(key=lambda e: e["ts"] or _epoch)
    total = len(events)
    window = events[page.offset: page.offset + page.limit]
    return window, total


async def get_scan_coverage(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, scan_id: uuid.UUID
) -> dict:
    """Engagement-wide coverage projection for a scan (Prompt 14): which discovered surface
    still has unfulfilled testing opportunities (coverage debt), derived deterministically
    from persisted assets + tool_runs. Read-only; ownership via get_scan (404 out-of-scope),
    tenant isolation via tenancy.py on assets/tool_runs. Never runs a tool."""
    from apps.api.scanner_engine.coverage import build_scan_coverage

    scan = await get_scan(db, workspace_id, project_id, scan_id)
    projection = await build_scan_coverage(db, scan)
    return {
        "has_debt": projection.has_debt,
        "debt_summary": projection.debt_summary(),
        "capability_states": projection.capability_states,
        "debt": [vars(s) for s in projection.debt],
        "surfaces": [vars(s) for s in projection.surfaces],
    }


async def get_scan_next_steps(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, scan_id: uuid.UUID
) -> dict:
    """Deterministic, evidence-driven adaptive next-step candidates for a scan (Prompt 21):
    which detection/investigation steps the accumulated evidence justifies next. Read-only;
    derived from persisted assets + tool_runs, gated by the same verified scope + RoE the
    orchestrator enforces. Ownership via get_scan (404 out-of-scope), tenant isolation via
    tenancy.py. Each entry is a CANDIDATE/signal, never a finding, and nothing is executed."""
    from apps.api.scanner_engine.adaptive import build_scan_next_steps

    scan = await get_scan(db, workspace_id, project_id, scan_id)
    candidates = await build_scan_next_steps(db, scan)
    return {
        "count": len(candidates),
        "candidates": [
            {
                "capability": c.capability,
                "tool": c.tool,
                "target": c.target,
                "reasons": list(c.reasons),
                "reason_trace": c.reason_trace(),
                "provenance": c.provenance,
            }
            for c in candidates
        ],
    }


async def list_evidence(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    scan_id: uuid.UUID,
    tool_run_id: uuid.UUID,
) -> list[Evidence]:
    await get_scan(db, workspace_id, project_id, scan_id)
    tool_run = await db.scalar(select(ToolRun).where(ToolRun.id == tool_run_id, ToolRun.scan_id == scan_id))
    if tool_run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tool run not found")

    result = await db.scalars(
        select(Evidence).where(Evidence.tool_run_id == tool_run_id).order_by(Evidence.created_at)
    )
    return list(result)


async def get_ai_plan(db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, scan_id: uuid.UUID):
    from apps.api.ai_agent.models import AIPlan

    await get_scan(db, workspace_id, project_id, scan_id)
    plan = await db.scalar(
        select(AIPlan).where(AIPlan.scan_id == scan_id).order_by(AIPlan.created_at.desc()).limit(1)
    )
    if plan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No AI plan for this scan (AI planning may be disabled)")
    return plan
