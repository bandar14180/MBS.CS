import hashlib
import logging
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.events import ScanCompleted, emit as emit_event, subscribe as subscribe_event
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


async def _load_scan(db: AsyncSession, scan_id: uuid.UUID) -> Scan:
    # scans is intentionally not RLS-protected; we read it by trusted id first,
    # THEN set the workspace RLS var so every subsequent read/write on
    # projects/targets/assets/authorization_scopes is correctly scoped.
    scan = await db.get(Scan, scan_id)
    if scan is None:
        raise ValueError(f"Scan {scan_id} not found")
    return scan


async def run_scan(db: AsyncSession, scan_id: uuid.UUID) -> None:
    scan = await _load_scan(db, scan_id)

    # Idempotency (P1-6): a task can be re-delivered after a worker crash
    # (acks_late) or a retry. If this scan already reached a terminal state, do
    # nothing -- never re-run a finished/cancelled scan.
    if scan.status in ("completed", "completed_with_errors", "cancelled"):
        logger.info("scan.skip_already_terminal scan=%s status=%s", scan.id, scan.status)
        return

    await db.execute(
        text("SELECT set_config('app.current_workspace_id', :wid, false)"),
        {"wid": str(scan.workspace_id)},
    )

    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    await db.commit()

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
            tool_statuses = await _run_agent_driven(db, scan, target_row, scope)
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
                    db, scan, runner, target_row.value, discovered, target_row.criticality
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
            scan.status = "failed"
        elif any(s in ("failed", "partial") for s in tool_statuses):
            scan.status = "completed_with_errors"
        else:
            scan.status = "completed"

        # Best-effort AI attack-path narrative over all of this scan's findings.
        # Fully fail-soft: an AI failure never changes the scan status or aborts.
        await _synthesize_attack_narrative(db, scan)
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        await db.commit()
        logger.error(
            "scan.failed scan=%s duration=%.2fs error=%s",
            scan.id, time.monotonic() - scan_started, exc, exc_info=True,
        )
        await _publish_scan_completed(db, scan)
        raise

    scan.completed_at = datetime.now(timezone.utc)
    await db.commit()
    logger.info(
        "scan.finished scan=%s status=%s duration=%.2fs tools_run=%d",
        scan.id, scan.status, time.monotonic() - scan_started, len(runners),
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


def _summarize_findings(discovered: list[CommonFinding]) -> str:
    """Bounded summary of discovered assets for the agent's context (never the raw
    tool output). Keeps the model's context small as an engagement grows."""
    if not discovered:
        return "(none yet)"
    from collections import Counter

    counts = Counter(f.asset_type for f in discovered)
    totals = "; ".join(f"{n} {t}(s)" for t, n in counts.items())
    examples = ", ".join(f"{f.asset_type}:{f.value}" for f in discovered[:8])
    return f"{totals}. Examples: {examples}"


async def _run_agent_driven(db: AsyncSession, scan: Scan, target_row, scope) -> list[str]:
    """Agent-driven engagement (M2): the single RedTeamAgent chooses tools
    dynamically by kill-chain phase + accumulated results, within the engagement's
    Rules of Engagement (safety enforced in code, not prompt). Every decision + tool
    run is recorded to agent_steps; engagement_state tracks the live phase. Reuses
    the deterministic `_run_single_tool` for execution. FAIL-SOFT: an AI failure
    ends the loop cleanly -- deterministic tools already run are kept -- and a
    per-tool safety violation blocks just that tool, never the engagement."""
    import asyncio

    from apps.api.ai_agent.agent import RedTeamAgent
    from apps.api.ai_agent.providers.usage import collect_ai_usage
    from apps.api.ai_agent.usage_repo import persist_ai_usage
    from apps.api.modules.agent.models import AgentStep, EngagementState
    from apps.api.scanner_engine.safety import RulesOfEngagement, SafetyViolation, assert_action_allowed

    settings = get_settings()
    roe = RulesOfEngagement.from_config(scan.config)
    agent = RedTeamAgent()

    state = EngagementState(
        workspace_id=scan.workspace_id,
        scan_id=scan.id,
        status="running",
        current_phase="reconnaissance",
        objective=f"Safe autonomous red-team assessment of {target_row.value}",
    )
    db.add(state)
    await db.flush()

    discovered: list[CommonFinding] = []
    tool_statuses: list[str] = []
    already_run: set[str] = set()
    step_no = 0

    def _record(phase, action_type, tool, tier, rationale, result, status):
        db.add(
            AgentStep(
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
        )

    while step_no < settings.agent_max_steps:
        available = agent.available_tools(
            target_type=target_row.type,
            active_testing_allowed=scope.active_testing_allowed,
            roe=roe,
            already_run=already_run,
        )
        with collect_ai_usage(
            agent_role="agent", workspace_id=str(scan.workspace_id), scan_id=str(scan.id)
        ) as usage:
            decision = await asyncio.to_thread(
                agent.decide,
                target_type=target_row.type,
                target_value=target_row.value,
                current_phase=state.current_phase,
                findings_summary=_summarize_findings(discovered),
                tools_run_summary=", ".join(sorted(already_run)) or "(none)",
                available=available,
            )
        await persist_ai_usage(usage)

        if decision.action != "run_tool" or not decision.tool:
            _record(decision.phase, "decision", None, None, decision.rationale, "engagement finished", "executed")
            await db.commit()
            break

        runner = TOOL_REGISTRY[decision.tool]()
        # Safety gate (belt and suspenders -- available_tools already filtered).
        try:
            assert_action_allowed(safety_tier=runner.safety_tier, roe=roe)
        except SafetyViolation as exc:
            _record(decision.phase, "tool_run", decision.tool, runner.safety_tier, decision.rationale, f"BLOCKED: {exc}", "blocked")
            already_run.add(decision.tool)
            await db.commit()
            step_no += 1
            continue

        findings, status = await _run_single_tool(
            db, scan, runner, target_row.value, discovered, target_row.criticality
        )
        discovered.extend(findings)
        tool_statuses.append(status)
        already_run.add(decision.tool)
        state.current_phase = decision.phase
        _record(decision.phase, "tool_run", decision.tool, runner.safety_tier, decision.rationale, f"{status}: {len(findings)} finding(s)", status)
        await db.commit()
        step_no += 1

    state.status = "completed"
    await db.commit()
    return tool_statuses


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
        from apps.api.modules.attack.models import AttackMapping
        from apps.api.modules.attack.service import kill_chain_steps, save_attack_narrative
        from apps.api.modules.vulnerabilities.models import Vulnerability

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
) -> tuple[list[CommonFinding], str]:
    """Run one tool resiliently and return (findings, status) where status is
    completed | partial | failed. A tool NEVER aborts the scan: a crash/timeout or
    a non-zero exit with no usable output is recorded as `failed` and the pipeline
    moves on; a non-zero exit that still produced parseable output is `partial`
    (its findings are kept). The overall scan status is aggregated by the caller."""
    config = scan.config or {}
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

    # A crash/timeout in the runner is a failed tool run, NOT a failed scan: record
    # it (with evidence of the exception) and let the pipeline continue.
    try:
        raw = await runner.run(target_value, config, prior_findings)
    except Exception as exc:
        tool_run.status = "failed"
        tool_run.completed_at = datetime.now(timezone.utc)
        tool_run.error_message = f"{type(exc).__name__}: {exc}"[:2000]
        await db.commit()
        logger.error(
            "tool.failed scan=%s tool=%s duration=%.2fs error=%s",
            scan.id, runner.name, time.monotonic() - started, exc, exc_info=True,
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

    tool_run.status = status
    tool_run.completed_at = datetime.now(timezone.utc)
    await db.commit()

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
