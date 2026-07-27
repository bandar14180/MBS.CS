import hashlib
import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.assets.models import Asset
from apps.api.modules.assets.service import upsert_asset
from apps.api.modules.authorization_scope.service import require_verified_target
from apps.api.modules.compliance.service import sync_mappings
from apps.api.modules.risk.service import upsert_risk_score
from apps.api.modules.scans.models import Scan
from apps.api.modules.vulnerabilities.service import ingest_finding
from apps.api.scanner_engine import evidence_store
from apps.api.scanner_engine.models import Evidence, ToolRun
from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY
from apps.api.scanner_engine.tool_runners.base import CommonFinding
from sqlalchemy import select


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

    await db.execute(
        text("SELECT set_config('app.current_workspace_id', :wid, false)"),
        {"wid": str(scan.workspace_id)},
    )

    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    await db.commit()

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

        requested = scan.config.get("requested_modules", [])

        # Opt-in AI planning (blueprint §7 step 2). When enabled, the AI Planner
        # proposes which of the requested tools to run and in what order; its
        # output is allowlist-enforced in code (planner._sanitize) so it can only
        # re-order/prune, never introduce a tool. Default off -> deterministic
        # phase order, unchanged behavior for every existing scan.
        if scan.config.get("use_ai_planner"):
            from apps.api.ai_agent.planner import AIPlanner

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

        runners = [TOOL_REGISTRY[m]() for m in requested if m in TOOL_REGISTRY]
        # Deterministic recon pipeline: run in phase order regardless of the
        # order they were requested (subfinder -> httpx -> naabu -> nmap -> nuclei).
        # The AI planner (above) may prune/reorder, but phase order still governs
        # the actual pipeline dependencies.
        runners.sort(key=lambda r: r.phase)

        # Findings accumulate across the pipeline so later tools build on earlier
        # ones (httpx probes subfinder's subdomains; nmap deep-scans naabu ports;
        # nuclei scans httpx's http services).
        discovered: list[CommonFinding] = []
        for runner in runners:
            # Skip tools that don't apply to this target's type (e.g. subfinder
            # on an ip_range) -- cleanly, without recording a failed run.
            if runner.applicable_target_types is not None and target_row.type not in runner.applicable_target_types:
                continue
            # Active-testing gate (blueprint §7): tools that send payloads run
            # only when the scope explicitly permits active testing. Creation
            # already 403s this combination, but authorization can be revoked
            # between queue and execution -- record a visible skipped run.
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
            findings = await _run_single_tool(
                db, scan, runner, target_row.value, discovered, target_row.criticality
            )
            discovered.extend(findings)

        scan.status = "completed"
    except Exception:
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        await db.commit()
        raise

    scan.completed_at = datetime.now(timezone.utc)
    await db.commit()


async def _run_single_tool(
    db: AsyncSession,
    scan: Scan,
    runner,
    target_value: str,
    prior_findings: list[CommonFinding],
    criticality: str,
) -> list[CommonFinding]:
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

    try:
        raw = await runner.run(target_value, config, prior_findings)
    except Exception:
        tool_run.status = "failed"
        tool_run.completed_at = datetime.now(timezone.utc)
        await db.commit()
        raise

    tool_run.command_hash = hashlib.sha256(raw.command.encode()).hexdigest()
    tool_run.exit_code = raw.exit_code

    # Every finding must trace to raw evidence (blueprint §1) -- store the raw
    # stdout/stderr blob in object storage and record an evidence row BEFORE
    # turning any of it into assets.
    blob = (
        f"$ {raw.command}\n\n=== STDOUT ===\n{raw.stdout}\n\n=== STDERR ===\n{raw.stderr}\n"
    ).encode()
    storage_uri, checksum = evidence_store.store_raw_output(tool_run.id, blob)
    tool_run.raw_output_ref = storage_uri
    evidence = Evidence(
        tool_run_id=tool_run.id,
        evidence_type="log_excerpt",
        storage_uri=storage_uri,
        checksum=checksum,
    )
    db.add(evidence)
    await db.flush()  # need evidence.id to link vulnerabilities to it

    findings = runner.parse(raw)
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
    # lifecycle), each linked to this run's evidence. Then the Risk Engine
    # weights CVSS by asset criticality, and the Compliance Engine maps the
    # finding's category to framework controls (blueprint §7 steps 7 & later).
    for vuln_finding in runner.parse_vulnerabilities(raw):
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

    tool_run.status = "completed" if raw.exit_code == 0 else "failed"
    tool_run.completed_at = datetime.now(timezone.utc)
    await db.commit()
    return findings


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
