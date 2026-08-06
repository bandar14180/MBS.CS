import uuid

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.attack.catalog import (
    KILL_CHAIN_ORDER,
    KILL_CHAIN_PHASE_NAMES,
    TACTIC_NAMES,
    techniques_for,
)
from apps.api.modules.attack.models import AttackMapping, AttackNarrative
from apps.api.modules.vulnerabilities.models import Vulnerability


async def sync_attack_mappings(
    db: AsyncSession, vulnerability_id: uuid.UUID, category: str | None, metadata: dict | None = None
) -> None:
    """Map a vulnerability to MITRE ATT&CK techniques + kill-chain phases and
    persist them. Idempotent: uses the (vuln, technique) unique key with
    do-nothing-on-conflict, so re-detection doesn't duplicate rows. Mirrors
    compliance.service.sync_mappings. Uses the finding's CWE `category` plus any
    Nuclei `tags` in its metadata."""
    tags = (metadata or {}).get("tags")
    techniques = techniques_for(category, tags)
    if not techniques:
        return
    rows = [
        {
            "vulnerability_id": vulnerability_id,
            "tactic_id": tactic_id,
            "tactic_name": TACTIC_NAMES.get(tactic_id, tactic_id),
            "technique_id": technique_id,
            "technique_name": technique_name,
            "kill_chain_phase": phase,
        }
        for tactic_id, technique_id, technique_name, phase in techniques
    ]
    stmt = pg_insert(AttackMapping.__table__).values(rows)
    stmt = stmt.on_conflict_do_nothing(constraint="uq_attack_vuln_technique")
    await db.execute(stmt)


async def list_attack_mappings(db: AsyncSession, vulnerability_id: uuid.UUID) -> list[AttackMapping]:
    result = await db.scalars(
        select(AttackMapping)
        .where(AttackMapping.vulnerability_id == vulnerability_id)
        .order_by(AttackMapping.tactic_id, AttackMapping.technique_id)
    )
    return list(result)


async def save_attack_narrative(
    db: AsyncSession,
    *,
    workspace_id: uuid.UUID,
    scan_id: uuid.UUID,
    summary: str | None,
    steps: list,
    model_version: str | None,
    prompt_version: str | None,
) -> None:
    """Upsert the one attack-path narrative for a scan (re-runs overwrite it)."""
    stmt = pg_insert(AttackNarrative.__table__).values(
        id=uuid.uuid4(),
        workspace_id=workspace_id,
        scan_id=scan_id,
        summary=summary,
        steps=steps,
        model_version=model_version,
        prompt_version=prompt_version,
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_attack_narrative_scan",
        set_={
            "summary": stmt.excluded.summary,
            "steps": stmt.excluded.steps,
            "model_version": stmt.excluded.model_version,
            "prompt_version": stmt.excluded.prompt_version,
        },
    )
    await db.execute(stmt)


async def get_attack_narrative(db: AsyncSession, scan_id: uuid.UUID) -> AttackNarrative | None:
    return await db.scalar(select(AttackNarrative).where(AttackNarrative.scan_id == scan_id))


# --- Scan-level aggregation (for the ATT&CK matrix + kill-chain endpoints) ------


async def _scan_mappings(db: AsyncSession, scan_id: uuid.UUID) -> list[AttackMapping]:
    """All ATT&CK mappings for the findings last seen in this scan."""
    return list(
        await db.scalars(
            select(AttackMapping)
            .join(Vulnerability, Vulnerability.id == AttackMapping.vulnerability_id)
            .where(Vulnerability.last_seen_scan_id == scan_id)
        )
    )


def kill_chain_steps(title_by_vuln_id: dict[uuid.UUID, str], mappings: list[AttackMapping]) -> list[dict]:
    """Pure: fold per-vulnerability ATT&CK mappings into ordered Cyber Kill Chain
    steps (one per phase, techniques + the finding titles evidencing them). Shared
    by the AI narrative synthesis and the deterministic kill-chain endpoint so the
    two never diverge."""
    phase_bucket: dict[str, dict[str, dict]] = {}
    for m in mappings:
        techniques = phase_bucket.setdefault(m.kill_chain_phase, {})
        tech = techniques.setdefault(
            m.technique_id,
            {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic_id": m.tactic_id,
                "tactic_name": m.tactic_name,
                "findings": set(),
            },
        )
        title = title_by_vuln_id.get(m.vulnerability_id)
        if title:
            tech["findings"].add(title)

    steps: list[dict] = []
    for phase in KILL_CHAIN_ORDER:
        if phase not in phase_bucket:
            continue
        techniques = [{**t, "findings": sorted(t["findings"])} for t in phase_bucket[phase].values()]
        steps.append({"phase": phase, "phase_name": KILL_CHAIN_PHASE_NAMES[phase], "techniques": techniques})
    return steps


async def scan_kill_chain_steps(db: AsyncSession, scan_id: uuid.UUID) -> list[dict]:
    """Deterministic kill-chain steps for a scan's findings so far (pure ATT&CK
    mapping, no AI). Shared by the live agent state-projection (mid-scan reasoning)
    and the kill-chain endpoint's fallback, so the two never diverge."""
    mappings = await _scan_mappings(db, scan_id)
    vulns = list(await db.scalars(select(Vulnerability).where(Vulnerability.last_seen_scan_id == scan_id)))
    return kill_chain_steps({v.id: v.title for v in vulns}, mappings)


async def attack_matrix_for_scan(db: AsyncSession, scan_id: uuid.UUID) -> list[dict]:
    """ATT&CK-navigator-style view: tactics -> techniques with a hit count (how
    many of the scan's findings map to each technique)."""
    mappings = await _scan_mappings(db, scan_id)
    tactics: dict[str, dict] = {}
    for m in mappings:
        tactic = tactics.setdefault(
            m.tactic_id, {"tactic_id": m.tactic_id, "tactic_name": m.tactic_name, "techniques": {}}
        )
        tech = tactic["techniques"].setdefault(
            m.technique_id,
            {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "kill_chain_phase": m.kill_chain_phase,
                "count": 0,
            },
        )
        tech["count"] += 1
    return [
        {"tactic_id": t["tactic_id"], "tactic_name": t["tactic_name"], "techniques": list(t["techniques"].values())}
        for t in tactics.values()
    ]


async def kill_chain_for_scan(db: AsyncSession, scan_id: uuid.UUID) -> dict:
    """The scan's kill-chain view. Prefers the AI Correlator narrative when
    present; otherwise falls back to the deterministic mapping so the endpoint is
    always useful (AI on or off)."""
    narrative = await get_attack_narrative(db, scan_id)
    if narrative is not None:
        return {
            "ai_generated": True,
            "summary": narrative.summary,
            "steps": narrative.steps,
            "model_version": narrative.model_version,
        }
    steps = await scan_kill_chain_steps(db, scan_id)
    return {"ai_generated": False, "summary": None, "steps": steps, "model_version": None}
