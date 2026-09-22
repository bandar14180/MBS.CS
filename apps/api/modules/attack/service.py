import uuid

from sqlalchemy import select
from sqlalchemy.dialects.mysql import insert as mysql_insert
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
    md = metadata or {}
    tags = md.get("tags")
    # Pass identifying metadata so techniques_for can skip DETECTIONS (P1.6): a technology/WAF/
    # version detection must not inherit ATT&CK techniques via a generic CWE. Genuine
    # vulnerabilities are unaffected -- see attack/catalog.techniques_for. cvss_score isn't in
    # this metadata; None is correct (the classifier then leans on template_id/cve/tags).
    techniques = techniques_for(
        category, tags, template_id=md.get("template_id"), cve=md.get("cve")
    )
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
    stmt = mysql_insert(AttackMapping.__table__).values(rows)
    # Phase 0 MySQL cutover: MySQL do-nothing-on-conflict idiom -- see
    # compliance/service.py's sync_mappings for the fuller explanation.
    stmt = stmt.on_duplicate_key_update(id=stmt.inserted.id)
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
    # Phase 0 MySQL cutover: Postgres's `excluded` (the row that would have been
    # inserted) -> MySQL's `.inserted` / VALUES(col), same concept under a different name.
    stmt = mysql_insert(AttackNarrative.__table__).values(
        id=uuid.uuid4(),
        workspace_id=workspace_id,
        scan_id=scan_id,
        summary=summary,
        steps=steps,
        model_version=model_version,
        prompt_version=prompt_version,
    )
    stmt = stmt.on_duplicate_key_update(
        summary=stmt.inserted.summary,
        steps=stmt.inserted.steps,
        model_version=stmt.inserted.model_version,
        prompt_version=stmt.inserted.prompt_version,
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


async def _scan_vulns_by_id(db: AsyncSession, scan_id: uuid.UUID) -> dict[uuid.UUID, Vulnerability]:
    """The scan's findings, indexed by id, so a mapping can be resolved back to the finding
    that produced it -- which is what makes canonical issue identity and the scorable filter
    available to the API surfaces (see attack.aggregation)."""
    return {
        v.id: v
        for v in await db.scalars(select(Vulnerability).where(Vulnerability.last_seen_scan_id == scan_id))
    }


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
        phase_techniques = [{**t, "findings": sorted(t["findings"])} for t in phase_bucket[phase].values()]
        steps.append({"phase": phase, "phase_name": KILL_CHAIN_PHASE_NAMES[phase], "techniques": phase_techniques})
    return steps


async def scan_kill_chain_steps(db: AsyncSession, scan_id: uuid.UUID) -> list[dict]:
    """Deterministic kill-chain steps for a scan's findings so far (pure ATT&CK
    mapping, no AI). Shared by the live agent state-projection (mid-scan reasoning)
    and the kill-chain endpoint's fallback, so the two never diverge.

    Restricted to the SCORABLE findings (attack.aggregation) so the kill chain describes
    the same population as the ATT&CK matrix and the PDF: a remediated or false-positive
    finding is no longer presented as evidence of a live attack path, and a technology
    DETECTION no longer contributes a step. Mappings whose finding is excluded are dropped
    before the fold, so an excluded finding cannot leave an empty technique behind."""
    from apps.api.modules.attack.aggregation import scorable_vuln_ids

    mappings = await _scan_mappings(db, scan_id)
    vulns_by_id = await _scan_vulns_by_id(db, scan_id)
    countable = scorable_vuln_ids(mappings, vulns_by_id)
    scorable_mappings = [m for m in mappings if m.vulnerability_id in countable]
    titles = {vid: v.title for vid, v in vulns_by_id.items() if vid in countable}
    return kill_chain_steps(titles, scorable_mappings)


async def attack_matrix_for_scan(db: AsyncSession, scan_id: uuid.UUID) -> list[dict]:
    """ATT&CK-navigator-style view: tactics -> techniques with a hit count.

    `count` is the number of DISTINCT LOGICAL ISSUES hitting the technique -- the SAME
    number the PDF report shows, because both now go through attack.aggregation (see that
    module for why the two used to disagree). It previously counted raw `attack_mappings`
    ROWS over every finding regardless of status, so one issue observed at five URLs read as
    five, and fixed / false-positive / informational / detection findings all contributed to
    what the UI presents as current coverage.
    """
    from apps.api.modules.attack.aggregation import count_issues_by_technique

    mappings = await _scan_mappings(db, scan_id)
    vulns_by_id = await _scan_vulns_by_id(db, scan_id)
    counts = count_issues_by_technique(mappings, vulns_by_id)

    # kill_chain_phase is a property of the technique, not of the count, so it is carried
    # over from the mapping rows.
    phase_by_technique = {m.technique_id: m.kill_chain_phase for m in mappings}

    tactics: dict[str, dict] = {}
    for (tactic_id, tactic_name, technique_id, technique_name), count in counts.items():
        tactic = tactics.setdefault(
            tactic_id, {"tactic_id": tactic_id, "tactic_name": tactic_name, "techniques": {}}
        )
        tactic["techniques"][technique_id] = {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "kill_chain_phase": phase_by_technique.get(technique_id),
            "count": count,
        }
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
