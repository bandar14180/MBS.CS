"""Persistence for the structured reasoning audit (agent_decisions, M4.4).

Unlike ai_usage (an independent best-effort tx), a decision record is part of the
scan's reasoning audit and is written on the ORCHESTRATOR's session -- the workspace
workspace is already bound on that session, and the row must share the transaction that
created its AgentStep so `agent_step_id` is a valid FK. Kept as thin functions (no
abstraction layer) matching the project's repo style (usage_repo / attack.service).
"""
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.agent.models import AgentDecision


def _serialize_candidates(decision) -> list[dict]:
    """The ranked candidate set as JSON (already allowlist-vetted in agent.decide)."""
    out: list[dict] = []
    for c in getattr(decision, "candidates", []) or []:
        out.append(
            {
                "tool": c.tool,
                "confidence": c.confidence,
                "expected_value": c.expected_value,
                "risk": c.risk,
                "expected_evidence": list(c.expected_evidence or []),
                "rationale": c.rationale,
            }
        )
    return out


async def persist_agent_decision(
    db: AsyncSession,
    *,
    workspace_id: uuid.UUID,
    scan_id: uuid.UUID,
    step_no: int,
    decision,
    agent_step_id: uuid.UUID | None = None,
    budget_state: dict | None = None,
) -> AgentDecision:
    """Insert one structured decision row for a reasoning cycle. Uses the caller's
    session/transaction (workspace already bound). Returns the row (flushed)."""
    row = AgentDecision(
        workspace_id=workspace_id,
        scan_id=scan_id,
        agent_step_id=agent_step_id,
        step_no=step_no,
        phase=decision.phase,
        action=decision.action,
        observations=list(decision.observations or []),
        inferences=list(decision.inferences or []),
        hypotheses=list(decision.hypotheses or []),
        candidates=_serialize_candidates(decision),
        selected_tool=decision.tool,
        selected_confidence=decision.confidence,
        rationale=(decision.rationale or None) and decision.rationale[:2000],
        stop_reason=decision.stop_reason,
        budget_state=budget_state or {},
        model_version=decision.model_version,
        prompt_version=decision.prompt_version,
    )
    db.add(row)
    await db.flush()
    return row


async def latest_agent_decision(db: AsyncSession, scan_id: uuid.UUID) -> AgentDecision | None:
    """The most recent decision row for a scan (highest step_no) -- the source of the
    prior observations/inferences/hypotheses fed into the NEXT reasoning cycle
    (M4.4.2). Workspace-scoped by tenancy.py's ORM filter on the caller's session."""
    return await db.scalar(
        select(AgentDecision)
        .where(AgentDecision.scan_id == scan_id)
        .order_by(AgentDecision.step_no.desc())
        .limit(1)
    )
