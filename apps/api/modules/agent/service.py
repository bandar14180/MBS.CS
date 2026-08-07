"""Read-only accessors for autonomous-engagement state (M4.4.5).

The attack graph is built and persisted ONLY by the orchestrator (deterministic,
evidence-driven). This layer just READS the persisted EngagementState -- there is no
write path here, so the API can never mutate graph/access state. Workspace isolation
comes from the request's RLS GUC (engagement_state is FORCE-RLS on workspace_id).
"""
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.pagination import Pagination, paginate
from apps.api.modules.agent.models import AgentDecision, EngagementState


async def get_engagement(db: AsyncSession, scan_id: uuid.UUID) -> EngagementState | None:
    """The engagement state for a scan (None for a non-agent scan). RLS-scoped."""
    return await db.scalar(select(EngagementState).where(EngagementState.scan_id == scan_id))


async def list_agent_decisions(db: AsyncSession, scan_id: uuid.UUID, page: Pagination):
    """Paginated structured agent-decision trace for a scan (Phase 1.3), ordered by
    step_no. FORCE-RLS on agent_decisions scopes this to the request's workspace; the
    caller additionally verifies scan ownership. Returns (rows, total)."""
    query = select(AgentDecision).where(AgentDecision.scan_id == scan_id).order_by(AgentDecision.step_no)
    return await paginate(db, query, page)
