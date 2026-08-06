"""Read-only accessors for autonomous-engagement state (M4.4.5).

The attack graph is built and persisted ONLY by the orchestrator (deterministic,
evidence-driven). This layer just READS the persisted EngagementState -- there is no
write path here, so the API can never mutate graph/access state. Workspace isolation
comes from the request's RLS GUC (engagement_state is FORCE-RLS on workspace_id).
"""
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.agent.models import EngagementState


async def get_engagement(db: AsyncSession, scan_id: uuid.UUID) -> EngagementState | None:
    """The engagement state for a scan (None for a non-agent scan). RLS-scoped."""
    return await db.scalar(select(EngagementState).where(EngagementState.scan_id == scan_id))
