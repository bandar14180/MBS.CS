import logging
import uuid

from apps.api.ai_agent.models import AIUsageRow
from apps.api.ai_agent.providers.usage import AIUsage
from apps.api.core import tenancy
from apps.api.core.db import SessionLocal

logger = logging.getLogger("mbs.ai")


async def persist_ai_usage(records: list[AIUsage]) -> None:
    """Write ai_usage rows best-effort. Uses an INDEPENDENT short transaction per
    row (its own session + workspace binding) so it never disturbs the caller's transaction
    -- critical for the scan path, where the orchestrator holds a session-level
    workspace context that a stray commit would disturb. Any failure is swallowed with a
    warning: usage accounting must never break an AI call or a scan."""
    for r in records:
        if not r.workspace_id:
            continue  # only persist tenant-attributed calls (the row requires a workspace)
        try:
            # AUDIT-004: workspace_scope(), NOT a bare bind_workspace().
            #
            # `records` is a LIST and its entries may carry DIFFERENT workspace_ids (the agent
            # batches usage across a run). A bare bind sets the ContextVar for the rest of the
            # Task and never restores it, so:
            #   * record N+1 started with record N's workspace still bound, and
            #   * after this function returned, the CALLER kept whichever workspace the last
            #     record happened to carry -- a tenancy context the caller never asked for,
            #     silently applied to its subsequent ORM queries.
            # The scope binds for exactly one row and always restores the previous value, on
            # the exception path too (the `except` below swallows failures, which made the
            # leak permanent for the rest of the Task).
            with tenancy.workspace_scope(r.workspace_id):
                async with SessionLocal() as session:
                    async with session.begin():
                        session.add(
                            AIUsageRow(
                                id=uuid.uuid4(),
                                workspace_id=uuid.UUID(r.workspace_id),
                                scan_id=uuid.UUID(r.scan_id) if r.scan_id else None,
                                provider=r.provider,
                                model=r.model,
                                agent_role=r.agent_role,
                                prompt_tokens=r.prompt_tokens,
                                completion_tokens=r.completion_tokens,
                                estimated_cost_usd=r.estimated_cost_usd,
                                correlation_id=r.correlation_id,
                                prompt_version=r.prompt_version,
                            )
                        )
        except Exception:  # noqa: BLE001 -- accounting is strictly best-effort
            logger.warning("failed to persist ai_usage row", exc_info=True)
