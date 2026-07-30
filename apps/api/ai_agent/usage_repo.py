import logging
import uuid

from sqlalchemy import text

from apps.api.ai_agent.models import AIUsageRow
from apps.api.ai_agent.providers.usage import AIUsage
from apps.api.core.db import SessionLocal

logger = logging.getLogger("mbs.ai")


async def persist_ai_usage(records: list[AIUsage]) -> None:
    """Write ai_usage rows best-effort. Uses an INDEPENDENT short transaction per
    row (its own session + RLS GUC) so it never disturbs the caller's transaction
    -- critical for the scan path, where the orchestrator holds a session-level
    RLS GUC that a stray commit would clear. Any failure is swallowed with a
    warning: usage accounting must never break an AI call or a scan."""
    for r in records:
        if not r.workspace_id:
            continue  # only persist tenant-attributed calls (RLS requires a workspace)
        try:
            async with SessionLocal() as session:
                async with session.begin():
                    # FORCE RLS requires the workspace GUC to match on INSERT.
                    await session.execute(
                        text("SELECT set_config('app.current_workspace_id', :wid, true)"),
                        {"wid": r.workspace_id},
                    )
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
