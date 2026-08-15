"""AI-2.2B-2 -- AI cost reporting (aggregation over ai_usage).

Read-only aggregation of a workspace's AI spend. `ai_usage` is FORCE-RLS on workspace_id and the
request already set the workspace GUC (WorkspaceContextDep), so reads are tenant-isolated; we ALSO
filter by workspace_id explicitly (defense-in-depth, and correct even under a RLS-bypassing dev
role). Metadata only -- no prompts/findings/secrets are stored on ai_usage, so none can leak.
"""
import uuid
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import Date, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.ai_agent.models import AIUsageRow
from apps.api.modules.ai_usage.schemas import AIUsageReport, UsageBucket

_MAX_RANGE_DAYS = 366   # bound the window so a report can't scan an unbounded history
_DEFAULT_RANGE_DAYS = 30


def _f(value) -> float:
    return round(float(value or 0), 6)


def _i(value) -> int:
    return int(value or 0)


async def get_usage_report(
    db: AsyncSession, workspace_id: uuid.UUID, from_date: date | None = None, to_date: date | None = None
) -> AIUsageReport:
    today = datetime.now(timezone.utc).date()
    to_d = to_date or today
    from_d = from_date or (to_d - timedelta(days=_DEFAULT_RANGE_DAYS))
    if from_d > to_d:
        from_d = to_d
    if (to_d - from_d).days > _MAX_RANGE_DAYS:
        from_d = to_d - timedelta(days=_MAX_RANGE_DAYS)

    start = datetime.combine(from_d, datetime.min.time(), tzinfo=timezone.utc)
    end = datetime.combine(to_d + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc)  # inclusive to_d
    scope = (
        AIUsageRow.workspace_id == workspace_id,
        AIUsageRow.created_at >= start,
        AIUsageRow.created_at < end,
    )

    totals = (
        await db.execute(
            select(
                func.count().label("calls"),
                func.coalesce(func.sum(AIUsageRow.prompt_tokens), 0),
                func.coalesce(func.sum(AIUsageRow.completion_tokens), 0),
                func.coalesce(func.sum(AIUsageRow.estimated_cost_usd), 0),
            ).where(*scope)
        )
    ).one()

    by_day = await _grouped(db, cast(AIUsageRow.created_at, Date), scope, order_desc=True)
    by_model = await _grouped(db, AIUsageRow.model, scope)
    by_agent_role = await _grouped(db, func.coalesce(AIUsageRow.agent_role, "unknown"), scope)

    return AIUsageReport(
        from_date=from_d,
        to_date=to_d,
        total_calls=_i(totals[0]),
        total_prompt_tokens=_i(totals[1]),
        total_completion_tokens=_i(totals[2]),
        total_cost_usd=_f(totals[3]),
        by_day=by_day,
        by_model=by_model,
        by_agent_role=by_agent_role,
    )


async def _grouped(db: AsyncSession, key_col, scope, *, order_desc: bool = False) -> list[UsageBucket]:
    key = key_col.label("key")
    cost = func.coalesce(func.sum(AIUsageRow.estimated_cost_usd), 0).label("cost")
    stmt = (
        select(
            key,
            func.count().label("calls"),
            func.coalesce(func.sum(AIUsageRow.prompt_tokens), 0),
            func.coalesce(func.sum(AIUsageRow.completion_tokens), 0),
            cost,
        )
        .where(*scope)
        .group_by(key)
    )
    stmt = stmt.order_by(key.desc()) if order_desc else stmt.order_by(cost.desc())
    rows = (await db.execute(stmt)).all()
    return [
        UsageBucket(
            key=str(r[0]),
            calls=_i(r[1]),
            prompt_tokens=_i(r[2]),
            completion_tokens=_i(r[3]),
            cost_usd=_f(r[4]),
        )
        for r in rows
    ]
