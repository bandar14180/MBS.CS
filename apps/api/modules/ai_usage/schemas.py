from datetime import date

from pydantic import BaseModel


class UsageBucket(BaseModel):
    """One aggregation bucket (a day, a model, or an agent role) with its totals."""

    key: str
    calls: int
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float


class AIUsageReport(BaseModel):
    """AI-2.2B-2: a workspace's AI spend over a date range. Metadata only -- provider/model/
    agent-role/token/cost aggregates; never prompts, findings, or secrets."""

    from_date: date
    to_date: date
    total_calls: int
    total_prompt_tokens: int
    total_completion_tokens: int
    total_cost_usd: float
    by_day: list[UsageBucket]
    by_model: list[UsageBucket]
    by_agent_role: list[UsageBucket]
