"""AI-2.2A -- AI cost budget enforcement.

A per-workspace rolling DAILY estimated-spend cap, backed by Redis. `add_spend` accumulates the
cost of each successful AI call; `enforce_budget` (called pre-call from BaseAIProvider.complete_json)
raises AIBudgetExceededError once a workspace reaches its daily cap, degrading through the existing
contract (assistant -> 503, agent -> finish). Because the error is AIProviderError(availability=
False), the AI-2.1 FallbackClient does NOT fail over -- a second provider can't fix a spend cap.

Default OFF: no enforcement unless ai_budget_enforce is true AND ai_daily_budget_usd > 0. All Redis
operations FAIL OPEN -- a Redis outage must never block AI (availability over enforcement), mirroring
the F4 reliability signals and the MFA lockout.
"""
from datetime import datetime, timezone

from apps.api.ai_agent.providers.base import AIProviderError
from apps.api.core.config import get_settings

# Key TTL: 2 days so the day's counter survives clock/timezone edges and self-expires.
_TTL_SECONDS = 2 * 24 * 3600


class AIBudgetExceededError(AIProviderError):
    """Raised when a workspace has reached its daily AI spend cap. availability is forced False so
    the fallback layer never tries another provider (the cap is per-tenant, not a provider outage)."""

    def __init__(self, *args):
        super().__init__(*args, availability=False)


def _key(workspace_id: str) -> str:
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"ai:spend:{workspace_id}:{day}"


def _redis():
    import redis

    return redis.from_url(get_settings().redis_url)


def add_spend(workspace_id: str, usd: float) -> None:
    """Add `usd` to the workspace's rolling daily spend. Best-effort: a Redis error is swallowed
    (accounting must never break an AI call)."""
    if not workspace_id or usd <= 0:
        return
    try:
        client = _redis()
        key = _key(workspace_id)
        client.incrbyfloat(key, float(usd))
        client.expire(key, _TTL_SECONDS)
    except Exception:  # noqa: BLE001
        pass


def get_spend(workspace_id: str) -> float:
    """Current rolling daily spend for the workspace (USD). Fail-open: 0.0 on any Redis error."""
    if not workspace_id:
        return 0.0
    try:
        val = _redis().get(_key(workspace_id))
        return float(val) if val is not None else 0.0
    except Exception:  # noqa: BLE001
        return 0.0


def over_budget(workspace_id: str) -> bool:
    """True only when enforcement is ON, a positive cap is set, and the workspace has reached it.
    Fail-open: any Redis error -> False (do not block)."""
    s = get_settings()
    if not s.ai_budget_enforce or s.ai_daily_budget_usd <= 0 or not workspace_id:
        return False
    return get_spend(workspace_id) >= s.ai_daily_budget_usd


def enforce_budget() -> None:
    """Pre-call gate invoked from BaseAIProvider.complete_json. Reads the workspace/agent-role of
    the AI call in progress from the collect_ai_usage contextvar; if that workspace is over its
    daily cap, records a metric + audit event and raises AIBudgetExceededError. No-op when
    enforcement is off, no cap is set, or the call has no workspace attribution."""
    s = get_settings()
    if not s.ai_budget_enforce or s.ai_daily_budget_usd <= 0:
        return
    from apps.api.ai_agent.providers.usage import current_call_context

    workspace_id, agent_role = current_call_context()
    if not workspace_id or not over_budget(workspace_id):
        return

    role = agent_role or "unknown"
    try:
        from apps.api.core.observability import record_ai_budget_blocked

        record_ai_budget_blocked(role)
    except Exception:  # noqa: BLE001 -- metrics best-effort
        pass
    try:
        from apps.api.ai_agent.audit import ai_security_event

        ai_security_event("ai.budget_exceeded", agent=role, workspace=workspace_id)
    except Exception:  # noqa: BLE001 -- audit best-effort
        pass
    raise AIBudgetExceededError(
        f"AI daily budget of ${s.ai_daily_budget_usd:.2f} reached for this workspace; "
        "AI is temporarily unavailable."
    )
