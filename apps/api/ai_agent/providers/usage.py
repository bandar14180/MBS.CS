import contextvars
import logging
from dataclasses import dataclass, field

logger = logging.getLogger("mbs.ai")


@dataclass
class AIUsage:
    """Token/cost accounting for a single provider call. Providers populate the
    hard facts (provider/model/tokens/cost); the orchestration site enriches it
    with tenant context (workspace/scan/correlation/agent) when persisting."""

    provider: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    estimated_cost_usd: float = 0.0
    # Enriched by collect_ai_usage() at the call site (not known to the provider):
    agent_role: str | None = None
    prompt_version: str | None = None
    workspace_id: str | None = None
    scan_id: str | None = None
    correlation_id: str | None = None


@dataclass
class _CallContext:
    agent_role: str | None = None
    prompt_version: str | None = None
    workspace_id: str | None = None
    scan_id: str | None = None
    correlation_id: str | None = None
    sink: list = field(default_factory=list)


# Set by collect_ai_usage() around an AI operation. Providers run synchronously
# inside the same async task, so they see this contextvar and append to its sink;
# the async site then drains the sink and persists ai_usage rows.
_call_ctx: contextvars.ContextVar[_CallContext | None] = contextvars.ContextVar(
    "mbs_ai_call_ctx", default=None
)


def current_call_context() -> tuple[str | None, str | None]:
    """AI-2.2A: (workspace_id, agent_role) for the AI call in progress, or (None, None) outside a
    collect_ai_usage() block. Lets the budget guard attribute/enforce without threading the
    workspace through every agent signature."""
    ctx = _call_ctx.get()
    return (ctx.workspace_id, ctx.agent_role) if ctx is not None else (None, None)


class collect_ai_usage:
    """Context manager that (a) tags AI calls made inside it with tenant context
    and (b) collects their usage records for persistence. Best-effort: never
    raises, and its absence simply means usage is logged/metered but not
    persisted."""

    def __init__(
        self,
        *,
        agent_role: str | None = None,
        prompt_version: str | None = None,
        workspace_id: str | None = None,
        scan_id: str | None = None,
        correlation_id: str | None = None,
    ):
        self._ctx = _CallContext(
            agent_role=agent_role,
            prompt_version=prompt_version,
            workspace_id=str(workspace_id) if workspace_id else None,
            scan_id=str(scan_id) if scan_id else None,
            correlation_id=correlation_id,
        )
        self._token = None

    def __enter__(self) -> list[AIUsage]:
        self._token = _call_ctx.set(self._ctx)
        return self._ctx.sink

    def __exit__(self, *exc) -> None:
        if self._token is not None:
            _call_ctx.reset(self._token)
        return None


def _update_metrics(usage: AIUsage) -> None:
    """Feed Prometheus if observability is wired; a missing dependency or an
    unconfigured registry must never break an AI call."""
    try:
        from apps.api.core.observability import record_ai_usage_metrics

        record_ai_usage_metrics(usage)
    except Exception:  # noqa: BLE001 -- metrics are strictly best-effort
        pass


def emit_usage(usage: AIUsage, *, latency_ms: float = 0.0) -> None:
    ctx = _call_ctx.get()
    if ctx is not None:
        usage.agent_role = usage.agent_role or ctx.agent_role
        usage.prompt_version = usage.prompt_version or ctx.prompt_version
        usage.workspace_id = ctx.workspace_id
        usage.scan_id = ctx.scan_id
        usage.correlation_id = ctx.correlation_id
        ctx.sink.append(usage)

    logger.info(
        "ai_call",
        extra={
            "provider": usage.provider,
            "model": usage.model,
            "prompt_tokens": usage.prompt_tokens,
            "completion_tokens": usage.completion_tokens,
            "estimated_cost_usd": usage.estimated_cost_usd,
            "agent_role": usage.agent_role,
            "latency_ms": round(latency_ms, 1),
            "correlation_id": usage.correlation_id,
        },
    )
    _update_metrics(usage)
    # AI-2.5: observe successful-call latency (best-effort; low-cardinality agent_role label).
    try:
        from apps.api.core.observability import record_ai_latency

        record_ai_latency(usage.agent_role or "unknown", max(0.0, latency_ms) / 1000.0)
    except Exception:  # noqa: BLE001 -- metrics strictly best-effort
        pass
    # AI-2.2A: accumulate this successful call's estimated cost into the workspace's rolling
    # daily budget (best-effort; a Redis failure is swallowed inside add_spend).
    if usage.workspace_id and usage.estimated_cost_usd:
        try:
            from apps.api.ai_agent.budget import add_spend

            add_spend(usage.workspace_id, float(usage.estimated_cost_usd))
        except Exception:  # noqa: BLE001 -- accounting must never break an AI call
            pass
