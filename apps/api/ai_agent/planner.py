import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.ai_agent.providers import SupportsComplete, get_ai_client
from apps.api.ai_agent.models import AIPlan
from apps.api.ai_agent.prompts.planner import (
    PLANNER_PROMPT_VERSION,
    PLANNER_SYSTEM,
    PLANNER_USER_TEMPLATE,
)
from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY


@dataclass
class PlanResult:
    tool_sequence: list[str]
    reasoning_summary: str
    model_version: str
    prompt_version: str


def _tool_catalog(active_testing_allowed: bool) -> str:
    lines = []
    for key, runner_cls in sorted(TOOL_REGISTRY.items(), key=lambda kv: kv[1].phase):
        kind = "active" if runner_cls.requires_active_testing else "passive"
        targets = (
            ",".join(sorted(runner_cls.applicable_target_types))
            if runner_cls.applicable_target_types
            else "any"
        )
        lines.append(f"- {key} (phase {runner_cls.phase}, {kind}, target types: {targets})")
    return "\n".join(lines)


def _sanitize(
    proposed: list, requested_modules: list[str], active_testing_allowed: bool, target_type: str
) -> list[str]:
    """The 'AI never freelances' guarantee, enforced in code (blueprint §7): the
    planner's output is filtered to registered tools only, restricted to what the
    user requested, with active-testing tools dropped unless authorized and tools
    whose applicable_target_types don't match the target removed. The AI can only
    re-order and prune within these bounds -- it cannot conjure a tool."""
    allowed = set(requested_modules) & set(TOOL_REGISTRY)
    result: list[str] = []
    seen: set[str] = set()
    for key in proposed:
        if not isinstance(key, str) or key in seen or key not in allowed:
            continue
        runner_cls = TOOL_REGISTRY[key]
        if runner_cls.requires_active_testing and not active_testing_allowed:
            continue
        if runner_cls.applicable_target_types is not None and target_type not in runner_cls.applicable_target_types:
            continue
        result.append(key)
        seen.add(key)
    return result


class AIPlanner:
    def __init__(self, client: SupportsComplete | None = None):
        self._client = client or get_ai_client()

    async def plan(
        self,
        db: AsyncSession,
        scan_id: uuid.UUID,
        target_type: str,
        target_value: str,
        requested_modules: list[str],
        active_testing_allowed: bool,
        prior_findings_summary: str = "",
    ) -> PlanResult:
        # IDEMPOTENCY (F3.1): a scan can be re-run -- Celery F2 transient retry, reaper reclaim,
        # or DLQ replay all re-execute run_scan for a scan that already ran the planner. Reuse
        # the persisted plan instead of calling the LLM again: no duplicate AI charge, no
        # duplicate ai_plans row, and (no provider call -> collect_ai_usage sink stays empty) no
        # duplicate ai_usage row. Newest-first so a legacy scan with pre-F3 duplicate plans reuses
        # the latest. A first-run scan has no plan -> unchanged behavior (falls through to the LLM).
        existing = await db.scalar(
            select(AIPlan).where(AIPlan.scan_id == scan_id).order_by(AIPlan.created_at.desc()).limit(1)
        )
        if existing is not None:
            return PlanResult(
                tool_sequence=list(existing.tool_sequence or []),
                reasoning_summary=existing.reasoning_summary or "",
                model_version=existing.model_version,
                prompt_version=existing.prompt_version,
            )

        user = PLANNER_USER_TEMPLATE.format(
            target_type=target_type,
            target_value=target_value,
            active_testing_allowed=active_testing_allowed,
            requested_modules=", ".join(requested_modules) or "(none)",
            tool_catalog=_tool_catalog(active_testing_allowed),
            prior_findings_summary=prior_findings_summary or "(none)",
        )
        raw = self._client.complete_json(PLANNER_SYSTEM, user)

        sequence = _sanitize(
            raw.get("tool_sequence", []), requested_modules, active_testing_allowed, target_type
        )
        result = PlanResult(
            tool_sequence=sequence,
            reasoning_summary=str(raw.get("reasoning_summary", "")),
            model_version=self._client.model_version,
            prompt_version=PLANNER_PROMPT_VERSION,
        )

        db.add(
            AIPlan(
                scan_id=scan_id,
                tool_sequence=result.tool_sequence,
                reasoning_summary=result.reasoning_summary,
                model_version=result.model_version,
                prompt_version=result.prompt_version,
            )
        )
        await db.flush()
        return result
