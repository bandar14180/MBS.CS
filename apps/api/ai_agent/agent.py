"""The single autonomous red-team agent.

Replaces the fleet of one-shot "agents" with ONE decision loop: given the current
engagement state (target, phase, findings, tools already run) it chooses the next
tool to run, from an **allowlist** only. The orchestrator owns execution (the
deterministic runners) and the audit log; this class is the pure decision layer, so
it is unit-testable without a DB and the "AI never freelances" guarantee is enforced
in code (like AIPlanner._sanitize): the agent can only pick a tool the code already
deemed available + safe.
"""
from dataclasses import dataclass

from apps.api.ai_agent.prompts.agent import AGENT_PROMPT_VERSION, AGENT_SYSTEM, AGENT_USER_TEMPLATE
from apps.api.ai_agent.providers import SupportsComplete, get_ai_client
from apps.api.scanner_engine.safety import RulesOfEngagement, tier_at_most
from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY


@dataclass
class AgentDecision:
    action: str              # "run_tool" | "finish"
    tool: str | None
    phase: str
    rationale: str
    model_version: str
    prompt_version: str


class RedTeamAgent:
    def __init__(self, client: SupportsComplete | None = None):
        self._client = client or get_ai_client()

    def available_tools(
        self, *, target_type: str, active_testing_allowed: bool, roe: RulesOfEngagement, already_run: set[str]
    ) -> list[str]:
        """The allowlist the agent may choose from RIGHT NOW: registered tools that
        apply to the target, are within the engagement's safety ceiling, are
        active-testing-gated by the verified scope, and haven't run yet. The agent
        cannot pick anything outside this list."""
        out: list[str] = []
        for name, cls in sorted(TOOL_REGISTRY.items(), key=lambda kv: kv[1].phase):
            if name in already_run:
                continue
            if cls.applicable_target_types is not None and target_type not in cls.applicable_target_types:
                continue
            if not tier_at_most(cls.safety_tier, roe.max_tier):
                continue
            if cls.requires_active_testing and not active_testing_allowed:
                continue
            out.append(name)
        return out

    def decide(
        self,
        *,
        target_type: str,
        target_value: str,
        current_phase: str,
        findings_summary: str,
        tools_run_summary: str,
        available: list[str],
    ) -> AgentDecision:
        """One decision. Returns a `run_tool` action ONLY for a tool on `available`
        (otherwise `finish`). Any AI weirdness (bad JSON, invented tool, empty list)
        degrades safely to `finish`."""
        mv = self._client.model_version
        if not available:
            return AgentDecision("finish", None, current_phase, "no further safe actions available", mv, AGENT_PROMPT_VERSION)

        catalog = "\n".join(
            f"- {n} (phase {TOOL_REGISTRY[n].kill_chain_phase}, {TOOL_REGISTRY[n].safety_tier})" for n in available
        )
        user = AGENT_USER_TEMPLATE.format(
            target_value=target_value,
            target_type=target_type,
            current_phase=current_phase,
            tools_run_summary=tools_run_summary or "(none yet)",
            findings_summary=findings_summary or "(none yet)",
            available_tools=catalog,
        )
        try:
            raw = self._client.complete_json(AGENT_SYSTEM, user)
        except Exception as exc:  # noqa: BLE001 -- AI failure must not break the engagement
            return AgentDecision("finish", None, current_phase, f"ai_unavailable: {type(exc).__name__}", mv, AGENT_PROMPT_VERSION)

        action = str(raw.get("action", "finish"))
        tool = raw.get("tool")
        phase = str(raw.get("phase") or current_phase)
        rationale = str(raw.get("rationale", ""))[:500]
        # The allowlist guarantee: only run a tool the code already vetted as available.
        if action == "run_tool" and isinstance(tool, str) and tool in available:
            return AgentDecision("run_tool", tool, phase, rationale, mv, AGENT_PROMPT_VERSION)
        return AgentDecision("finish", None, phase, rationale or "finished", mv, AGENT_PROMPT_VERSION)
