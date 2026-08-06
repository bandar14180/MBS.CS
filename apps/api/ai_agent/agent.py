"""The single autonomous red-team agent.

Replaces the fleet of one-shot "agents" with ONE decision loop: given the current
engagement state (target, phase, findings, ATT&CK coverage, prior outcomes) it
proposes the next assessment actions as a RANKED, confidence-scored candidate set,
each from an **allowlist** only. The orchestrator owns execution (the deterministic
runners) and the audit log; this class is the pure decision layer, so it is
unit-testable without a DB.

Two guarantees are enforced in code, never in the prompt:
  * "AI never freelances" -- a candidate is dropped unless its tool is on the
    code-computed allowlist (like AIPlanner._sanitize).
  * "code selects, not the raw LLM order" (blueprint §15) -- the model RANKS
    candidates; this layer picks the highest-confidence allowed one by an explicit
    policy. Any AI weirdness (bad JSON, invented tool, empty list) degrades to
    `finish`.

The reasoning is kept in evidence tiers -- observations (facts), inferences, and
hypotheses (blueprint §8) -- so downstream can distinguish confirmed from possible.
"""
from dataclasses import dataclass, field

from apps.api.ai_agent.prompts.agent import AGENT_PROMPT_VERSION, AGENT_SYSTEM, AGENT_USER_TEMPLATE
from apps.api.ai_agent.providers import SupportsComplete, get_ai_client
from apps.api.scanner_engine.safety import RulesOfEngagement, tier_at_most
from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY

# Ordinal for the qualitative expected_value / risk labels (tie-break in ranking).
_VALUE_RANK = {"low": 1, "medium": 2, "high": 3}
# Deterministic selection scoring (M4.4.3): confidence is dominant; expected_value
# gives a mild boost; risk applies a mild penalty so a higher-risk candidate is
# demoted relative to an equal-confidence, equal-value, lower-risk one. These are
# code-side constants -- the LLM never sets them and cannot bypass them.
_VALUE_WEIGHT = {"low": 1.0, "medium": 1.15, "high": 1.3}
_RISK_RANK = {"low": 0, "medium": 1, "high": 2}
_RISK_PENALTY = 0.1


def _candidate_score(c: "CandidateAction") -> float:
    """Deterministic desirability score. Confidence dominates; value boosts; risk
    penalizes. Used by the code to SELECT -- never the raw LLM order (blueprint §15)."""
    return c.confidence * _VALUE_WEIGHT.get(c.expected_value, 1.0) - _RISK_PENALTY * _RISK_RANK.get(c.risk, 0)


@dataclass
class CandidateAction:
    """One proposed next action the model ranked, already vetted against the
    allowlist. `confidence` is 0..1; `expected_value`/`risk` are low|medium|high."""

    tool: str
    confidence: float
    expected_value: str
    risk: str
    expected_evidence: list[str]
    rationale: str


@dataclass
class AgentDecision:
    action: str              # "run_tool" | "finish"
    tool: str | None
    phase: str
    rationale: str
    model_version: str
    prompt_version: str
    # M4.2 reasoning detail (evidence tiers + the ranked candidate set the code
    # selected from). All best-effort: empty when the model omitted them.
    observations: list[str] = field(default_factory=list)
    inferences: list[str] = field(default_factory=list)
    hypotheses: list[str] = field(default_factory=list)
    candidates: list[CandidateAction] = field(default_factory=list)  # ranked, best first
    confidence: float = 0.0          # confidence of the SELECTED action
    stop_reason: str | None = None

    def summary(self) -> str:
        """Compact, human-readable reasoning trace for the audit log (AgentStep).
        Captures WHY this action was chosen -- the accountability §25 asks for."""
        parts: list[str] = []
        if self.observations:
            parts.append("obs: " + "; ".join(self.observations[:4]))
        if self.inferences:
            parts.append("inf: " + "; ".join(self.inferences[:3]))
        if self.hypotheses:
            parts.append("hyp: " + "; ".join(self.hypotheses[:3]))
        if self.candidates:
            parts.append("candidates: " + ", ".join(f"{c.tool}@{c.confidence:.2f}" for c in self.candidates[:5]))
        if self.action == "run_tool":
            parts.append(f"selected: {self.tool}@{self.confidence:.2f} -- {self.rationale}")
        else:
            parts.append(f"finish: {self.stop_reason or self.rationale or 'no further safe actions'}")
        return " | ".join(parts)[:2000]


def _str_list(value, *, limit: int = 8, max_len: int = 300) -> list[str]:
    """Coerce an AI field into a bounded list of clean strings (tolerant of a bare
    string or None). Keeps the model's free text from bloating state/audit rows."""
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    for item in value:
        text = str(item).strip()
        if text:
            out.append(text[:max_len])
        if len(out) >= limit:
            break
    return out


def _clamp_confidence(value, default: float = 0.5) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return default


def _norm_label(value, default: str = "medium") -> str:
    text = str(value or "").strip().lower()
    return text if text in _VALUE_RANK else default


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

    def _parse_candidates(self, raw: dict, available: list[str], min_confidence: float = 0.0) -> list[CandidateAction]:
        """Turn the model's proposal into vetted CandidateActions. Accepts the
        v3 `candidate_actions` list AND the legacy flat `{action, tool}` schema, so
        the layer is robust to model/schema drift. Any candidate whose tool is not
        on `available` is dropped -- the non-bypassable 'never freelances' rule --
        and any candidate below `min_confidence` is dropped (deterministic floor)."""
        allowed = set(available)
        items = raw.get("candidate_actions")
        out: list[CandidateAction] = []
        if isinstance(items, list):
            for it in items:
                if not isinstance(it, dict):
                    continue
                tool = it.get("tool")
                if not isinstance(tool, str) or tool not in allowed:
                    continue
                out.append(
                    CandidateAction(
                        tool=tool,
                        confidence=_clamp_confidence(it.get("confidence")),
                        expected_value=_norm_label(it.get("expected_value")),
                        risk=_norm_label(it.get("risk")),
                        expected_evidence=_str_list(it.get("expected_evidence"), limit=6),
                        rationale=str(it.get("rationale", ""))[:300],
                    )
                )
        else:
            # Legacy flat schema: a single {action:"run_tool", tool, rationale}.
            tool = raw.get("tool")
            if str(raw.get("action")) == "run_tool" and isinstance(tool, str) and tool in allowed:
                out.append(
                    CandidateAction(
                        tool=tool,
                        confidence=_clamp_confidence(raw.get("confidence")),
                        expected_value="medium",
                        risk="medium",
                        expected_evidence=[],
                        rationale=str(raw.get("rationale", ""))[:300],
                    )
                )
        # Deterministic confidence floor (M4.4.3): drop sub-floor candidates before ranking.
        if min_confidence > 0.0:
            out = [c for c in out if c.confidence >= min_confidence]
        # Rank by the risk-aware score (confidence dominant, value boosts, risk
        # penalizes); stable so exact ties keep the model's own ordering. Selection
        # is the code's, not the raw LLM order (§15).
        out.sort(key=_candidate_score, reverse=True)
        return out

    def decide(
        self,
        *,
        target_type: str,
        target_value: str,
        current_phase: str,
        findings_summary: str,
        available: list[str],
        attack_summary: str = "",
        actions_summary: str = "",
        graph_summary: str = "",
        objective: str = "",
        prior_beliefs: str = "",
        min_confidence: float = 0.0,
        tools_run_summary: str = "",
    ) -> AgentDecision:
        """One decision cycle. The model proposes ranked candidate actions over the
        current security state; this layer selects the highest-confidence one whose
        tool is on `available`, else `finish`. Bad JSON / invented tool / empty list
        / provider error all degrade safely to `finish`.

        `attack_summary` (MITRE ATT&CK / kill-chain phases already evidenced),
        `actions_summary` (prior outcomes incl. failures/blocks), and `graph_summary`
        (the evidence-driven attack graph: asset->service->finding->technique paths)
        make ATT&CK and the graph reasoning inputs and let the model avoid dead paths
        (blueprint §7/§14/§16/§17). `tools_run_summary` is the legacy plain list,
        used only as a fallback."""
        mv = self._client.model_version
        if not available:
            return AgentDecision(
                "finish", None, current_phase, "no further safe actions available", mv, AGENT_PROMPT_VERSION,
                stop_reason="no_available_tools",
            )

        catalog = "\n".join(
            f"- {n} (phase {TOOL_REGISTRY[n].kill_chain_phase}, {TOOL_REGISTRY[n].safety_tier})" for n in available
        )
        user = AGENT_USER_TEMPLATE.format(
            target_value=target_value,
            target_type=target_type,
            current_phase=current_phase,
            objective=objective or "(not specified)",
            prior_beliefs=prior_beliefs or "(none yet)",
            actions_summary=actions_summary or tools_run_summary or "(none yet)",
            attack_summary=attack_summary or "(no techniques mapped yet)",
            graph_summary=graph_summary or "(empty)",
            findings_summary=findings_summary or "(none yet)",
            available_tools=catalog,
        )
        try:
            raw = self._client.complete_json(AGENT_SYSTEM, user)
        except Exception as exc:  # noqa: BLE001 -- AI failure must not break the engagement
            return AgentDecision(
                "finish", None, current_phase, f"ai_unavailable: {type(exc).__name__}", mv, AGENT_PROMPT_VERSION,
                stop_reason="ai_unavailable",
            )
        if not isinstance(raw, dict):
            return AgentDecision(
                "finish", None, current_phase, "ai returned non-object", mv, AGENT_PROMPT_VERSION,
                stop_reason="bad_ai_output",
            )

        observations = _str_list(raw.get("observations"))
        inferences = _str_list(raw.get("inferences"))
        hypotheses = _str_list(raw.get("hypotheses"))
        phase = str(raw.get("kill_chain_phase") or raw.get("phase") or current_phase)
        stop_reason = raw.get("stop_reason")
        stop_reason = str(stop_reason)[:200] if stop_reason else None

        candidates = self._parse_candidates(raw, available, min_confidence)

        # Explicit finish, or nothing valid to run -> finish (never freelances). When
        # a confidence floor removed every candidate, say so in the stop reason.
        if str(raw.get("action")) == "finish" or not candidates:
            default_stop = "below_confidence_floor" if (min_confidence > 0.0 and not candidates) else "no_candidates"
            return AgentDecision(
                "finish", None, phase, stop_reason or "no valid candidate actions", mv, AGENT_PROMPT_VERSION,
                observations=observations, inferences=inferences, hypotheses=hypotheses,
                candidates=candidates, stop_reason=stop_reason or default_stop,
            )

        best = candidates[0]
        return AgentDecision(
            "run_tool", best.tool, phase, best.rationale or "selected by confidence", mv, AGENT_PROMPT_VERSION,
            observations=observations, inferences=inferences, hypotheses=hypotheses,
            candidates=candidates, confidence=best.confidence, stop_reason=None,
        )
