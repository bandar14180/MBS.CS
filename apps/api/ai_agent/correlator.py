import json
from dataclasses import dataclass

from apps.api.ai_agent.guards import redact_output
from apps.api.ai_agent.providers import SupportsComplete, get_ai_client
from apps.api.ai_agent.prompts.correlator import (
    CORRELATOR_PROMPT_VERSION,
    CORRELATOR_SYSTEM,
    CORRELATOR_USER_TEMPLATE,
)
from apps.api.ai_agent.sanitize import sanitize_finding_dicts, wrap_untrusted


@dataclass
class CorrelationGroup:
    finding_ids: list[str]
    rationale: str


@dataclass
class CorrelationResult:
    groups: list[CorrelationGroup]
    model_version: str
    prompt_version: str


class AICorrelator:
    def __init__(self, client: SupportsComplete | None = None):
        self._client = client or get_ai_client()

    def correlate(self, findings: list[dict]) -> CorrelationResult:
        """`findings` is a list of dicts each with at least an `id`, plus title/
        severity/category/matched_at/tool. Returns groups of ids that describe the
        same underlying issue. Enforced in code (blueprint §5 'never invent'):
        the AI's grouping is filtered back to the exact input ids, and any input
        id the model dropped is emitted as its own singleton group so nothing is
        silently lost."""
        input_ids = [str(f["id"]) for f in findings]
        if len(input_ids) <= 1:
            return CorrelationResult(
                groups=[CorrelationGroup([i], "single finding") for i in input_ids],
                model_version=self._client.model_version,
                prompt_version=CORRELATOR_PROMPT_VERSION,
            )

        # AI-1 Step 1-2: defang untrusted finding fields + wrap in delimiters before templating.
        safe_json = json.dumps(sanitize_finding_dicts(findings), default=str, indent=2)
        user = CORRELATOR_USER_TEMPLATE.format(findings_json=wrap_untrusted("findings", safe_json, sanitize=False))
        raw = self._client.complete_json(CORRELATOR_SYSTEM, user)

        id_set = set(input_ids)
        assigned: set[str] = set()
        groups: list[CorrelationGroup] = []
        for group in raw.get("groups", []):
            ids = [str(i) for i in group.get("finding_ids", []) if str(i) in id_set and str(i) not in assigned]
            if not ids:
                continue
            assigned.update(ids)
            # AI-1 Step 3: rationale is model free-text -> redact any leaked secret/PII/token.
            groups.append(CorrelationGroup(finding_ids=ids, rationale=redact_output(str(group.get("rationale", "")))))

        # Any input finding the model failed to place -> its own group (never drop a finding).
        for fid in input_ids:
            if fid not in assigned:
                groups.append(CorrelationGroup(finding_ids=[fid], rationale="uncorrelated (fallback)"))

        from apps.api.ai_agent.audit import ai_security_event

        ai_security_event(
            "ai.decision", agent="correlator", decision="correlate",
            inputs=len(input_ids), groups=len(groups),
            model_version=self._client.model_version, prompt_version=CORRELATOR_PROMPT_VERSION,
        )
        return CorrelationResult(
            groups=groups,
            model_version=self._client.model_version,
            prompt_version=CORRELATOR_PROMPT_VERSION,
        )
