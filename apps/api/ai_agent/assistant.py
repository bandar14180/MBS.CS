from dataclasses import dataclass

from apps.api.ai_agent.guards import ASSISTANT_FALLBACK_ANSWER, validate_output
from apps.api.ai_agent.providers import SupportsComplete, get_ai_client
from apps.api.ai_agent.prompts.assistant import (
    ASSISTANT_PROMPT_VERSION,
    ASSISTANT_SYSTEM,
    ASSISTANT_USER_TEMPLATE,
)
from apps.api.ai_agent.sanitize import wrap_untrusted


@dataclass
class AssistantResult:
    answer: str
    model_version: str
    prompt_version: str = ASSISTANT_PROMPT_VERSION


class SecurityAssistant:
    """In-product Q&A. Same injectable-client pattern as the other agents, so it
    is unit-testable without a key and fails soft (503) when no key is set."""

    def __init__(self, client: SupportsComplete | None = None):
        self._client = client or get_ai_client()

    def answer(self, question: str, context: str | None = None) -> AssistantResult:
        # AI-1 Step 1-2: both the finding context and the user question are untrusted -> sanitize
        # + delimit so an injection in either cannot override the system rules.
        user = ASSISTANT_USER_TEMPLATE.format(
            question=wrap_untrusted("question", question, max_len=4000),
            context=wrap_untrusted("context", context, max_len=4000) if context else "(none)",
        )
        raw = self._client.complete_json(ASSISTANT_SYSTEM, user)
        # Enforce shape in code -- never trust the model's structure blindly.
        # AI-1 Step 3: validate + redact the user-facing answer; a jailbroken exploit/unsafe
        # answer is withheld in favor of a safe fallback.
        answer, ok, reason = validate_output(
            str(raw.get("answer", "")).strip(), fallback=ASSISTANT_FALLBACK_ANSWER
        )
        # AI-1 Step 4: audit the outcome (category reason only; never the question/answer text).
        from apps.api.ai_agent.audit import ai_security_event

        if not ok:
            ai_security_event(
                "ai.output_blocked", agent="assistant", reason=reason or "unsafe_output",
                model_version=self._client.model_version, prompt_version=ASSISTANT_PROMPT_VERSION,
            )
        else:
            ai_security_event(
                "ai.decision", agent="assistant", decision="answer", blocked=False,
                model_version=self._client.model_version, prompt_version=ASSISTANT_PROMPT_VERSION,
            )
        return AssistantResult(answer=answer, model_version=self._client.model_version)
