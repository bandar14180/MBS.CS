from dataclasses import dataclass

from apps.api.ai_agent.providers import SupportsComplete, get_ai_client
from apps.api.ai_agent.prompts.assistant import (
    ASSISTANT_PROMPT_VERSION,
    ASSISTANT_SYSTEM,
    ASSISTANT_USER_TEMPLATE,
)


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
        user = ASSISTANT_USER_TEMPLATE.format(question=question, context=context or "(none)")
        raw = self._client.complete_json(ASSISTANT_SYSTEM, user)
        # Enforce shape in code -- never trust the model's structure blindly.
        answer = str(raw.get("answer", "")).strip()
        return AssistantResult(answer=answer, model_version=self._client.model_version)
