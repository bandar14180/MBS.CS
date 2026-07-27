import json
from typing import Any, Protocol

from apps.api.core.config import get_settings


class SupportsComplete(Protocol):
    """The one surface the AI agents depend on. Real impl calls Claude; tests
    inject a fake. Keeping this narrow is what makes planner/correlator unit-
    testable without an API key (blueprint: AI provider isolated so it can change
    without touching scan logic)."""

    def complete_json(self, system: str, user: str) -> dict[str, Any]: ...

    @property
    def model_version(self) -> str: ...


class ClaudeClient:
    """Thin wrapper over the Anthropic Messages API that returns parsed JSON.

    Deliberately uses only the classic Messages API surface (model, max_tokens,
    system, messages) so it works across SDK versions and against Opus 4.8
    without requiring newer params. The system prompt instructs strict-JSON
    output, which also serves as the 'final answer only' guard Opus 4.8 wants
    when thinking is off. Adaptive thinking / structured-outputs
    (output_config) can be layered on once the SDK is bumped and a live key is
    available -- see the Step 7 blueprint notes.
    """

    def __init__(self, api_key: str | None = None, model: str | None = None, max_tokens: int | None = None):
        settings = get_settings()
        self._api_key = api_key if api_key is not None else settings.anthropic_api_key
        self._model = model or settings.ai_model
        self._max_tokens = max_tokens or settings.ai_max_tokens
        self._client = None  # lazily constructed so importing this module never needs a key

    @property
    def model_version(self) -> str:
        return self._model

    def _ensure_client(self):
        if self._client is None:
            if not self._api_key:
                raise RuntimeError(
                    "ANTHROPIC_API_KEY is not set; the AI Agent Service cannot call Claude. "
                    "Set it in .env, or run the scan without AI (use_ai_planner/use_ai_correlation off)."
                )
            import anthropic

            self._client = anthropic.Anthropic(api_key=self._api_key)
        return self._client

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        client = self._ensure_client()
        message = client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(block.text for block in message.content if getattr(block, "type", None) == "text")
        return _extract_json(text)


def _extract_json(text: str) -> dict[str, Any]:
    """Parse a JSON object out of the model's text, tolerating stray prose or a
    ```json fence around it (the prompt asks for bare JSON, but be forgiving)."""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip().rstrip("`").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise
