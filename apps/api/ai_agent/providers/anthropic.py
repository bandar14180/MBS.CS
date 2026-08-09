from apps.api.ai_agent.providers.base import (
    AIProviderError,
    BaseAIProvider,
    _Attempt,
    estimate_cost_usd,
)
from apps.api.ai_agent.providers.usage import AIUsage
from apps.api.core.config import get_settings


class AnthropicClient(BaseAIProvider):
    """Alternate provider: calls the Anthropic Messages API directly with the
    native model id (e.g. claude-opus-4-8). Deliberately uses only the classic
    Messages surface (model, max_tokens, system, messages) so it works across SDK
    versions. The client is constructed lazily so importing this module never
    needs a key."""

    provider_name = "anthropic"

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        max_tokens: int | None = None,
        timeout_s: float | None = None,
        max_retries: int | None = None,
    ):
        s = get_settings()
        super().__init__(
            model=model or s.ai_model,
            max_tokens=max_tokens or s.ai_max_tokens,
            timeout_s=timeout_s if timeout_s is not None else s.ai_request_timeout_s,
            max_retries=max_retries if max_retries is not None else s.ai_max_retries,
        )
        self._api_key = api_key if api_key is not None else s.anthropic_api_key
        self._client = None

    def _ensure_client(self):
        if self._client is None:
            if not self._api_key:
                raise AIProviderError(
                    "ANTHROPIC_API_KEY is not set; the AI Agent Service cannot call Claude. "
                    "Set it, switch AI_PROVIDER, or run scans with AI off."
                )
            import anthropic

            self._client = anthropic.Anthropic(api_key=self._api_key, timeout=self._timeout_s)
        return self._client

    def _invoke(self, system: str, user: str) -> _Attempt:
        client = self._ensure_client()
        message = client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(
            block.text for block in message.content if getattr(block, "type", None) == "text"
        )
        usage_obj = getattr(message, "usage", None)
        prompt_tokens = int(getattr(usage_obj, "input_tokens", 0) or 0)
        completion_tokens = int(getattr(usage_obj, "output_tokens", 0) or 0)
        usage = AIUsage(
            provider=self.provider_name,
            model=self._model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            estimated_cost_usd=estimate_cost_usd(self._model, prompt_tokens, completion_tokens),
        )
        return _Attempt(text=text, usage=usage)

    def _is_retryable(self, exc: Exception) -> bool:
        try:
            import anthropic
        except Exception:  # noqa: BLE001
            return False
        if isinstance(exc, (anthropic.RateLimitError, anthropic.APITimeoutError, anthropic.APIConnectionError)):
            return True
        status = getattr(exc, "status_code", None)
        return isinstance(status, int) and status >= 500
