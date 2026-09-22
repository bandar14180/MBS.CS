import httpx

from apps.api.ai_agent.providers._http import sync_client
from apps.api.ai_agent.providers.base import (
    AIProviderError,
    BaseAIProvider,
    _Attempt,
    estimate_cost_usd,
)
from apps.api.ai_agent.providers.usage import AIUsage
from apps.api.core.config import get_settings


class OpenRouterClient(BaseAIProvider):
    """Primary provider. OpenRouter exposes an OpenAI-compatible Chat Completions
    API and can proxy Claude/GPT/Gemini/open models, so one integration covers
    most of the multi-provider target list -- the model is chosen by config
    (OPENROUTER_MODEL). Uses httpx directly (already a dependency) so no extra SDK
    is pulled in and the sync surface matches SupportsComplete."""

    provider_name = "openrouter"
    # Subclass override point: request the OpenAI-compatible `response_format: json_object`
    # mode. Left off here (OpenRouter fans out to many backing models, not all of which
    # reliably honor the field the same way) -- LocalClient turns it on for its single,
    # known-compatible Ollama server (see that subclass).
    _json_mode: bool = False

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        max_tokens: int | None = None,
        timeout_s: float | None = None,
        max_retries: int | None = None,
    ):
        s = get_settings()
        super().__init__(
            model=model or s.openrouter_model,
            max_tokens=max_tokens or s.ai_max_tokens,
            timeout_s=timeout_s if timeout_s is not None else s.ai_request_timeout_s,
            max_retries=max_retries if max_retries is not None else s.ai_max_retries,
        )
        self._api_key = api_key if api_key is not None else s.openrouter_api_key
        self._base_url = (base_url or s.openrouter_base_url).rstrip("/")

    def _invoke(self, system: str, user: str) -> _Attempt:
        if not self._api_key:
            raise AIProviderError(
                "OPENROUTER_API_KEY is not set; the AI Agent Service cannot call OpenRouter. "
                "Set it, switch AI_PROVIDER, or run scans with AI off."
            )
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            # Optional attribution headers OpenRouter recommends; harmless if unused.
            "HTTP-Referer": "https://mbs.sc",
            "X-Title": "MBS.SC",
        }
        payload = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if self._json_mode:
            payload["response_format"] = {"type": "json_object"}
        with sync_client(self._timeout_s) as client:
            resp = client.post(f"{self._base_url}/chat/completions", headers=headers, json=payload)
        # Terminal client errors (bad request / auth / payment / forbidden /
        # not found) -> do not retry; surface a clear message. 429 and 5xx fall
        # through to raise_for_status and are classified retryable below.
        # AI-2.1: 402 (credits exhausted) is a PROVIDER AVAILABILITY failure -> availability=True
        # so a fallback provider is tried. 400/401/403/404 (bad request / auth / forbidden /
        # model-not-found) are config/invalid errors a second provider can't fix -> no failover.
        if resp.status_code == 402:
            raise AIProviderError(f"OpenRouter {resp.status_code}: {resp.text[:300]}", availability=True)
        if resp.status_code in (400, 401, 403, 404):
            raise AIProviderError(f"OpenRouter {resp.status_code}: {resp.text[:300]}", availability=False)
        resp.raise_for_status()  # 429/5xx raise HTTPStatusError -> classified retryable
        data = resp.json()
        text = data["choices"][0]["message"]["content"] or ""
        u = data.get("usage") or {}
        prompt_tokens = int(u.get("prompt_tokens", 0))
        completion_tokens = int(u.get("completion_tokens", 0))
        usage = AIUsage(
            provider=self.provider_name,
            model=self._model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            estimated_cost_usd=estimate_cost_usd(self._model, prompt_tokens, completion_tokens),
        )
        return _Attempt(text=text, usage=usage)

    def _is_retryable(self, exc: Exception) -> bool:
        if isinstance(exc, (httpx.TimeoutException, httpx.TransportError)):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            return exc.response.status_code in (429, 500, 502, 503, 504)
        return False
