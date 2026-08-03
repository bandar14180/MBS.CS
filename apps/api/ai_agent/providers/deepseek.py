from apps.api.ai_agent.providers.openrouter import OpenRouterClient
from apps.api.core.config import get_settings


class DeepSeekClient(OpenRouterClient):
    """DeepSeek via its OpenAI-compatible API. Reuses the OpenRouter path unchanged
    (same `/chat/completions` surface) -- only the base URL, model, and key differ.
    `deepseek-chat` is strong at structured JSON output, which makes it a good brain
    for the autonomous agent's decision loop. Selected by AI_PROVIDER=deepseek.

    Cloud-hosted: needs outbound egress. On a TLS-intercepting network set
    SSL_CA_BUNDLE / HTTPS_PROXY (never disable verification) -- otherwise use the
    local provider for offline/restricted environments.
    """

    provider_name = "deepseek"

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
            api_key=api_key if api_key is not None else s.deepseek_api_key,
            model=model or s.deepseek_model,
            base_url=base_url or s.deepseek_base_url,
            max_tokens=max_tokens,
            timeout_s=timeout_s,
            max_retries=max_retries,
        )
