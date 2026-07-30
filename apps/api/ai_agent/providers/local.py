from apps.api.ai_agent.providers._http import sync_client
from apps.api.ai_agent.providers.openrouter import OpenRouterClient
from apps.api.core.config import get_settings


class LocalClient(OpenRouterClient):
    """Local, self-hosted model via an OpenAI-compatible endpoint (Ollama/vLLM).

    Reuses the OpenRouter path unchanged -- Ollama's `/v1/chat/completions` is
    OpenAI-compatible, so only the base URL, model, and auth differ. Ollama needs
    no API key (a dummy is sent and ignored). This provider keeps scan data
    in-house and needs NO external egress, so the AI layer works even when the
    network blocks the internet or intercepts TLS. Selected by AI_PROVIDER=local.
    """

    provider_name = "local"

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
            # Ollama ignores auth; send a dummy so the shared client's key guard passes.
            api_key=api_key if api_key is not None else (s.ollama_api_key or "ollama"),
            model=model or s.ollama_model,
            base_url=base_url or s.ollama_base_url,
            max_tokens=max_tokens,
            timeout_s=timeout_s,
            max_retries=max_retries,
        )

    def health(self) -> bool:
        """Best-effort reachability probe: is the local model server up? Hits the
        OpenAI-compatible /models listing. Never raises -- returns False on any
        error (used by /ai/status; the model server may be on the host, so it must
        be reachable from wherever this runs, e.g. host.docker.internal)."""
        try:
            with sync_client(min(self._timeout_s, 5.0)) as client:
                resp = client.get(f"{self._base_url}/models")
            return resp.status_code < 500
        except Exception:  # noqa: BLE001 -- health is strictly best-effort
            return False
