from apps.api.ai_agent.providers.base import SupportsComplete
from apps.api.core.config import get_settings


def get_ai_client(model: str | None = None) -> SupportsComplete:
    """Return the AI client for the configured provider (AI_PROVIDER). This is the
    only place that maps a provider name to a concrete class -- agents call this
    and depend solely on the SupportsComplete surface, so a provider swap is a
    config change with zero code changes. Unknown values fall back to OpenRouter
    (the primary); production startup validation rejects unknown providers.

    `model` optionally overrides the provider's default model (e.g. a smaller/
    faster model for the correlator); None keeps the configured default."""
    provider = get_settings().ai_provider
    if provider == "anthropic":
        from apps.api.ai_agent.providers.anthropic import AnthropicClient

        return AnthropicClient(model=model)
    if provider == "local":
        from apps.api.ai_agent.providers.local import LocalClient

        return LocalClient(model=model)
    from apps.api.ai_agent.providers.openrouter import OpenRouterClient

    return OpenRouterClient(model=model)
