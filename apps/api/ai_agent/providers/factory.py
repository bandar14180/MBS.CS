from apps.api.ai_agent.providers.base import SupportsComplete
from apps.api.core.config import get_settings


def get_ai_client() -> SupportsComplete:
    """Return the AI client for the configured provider (AI_PROVIDER). This is the
    only place that maps a provider name to a concrete class -- agents call this
    and depend solely on the SupportsComplete surface, so a provider swap is a
    config change with zero code changes. Unknown values fall back to OpenRouter
    (the primary); production startup validation rejects unknown providers."""
    provider = get_settings().ai_provider
    if provider == "anthropic":
        from apps.api.ai_agent.providers.anthropic import AnthropicClient

        return AnthropicClient()
    if provider == "local":
        from apps.api.ai_agent.providers.local import LocalClient

        return LocalClient()
    from apps.api.ai_agent.providers.openrouter import OpenRouterClient

    return OpenRouterClient()
