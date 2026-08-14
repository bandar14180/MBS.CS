from apps.api.ai_agent.providers.base import SupportsComplete
from apps.api.core.config import get_settings

_KNOWN = ("openrouter", "anthropic", "local", "deepseek")


def _build_one(name: str, model: str | None) -> SupportsComplete:
    """Construct one concrete provider client (lazy imports keep this module key-free)."""
    if name == "anthropic":
        from apps.api.ai_agent.providers.anthropic import AnthropicClient

        return AnthropicClient(model=model)
    if name == "local":
        from apps.api.ai_agent.providers.local import LocalClient

        return LocalClient(model=model)
    if name == "deepseek":
        from apps.api.ai_agent.providers.deepseek import DeepSeekClient

        return DeepSeekClient(model=model)
    from apps.api.ai_agent.providers.openrouter import OpenRouterClient

    return OpenRouterClient(model=model)


def _has_key(name: str, s) -> bool:
    """A fallback provider is only usable if its credential is configured (local/Ollama needs
    none). Keyless fallbacks are dropped at build time so they never abort the chain with a
    config error mid-failover."""
    return {
        "openrouter": bool(s.openrouter_api_key),
        "anthropic": bool(s.anthropic_api_key),
        "deepseek": bool(s.deepseek_api_key),
        "local": True,
    }.get(name, False)


def get_ai_client(model: str | None = None) -> SupportsComplete:
    """Return the AI client for the configured provider (AI_PROVIDER). The only place that maps a
    provider name to a concrete class -- agents depend solely on the SupportsComplete surface, so
    a provider swap is a config change.

    AI-2.1: when AI_FALLBACK_PROVIDERS is set, returns a FallbackClient over the ordered chain
    [primary, *fallbacks] -- deterministic order, duplicates and a self-reference dropped, and
    keyless fallbacks skipped. When the list is EMPTY, behavior is UNCHANGED: a single client for
    the configured provider (unknown -> OpenRouter, the primary).

    `model` optionally overrides each provider's default model; None keeps the configured default.
    """
    s = get_settings()
    primary = s.ai_provider if s.ai_provider in _KNOWN else "openrouter"

    fallbacks = [str(x).strip().lower() for x in (s.ai_fallback_providers or [])]
    if not fallbacks:
        return _build_one(primary, model)  # default path -- identical to pre-AI-2.1 behavior

    chain: list[str] = [primary]
    for name in fallbacks:
        if name in _KNOWN and name != primary and name not in chain and _has_key(name, s):
            chain.append(name)
    if len(chain) == 1:
        return _build_one(primary, model)  # no usable fallback -> single client

    from apps.api.ai_agent.providers.fallback import FallbackClient

    return FallbackClient([_build_one(name, model) for name in chain])
