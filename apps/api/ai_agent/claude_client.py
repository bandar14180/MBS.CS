"""Back-compat shim.

The AI layer moved to a provider abstraction under `apps/api/ai_agent/providers/`
(OpenRouter primary, Anthropic alternate, selectable via AI_PROVIDER). This module
is kept so existing imports keep working:

    from apps.api.ai_agent.claude_client import ClaudeClient, SupportsComplete

`ClaudeClient` is now an alias for the Anthropic provider. New code should depend on
`SupportsComplete` and obtain a client from `get_ai_client()` instead of naming a
provider directly.
"""

from apps.api.ai_agent.providers.anthropic import AnthropicClient
from apps.api.ai_agent.providers.base import (  # noqa: F401 -- re-exported for callers/tests
    AIProviderError,
    SupportsComplete,
    extract_json as _extract_json,
)

# Historical name. Kept as an alias so no caller/test needs to change.
ClaudeClient = AnthropicClient

__all__ = ["ClaudeClient", "SupportsComplete", "AIProviderError", "_extract_json"]
