"""AI-2.1 -- provider fallback.

Wraps an ORDERED chain of providers behind the same SupportsComplete surface, so agents are
unaware of it. Falls over to the next provider ONLY on a provider AVAILABILITY failure
(AIProviderError.availability=True: 429 / 402 credits / 5xx / timeout / connection). A config/
auth/invalid-request/model-not-found failure (availability=False) is re-raised immediately -- a
second provider cannot fix it. If every provider fails, the LAST error is re-raised, preserving
the existing AIProviderError degradation contract.

Deterministic: providers are tried strictly in order (no randomness). Usage/cost metrics are
emitted by the provider that actually serves the call (BaseAIProvider emits only on success), so
a failover never double-counts. Failover logs/metrics carry provider NAMES only -- never a key,
endpoint, or the provider's error body.
"""
import logging

from apps.api.ai_agent.providers.base import AIProviderError, SupportsComplete

logger = logging.getLogger("mbs.ai")


def _name(provider) -> str:
    return getattr(provider, "provider_name", "unknown")


class FallbackClient:
    """SupportsComplete-compatible ordered provider chain (see module docstring)."""

    def __init__(self, providers: list[SupportsComplete]):
        if not providers:
            raise ValueError("FallbackClient requires at least one provider")
        self._providers = list(providers)
        self._last_model = providers[0].model_version

    @property
    def model_version(self) -> str:
        # Reflects the provider that served the most recent successful call (primary before any).
        return self._last_model

    def complete_json(self, system: str, user: str) -> dict:
        last_exc: AIProviderError | None = None
        n = len(self._providers)
        for i, provider in enumerate(self._providers):
            try:
                result = provider.complete_json(system, user)
                self._last_model = provider.model_version
                return result
            except AIProviderError as exc:
                last_exc = exc
                if not getattr(exc, "availability", False):
                    raise  # config/auth/invalid-request -> do NOT fall over
                if i + 1 < n:
                    self._emit_failover(_name(provider), _name(self._providers[i + 1]))
                # else: chain exhausted -> fall through and re-raise the last error
        raise last_exc  # all providers had an availability failure -> preserve degradation

    @staticmethod
    def _emit_failover(from_provider: str, to_provider: str) -> None:
        # NAMES ONLY -- never the exception message (which may embed the provider's error body),
        # a key, or an endpoint.
        try:
            from apps.api.core.observability import record_ai_failover

            record_ai_failover(from_provider, to_provider)
        except Exception:  # noqa: BLE001 -- metrics are best-effort
            pass
        logger.warning(
            "ai.provider_failover from=%s to=%s", from_provider, to_provider,
            extra={"event": "ai.provider_failover", "from_provider": from_provider, "to_provider": to_provider},
        )
