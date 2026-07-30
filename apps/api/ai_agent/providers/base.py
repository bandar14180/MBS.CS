import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Protocol

from apps.api.ai_agent.providers.usage import AIUsage, emit_usage


class AIProviderError(RuntimeError):
    """Raised when an AI provider call ultimately fails: no API key, request
    timeout, rate-limit exhausted, or a non-retryable HTTP/API error.

    Subclasses RuntimeError on purpose -- existing callers already
    `except RuntimeError` to implement the platform's degradation contract
    (planner path fails loud -> 400 / scan failed; assistant/remediation/FP
    paths fail soft -> HTTP 503). Keeping that base class means those call sites
    keep working unchanged regardless of which provider is active.
    """


class SupportsComplete(Protocol):
    """The one surface the AI agents depend on. Real impls call a provider; tests
    inject a fake. Keeping this narrow is what makes planner/correlator unit-
    testable without an API key, and what makes the provider swappable by config
    without touching any agent."""

    def complete_json(self, system: str, user: str) -> dict[str, Any]: ...

    @property
    def model_version(self) -> str: ...


# Rough per-1K-token USD pricing keyed by a substring of the model id. Used only
# for cost *estimation* in logs/metrics/usage rows -- deliberately approximate
# and easy to update; billing does not depend on it. Unknown models fall through
# to a conservative default so cost is never silently zero.
_PRICING_PER_1K = {
    "opus": (0.015, 0.075),
    "sonnet": (0.003, 0.015),
    "haiku": (0.0008, 0.004),
    "gpt-4o": (0.005, 0.015),
    "gpt-4": (0.01, 0.03),
    "gemini": (0.00125, 0.005),
}
_PRICING_DEFAULT = (0.005, 0.015)


def estimate_cost_usd(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    model_l = (model or "").lower()
    prices = _PRICING_DEFAULT
    for key, val in _PRICING_PER_1K.items():
        if key in model_l:
            prices = val
            break
    in_rate, out_rate = prices
    return round((prompt_tokens / 1000) * in_rate + (completion_tokens / 1000) * out_rate, 6)


def extract_json(text: str) -> dict[str, Any]:
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


@dataclass
class _Attempt:
    text: str
    usage: AIUsage


class BaseAIProvider(ABC):
    """Shared retry/timeout/logging/usage skeleton for every provider.

    Subclasses implement `_invoke()` (a single attempt) and `_is_retryable()`.
    `complete_json()` wraps that with bounded exponential-backoff retries, parses
    the JSON out, and emits usage (structured log + Prometheus metrics + the
    contextvar sink that persists ai_usage rows). A provider failure NEVER crashes
    the caller -- it raises AIProviderError, which the degradation contract maps to
    400/503 upstream so the scan pipeline stays alive."""

    provider_name: str = "base"

    def __init__(self, model: str, max_tokens: int, timeout_s: float, max_retries: int):
        self._model = model
        self._max_tokens = max_tokens
        self._timeout_s = timeout_s
        self._max_retries = max(0, int(max_retries))

    @property
    def model_version(self) -> str:
        return self._model

    @abstractmethod
    def _invoke(self, system: str, user: str) -> _Attempt:
        """One attempt. May raise a retryable or non-retryable exception."""

    @abstractmethod
    def _is_retryable(self, exc: Exception) -> bool:
        """Whether `exc` from `_invoke` is worth retrying (429/5xx/timeout/conn)."""

    def complete_json(self, system: str, user: str) -> dict[str, Any]:
        started = time.monotonic()
        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                result = self._invoke(system, user)
                emit_usage(result.usage, latency_ms=(time.monotonic() - started) * 1000)
                return extract_json(result.text)
            except AIProviderError:
                raise  # already-terminal (e.g. missing key): do not retry
            except Exception as exc:  # noqa: BLE001 -- classify then re-raise
                last_exc = exc
                if attempt < self._max_retries and self._is_retryable(exc):
                    time.sleep(min(2**attempt * 0.5, 8.0))
                    continue
                break
        raise AIProviderError(
            f"{self.provider_name} call failed after {self._max_retries + 1} attempt(s): {last_exc}"
        ) from last_exc
