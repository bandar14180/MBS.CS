"""Unit tests for the AI provider abstraction (Phase 1). Pure -- no DB/app/key."""
import httpx
import pytest

from apps.api.ai_agent.providers.base import (
    AIProviderError,
    estimate_cost_usd,
    extract_json,
)
from apps.api.ai_agent.providers.openrouter import OpenRouterClient
from apps.api.ai_agent.providers.usage import collect_ai_usage
from apps.api.core.config import Settings


def _mock_httpx(monkeypatch, handler) -> None:
    """Route OpenRouterClient's internal httpx.Client through a MockTransport."""
    orig = httpx.Client
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kw: orig(transport=transport, **{k: v for k, v in kw.items() if k != "transport"}),
    )
    # Don't actually sleep between retries.
    monkeypatch.setattr("apps.api.ai_agent.providers.base.time.sleep", lambda *_: None)


def test_extract_json_variants() -> None:
    assert extract_json('{"a": 1}') == {"a": 1}
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('prose {"a": 1} more') == {"a": 1}


def test_estimate_cost_nonzero() -> None:
    # opus pricing: 0.015/1k in, 0.075/1k out.
    assert estimate_cost_usd("anthropic/claude-opus-4.1", 1000, 1000) == pytest.approx(0.09)
    # unknown model still costs something (never silently zero).
    assert estimate_cost_usd("mystery-model", 1000, 0) > 0


def test_openrouter_parses_content_and_usage(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": '{"answer": "hello"}'}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 3},
            },
        )

    _mock_httpx(monkeypatch, handler)
    client = OpenRouterClient(api_key="sk-test", model="anthropic/claude-opus-4.1")
    with collect_ai_usage(agent_role="assistant", workspace_id="w1") as records:
        result = client.complete_json("sys", "user")
    assert result == {"answer": "hello"}
    assert len(records) == 1
    assert records[0].prompt_tokens == 12 and records[0].completion_tokens == 3
    assert records[0].agent_role == "assistant" and records[0].workspace_id == "w1"
    assert records[0].estimated_cost_usd > 0


def test_openrouter_retries_then_succeeds(monkeypatch) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, text="upstream busy")
        return httpx.Response(
            200, json={"choices": [{"message": {"content": '{"ok": true}'}}], "usage": {}}
        )

    _mock_httpx(monkeypatch, handler)
    client = OpenRouterClient(api_key="sk-test", max_retries=2)
    assert client.complete_json("s", "u") == {"ok": True}
    assert calls["n"] == 2  # one retry after the 503


def test_openrouter_missing_key_raises_provider_error() -> None:
    client = OpenRouterClient(api_key="")
    with pytest.raises(AIProviderError):
        client.complete_json("s", "u")


def test_openrouter_terminal_4xx_not_retried(monkeypatch) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(401, text="bad key")

    _mock_httpx(monkeypatch, handler)
    client = OpenRouterClient(api_key="sk-bad", max_retries=3)
    with pytest.raises(AIProviderError):
        client.complete_json("s", "u")
    assert calls["n"] == 1  # 401 is terminal -> no retries


def test_openrouter_402_terminal_not_retried(monkeypatch) -> None:
    # 402 Payment Required (no OpenRouter credits) is terminal -> one attempt,
    # surfaced with a clear provider message rather than a stringified HTTP error.
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(402, text="insufficient credits")

    _mock_httpx(monkeypatch, handler)
    client = OpenRouterClient(api_key="sk-test", max_retries=3)
    with pytest.raises(AIProviderError) as exc:
        client.complete_json("s", "u")
    assert calls["n"] == 1  # 402 is terminal -> no retries
    assert "402" in str(exc.value)


def test_failure_message_reports_actual_attempts(monkeypatch) -> None:
    # A non-retryable, non-terminal status (e.g. 422) breaks after one attempt;
    # the error must report attempts actually made, not the configured max.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, text="unprocessable")

    _mock_httpx(monkeypatch, handler)
    client = OpenRouterClient(api_key="sk-test", max_retries=3)
    with pytest.raises(AIProviderError) as exc:
        client.complete_json("s", "u")
    assert "after 1 attempt(s)" in str(exc.value)


def test_provider_error_is_runtimeerror() -> None:
    # The degradation contract relies on `except RuntimeError` upstream.
    assert issubclass(AIProviderError, RuntimeError)


def test_validate_production_rejects_dev_defaults() -> None:
    s = Settings(environment="production")  # all insecure defaults
    with pytest.raises(RuntimeError) as exc:
        s.validate_production()
    msg = str(exc.value)
    assert "JWT_SECRET_KEY" in msg and "minioadmin" in msg


def test_validate_production_accepts_hardened_config() -> None:
    s = Settings(
        environment="production",
        jwt_secret_key="a" * 48,
        s3_access_key="real-access",
        s3_secret_key="real-secret",
        database_url="postgresql+asyncpg://user:strongpass@db:5432/mbs",
        cors_allow_origins=["https://mbs.example.com"],
        trusted_hosts=["mbs.example.com"],
        ai_provider="openrouter",
    )
    s.validate_production()  # must not raise


def test_validate_production_noop_in_dev() -> None:
    Settings(environment="development").validate_production()  # never raises


# --- local (Ollama) provider + enterprise TLS/proxy ---

def test_local_provider_reuses_openai_compatible_path(monkeypatch) -> None:
    from apps.api.ai_agent.providers.local import LocalClient

    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"ok": true}'}}], "usage": {"prompt_tokens": 5, "completion_tokens": 2}},
        )

    _mock_httpx(monkeypatch, handler)
    client = LocalClient(model="llama3.1:8b", base_url="http://ollama:11434/v1")
    with collect_ai_usage(agent_role="planner", workspace_id="w1") as records:
        assert client.complete_json("s", "u") == {"ok": True}
    assert captured["url"] == "http://ollama:11434/v1/chat/completions"
    assert records[0].provider == "local" and records[0].model == "llama3.1:8b"


def test_factory_selects_local(monkeypatch) -> None:
    from apps.api.ai_agent.providers import factory
    from apps.api.ai_agent.providers.local import LocalClient
    from apps.api.core.config import get_settings

    monkeypatch.setattr(get_settings(), "ai_provider", "local")
    assert isinstance(factory.get_ai_client(), LocalClient)


def test_local_provider_enables_ai_without_key() -> None:
    s = Settings(ai_provider="local")
    assert s.ai_enabled is True  # local needs no API key
    assert s.active_ai_model == s.ollama_model


def test_httpx_verify_reflects_settings() -> None:
    assert Settings().httpx_verify is True  # secure default
    assert Settings(ssl_verify=False).httpx_verify is False  # explicit dev override
    assert Settings(ssl_ca_bundle="/etc/ssl/corp-root.pem").httpx_verify == "/etc/ssl/corp-root.pem"


def test_validate_production_rejects_disabled_ssl() -> None:
    s = Settings(
        environment="production",
        jwt_secret_key="a" * 48,
        s3_access_key="real",
        s3_secret_key="real",
        database_url="postgresql+asyncpg://u:p@db:5432/mbs",
        cors_allow_origins=["https://x.example.com"],
        trusted_hosts=["x.example.com"],
        ssl_verify=False,
    )
    with pytest.raises(RuntimeError) as exc:
        s.validate_production()
    assert "SSL_VERIFY" in str(exc.value)


def test_configure_networking_mirrors_env(monkeypatch) -> None:
    from apps.api.core.config import configure_networking

    for var in ("HTTP_PROXY", "HTTPS_PROXY", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"):
        monkeypatch.delenv(var, raising=False)
        monkeypatch.delenv(var.lower(), raising=False)
    configure_networking(Settings(https_proxy="http://proxy:3128", ssl_ca_bundle="/etc/ssl/corp.pem"))
    import os

    assert os.environ["HTTPS_PROXY"] == "http://proxy:3128"
    assert os.environ["REQUESTS_CA_BUNDLE"] == "/etc/ssl/corp.pem"
