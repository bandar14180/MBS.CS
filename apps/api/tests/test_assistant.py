import uuid

from fastapi.testclient import TestClient

from apps.api.ai_agent.assistant import SecurityAssistant

# Shared session-scoped `client` fixture lives in conftest.py.


class FakeClient:
    def __init__(self, response: dict):
        self._response = response

    def complete_json(self, system: str, user: str) -> dict:
        self._last_user = user
        return self._response

    @property
    def model_version(self) -> str:
        return "test-model"


# --- Agent unit tests (no key needed) ---

def test_assistant_structures_answer() -> None:
    agent = SecurityAssistant(client=FakeClient({"answer": "  Enable HSTS and set secure headers.  "}))
    result = agent.answer("How do I fix missing headers?")
    assert result.answer == "Enable HSTS and set secure headers."  # trimmed
    assert result.model_version == "test-model"
    assert result.prompt_version == "assistant/v1"


def test_assistant_grounds_prompt_in_finding_context() -> None:
    client = FakeClient({"answer": "ok"})
    SecurityAssistant(client=client).answer(
        "How dangerous is this?",
        context="Title: SQL Injection\nSeverity: high\nCategory: cwe-89",
    )
    assert "SQL Injection" in client._last_user
    assert "cwe-89" in client._last_user
    assert "How dangerous is this?" in client._last_user


def test_assistant_handles_missing_answer_key() -> None:
    result = SecurityAssistant(client=FakeClient({})).answer("hi there")
    assert result.answer == ""


# --- Endpoint tests (wiring, validation, fail-soft) ---

def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct horse battery staple", "full_name": "Asst User"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _headers(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def test_assistant_ask_requires_valid_question(client: TestClient) -> None:
    headers = _headers(_register(client))
    ws = client.post("/api/v1/workspaces", headers=headers, json={"name": "Asst WS"}).json()["id"]
    # too short -> 422 validation
    resp = client.post(f"/api/v1/workspaces/{ws}/assistant/ask", headers=headers, json={"question": "hi"})
    assert resp.status_code == 422


def test_assistant_vuln_without_project_is_400(client: TestClient) -> None:
    headers = _headers(_register(client))
    ws = client.post("/api/v1/workspaces", headers=headers, json={"name": "Asst WS2"}).json()["id"]
    resp = client.post(
        f"/api/v1/workspaces/{ws}/assistant/ask",
        headers=headers,
        json={"question": "What does this mean?", "vulnerability_id": str(uuid.uuid4())},
    )
    assert resp.status_code == 400


def test_assistant_ask_fails_soft_without_key(client: TestClient, monkeypatch) -> None:
    # Force no key for the active provider (don't depend on ambient env) -> the
    # assistant must fail soft with a clean 503, never a 500. Provider-agnostic.
    from apps.api.core.config import get_settings

    settings = get_settings()
    # Pin the provider so the test is deterministic regardless of the dev's .env
    # (AI_PROVIDER=local would otherwise be key-less-but-enabled).
    monkeypatch.setattr(settings, "ai_provider", "openrouter")
    monkeypatch.setattr(settings, "openrouter_api_key", "")
    monkeypatch.setattr(settings, "anthropic_api_key", "")

    headers = _headers(_register(client))
    ws = client.post("/api/v1/workspaces", headers=headers, json={"name": "Asst WS3"}).json()["id"]
    resp = client.post(
        f"/api/v1/workspaces/{ws}/assistant/ask",
        headers=headers,
        json={"question": "What is cross-site scripting?"},
    )
    assert resp.status_code == 503
