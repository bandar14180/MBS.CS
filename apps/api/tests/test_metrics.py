"""/metrics access-control modes (P1-5). Secure by default."""
from fastapi.testclient import TestClient

from apps.api.core.config import get_settings

# `client` fixture (session-scoped) lives in conftest.py. The app captures the
# settings singleton, so monkeypatching its attributes here changes what the
# running endpoint sees; monkeypatch reverts them after each test.


def test_metrics_default_token_mode_denies_without_token(client: TestClient) -> None:
    # Default mode is "token" with no METRICS_TOKEN configured -> fail closed.
    assert client.get("/metrics").status_code == 403


def test_metrics_public_mode_serves(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(get_settings(), "metrics_mode", "public")
    r = client.get("/metrics")
    assert r.status_code == 200


def test_metrics_token_mode_requires_matching_header(client: TestClient, monkeypatch) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "metrics_mode", "token")
    monkeypatch.setattr(s, "metrics_token", "s3cr3t")
    assert client.get("/metrics").status_code == 403
    assert client.get("/metrics", headers={"X-Metrics-Token": "wrong"}).status_code == 403
    assert client.get("/metrics", headers={"X-Metrics-Token": "s3cr3t"}).status_code == 200


def test_metrics_disabled_mode_404(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(get_settings(), "metrics_mode", "disabled")
    assert client.get("/metrics").status_code == 404


def test_metrics_authenticated_mode(client: TestClient, monkeypatch) -> None:
    import uuid

    monkeypatch.setattr(get_settings(), "metrics_mode", "authenticated")
    assert client.get("/metrics").status_code == 401  # no bearer
    tokens = client.post(
        "/api/v1/auth/register",
        json={"email": f"{uuid.uuid4()}@example.com", "password": "correct horse battery staple", "full_name": "M"},
    ).json()
    r = client.get("/metrics", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 200
