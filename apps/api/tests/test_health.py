from fastapi.testclient import TestClient

from apps.api.main import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_health_discloses_nothing_beyond_liveness() -> None:
    """/health is unauthenticated, so its body must stay minimal: no service name, no
    environment, no deployment metadata. Pinned because the payload is a published contract --
    apps/web/lib/api-client.ts types it as exactly {status} and would silently drift otherwise."""
    body = client.get("/health").json()
    assert body == {"status": "ok"}
