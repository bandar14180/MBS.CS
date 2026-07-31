"""Pagination behavior (P1-3): bounds, headers, validation, tenant isolation.
Uses the projects list as the representative endpoint (cheap to populate)."""
import uuid

from fastapi.testclient import TestClient


def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    r = client.post("/api/v1/auth/register", json={"email": email, "password": "correct horse battery staple", "full_name": "P"})
    assert r.status_code == 201, r.text
    return r.json()


def _auth(t: dict) -> dict:
    return {"Authorization": f"Bearer {t['access_token']}"}


def _ws_with_projects(client: TestClient, headers: dict, n: int) -> str:
    ws = client.post("/api/v1/workspaces", headers=headers, json={"name": "WS"}).json()["id"]
    for i in range(n):
        client.post(f"/api/v1/workspaces/{ws}/projects", headers=headers, json={"name": f"P{i}"})
    return ws


def test_default_pagination_returns_list_and_headers(client: TestClient) -> None:
    h = _auth(_register(client))
    ws = _ws_with_projects(client, h, 3)
    r = client.get(f"/api/v1/workspaces/{ws}/projects", headers=h)
    assert r.status_code == 200
    assert isinstance(r.json(), list)                      # body shape unchanged (backward compatible)
    assert r.headers["X-Total-Count"] == "3"
    assert r.headers["X-Has-More"] == "false"


def test_custom_limit_and_offset_and_has_more(client: TestClient) -> None:
    h = _auth(_register(client))
    ws = _ws_with_projects(client, h, 3)
    r1 = client.get(f"/api/v1/workspaces/{ws}/projects?limit=2&offset=0", headers=h)
    assert len(r1.json()) == 2
    assert r1.headers["X-Total-Count"] == "3" and r1.headers["X-Has-More"] == "true"
    r2 = client.get(f"/api/v1/workspaces/{ws}/projects?limit=2&offset=2", headers=h)
    assert len(r2.json()) == 1
    assert r2.headers["X-Has-More"] == "false"


def test_empty_page_beyond_end(client: TestClient) -> None:
    h = _auth(_register(client))
    ws = _ws_with_projects(client, h, 1)
    r = client.get(f"/api/v1/workspaces/{ws}/projects?offset=50", headers=h)
    assert r.json() == []
    assert r.headers["X-Total-Count"] == "1"


def test_invalid_pagination_values_rejected(client: TestClient) -> None:
    h = _auth(_register(client))
    ws = _ws_with_projects(client, h, 1)
    base = f"/api/v1/workspaces/{ws}/projects"
    assert client.get(f"{base}?limit=0", headers=h).status_code == 422       # below min
    assert client.get(f"{base}?limit=99999", headers=h).status_code == 422   # above max (200)
    assert client.get(f"{base}?limit=-5", headers=h).status_code == 422
    assert client.get(f"{base}?offset=-1", headers=h).status_code == 422


def test_pagination_is_tenant_isolated(client: TestClient) -> None:
    ha = _auth(_register(client))
    hb = _auth(_register(client))
    _ws_with_projects(client, ha, 2)
    ws_b = _ws_with_projects(client, hb, 3)
    # user A cannot page user B's workspace projects (RLS/scope -> not 200 with data)
    r = client.get(f"/api/v1/workspaces/{ws_b}/projects", headers=ha)
    assert r.status_code in (403, 404)
