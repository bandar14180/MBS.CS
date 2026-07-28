import uuid

from fastapi.testclient import TestClient

from apps.api.modules.billing.plans import get_plan
from apps.api.modules.billing.service import _over


# --- Pure plan logic ---

def test_over_limit_helper() -> None:
    assert _over(2, 2) is True   # at the cap -> next one is over
    assert _over(1, 2) is False
    assert _over(100, None) is False  # None = unlimited


def test_get_plan_defaults_to_unlimited_pilot() -> None:
    assert get_plan("pilot").max_projects is None
    assert get_plan(None).max_projects is None
    assert get_plan("bogus-legacy").max_projects is None  # unknown -> safe default
    assert get_plan("free").max_projects == 2


# --- API helpers ---

def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct horse battery staple", "full_name": "Billing User"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _auth(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _ws(client: TestClient, headers: dict) -> str:
    return client.post("/api/v1/workspaces", headers=headers, json={"name": "Billing WS"}).json()["id"]


# --- Public catalog ---

def test_public_plan_catalog(client: TestClient) -> None:
    resp = client.get("/api/v1/plans")
    assert resp.status_code == 200
    tiers = {p["tier"] for p in resp.json()}
    assert tiers == {"free", "pro", "enterprise"}


# --- Usage + default (pilot) is unlimited ---

def test_usage_default_pilot_is_unlimited(client: TestClient) -> None:
    headers = _auth(_register(client))
    ws = _ws(client, headers)
    resp = client.get(f"/api/v1/workspaces/{ws}/billing/usage", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["plan_tier"] == "pilot"
    assert body["limits"]["projects"] is None  # unlimited
    assert body["usage"]["projects"] == 0


# --- Plan change validation ---

def test_set_plan_rejects_unknown_tier(client: TestClient) -> None:
    headers = _auth(_register(client))
    ws = _ws(client, headers)
    resp = client.patch(f"/api/v1/workspaces/{ws}/billing/plan", headers=headers, json={"tier": "platinum"})
    assert resp.status_code == 400


# --- Quota enforcement (free plan) ---

def test_free_plan_enforces_project_limit(client: TestClient) -> None:
    headers = _auth(_register(client))
    ws = _ws(client, headers)
    client.patch(f"/api/v1/workspaces/{ws}/billing/plan", headers=headers, json={"tier": "free"})

    # free allows 2 projects
    for i in range(2):
        r = client.post(f"/api/v1/workspaces/{ws}/projects", headers=headers, json={"name": f"P{i}"})
        assert r.status_code == 201, r.text
    # the 3rd is blocked with 402 Payment Required
    r = client.post(f"/api/v1/workspaces/{ws}/projects", headers=headers, json={"name": "P3"})
    assert r.status_code == 402
    assert "limit" in r.json()["detail"].lower()

    # usage reflects the cap
    usage = client.get(f"/api/v1/workspaces/{ws}/billing/usage", headers=headers).json()
    assert usage["usage"]["projects"] == 2 and usage["limits"]["projects"] == 2


def test_free_plan_enforces_target_limit(client: TestClient) -> None:
    headers = _auth(_register(client))
    ws = _ws(client, headers)
    client.patch(f"/api/v1/workspaces/{ws}/billing/plan", headers=headers, json={"tier": "free"})
    project_id = client.post(f"/api/v1/workspaces/{ws}/projects", headers=headers, json={"name": "P"}).json()["id"]

    # free allows 5 targets across the workspace
    for i in range(5):
        r = client.post(
            f"/api/v1/workspaces/{ws}/projects/{project_id}/targets",
            headers=headers,
            json={"type": "domain", "value": f"t{i}.example.test"},
        )
        assert r.status_code == 201, r.text
    r = client.post(
        f"/api/v1/workspaces/{ws}/projects/{project_id}/targets",
        headers=headers,
        json={"type": "domain", "value": "t6.example.test"},
    )
    assert r.status_code == 402
