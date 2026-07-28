import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from apps.api.modules.schedules.service import compute_next_run


# --- Pure next-run logic ---

def test_compute_next_run_adds_interval() -> None:
    base = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert compute_next_run(base, 60) == datetime(2026, 1, 1, 13, 0, tzinfo=timezone.utc)
    assert compute_next_run(base, 5) == datetime(2026, 1, 1, 12, 5, tzinfo=timezone.utc)


# --- API helpers ---

def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct horse battery staple", "full_name": "Sched User"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _auth(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _setup(client: TestClient, headers: dict) -> tuple[str, str, str]:
    ws = client.post("/api/v1/workspaces", headers=headers, json={"name": "Sched WS"}).json()["id"]
    project = client.post(f"/api/v1/workspaces/{ws}/projects", headers=headers, json={"name": "P"}).json()["id"]
    target = client.post(
        f"/api/v1/workspaces/{ws}/projects/{project}/targets",
        headers=headers,
        json={"type": "domain", "value": "sched.example.test"},
    ).json()["id"]
    return ws, project, target


def test_schedule_crud(client: TestClient) -> None:
    headers = _auth(_register(client))
    ws, project, target = _setup(client, headers)
    base = f"/api/v1/workspaces/{ws}/projects/{project}/schedules"

    created = client.post(
        base,
        headers=headers,
        json={"target_id": target, "scan_type": "web", "requested_modules": ["httpx"], "interval_minutes": 60},
    )
    assert created.status_code == 201, created.text
    sid = created.json()["id"]
    assert created.json()["enabled"] is True
    assert created.json()["next_run_at"] is not None

    listed = client.get(base, headers=headers)
    assert listed.status_code == 200 and len(listed.json()) == 1

    # disable it
    patched = client.patch(f"{base}/{sid}", headers=headers, json={"enabled": False})
    assert patched.status_code == 200 and patched.json()["enabled"] is False

    # delete it
    assert client.delete(f"{base}/{sid}", headers=headers).status_code == 204
    assert client.get(base, headers=headers).json() == []


def test_schedule_rejects_too_frequent_interval(client: TestClient) -> None:
    headers = _auth(_register(client))
    ws, project, target = _setup(client, headers)
    resp = client.post(
        f"/api/v1/workspaces/{ws}/projects/{project}/schedules",
        headers=headers,
        json={"target_id": target, "scan_type": "web", "requested_modules": ["httpx"], "interval_minutes": 1},
    )
    assert resp.status_code == 422  # schema floor is 5 minutes


def test_schedule_isolated_from_other_project(client: TestClient) -> None:
    headers = _auth(_register(client))
    ws, project, target = _setup(client, headers)
    base = f"/api/v1/workspaces/{ws}/projects/{project}/schedules"
    sid = client.post(
        base,
        headers=headers,
        json={"target_id": target, "scan_type": "web", "requested_modules": ["httpx"], "interval_minutes": 60},
    ).json()["id"]

    other = client.post(f"/api/v1/workspaces/{ws}/projects", headers=headers, json={"name": "Other"}).json()["id"]
    # the schedule belongs to `project`, not `other` -> 404 when addressed via the other project
    resp = client.patch(
        f"/api/v1/workspaces/{ws}/projects/{other}/schedules/{sid}", headers=headers, json={"enabled": False}
    )
    assert resp.status_code == 404
