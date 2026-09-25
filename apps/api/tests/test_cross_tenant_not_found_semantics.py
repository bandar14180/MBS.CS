"""AUDIT-010 -- cross-tenant project references must answer consistently.

THE INCONSISTENCY (measured, before the fix)
--------------------------------------------
Tenant A naming Tenant B's project id got DIFFERENT answers from endpoints under the same
`/workspaces/{ws}/projects/{project_id}/...` prefix:

    vulnerabilities (list)   200 []      <-- treats a foreign project as an empty owned one
    scans (list)             200 []
    schedules (list)         200 []
    assets (list)            200 []      <-- not named in the finding; found by this sweep
    reports (list)           404
    targets (list)           404
    project (single)         404

No data leaked: every one of those queries was correctly workspace-scoped, which is why the
body was `[]`. The defect is the SEMANTICS. `200 []` asserts "this project is yours and
contains nothing"; the truth is "this project is not yours". That:

  * contradicts the contract the same API already implements everywhere else (get_project()),
  * is a weak existence oracle -- the moment a foreign id and a random id could diverge, the
    difference is observable, and
  * hides real client bugs behind a success response.

THE FIX
-------
The four list services now call the established `projects.service.get_project()` first --
exactly what reports/targets already did. A foreign or nonexistent project id gets 404;
legitimate list behaviour for a project you DO own is untouched, including the empty case.

These tests are BLACK BOX: two real tenants over HTTP, no internals.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

_PW = "correct horse battery staple"

# Every list endpoint hanging off /projects/{project_id}. The point of AUDIT-010 is that these
# agree with each other, so they are asserted as one set rather than individually.
PROJECT_SUBRESOURCES = [
    "vulnerabilities",
    "scans",
    "schedules",
    "assets",
    "reports",
    "targets",
]


def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": _PW, "full_name": "Tenant"},
    )
    assert r.status_code == 201, r.text
    tokens = r.json()
    return {"email": email, "headers": {"Authorization": f"Bearer {tokens['access_token']}"}}


def _workspace(client: TestClient, headers: dict, name: str) -> str:
    r = client.post("/api/v1/workspaces", headers=headers, json={"name": name})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _project(client: TestClient, headers: dict, ws: str, name: str) -> str:
    r = client.post(f"/api/v1/workspaces/{ws}/projects", headers=headers, json={"name": name})
    assert r.status_code == 201, r.text
    return r.json()["id"]


@pytest.fixture
def two_tenants(client: TestClient):
    """Tenant A and Tenant B, each with their own workspace and project."""
    a, b = _register(client), _register(client)
    ws_a = _workspace(client, a["headers"], "Tenant A WS")
    ws_b = _workspace(client, b["headers"], "Tenant B WS")
    proj_a = _project(client, a["headers"], ws_a, "A project")
    proj_b = _project(client, b["headers"], ws_b, "B project")
    return {
        "a": a, "b": b,
        "ws_a": ws_a, "ws_b": ws_b,
        "proj_a": proj_a, "proj_b": proj_b,
    }


# --------------------------------------------------------------------------------------------
# The core contract.
# --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("sub", PROJECT_SUBRESOURCES)
def test_foreign_project_id_is_not_found(two_tenants, client: TestClient, sub):
    """THE AUDIT-010 LOCK. Tenant A asks for Tenant B's project id, inside A's OWN workspace.

    Before the fix, vulnerabilities/scans/schedules/assets answered `200 []` here.
    """
    t = two_tenants
    r = client.get(
        f"/api/v1/workspaces/{t['ws_a']}/projects/{t['proj_b']}/{sub}",
        headers=t["a"]["headers"],
    )
    assert r.status_code == 404, (
        f"/{sub} returned {r.status_code} for another tenant's project id -- it must be 404, "
        f"the same answer this API gives everywhere else. Body: {r.text[:200]}"
    )


@pytest.mark.parametrize("sub", PROJECT_SUBRESOURCES)
def test_nonexistent_project_id_is_not_found(two_tenants, client: TestClient, sub):
    """A random UUID must get the SAME answer as a foreign project id -- otherwise the
    difference between the two responses is an existence oracle."""
    t = two_tenants
    r = client.get(
        f"/api/v1/workspaces/{t['ws_a']}/projects/{uuid.uuid4()}/{sub}",
        headers=t["a"]["headers"],
    )
    assert r.status_code == 404, f"/{sub} returned {r.status_code} for a nonexistent project id"


def test_foreign_and_nonexistent_projects_are_indistinguishable(two_tenants, client: TestClient):
    """Explicit oracle check: for every endpoint, the two responses must match in status AND
    body, so a caller cannot learn that a project id exists in some other tenant."""
    t = two_tenants
    ghost = str(uuid.uuid4())
    for sub in PROJECT_SUBRESOURCES:
        foreign = client.get(
            f"/api/v1/workspaces/{t['ws_a']}/projects/{t['proj_b']}/{sub}",
            headers=t["a"]["headers"],
        )
        unknown = client.get(
            f"/api/v1/workspaces/{t['ws_a']}/projects/{ghost}/{sub}",
            headers=t["a"]["headers"],
        )
        assert foreign.status_code == unknown.status_code, (
            f"/{sub} distinguishes a foreign project ({foreign.status_code}) from an unknown "
            f"one ({unknown.status_code}) -- that difference is an existence oracle"
        )
        # Compare the bodies with the per-request correlation_id normalised away: it is
        # deliberately unique per request (it is how a client ties a response to a log line),
        # so it differs between ANY two calls and says nothing about the project.
        def _stable(resp):
            body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text
            if isinstance(body, dict):
                body.pop("correlation_id", None)
            return body

        assert _stable(foreign) == _stable(unknown), (
            f"/{sub} returns different bodies for a foreign vs unknown project id"
        )


# --------------------------------------------------------------------------------------------
# No collateral damage: legitimate list behaviour must be untouched.
# --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("sub", PROJECT_SUBRESOURCES)
def test_own_empty_project_still_lists_successfully(two_tenants, client: TestClient, sub):
    """The fix must NOT turn 'your own project, which happens to be empty' into a 404. That is
    the one legitimate `200 []`, and it has to keep working."""
    t = two_tenants
    r = client.get(
        f"/api/v1/workspaces/{t['ws_a']}/projects/{t['proj_a']}/{sub}",
        headers=t["a"]["headers"],
    )
    assert r.status_code == 200, (
        f"/{sub} returned {r.status_code} for the caller's OWN empty project -- the AUDIT-010 "
        f"guard has over-reached. Body: {r.text[:200]}"
    )


def test_no_cross_tenant_data_is_ever_returned(two_tenants, client: TestClient):
    """The original behaviour leaked no data, and the fix must not introduce any: a 404 body
    must not echo the foreign project's name or id details beyond the plain not-found message."""
    t = two_tenants
    for sub in PROJECT_SUBRESOURCES:
        r = client.get(
            f"/api/v1/workspaces/{t['ws_a']}/projects/{t['proj_b']}/{sub}",
            headers=t["a"]["headers"],
        )
        assert "B project" not in r.text, (
            f"/{sub} disclosed the foreign project's NAME in its response"
        )


def test_tenant_b_still_reaches_its_own_project(two_tenants, client: TestClient):
    """Sanity: the guard is about ownership, not about breaking the owner."""
    t = two_tenants
    for sub in PROJECT_SUBRESOURCES:
        r = client.get(
            f"/api/v1/workspaces/{t['ws_b']}/projects/{t['proj_b']}/{sub}",
            headers=t["b"]["headers"],
        )
        assert r.status_code == 200, (
            f"/{sub} returned {r.status_code} to the project's actual owner"
        )


def test_workspace_mismatch_is_rejected_before_the_project_is_considered(
    two_tenants, client: TestClient
):
    """Naming B's WORKSPACE (not just B's project) must be refused by the membership check --
    the outer guard that has always been there."""
    t = two_tenants
    r = client.get(
        f"/api/v1/workspaces/{t['ws_b']}/projects/{t['proj_b']}/vulnerabilities",
        headers=t["a"]["headers"],
    )
    assert r.status_code in (403, 404), (
        f"a non-member reached another tenant's workspace: {r.status_code}"
    )
