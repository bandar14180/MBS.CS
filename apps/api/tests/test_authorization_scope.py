import uuid

from fastapi.testclient import TestClient

# `client` fixture (session-scoped TestClient) lives in conftest.py -- see
# that file for why it must be shared across every test module.


def _register(client: TestClient, full_name: str) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct horse battery staple", "full_name": full_name},
    )
    assert resp.status_code == 201, resp.text
    return {"email": email, **resp.json()}


def _auth_headers(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _make_target(client: TestClient, owner_headers: dict, workspace_name: str) -> tuple[str, str, str]:
    ws = client.post("/api/v1/workspaces", headers=owner_headers, json={"name": workspace_name})
    assert ws.status_code == 201, ws.text
    workspace_id = ws.json()["id"]

    project = client.post(
        f"/api/v1/workspaces/{workspace_id}/projects", headers=owner_headers, json={"name": "Project"}
    )
    assert project.status_code == 201, project.text
    project_id = project.json()["id"]

    target = client.post(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/targets",
        headers=owner_headers,
        json={"type": "domain", "value": f"{uuid.uuid4()}.test"},
    )
    assert target.status_code == 201, target.text
    target_id = target.json()["id"]

    return workspace_id, project_id, target_id


def _scope_url(workspace_id: str, project_id: str, target_id: str) -> str:
    return f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/targets/{target_id}/authorization-scope"


def test_no_scope_submitted_yet_is_404(client: TestClient) -> None:
    owner = _register(client, "Owner")
    workspace_id, project_id, target_id = _make_target(client, _auth_headers(owner), "WS A")

    resp = client.get(_scope_url(workspace_id, project_id, target_id), headers=_auth_headers(owner))
    assert resp.status_code == 404


def test_submit_starts_unverified_with_active_testing_disallowed(client: TestClient) -> None:
    owner = _register(client, "Owner")
    workspace_id, project_id, target_id = _make_target(client, _auth_headers(owner), "WS B")

    resp = client.post(
        _scope_url(workspace_id, project_id, target_id),
        headers=_auth_headers(owner),
        json={"proof_type": "dns_txt", "proof_reference": "mbs-verify=xyz"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["verified"] is False
    assert body["active_testing_allowed"] is False
    assert body["verified_by"] is None


def test_member_cannot_verify_only_owner_can(client: TestClient) -> None:
    owner = _register(client, "Owner")
    member = _register(client, "Member")
    owner_headers = _auth_headers(owner)
    workspace_id, project_id, target_id = _make_target(client, owner_headers, "WS C")

    invite = client.post(
        f"/api/v1/workspaces/{workspace_id}/members/invite",
        headers=owner_headers,
        json={"email": member["email"], "role_name": "member"},
    )
    assert invite.status_code == 201, invite.text

    member_headers = _auth_headers(member)
    submit = client.post(
        _scope_url(workspace_id, project_id, target_id),
        headers=member_headers,
        json={"proof_type": "file_upload", "proof_reference": "https://example.test/proof.pdf"},
    )
    assert submit.status_code == 201, submit.text

    denied = client.post(
        f"{_scope_url(workspace_id, project_id, target_id)}/verify",
        headers=member_headers,
        json={"active_testing_allowed": True},
    )
    assert denied.status_code == 403

    allowed = client.post(
        f"{_scope_url(workspace_id, project_id, target_id)}/verify",
        headers=owner_headers,
        json={"active_testing_allowed": True, "scope_notes": "checked manually"},
    )
    assert allowed.status_code == 200, allowed.text
    body = allowed.json()
    assert body["verified"] is True
    assert body["active_testing_allowed"] is True
    assert body["verified_by"] is not None


def test_resubmission_preserves_history_and_get_returns_latest(client: TestClient) -> None:
    owner = _register(client, "Owner")
    owner_headers = _auth_headers(owner)
    workspace_id, project_id, target_id = _make_target(client, owner_headers, "WS D")
    url = _scope_url(workspace_id, project_id, target_id)

    first = client.post(
        url, headers=owner_headers, json={"proof_type": "dns_txt", "proof_reference": "first"}
    )
    second = client.post(
        url, headers=owner_headers, json={"proof_type": "signed_letter", "proof_reference": "second"}
    )
    assert first.json()["id"] != second.json()["id"]

    current = client.get(url, headers=owner_headers)
    assert current.status_code == 200
    assert current.json()["id"] == second.json()["id"]


def test_outsider_cannot_read_scope(client: TestClient) -> None:
    owner = _register(client, "Owner")
    outsider = _register(client, "Outsider")
    workspace_id, project_id, target_id = _make_target(client, _auth_headers(owner), "WS E")

    resp = client.get(_scope_url(workspace_id, project_id, target_id), headers=_auth_headers(outsider))
    assert resp.status_code == 403
