import uuid

from fastapi.testclient import TestClient

# `client` fixture (session-scoped TestClient) lives in conftest.py -- see
# that file for why it must be shared across every test module.


def _register(client: TestClient, full_name: str = "Test User") -> dict:
    email = f"{uuid.uuid4()}@example.com"
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct horse battery staple", "full_name": full_name},
    )
    assert resp.status_code == 201, resp.text
    tokens = resp.json()
    return {"email": email, **tokens}


def _auth_headers(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def test_register_and_me(client: TestClient) -> None:
    tokens = _register(client)
    resp = client.get("/api/v1/users/me", headers=_auth_headers(tokens))
    assert resp.status_code == 200
    assert resp.json()["email"] == tokens["email"]


def test_workspace_project_target_lifecycle(client: TestClient) -> None:
    owner = _register(client, "Owner")
    headers = _auth_headers(owner)

    ws = client.post("/api/v1/workspaces", headers=headers, json={"name": "Test Workspace"})
    assert ws.status_code == 201, ws.text
    workspace_id = ws.json()["id"]

    members = client.get(f"/api/v1/workspaces/{workspace_id}/members", headers=headers)
    assert members.status_code == 200
    assert len(members.json()) == 1
    assert members.json()[0]["role_name"] == "owner"

    project = client.post(
        f"/api/v1/workspaces/{workspace_id}/projects",
        headers=headers,
        json={"name": "Test Project"},
    )
    assert project.status_code == 201, project.text
    project_id = project.json()["id"]

    target = client.post(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/targets",
        headers=headers,
        json={"type": "domain", "value": "example.test"},
    )
    assert target.status_code == 201, target.text

    targets = client.get(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}/targets", headers=headers
    )
    assert targets.status_code == 200
    assert len(targets.json()) == 1
    assert targets.json()[0]["value"] == "example.test"


def test_non_member_is_denied(client: TestClient) -> None:
    owner = _register(client, "Owner2")
    outsider = _register(client, "Outsider")

    ws = client.post("/api/v1/workspaces", headers=_auth_headers(owner), json={"name": "Private Workspace"})
    workspace_id = ws.json()["id"]

    resp = client.get(f"/api/v1/workspaces/{workspace_id}/members", headers=_auth_headers(outsider))
    assert resp.status_code == 403


def test_member_role_cannot_manage_workspace(client: TestClient) -> None:
    owner = _register(client, "Owner3")
    member = _register(client, "Member3")

    ws = client.post("/api/v1/workspaces", headers=_auth_headers(owner), json={"name": "RBAC Workspace"})
    workspace_id = ws.json()["id"]

    invite = client.post(
        f"/api/v1/workspaces/{workspace_id}/members/invite",
        headers=_auth_headers(owner),
        json={"email": member["email"], "role_name": "member"},
    )
    assert invite.status_code == 201, invite.text

    project = client.post(
        f"/api/v1/workspaces/{workspace_id}/projects",
        headers=_auth_headers(member),
        json={"name": "Member project"},
    )
    assert project.status_code == 201
    project_id = project.json()["id"]

    delete_resp = client.delete(
        f"/api/v1/workspaces/{workspace_id}/projects/{project_id}", headers=_auth_headers(member)
    )
    assert delete_resp.status_code == 403

    invite_resp = client.post(
        f"/api/v1/workspaces/{workspace_id}/members/invite",
        headers=_auth_headers(member),
        json={"email": "another@example.com", "role_name": "member"},
    )
    assert invite_resp.status_code == 403


def test_refresh_token_rotation_invalidates_old_token(client: TestClient) -> None:
    tokens = _register(client, "Refresher")

    refreshed = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 200

    stale = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert stale.status_code == 401


def test_unauthenticated_request_rejected(client: TestClient) -> None:
    resp = client.get("/api/v1/workspaces")
    assert resp.status_code == 401


# --- F-04: refresh-token reuse detection --------------------------------------------------
# Rotation always recorded `replaced_by_id`, but nothing read it: replaying an already-rotated
# token returned a flat 401 identical to garbage input, so the ONE observable signal that a
# refresh token had been cloned was discarded and the thief's newer token stayed valid.
# These tests pin the family-revocation behaviour that closes that hole.


def test_replaying_a_rotated_token_revokes_the_whole_family(client: TestClient) -> None:
    """THE F-04 PROPERTY. Attacker steals refresh token A and rotates it to B. The legitimate
    client later presents its stale copy of A. That replay must invalidate B as well -- before
    the fix, B remained usable indefinitely."""
    tokens = _register(client, "FamilyRevoke")
    stolen = tokens["refresh_token"]

    # Attacker rotates the stolen token: A -> B
    attacker = client.post("/api/v1/auth/refresh", json={"refresh_token": stolen})
    assert attacker.status_code == 200
    b_token = attacker.json()["refresh_token"]

    # Sanity: B works before any replay is observed.
    probe = client.post("/api/v1/auth/refresh", json={"refresh_token": b_token})
    assert probe.status_code == 200, "the rotated token should be usable before reuse is detected"
    c_token = probe.json()["refresh_token"]

    # Legitimate client replays its stale copy of A -> reuse detected.
    replay = client.post("/api/v1/auth/refresh", json={"refresh_token": stolen})
    assert replay.status_code == 401

    # THE ASSERTION THAT WAS MISSING: the attacker's descendant is now dead too.
    after = client.post("/api/v1/auth/refresh", json={"refresh_token": c_token})
    assert after.status_code == 401, (
        "reuse of a rotated token must revoke its descendants -- the attacker's live token "
        "survived, so the family was never invalidated"
    )


def test_reuse_detection_is_idempotent(client: TestClient) -> None:
    """Replaying the same dead token repeatedly must stay a plain 401, not error out."""
    tokens = _register(client, "IdempotentReuse")
    stolen = tokens["refresh_token"]
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": stolen}).status_code == 200
    for _ in range(3):
        assert client.post("/api/v1/auth/refresh", json={"refresh_token": stolen}).status_code == 401


def test_reuse_detection_does_not_leak_token_existence(client: TestClient) -> None:
    """A revoked-but-real token and a garbage token must be indistinguishable to the caller,
    so probing cannot enumerate valid tokens."""
    tokens = _register(client, "NoLeak")
    stolen = tokens["refresh_token"]
    client.post("/api/v1/auth/refresh", json={"refresh_token": stolen})

    reused = client.post("/api/v1/auth/refresh", json={"refresh_token": stolen})
    garbage = client.post("/api/v1/auth/refresh", json={"refresh_token": "not-a-real-token"})
    assert reused.status_code == garbage.status_code == 401
    # correlation_id is unique per request by design, so compare the meaningful envelope only.
    def _envelope(body: dict) -> dict:
        return {k: v for k, v in body.items() if k != "correlation_id"}

    assert _envelope(reused.json()) == _envelope(garbage.json()), (
        "reuse must not be distinguishable from an unknown token"
    )


def test_reuse_of_one_users_token_does_not_affect_another_user(client: TestClient) -> None:
    """Family revocation must be scoped to the compromised chain only."""
    victim = _register(client, "VictimUser")
    bystander = _register(client, "BystanderUser")

    client.post("/api/v1/auth/refresh", json={"refresh_token": victim["refresh_token"]})
    client.post("/api/v1/auth/refresh", json={"refresh_token": victim["refresh_token"]})  # replay

    still_ok = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": bystander["refresh_token"]}
    )
    assert still_ok.status_code == 200, "an unrelated user's session must be untouched"


def test_normal_rotation_chain_still_works(client: TestClient) -> None:
    """Reuse detection must not break ordinary repeated rotation by a single honest client."""
    tokens = _register(client, "HonestRotator")
    current = tokens["refresh_token"]
    for _ in range(4):
        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": current})
        assert resp.status_code == 200
        current = resp.json()["refresh_token"]


# --- F-08: refresh token is an HttpOnly cookie, not a JS-readable body value ---------------
# It used to be returned in the JSON body and stored in localStorage, where any XSS could read
# a 7-day credential. These pin the cookie's security attributes, the cookie-authenticated
# refresh/logout flow, and the CSRF posture that cookie authentication makes necessary.

def _refresh_cookie_header(resp) -> str:
    """The raw Set-Cookie line for the refresh cookie (attributes are not exposed by the jar)."""
    from apps.api.core.config import get_settings

    name = get_settings().refresh_cookie_name
    for raw in resp.headers.get_list("set-cookie"):
        if raw.startswith(f"{name}="):
            return raw
    return ""


def test_f08_login_sets_an_httponly_refresh_cookie(client: TestClient) -> None:
    """THE F-08 PROPERTY: the refresh token arrives as a cookie JS cannot read."""
    email = f"f08cookie_{uuid.uuid4().hex[:8]}@example.com"
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "Passw0rd!x", "full_name": "F08 Cookie"},
    )
    assert resp.status_code == 201
    raw = _refresh_cookie_header(resp)
    assert raw, "register must set the refresh cookie"
    lowered = raw.lower()
    assert "httponly" in lowered, "refresh cookie MUST be HttpOnly -- that is the whole fix"
    assert "samesite=strict" in lowered, "SameSite=strict is the CSRF control for /auth/*"
    assert "path=/api/v1/auth" in lowered, "cookie must be scoped to the auth routes"
    assert "max-age=" in lowered, "cookie must expire with the refresh token"


def test_f08_refresh_works_from_the_cookie_with_no_body_token(client: TestClient) -> None:
    """A browser posts an EMPTY body; the cookie alone authenticates the rotation."""
    email = f"f08ck2_{uuid.uuid4().hex[:8]}@example.com"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "Passw0rd!x", "full_name": "F08 Cookie2"},
    )
    resp = client.post("/api/v1/auth/refresh")           # no JSON body at all
    assert resp.status_code == 200
    assert resp.json()["access_token"]
    assert _refresh_cookie_header(resp), "rotation must re-issue the cookie"


def test_f08_refresh_without_a_cookie_is_rejected(client: TestClient) -> None:
    client.cookies.clear()
    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_f08_logout_clears_the_cookie_and_revokes_server_side(client: TestClient) -> None:
    email = f"f08lo_{uuid.uuid4().hex[:8]}@example.com"
    reg = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "Passw0rd!x", "full_name": "F08 Logout"},
    )
    access = reg.json()["access_token"]
    out = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {access}"})
    assert out.status_code == 204
    cleared = _refresh_cookie_header(out)
    assert cleared, "logout must emit a Set-Cookie that expires the refresh cookie"
    assert 'mbs_refresh=""' in cleared or "max-age=0" in cleared.lower() or "expires=" in cleared.lower()
    # and the token itself is dead server-side, so a client that kept a copy gains nothing
    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_f08_cross_origin_refresh_is_refused(client: TestClient) -> None:
    """Cookie auth without an origin check would be CSRF-able. SameSite=strict is the primary
    control; this pins the explicit Origin check behind it."""
    email = f"f08csrf_{uuid.uuid4().hex[:8]}@example.com"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "Passw0rd!x", "full_name": "F08 CSRF"},
    )
    resp = client.post("/api/v1/auth/refresh", headers={"Origin": "https://evil.example.com"})
    assert resp.status_code == 403, "a cross-origin refresh must not be honoured"


def test_f08_same_origin_refresh_is_allowed(client: TestClient) -> None:
    """The origin check must not break the real frontend."""
    email = f"f08ok_{uuid.uuid4().hex[:8]}@example.com"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "Passw0rd!x", "full_name": "F08 OK"},
    )
    resp = client.post("/api/v1/auth/refresh", headers={"Origin": "http://localhost"})
    assert resp.status_code == 200


def test_f08_rotation_and_reuse_detection_still_work_through_cookies(client: TestClient) -> None:
    """F-04 must survive the transport change: replaying a rotated token still kills the family."""
    email = f"f08rot_{uuid.uuid4().hex[:8]}@example.com"
    reg = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "Passw0rd!x", "full_name": "F08 Rot"},
    )
    a = reg.json()["refresh_token"]                      # captured for the replay only
    assert client.post("/api/v1/auth/refresh").status_code == 200      # A -> B (cookie now B)
    # Replay A explicitly by body -- the non-browser path -- which must trip reuse detection.
    assert client.post("/api/v1/auth/refresh", json={"refresh_token": a}).status_code == 401
    # B (still in the jar) must now be dead too.
    assert client.post("/api/v1/auth/refresh").status_code == 401
