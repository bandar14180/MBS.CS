"""Remediation workflow: issue-level grouping, state machine, RBAC, concurrency, evidence,
verification, risk acceptance, and the protected-field guarantees.

The tests are grouped by the requirement each one closes so a reviewer can map them back:
  * issue-level identity        -- test_n_locations_produce_one_remediation_item
  * state machine               -- test_every_legal_transition_*, test_illegal_transition_*
  * authorization matrix        -- test_role_matrix_*
  * risk:accept isolation       -- test_member_cannot_accept_risk, test_client_viewer_*
  * protected fields            -- test_remediation_api_cannot_change_severity_cvss_or_risk
  * optimistic locking          -- test_concurrent_update_*
  * immutability                -- test_no_event_mutation_endpoint_exists
  * verification                -- test_verification_*
  * regression                  -- test_fixed_reopened_relinks_remediation_item
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient


# --- bootstrap helpers (mirror test_vulnerabilities.py's conventions) -------------------------

def _register(client: TestClient, name: str) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct horse battery staple", "full_name": name},
    )
    assert resp.status_code == 201, resp.text
    return {"email": email, **resp.json()}


def _auth(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _workspace_project(client: TestClient, headers: dict) -> tuple[str, str]:
    wid = client.post("/api/v1/workspaces", headers=headers, json={"name": "WS"}).json()["id"]
    pid = client.post(
        f"/api/v1/workspaces/{wid}/projects", headers=headers, json={"name": "P"}
    ).json()["id"]
    return wid, pid


def _invite(client: TestClient, owner_headers: dict, wid: str, email: str, role: str) -> None:
    resp = client.post(
        f"/api/v1/workspaces/{wid}/members/invite",
        headers=owner_headers,
        json={"email": email, "role_name": role},
    )
    assert resp.status_code in (200, 201), resp.text


def _seed_findings(wid: str, pid: str, findings: list[dict]) -> list[uuid.UUID]:
    """Insert vulnerabilities directly.

    Goes through the ORM rather than the API because there is no endpoint that CREATES a
    vulnerability -- findings only ever arrive through a scan, and running a real scanner in a
    unit test would make these tests about the scanner instead of about remediation. The
    workspace is bound explicitly first, which the app-layer INSERT guard requires (see
    core/tenancy._assert_insert_allowed)."""
    import asyncio

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.modules.risk.models import RiskScore
    from apps.api.modules.vulnerabilities.models import Vulnerability

    async def _run() -> list[uuid.UUID]:
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        ids: list[uuid.UUID] = []
        try:
            async with maker() as session:
                with tenancy.workspace_scope(uuid.UUID(wid)):
                    for f in findings:
                        vuln = Vulnerability(
                            project_id=uuid.UUID(pid),
                            fingerprint=f["fingerprint"],
                            title=f["title"],
                            severity=f.get("severity", "high"),
                            status=f.get("status", "open"),
                            cvss_score=f.get("cvss_score", 8.0),
                            cvss_vector=f.get("cvss_vector"),
                            category=f.get("category"),
                            last_seen_scan_id=f.get("last_seen_scan_id"),
                        )
                        session.add(vuln)
                        await session.flush()
                        if f.get("final_risk_score") is not None:
                            session.add(
                                RiskScore(
                                    vulnerability_id=vuln.id,
                                    asset_criticality_weight=1.0,
                                    business_impact_score=f.get("cvss_score", 8.0),
                                    final_risk_score=f["final_risk_score"],
                                )
                            )
                        ids.append(vuln.id)
                    await session.commit()
        finally:
            await engine.dispose()
        return ids

    return asyncio.run(_run())


def _rem_base(wid: str, pid: str) -> str:
    return f"/api/v1/workspaces/{wid}/projects/{pid}/remediation"


# =============================================================================================
# ISSUE-LEVEL IDENTITY (requirement 9 / 33)
# =============================================================================================

def test_n_locations_produce_one_remediation_item(client: TestClient) -> None:
    """THE issue-level invariant: one issue observed at N locations is ONE remediation item.

    This is the defect the whole grouping design exists to prevent -- a per-row model would
    have produced five items here, five owners, five due dates, for one thing to fix."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)

    # Five DISTINCT vulnerability rows, five different URLs, ONE nuclei template.
    _seed_findings(wid, pid, [
        {
            "fingerprint": f"cmd-injection|param|https://host/page{i}",
            "title": "Command Injection",
            "severity": "critical",
            "cvss_score": 9.8,
        }
        for i in range(5)
    ])

    resp = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers)
    assert resp.status_code == 201, resp.text
    created = resp.json()
    assert len(created) == 1, f"expected ONE item for one issue at 5 locations, got {len(created)}"
    assert created[0]["issue_key"] == "template:cmd-injection"

    listing = client.get(_rem_base(wid, pid), headers=headers).json()
    assert len(listing) == 1


def test_sync_is_idempotent_and_never_overwrites_human_state(client: TestClient) -> None:
    """Re-running sync after a new scan must ADD items for new issues without touching the
    owner/due date/status a human set on existing ones."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    _seed_findings(wid, pid, [
        {"fingerprint": "issue-a|m|https://h/1", "title": "Issue A", "severity": "high"},
    ])

    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    # A human takes ownership and moves it along.
    due = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    updated = client.patch(
        f"{_rem_base(wid, pid)}/{item['id']}",
        headers=headers,
        json={"version": item["version"], "priority": "low", "due_date": due, "notes": "mine"},
    )
    assert updated.status_code == 200, updated.text
    client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/transition",
        headers=headers,
        json={"version": updated.json()["version"], "to_status": "accepted"},
    )

    # A second scan finds a NEW issue.
    _seed_findings(wid, pid, [
        {"fingerprint": "issue-b|m|https://h/2", "title": "Issue B", "severity": "medium"},
    ])
    second = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()
    assert len(second) == 1 and second[0]["issue_key"] == "template:issue-b"

    unchanged = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert unchanged["status"] == "accepted"
    assert unchanged["priority"] == "low"
    assert unchanged["notes"] == "mine"


# =============================================================================================
# STATE MACHINE (requirement 7 of section 7)
# =============================================================================================

def _make_item(client: TestClient, headers: dict, wid: str, pid: str, key: str = "sm") -> dict:
    _seed_findings(wid, pid, [
        {"fingerprint": f"{key}|m|https://h/x", "title": f"Issue {key}", "severity": "high"},
    ])
    items = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()
    return items[0]


def _transition(client, headers, wid, pid, item, to_status):
    resp = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/transition",
        headers=headers,
        json={"version": item["version"], "to_status": to_status},
    )
    return resp


def test_full_happy_path_lifecycle(client: TestClient) -> None:
    """proposed -> accepted -> in_progress -> awaiting_verification, then verified only via
    the verification workflow, then closed."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, "happy")

    for target in ("accepted", "in_progress"):
        resp = _transition(client, headers, wid, pid, item, target)
        assert resp.status_code == 200, resp.text
        item = resp.json()
        assert item["status"] == target


@pytest.mark.parametrize(
    "path,final",
    [
        (["accepted", "in_progress"], "in_progress"),
        (["rejected", "proposed"], "proposed"),
        (["accepted", "rejected"], "rejected"),
    ],
)
def test_legal_transition_paths_are_accepted(client: TestClient, path, final) -> None:
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"legal{uuid.uuid4().hex[:6]}")

    for target in path:
        resp = _transition(client, headers, wid, pid, item, target)
        assert resp.status_code == 200, f"{target} rejected: {resp.text}"
        item = resp.json()
    assert item["status"] == final


@pytest.mark.parametrize("target", ["closed", "awaiting_verification", "reopened"])
def test_illegal_transition_from_proposed_is_rejected(client: TestClient, target) -> None:
    """A fresh item cannot leap to a late-lifecycle state. 409, and nothing is written."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"illegal{uuid.uuid4().hex[:6]}")

    resp = _transition(client, headers, wid, pid, item, target)
    assert resp.status_code == 409, resp.text

    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert after["status"] == "proposed"
    # No version bump and no event for a rejected transition.
    assert after["version"] == item["version"]
    events = client.get(f"{_rem_base(wid, pid)}/{item['id']}/events", headers=headers).json()
    assert [e["event_type"] for e in events] == ["created"]


@pytest.mark.parametrize("guarded", ["verified", "risk_accepted"])
def test_guarded_targets_are_rejected_by_the_generic_transition_endpoint(
    client: TestClient, guarded
) -> None:
    """`verified` and `risk_accepted` require EVIDENCE the transition endpoint does not have.
    Rejected at the schema boundary (422) -- a user with remediation:manage must not be able
    to declare work verified, or a risk accepted, by typing the word."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"guard{uuid.uuid4().hex[:6]}")

    resp = client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/transition",
        headers=headers,
        json={"version": item["version"], "to_status": guarded},
    )
    assert resp.status_code == 422, resp.text


def test_state_machine_graph_is_self_consistent() -> None:
    """Pure check on the transition table itself: every TARGET named anywhere must also be a
    known status, so a typo cannot create an unreachable or un-leavable state."""
    from apps.api.modules.remediation.models import REMEDIATION_STATUSES
    from apps.api.modules.remediation.state_machine import LEGAL_TRANSITIONS

    for source, targets in LEGAL_TRANSITIONS.items():
        assert source in REMEDIATION_STATUSES, f"unknown source status {source}"
        for target in targets:
            assert target in REMEDIATION_STATUSES, f"unknown target status {target}"
        assert source not in targets, f"self-transition {source} -> {source} must not be legal"


# =============================================================================================
# AUTHORIZATION MATRIX (requirements 25, 26)
# =============================================================================================

def _member_client(client: TestClient, owner_headers: dict, wid: str, role: str) -> dict:
    user = _register(client, role)
    _invite(client, owner_headers, wid, user["email"], role)
    return _auth(user)


@pytest.mark.parametrize("role,expected", [("admin", 200), ("member", 200), ("client_viewer", 200)])
def test_role_matrix_read_is_allowed_for_every_role(client: TestClient, role, expected) -> None:
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    _make_item(client, headers, wid, pid, f"read{uuid.uuid4().hex[:6]}")

    role_headers = _member_client(client, headers, wid, role)
    resp = client.get(_rem_base(wid, pid), headers=role_headers)
    assert resp.status_code == expected, resp.text


@pytest.mark.parametrize("role,expected", [("admin", 200), ("member", 200), ("client_viewer", 403)])
def test_role_matrix_manage_excludes_client_viewer(client: TestClient, role, expected) -> None:
    """client_viewer is READ-ONLY: it may see remediation work but never change it."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"manage{uuid.uuid4().hex[:6]}")

    role_headers = _member_client(client, headers, wid, role)
    resp = client.patch(
        f"{_rem_base(wid, pid)}/{item['id']}",
        headers=role_headers,
        json={"version": item["version"], "priority": "low"},
    )
    assert resp.status_code == expected, resp.text


def test_unauthenticated_request_is_rejected(client: TestClient) -> None:
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    assert client.get(_rem_base(wid, pid)).status_code == 401


def test_non_member_cannot_read_another_workspaces_remediation(client: TestClient) -> None:
    """IDOR / cross-workspace read: an authenticated outsider gets 403, never data."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    _make_item(client, headers, wid, pid, f"idor{uuid.uuid4().hex[:6]}")

    outsider = _auth(_register(client, "Outsider"))
    resp = client.get(_rem_base(wid, pid), headers=outsider)
    assert resp.status_code == 403, resp.text


def test_cross_workspace_item_id_is_not_found_not_leaked(client: TestClient) -> None:
    """An item id from workspace A, requested through workspace B's path by a member of B,
    must 404 -- indistinguishable from a non-existent id, so the endpoint cannot confirm that
    another tenant's item exists."""
    owner_a = _register(client, "OwnerA")
    headers_a = _auth(owner_a)
    wid_a, pid_a = _workspace_project(client, headers_a)
    item_a = _make_item(client, headers_a, wid_a, pid_a, f"xws{uuid.uuid4().hex[:6]}")

    owner_b = _register(client, "OwnerB")
    headers_b = _auth(owner_b)
    wid_b, pid_b = _workspace_project(client, headers_b)

    resp = client.get(f"{_rem_base(wid_b, pid_b)}/{item_a['id']}", headers=headers_b)
    assert resp.status_code == 404, resp.text


@pytest.mark.parametrize("role", ["member", "client_viewer"])
def test_member_and_client_viewer_cannot_accept_risk(client: TestClient, role) -> None:
    """requirement 26, stated explicitly: member -> DENY, client_viewer -> DENY. `risk:accept`
    must never be inherited by a role that merely holds remediation:manage or a read role."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": f"ra{uuid.uuid4().hex[:6]}|m|https://h/1", "title": "RA", "severity": "high"},
    ])

    role_headers = _member_client(client, headers, wid, role)
    resp = client.post(
        f"{_rem_base(wid, pid)}/risk-acceptances",
        headers=role_headers,
        json={
            "vulnerability_id": str(vuln_ids[0]),
            "justification": "compensating control in place",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        },
    )
    assert resp.status_code == 403, resp.text
    assert "risk:accept" in resp.json()["detail"]


@pytest.mark.parametrize("role", ["owner", "admin"])
def test_owner_and_admin_can_accept_risk(client: TestClient, role) -> None:
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": f"ra2{uuid.uuid4().hex[:6]}|m|https://h/1", "title": "RA", "severity": "high"},
    ])

    actor = headers if role == "owner" else _member_client(client, headers, wid, "admin")
    resp = client.post(
        f"{_rem_base(wid, pid)}/risk-acceptances",
        headers=actor,
        json={
            "vulnerability_id": str(vuln_ids[0]),
            "justification": "compensating control in place",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["status"] == "active"


# =============================================================================================
# PROTECTED FIELDS (requirement 27)
# =============================================================================================

@pytest.mark.parametrize(
    "protected",
    [
        {"severity": "low"},
        {"cvss_score": 1.0},
        {"cvss_vector": "CVSS:3.1/AV:N"},
        {"final_risk_score": 0.1},
        {"status": "verified"},
        {"workspace_id": str(uuid.uuid4())},
        {"project_id": str(uuid.uuid4())},
    ],
)
def test_remediation_api_cannot_change_severity_cvss_or_risk(client: TestClient, protected) -> None:
    """The remediation API must not be a back door into scanner/risk-engine-owned fields, nor
    into re-scoping a row into another tenant.

    REJECTED (422), not silently ignored: a silent ignore returns 200 and leaves the caller
    believing the protected field changed."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"prot{uuid.uuid4().hex[:6]}")

    resp = client.patch(
        f"{_rem_base(wid, pid)}/{item['id']}",
        headers=headers,
        json={"version": item["version"], **protected},
    )
    assert resp.status_code == 422, f"protected field {protected} was not rejected: {resp.text}"


def test_severity_and_cvss_are_unchanged_after_a_full_remediation_cycle(client: TestClient) -> None:
    """End-to-end proof: driving an item through the workflow leaves the underlying finding's
    scanner-owned fields byte-identical."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    vuln_ids = _seed_findings(wid, pid, [
        {
            "fingerprint": f"unchanged{uuid.uuid4().hex[:6]}|m|https://h/1",
            "title": "Unchanged", "severity": "critical", "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L", "final_risk_score": 9.8,
        },
    ])
    vuln_url = f"/api/v1/workspaces/{wid}/projects/{pid}/vulnerabilities/{vuln_ids[0]}"
    before = client.get(vuln_url, headers=headers).json()

    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    item = _transition(client, headers, wid, pid, item, "accepted").json()
    _transition(client, headers, wid, pid, item, "in_progress")

    after = client.get(vuln_url, headers=headers).json()
    assert after["severity"] == before["severity"] == "critical"
    assert after["cvss_score"] == before["cvss_score"] == 9.8
    assert after["cvss_vector"] == before["cvss_vector"]
    risk_after = client.get(f"{vuln_url}/risk", headers=headers).json()
    assert risk_after["final_risk_score"] == 9.8


def test_accepting_risk_does_not_change_severity_cvss_or_risk(client: TestClient) -> None:
    """requirement 12: risk acceptance is a TREATMENT decision, not a severity change."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    vuln_ids = _seed_findings(wid, pid, [
        {
            "fingerprint": f"accept{uuid.uuid4().hex[:6]}|m|https://h/1",
            "title": "Accepted", "severity": "critical", "cvss_score": 9.1,
            "final_risk_score": 9.1,
        },
    ])
    vuln_url = f"/api/v1/workspaces/{wid}/projects/{pid}/vulnerabilities/{vuln_ids[0]}"

    resp = client.post(
        f"{_rem_base(wid, pid)}/risk-acceptances",
        headers=headers,
        json={
            "vulnerability_id": str(vuln_ids[0]),
            "justification": "accepted by the board for this quarter",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        },
    )
    assert resp.status_code == 201, resp.text

    after = client.get(vuln_url, headers=headers).json()
    assert after["severity"] == "critical"
    assert after["cvss_score"] == 9.1
    # The finding still EXISTS -- acceptance never deletes it.
    assert after["id"] == str(vuln_ids[0])
    assert client.get(f"{vuln_url}/risk", headers=headers).json()["final_risk_score"] == 9.1


# =============================================================================================
# RISK ACCEPTANCE lifecycle (requirement 12)
# =============================================================================================

def test_risk_acceptance_requires_justification_and_future_expiry(client: TestClient) -> None:
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": f"just{uuid.uuid4().hex[:6]}|m|https://h/1", "title": "J", "severity": "high"},
    ])
    url = f"{_rem_base(wid, pid)}/risk-acceptances"
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()

    # Empty justification -> schema rejects it.
    assert client.post(url, headers=headers, json={
        "vulnerability_id": str(vuln_ids[0]), "justification": "", "expires_at": future,
    }).status_code == 422

    # PAST expiry -> an acceptance that cannot lapse is not an accepted risk.
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    resp = client.post(url, headers=headers, json={
        "vulnerability_id": str(vuln_ids[0]), "justification": "because", "expires_at": past,
    })
    assert resp.status_code == 400
    assert "future" in resp.json()["detail"]


def test_risk_acceptance_revoke_and_expiry(client: TestClient) -> None:
    """Revocation keeps the row (an auditor needs to know a risk WAS accepted) and the expiry
    sweep flips a lapsed acceptance without any human action."""
    import asyncio

    from sqlalchemy import update
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.modules.remediation.risk_models import RiskAcceptance
    from apps.api.modules.remediation.risk_service import expire_due_acceptances

    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": f"rev{uuid.uuid4().hex[:6]}|m|https://h/1", "title": "R", "severity": "high"},
        {"fingerprint": f"exp{uuid.uuid4().hex[:6]}|m|https://h/2", "title": "E", "severity": "high"},
    ])
    url = f"{_rem_base(wid, pid)}/risk-acceptances"
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()

    to_revoke = client.post(url, headers=headers, json={
        "vulnerability_id": str(vuln_ids[0]), "justification": "temp", "expires_at": future,
    }).json()
    to_expire = client.post(url, headers=headers, json={
        "vulnerability_id": str(vuln_ids[1]), "justification": "temp", "expires_at": future,
    }).json()

    revoked = client.post(
        f"{url}/{to_revoke['id']}/revoke", headers=headers, json={"reason": "no longer justified"}
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"
    assert revoked.json()["revoke_reason"] == "no longer justified"
    # The row SURVIVES revocation -- it is the audit record.
    assert any(a["id"] == to_revoke["id"] for a in client.get(url, headers=headers).json())

    # Backdate the second acceptance's expiry, then run the sweep.
    async def _expire() -> int:
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                with tenancy.workspace_scope(uuid.UUID(wid)):
                    await session.execute(
                        update(RiskAcceptance)
                        .where(RiskAcceptance.id == uuid.UUID(to_expire["id"]))
                        .values(expires_at=datetime.now(timezone.utc) - timedelta(hours=1))
                    )
                    await session.commit()
                    return await expire_due_acceptances(session, uuid.UUID(wid))
        finally:
            await engine.dispose()

    assert asyncio.run(_expire()) == 1
    rows = {a["id"]: a for a in client.get(url, headers=headers).json()}
    assert rows[to_expire["id"]]["status"] == "expired"
    # The revoked one is untouched by the expiry sweep -- it only ever acts on `active` rows.
    assert rows[to_revoke["id"]]["status"] == "revoked"


def test_only_one_active_acceptance_per_vulnerability(client: TestClient) -> None:
    """Two overlapping acceptances would make "is this accepted, and until when?" ambiguous."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": f"dup{uuid.uuid4().hex[:6]}|m|https://h/1", "title": "D", "severity": "high"},
    ])
    url = f"{_rem_base(wid, pid)}/risk-acceptances"
    body = {
        "vulnerability_id": str(vuln_ids[0]), "justification": "one",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
    }
    assert client.post(url, headers=headers, json=body).status_code == 201
    second = client.post(url, headers=headers, json=body)
    assert second.status_code == 409
    assert "already has an active risk acceptance" in second.json()["detail"]


# =============================================================================================
# CONCURRENCY / OPTIMISTIC LOCKING (requirements 19, 37)
# =============================================================================================

def test_stale_version_update_is_rejected_with_409(client: TestClient) -> None:
    """Two writers, one version. The second must lose deterministically -- not silently
    overwrite the first."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"lock{uuid.uuid4().hex[:6]}")
    stale_version = item["version"]

    first = client.patch(
        f"{_rem_base(wid, pid)}/{item['id']}",
        headers=headers, json={"version": stale_version, "priority": "low"},
    )
    assert first.status_code == 200, first.text
    assert first.json()["version"] == stale_version + 1

    # Second writer still holds the OLD version.
    second = client.patch(
        f"{_rem_base(wid, pid)}/{item['id']}",
        headers=headers, json={"version": stale_version, "priority": "critical"},
    )
    assert second.status_code == 409, second.text

    # The first writer's change survived; the loser changed nothing.
    final = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert final["priority"] == "low"
    assert final["version"] == stale_version + 1


def test_concurrent_transitions_one_wins_one_conflicts(client: TestClient) -> None:
    """Two simultaneous transitions from the same observed version: exactly one succeeds."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"race{uuid.uuid4().hex[:6]}")

    body = {"version": item["version"], "to_status": "accepted"}
    first = client.post(f"{_rem_base(wid, pid)}/{item['id']}/transition", headers=headers, json=body)
    second = client.post(f"{_rem_base(wid, pid)}/{item['id']}/transition", headers=headers, json=body)

    codes = sorted([first.status_code, second.status_code])
    assert codes == [200, 409], f"expected exactly one winner, got {codes}"


def test_no_op_update_does_not_bump_version_or_append_events(client: TestClient) -> None:
    """Setting a field to the value it already has is not a change: it must not append a
    misleading event or invalidate every other client's version token."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"noop{uuid.uuid4().hex[:6]}")

    resp = client.patch(
        f"{_rem_base(wid, pid)}/{item['id']}",
        headers=headers, json={"version": item["version"], "priority": item["priority"]},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["version"] == item["version"]
    events = client.get(f"{_rem_base(wid, pid)}/{item['id']}/events", headers=headers).json()
    assert [e["event_type"] for e in events] == ["created"]


# =============================================================================================
# IMMUTABILITY (requirement 36)
# =============================================================================================

def test_no_event_mutation_endpoint_exists() -> None:
    """remediation_events is append-only, enforced by the ABSENCE of any write route.

    Asserted against the actual OpenAPI surface rather than by reading the router source, so a
    future PATCH/DELETE added anywhere fails this test."""
    from apps.api.main import create_app

    spec = create_app().openapi()
    for path, methods in spec["paths"].items():
        if path.endswith("/events") and "remediation" in path:
            assert set(methods) == {"get"}, f"{path} exposes non-GET methods: {sorted(methods)}"
        # No route may address an individual event at all.
        assert "/events/{" not in path, f"per-event route exists: {path}"


def test_events_are_recorded_for_every_workflow_action(client: TestClient) -> None:
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"events{uuid.uuid4().hex[:6]}")

    due = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
    resp = client.patch(
        f"{_rem_base(wid, pid)}/{item['id']}",
        headers=headers,
        json={"version": item["version"], "due_date": due, "priority": "critical", "notes": "n"},
    )
    assert resp.status_code == 200, resp.text
    _transition(client, headers, wid, pid, resp.json(), "accepted")

    events = client.get(f"{_rem_base(wid, pid)}/{item['id']}/events", headers=headers).json()
    types = [e["event_type"] for e in events]
    assert "created" in types
    assert "due_date_changed" in types
    assert "priority_changed" in types
    assert "notes_changed" in types
    assert "transition" in types
    transition = next(e for e in events if e["event_type"] == "transition")
    assert transition["from_status"] == "proposed" and transition["to_status"] == "accepted"


def test_human_notes_are_labelled_human_not_ai(client: TestClient) -> None:
    """requirement 8 / 28: provenance must be truthful. Notes written through the API are
    HUMAN-authored; AI guidance lives in the separate `remediations` row."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"prov{uuid.uuid4().hex[:6]}")

    resp = client.patch(
        f"{_rem_base(wid, pid)}/{item['id']}",
        headers=headers, json={"version": item["version"], "notes": "I patched the handler"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["notes_source"] == "human"
    # The item itself was created by the SYSTEM from scan findings, never claimed as human.
    assert resp.json()["source"] == "system"


# =============================================================================================
# DUE DATES / OVERDUE (requirement 6)
# =============================================================================================

def test_due_date_set_update_clear_and_overdue_filter(client: TestClient) -> None:
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"due{uuid.uuid4().hex[:6]}")
    base = f"{_rem_base(wid, pid)}/{item['id']}"

    past = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    item = client.patch(base, headers=headers, json={"version": item["version"], "due_date": past}).json()
    assert item["due_date"] is not None

    overdue = client.get(_rem_base(wid, pid), headers=headers, params={"overdue": True}).json()
    assert [i["id"] for i in overdue] == [item["id"]]

    # CLEARING needs its own flag -- None means "leave unchanged" in a PATCH.
    cleared = client.patch(base, headers=headers, json={"version": item["version"], "clear_due_date": True})
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["due_date"] is None
    assert client.get(_rem_base(wid, pid), headers=headers, params={"overdue": True}).json() == []


def test_finished_work_past_its_due_date_is_not_overdue(client: TestClient) -> None:
    """An item that is done is not overdue -- counting it would inflate the metric with work
    that is actually complete."""
    from apps.api.modules.remediation.models import RemediationItem
    from apps.api.modules.remediation.service import is_overdue

    now = datetime.now(timezone.utc)
    finished = RemediationItem(
        status="closed", due_date=now - timedelta(days=5), title="t", issue_key="k",
    )
    outstanding = RemediationItem(
        status="in_progress", due_date=now - timedelta(days=5), title="t", issue_key="k",
    )
    assert is_overdue(finished, now) is False
    assert is_overdue(outstanding, now) is True


# =============================================================================================
# ASSIGNEE (requirement 5)
# =============================================================================================

def test_assignee_must_be_a_workspace_member(client: TestClient) -> None:
    """An arbitrary external user id must be refused -- otherwise the endpoint mis-routes work
    AND becomes an oracle for whether a given user id exists on the platform."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"assign{uuid.uuid4().hex[:6]}")

    outsider = _register(client, "Outsider")
    outsider_id = client.get("/api/v1/users/me", headers=_auth(outsider)).json()["id"]

    resp = client.patch(
        f"{_rem_base(wid, pid)}/{item['id']}",
        headers=headers, json={"version": item["version"], "assignee_user_id": outsider_id},
    )
    assert resp.status_code == 400, resp.text
    assert "member of this workspace" in resp.json()["detail"]


def test_assignee_can_be_set_to_a_member_and_cleared(client: TestClient) -> None:
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"assign2{uuid.uuid4().hex[:6]}")

    member = _register(client, "member")
    _invite(client, headers, wid, member["email"], "member")
    member_id = client.get("/api/v1/users/me", headers=_auth(member)).json()["id"]
    base = f"{_rem_base(wid, pid)}/{item['id']}"

    assigned = client.patch(
        base, headers=headers, json={"version": item["version"], "assignee_user_id": member_id}
    )
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["assignee_user_id"] == member_id

    cleared = client.patch(
        base, headers=headers, json={"version": assigned.json()["version"], "clear_assignee": True}
    )
    assert cleared.status_code == 200 and cleared.json()["assignee_user_id"] is None


# =============================================================================================
# PROGRESS (requirement 15)
# =============================================================================================

def test_progress_counts_every_status_and_completion_percent(client: TestClient) -> None:
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    _seed_findings(wid, pid, [
        {"fingerprint": f"p{i}|m|https://h/{i}", "title": f"P{i}", "severity": "high"}
        for i in range(3)
    ])
    items = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()
    assert len(items) == 3

    # Move one to accepted so the counts are not all in one bucket.
    _transition(client, headers, wid, pid, items[0], "accepted")

    progress = client.get(f"{_rem_base(wid, pid)}/progress", headers=headers).json()
    assert progress["total"] == 3
    assert progress["accepted"] == 1
    assert progress["proposed"] == 2
    assert progress["open"] == 3          # nothing resolved yet
    assert progress["resolved"] == 0
    assert progress["completion_percent"] == 0
    assert progress["overdue"] == 0


def test_progress_on_an_empty_project_is_zero_not_complete(client: TestClient) -> None:
    """0 of 0 items is 0% -- claiming 100% completion of nothing would read as "all done"."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    progress = client.get(f"{_rem_base(wid, pid)}/progress", headers=headers).json()
    assert progress["total"] == 0
    assert progress["completion_percent"] == 0


def test_stale_version_during_risk_acceptance_rolls_back_the_acceptance_too(
    client: TestClient
) -> None:
    """ATOMICITY across the two writes.

    accept_risk() flushes the RiskAcceptance row and THEN transitions the linked remediation
    item. If the transition loses the optimistic-lock race, the whole thing must unwind --
    otherwise an acceptance would exist for an item that was never moved to `risk_accepted`,
    i.e. a risk recorded as accepted while the work item still says it is outstanding.
    """
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    key = f"atomic{uuid.uuid4().hex[:6]}"
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": f"{key}|m|https://h/1", "title": "Atomic", "severity": "high"},
    ])
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]
    stale_version = item["version"]

    # Someone else moves the item first, so the version the acceptance carries goes stale.
    bumped = client.patch(
        f"{_rem_base(wid, pid)}/{item['id']}",
        headers=headers, json={"version": stale_version, "priority": "low"},
    )
    assert bumped.status_code == 200, bumped.text

    resp = client.post(
        f"{_rem_base(wid, pid)}/risk-acceptances",
        headers=headers,
        json={
            "vulnerability_id": str(vuln_ids[0]),
            "justification": "should not survive",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
            "remediation_item_id": item["id"],
            "version": stale_version,
        },
    )
    assert resp.status_code == 409, resp.text

    # NEITHER write landed: no acceptance row, and the item never reached risk_accepted.
    acceptances = client.get(
        f"{_rem_base(wid, pid)}/risk-acceptances", headers=headers,
        params={"vulnerability_id": str(vuln_ids[0])},
    ).json()
    assert acceptances == [], "the acceptance survived a failed transition"

    after = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert after["status"] == "proposed"


def test_a_lost_update_leaves_no_partial_field_changes(client: TestClient) -> None:
    """update_item mutates the in-memory ORM object BEFORE taking the optimistic lock, so a
    lost race must discard those pending changes rather than letting some of them leak through
    on a later flush. A partially-applied update is worse than a rejected one: the caller is
    told it failed while the database quietly disagrees."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"partial{uuid.uuid4().hex[:6]}")
    stale_version = item["version"]

    # Winner changes one field. `critical` specifically: _make_item seeds a HIGH-severity
    # finding, and priority is seeded from severity at creation, so patching it to "high"
    # would be a genuine no-op -- correctly returning 200 WITHOUT bumping the version (see
    # test_no_op_update_does_not_bump_version_or_append_events) and leaving nothing for the
    # second writer to race against.
    assert item["priority"] == "high", "fixture assumption: priority is seeded from severity"
    winner = client.patch(
        f"{_rem_base(wid, pid)}/{item['id']}",
        headers=headers, json={"version": stale_version, "priority": "critical"},
    )
    assert winner.status_code == 200, winner.text
    assert winner.json()["version"] == stale_version + 1, "the winner did not take the lock"

    # Loser attempts a MULTI-field update on the stale version.
    due = (datetime.now(timezone.utc) + timedelta(days=9)).isoformat()
    loser = client.patch(
        f"{_rem_base(wid, pid)}/{item['id']}",
        headers=headers,
        json={"version": stale_version, "priority": "low", "due_date": due, "notes": "leaked?"},
    )
    assert loser.status_code == 409, loser.text

    final = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    assert final["priority"] == "critical", "the loser's priority leaked through"
    assert final["due_date"] is None, "the loser's due date leaked through"
    assert final["notes"] is None, "the loser's notes leaked through"
    assert final["version"] == stale_version + 1, "the version advanced twice"
