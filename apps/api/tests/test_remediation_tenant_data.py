"""Tenant export and deletion coverage for the remediation/assessment data (requirement 22).

Two guarantees, tested end to end:
  1. an export CONTAINS the new data (not merely an empty key of the right name);
  2. deleting a workspace leaves NO orphaned remediation/assessment rows.
"""
import base64
import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from apps.api.tests.test_remediation import (
    _auth,
    _make_item,
    _register,
    _rem_base,
    _seed_findings,
    _transition,
    _workspace_project,
)


def _populate(client: TestClient, headers: dict, wid: str, pid: str) -> dict:
    """Create one of everything the new subsystem can hold."""
    key = f"tenant{uuid.uuid4().hex[:6]}"
    vuln_ids = _seed_findings(wid, pid, [
        {"fingerprint": f"{key}|m|https://h/1", "title": "Tenant Issue", "severity": "high"},
    ])
    item = client.post(f"{_rem_base(wid, pid)}/sync", headers=headers).json()[0]

    # An event beyond `created`, plus evidence.
    item = _transition(client, headers, wid, pid, item, "accepted").json()
    client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/evidence",
        headers=headers,
        json={"filename": "p.txt", "content_base64": base64.b64encode(b"proof").decode()},
    )
    item = client.get(f"{_rem_base(wid, pid)}/{item['id']}", headers=headers).json()
    item = _transition(client, headers, wid, pid, item, "in_progress").json()
    client.post(
        f"{_rem_base(wid, pid)}/{item['id']}/verification",
        headers=headers, json={"version": item["version"]},
    )

    client.post(
        f"{_rem_base(wid, pid)}/risk-acceptances",
        headers=headers,
        json={
            "vulnerability_id": str(vuln_ids[0]),
            "justification": "accepted for this cycle",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        },
    )

    now = datetime.now(timezone.utc)
    ra_base = f"/api/v1/workspaces/{wid}/projects/{pid}/risk-assessments"
    draft = client.post(ra_base, headers=headers, json={
        "title": "Export Assessment",
        "period_start": (now - timedelta(days=7)).isoformat(),
        "period_end": now.isoformat(),
    }).json()
    client.post(f"{ra_base}/{draft['id']}/issue", headers=headers)
    return {"item_id": item["id"], "vuln_id": str(vuln_ids[0]), "assessment_id": draft["id"]}


def test_export_contains_populated_remediation_and_assessment_data(client: TestClient) -> None:
    """Present AND populated -- an empty key of the right name would pass a shape check while
    silently losing the tenant's data."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    _populate(client, headers, wid, pid)

    resp = client.get(f"/api/v1/workspaces/{wid}/export", headers=headers)
    assert resp.status_code == 200, resp.text
    export = resp.json()

    for key in (
        "remediation_items", "remediation_events", "remediation_evidence",
        "verification_requests", "risk_acceptances", "risk_assessments",
        "risk_assessment_findings",
    ):
        assert key in export, f"export is missing '{key}'"
        assert export[key], f"export['{key}'] is empty -- the tenant's data was not exported"

    summary = export["summary"]
    assert summary["remediation_item_count"] >= 1
    assert summary["remediation_event_count"] >= 1
    assert summary["remediation_evidence_count"] >= 1
    assert summary["verification_request_count"] >= 1
    assert summary["risk_acceptance_count"] >= 1
    assert summary["risk_assessment_count"] >= 1
    assert summary["risk_assessment_finding_count"] >= 1

    # The remediation PROOF artifact must be in the evidence export too -- its tool_run_id is
    # NULL, so a tool-run-only query would have silently dropped it.
    proofs = [e for e in export["evidence"] if e["evidence_type"] == "remediation_proof"]
    assert proofs, "human-uploaded remediation proof was omitted from the evidence export"
    assert proofs[0]["tool_run_id"] is None
    assert proofs[0]["uploaded_by"] is not None


def test_export_never_includes_another_workspaces_remediation_data(client: TestClient) -> None:
    owner_a = _register(client, "OwnerA")
    headers_a = _auth(owner_a)
    wid_a, pid_a = _workspace_project(client, headers_a)
    seeded_a = _populate(client, headers_a, wid_a, pid_a)

    owner_b = _register(client, "OwnerB")
    headers_b = _auth(owner_b)
    wid_b, pid_b = _workspace_project(client, headers_b)
    _populate(client, headers_b, wid_b, pid_b)

    export_b = client.get(f"/api/v1/workspaces/{wid_b}/export", headers=headers_b).json()
    assert seeded_a["item_id"] not in {i["id"] for i in export_b["remediation_items"]}
    assert seeded_a["assessment_id"] not in {a["id"] for a in export_b["risk_assessments"]}


def test_workspace_deletion_leaves_no_orphaned_remediation_or_assessment_rows(
    client: TestClient
) -> None:
    """Every new table hangs off `workspaces` with ON DELETE CASCADE, so the hard delete must
    clear the whole subtree. Asserted with a RAW count (admin_bypass) rather than through the
    API, because the API would return nothing either way once the workspace is gone -- which
    would pass whether or not the rows were actually removed."""
    import asyncio

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core import tenancy
    from apps.api.core.config import get_settings
    from apps.api.modules.workspaces.tenant_service import perform_workspace_deletion

    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    _populate(client, headers, wid, pid)
    owner_id = client.get("/api/v1/users/me", headers=headers).json()["id"]

    tables = [
        "remediation_items", "remediation_events", "remediation_evidence",
        "verification_requests", "risk_acceptances", "risk_assessments",
        "risk_assessment_findings",
    ]

    async def _counts(session) -> dict:
        out = {}
        for table in tables:
            # Raw SQL by design: it bypasses the ORM tenancy filter, so a row that SURVIVED
            # the delete is still visible here. Counting through the filter would report 0 for
            # a surviving orphan and make this test vacuous.
            out[table] = int(
                await session.scalar(
                    text(f"SELECT count(*) FROM {table} WHERE workspace_id = :wid"),
                    {"wid": wid},
                ) or 0
            )
        return out

    async def _run() -> tuple[dict, dict]:
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as session:
                before = await _counts(session)
            async with maker() as session:
                # admin_bypass, exactly as the production Celery task does (tenant_tasks._run):
                # deletion spans tenancy-EXEMPT tables too, and tenant_service carries its own
                # explicit workspace_id filters. Calling it unbound is not how it ever runs.
                with tenancy.admin_bypass():
                    await perform_workspace_deletion(session, uuid.UUID(wid), uuid.UUID(owner_id))
            async with maker() as session:
                after = await _counts(session)
            return before, after
        finally:
            await engine.dispose()

    before, after = asyncio.run(_run())

    # The fixture really did create rows in every table -- otherwise "0 after" proves nothing.
    for table in tables:
        assert before[table] > 0, f"{table} had no rows before deletion; the test proves nothing"
    for table in tables:
        assert after[table] == 0, f"{table} still holds {after[table]} orphaned row(s) after deletion"


def test_retention_covers_the_new_growth_tables() -> None:
    """requirement 21: the unbounded-growth table and the client deliverable both have a
    retention class, with the deliverable held longest."""
    from apps.api.retention.repo import RESOURCE_TABLE, _WORKSPACE_FILTER
    from apps.api.retention.service import PROCESSED, build_plan

    assert RESOURCE_TABLE["remediation_event"] == ("remediation_events", "created_at")
    assert RESOURCE_TABLE["risk_assessment"] == ("risk_assessments", "created_at")
    assert "remediation_event" in PROCESSED and "risk_assessment" in PROCESSED

    # Every new resource carries an EXPLICIT workspace filter in its raw SQL -- the ORM
    # auto-filter does not see raw text() queries.
    assert "workspace_id = :wid" in _WORKSPACE_FILTER["remediation_events"]
    assert "workspace_id = :wid" in _WORKSPACE_FILTER["risk_assessments"]
    # A DRAFT assessment is unfinished work someone is still editing -- never retention-swept.
    assert "status = 'issued'" in _WORKSPACE_FILTER["risk_assessments"]

    plan = {p.resource: p.retention_days for p in build_plan()}
    assert plan["risk_assessment"] > plan["report"], (
        "the client-facing assessment must outlive the rendered PDF"
    )


def test_audit_events_are_written_for_every_security_relevant_action(client: TestClient) -> None:
    """remediation_events COMPLEMENT the existing audit log -- they do not replace it. Both
    must be written."""
    owner = _register(client, "Owner")
    headers = _auth(owner)
    wid, pid = _workspace_project(client, headers)
    item = _make_item(client, headers, wid, pid, f"audit{uuid.uuid4().hex[:6]}")
    _transition(client, headers, wid, pid, item, "accepted")

    events = client.get(f"/api/v1/workspaces/{wid}/audit", headers=headers).json()
    actions = {e["action"] for e in events}
    assert "remediation.items_synced" in actions
    assert "remediation.transitioned" in actions
