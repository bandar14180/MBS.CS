"""P1 -- tenant/workspace deletion + export.

Deletion tests drive the service body (perform_workspace_deletion) directly against a seeded
test-DB workspace, with object cleanup stubbed so nothing touches real storage. Export/auth tests
go through the API. Everything runs on the test DB; no production workspace is touched.
"""
import asyncio
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings

_PW = "correct horse battery staple"


# --- helpers -------------------------------------------------------------------------------

def _register(client: TestClient, name="Tenant User") -> dict:
    email = f"{uuid.uuid4()}@example.com"
    r = client.post("/api/v1/auth/register", json={"email": email, "password": _PW, "full_name": name})
    assert r.status_code == 201, r.text
    tokens = r.json()
    me = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    return {"email": email, "id": me.json()["id"], **tokens}


def _auth(t: dict) -> dict:
    return {"Authorization": f"Bearer {t['access_token']}"}


def _workspace(client: TestClient, headers: dict, name="Acme") -> str:
    r = client.post("/api/v1/workspaces", headers=headers, json={"name": name})
    assert r.status_code == 201, r.text
    return r.json()["id"]


_EVIDENCE_URI = "s3://mbs-evidence/tool-runs/{tr}/raw-output.txt"
_REPORT_URI = "s3://mbs-reports/reports/{rid}.pdf"


async def _seed(workspace_id: str, user_id: str) -> dict:
    """project -> target -> scan -> tool_run -> evidence-link + report + vuln + audit, so
    deletion/export exercise the full subtree. Direct SQL under the workspace GUC."""
    eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    ids = {k: str(uuid.uuid4()) for k in (
        "project", "target", "scan", "tool_run", "report", "vuln", "audit",
        "authz_scope", "evidence", "role")}
    try:
        async with eng.begin() as c:
            tenancy.bind_workspace(workspace_id)
            await c.execute(text(
                "INSERT INTO projects (id, workspace_id, name, status, created_by, created_at) "
                "VALUES (:id,:w,'Proj','active',:u, now())"), {"id": ids["project"], "w": workspace_id, "u": user_id})
            await c.execute(text(
                "INSERT INTO targets (id, project_id, type, value, criticality, added_by, created_at) "
                "VALUES (:id,:p,'domain','example.com','medium',:u, now())"),
                {"id": ids["target"], "p": ids["project"], "u": user_id})
            await c.execute(text(
                "INSERT INTO scans (id, workspace_id, project_id, target_id, initiated_by, scan_type, "
                "status, config, created_at) VALUES (:id,:w,:p,:t,:u,'recon','completed','{}', now())"),
                {"id": ids["scan"], "w": workspace_id, "p": ids["project"], "t": ids["target"], "u": user_id})
            await c.execute(text(
                "INSERT INTO tool_runs (id, scan_id, tool_name, tool_version, command_hash, status, started_at) "
                "VALUES (:id,:s,'nuclei','3.0','abc','completed', now())"),
                {"id": ids["tool_run"], "s": ids["scan"]})
            await c.execute(text(
                "INSERT INTO reports (id, project_id, type, format, storage_uri, scan_ids, generated_by, generated_at) "
                "VALUES (:id,:p,'technical','pdf',:uri,'[]',:u, now())"),
                {"id": ids["report"], "p": ids["project"], "uri": _REPORT_URI.format(rid=ids["report"]), "u": user_id})
            await c.execute(text(
                "INSERT INTO vulnerabilities (id, project_id, first_detected_scan_id, fingerprint, title, "
                "severity, status, ai_validated, created_at, updated_at) "
                "VALUES (:id,:p,:s,'unix-ci|time|https://h/x','Unix CI','high','open', 0, now(), now())"),
                {"id": ids["vuln"], "p": ids["project"], "s": ids["scan"]})
            await c.execute(text(
                "INSERT INTO audit_events (id, workspace_id, actor_user_id, actor_email, action, resource_type, "
                "resource_id, created_at) VALUES (:id,:w,:u,'seed@x','scan.created','scan',:s, now())"),
                {"id": ids["audit"], "w": workspace_id, "u": user_id, "s": ids["scan"]})
            # --- newly exported workspace-owned entities ---------------------------------
            await c.execute(text(
                "INSERT INTO authorization_scopes (id, target_id, proof_type, proof_reference, "
                "verified, verified_by, active_testing_allowed, scope_notes, created_at) "
                "VALUES (:id,:t,'contract','CONTRACT-7788',1,:u,1,'seeded scope', now())"),
                {"id": ids["authz_scope"], "t": ids["target"], "u": user_id})
            await c.execute(text(
                "INSERT INTO evidence (id, tool_run_id, evidence_type, storage_uri, checksum, created_at) "
                "VALUES (:id,:tr,'raw_output',:uri,'deadbeef', now())"),
                {"id": ids["evidence"], "tr": ids["tool_run"],
                 "uri": _EVIDENCE_URI.format(tr=ids["tool_run"])})
            await c.execute(text(
                "INSERT INTO vulnerability_evidence (vulnerability_id, evidence_id, tool_run_id, created_at) "
                "VALUES (:v,:e,:tr, now())"),
                {"v": ids["vuln"], "e": ids["evidence"], "tr": ids["tool_run"]})
            # a WORKSPACE-SCOPED custom role + one permission grant (system roles have
            # workspace_id IS NULL and must never be exported as tenant data).
            await c.execute(text(
                "INSERT INTO roles (id, workspace_id, name, description) "
                "VALUES (:id,:w,'custom-auditor','seeded workspace role')"),
                {"id": ids["role"], "w": workspace_id})
            await c.execute(text(
                "INSERT INTO role_permissions (role_id, permission_id) "
                "SELECT :r, id FROM permissions ORDER BY `key` LIMIT 1"), {"r": ids["role"]})
    finally:
        await eng.dispose()
    return ids


async def _count(workspace_id: str) -> dict:
    eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    try:
        async with eng.connect() as c:
            tenancy.bind_workspace(workspace_id)
            out = {}
            out["workspace"] = (await c.execute(
                text("SELECT COUNT(*) FROM workspaces WHERE id=:w"), {"w": workspace_id})).scalar()
            out["projects"] = (await c.execute(
                text("SELECT COUNT(*) FROM projects WHERE workspace_id=:w"), {"w": workspace_id})).scalar()
            out["scans"] = (await c.execute(
                text("SELECT COUNT(*) FROM scans WHERE workspace_id=:w"), {"w": workspace_id})).scalar()
            out["vulns"] = (await c.execute(text(
                "SELECT COUNT(*) FROM vulnerabilities v JOIN projects p ON p.id=v.project_id WHERE p.workspace_id=:w"),
                {"w": workspace_id})).scalar()
            out["reports"] = (await c.execute(text(
                "SELECT COUNT(*) FROM reports r JOIN projects p ON p.id=r.project_id WHERE p.workspace_id=:w"),
                {"w": workspace_id})).scalar()
            out["members"] = (await c.execute(
                text("SELECT COUNT(*) FROM workspace_members WHERE workspace_id=:w"), {"w": workspace_id})).scalar()
            return out
    finally:
        await eng.dispose()


async def _delete(workspace_id: str, user_id: str, monkeypatch_cleanup=None) -> tuple[bool, list]:
    """Run the deletion body directly (no Celery), capturing what storage cleanup was asked to
    remove. Returns (deleted, captured_targets)."""
    from apps.api.modules.workspaces import tenant_service

    captured = []

    def _fake_cleanup(settings, targets):
        captured.append(targets)

    eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    from sqlalchemy.ext.asyncio import async_sessionmaker
    Session = async_sessionmaker(eng, expire_on_commit=False)
    try:
        with tenancy.admin_bypass():
            # patch the reused cleanup so no real storage call happens
            orig = tenant_service._cleanup_storage
            tenant_service._cleanup_storage = _fake_cleanup
            try:
                async with Session() as s:
                    deleted = await tenant_service.perform_workspace_deletion(
                        s, uuid.UUID(workspace_id), uuid.UUID(user_id))
            finally:
                tenant_service._cleanup_storage = orig
        return deleted, captured
    finally:
        await eng.dispose()


# --- export: authorization + isolation + secrets + completeness ----------------------------

def test_export_requires_permission(client: TestClient):
    """(8/authz) A member without workspace:export is 403; owner (who has it) is 200."""
    owner = _register(client)
    ws = _workspace(client, _auth(owner))
    # owner has workspace:export
    assert client.get(f"/api/v1/workspaces/{ws}/export", headers=_auth(owner)).status_code == 200
    # a non-member gets 403 (not even a member of this workspace)
    other = _register(client)
    assert client.get(f"/api/v1/workspaces/{ws}/export", headers=_auth(other)).status_code == 403


def test_export_is_workspace_isolated(client: TestClient):
    """(11) Exporting W1 never returns W2's data."""
    owner = _register(client)
    ws1 = _workspace(client, _auth(owner), "WS-One")
    ws2 = _workspace(client, _auth(owner), "WS-Two")
    asyncio.run(_seed(ws2, owner["id"]))
    exp1 = client.get(f"/api/v1/workspaces/{ws1}/export", headers=_auth(owner)).json()
    assert exp1["workspace_name"] == "WS-One"
    assert exp1["summary"]["project_count"] == 0            # ws1 has nothing
    assert all(p["id"] for p in exp1["projects"]) or exp1["projects"] == []


def test_export_completeness_and_counts(client: TestClient):
    """(12) Every seeded entity appears and the summary counts match."""
    owner = _register(client)
    ws = _workspace(client, _auth(owner))
    ids = asyncio.run(_seed(ws, owner["id"]))
    exp = client.get(f"/api/v1/workspaces/{ws}/export", headers=_auth(owner)).json()
    assert exp["summary"]["project_count"] == 1
    assert exp["summary"]["scan_count"] == 1
    assert exp["summary"]["vulnerability_count"] == 1
    assert exp["summary"]["report_count"] == 1
    assert exp["summary"]["member_count"] == 1
    assert {p["id"] for p in exp["projects"]} == {ids["project"]}
    assert {v["id"] for v in exp["vulnerabilities"]} == {ids["vuln"]}
    # extended coverage: the seed also inserts a target + tool_run.
    assert exp["summary"]["target_count"] == 1
    assert exp["summary"]["tool_run_count"] == 1
    assert {t["id"] for t in exp["targets"]} == {ids["target"]}
    assert {tr["id"] for tr in exp["tool_runs"]} == {ids["tool_run"]}


def test_export_covers_all_workspace_owned_entity_keys(client: TestClient):
    """(2-corrective) The export payload has a key for EVERY workspace-owned entity class, so no
    table is silently omitted (empty lists are fine; a missing key is not)."""
    owner = _register(client)
    ws = _workspace(client, _auth(owner))
    exp = client.get(f"/api/v1/workspaces/{ws}/export", headers=_auth(owner)).json()
    for key in ("members", "api_keys", "projects", "targets", "assets", "schedules", "scans",
                "tool_runs", "vulnerabilities", "risk_scores", "compliance_mappings",
                "attack_mappings", "remediations", "reports", "audit_events", "notifications",
                "ai_usage", "ai_plans", "agent_steps", "agent_decisions", "engagement_states",
                "attack_narratives"):
        assert key in exp, f"export missing workspace-owned entity: {key}"


# Maps each workspace-owned TABLE (derived below from the live FK graph) to the export payload
# key that must carry it. Deliberately kept as table->key so the assertion is driven by the
# DATABASE schema, not by the export implementation's own field list.
_TABLE_TO_EXPORT_KEY = {
    "workspace_members": "members",
    "api_keys": "api_keys",
    "projects": "projects",
    "targets": "targets",
    # MBS.SC. Both are workspace-owned and both are exported. private_sites carries the
    # customer's own network configuration (public key material only -- no private key
    # exists anywhere in the control plane to export). scanner_workers exports identity and
    # health for the workers bound to this workspace, minus the credential columns.
    "private_sites": "private_sites",
    "scanner_workers": "scanner_workers",
    "assets": "assets",
    "scan_schedules": "schedules",
    "scans": "scans",
    "tool_runs": "tool_runs",
    "vulnerabilities": "vulnerabilities",
    "risk_scores": "risk_scores",
    "compliance_mappings": "compliance_mappings",
    "attack_mappings": "attack_mappings",
    "remediations": "remediations",
    "reports": "reports",
    "audit_events": "audit_events",
    "notifications": "notifications",
    "ai_usage": "ai_usage",
    "ai_plans": "ai_plans",
    "agent_steps": "agent_steps",
    "agent_decisions": "agent_decisions",
    "engagement_state": "engagement_states",
    "attack_narratives": "attack_narratives",
    "authorization_scopes": "authorization_scopes",
    "evidence": "evidence",
    "vulnerability_evidence": "vulnerability_evidence",
    "vulnerability_lineage": "vulnerability_lineage",
    "vulnerability_history": "vulnerability_history",
    "remediation_items": "remediation_items",
    "remediation_events": "remediation_events",
    "remediation_evidence": "remediation_evidence",
    "verification_requests": "verification_requests",
    "risk_acceptances": "risk_acceptances",
    "risk_assessments": "risk_assessments",
    "risk_assessment_findings": "risk_assessment_findings",
    "roles": "roles",
    "role_permissions": "role_permissions",
}

# Platform-level tables: real rows, but NOT tenant-owned data. Excluded from the export by design.
_NON_TENANT_TABLES = {
    "workspaces",             # the workspace itself -> exported as scalar header fields
    "users",                  # global identities (shared across workspaces)
    "permissions",            # global permission catalogue
    "alembic_version",
    "platform_audit_events",  # platform audit; deliberately NOT tenant-owned
    "refresh_tokens",         # user-owned auth material, never exported
    "mfa_recovery_codes",     # user-owned secret material, never exported
}


async def _workspace_owned_tables() -> set[str]:
    """Derive the authoritative set of workspace-owned tables from the LIVE FK graph: start at
    `workspaces` and take the transitive closure of every child table. This is what makes the
    completeness assertion independent of the export's own hand-written entity list -- a new
    workspace-owned table appears here automatically and fails the test until it is exported."""
    eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    try:
        async with eng.connect() as c:
            db_name = (await c.execute(text("SELECT DATABASE()"))).scalar()
            rows = (await c.execute(text(
                "SELECT TABLE_NAME, REFERENCED_TABLE_NAME FROM information_schema.KEY_COLUMN_USAGE "
                "WHERE TABLE_SCHEMA = :db AND REFERENCED_TABLE_NAME IS NOT NULL"),
                {"db": db_name})).fetchall()
    finally:
        await eng.dispose()

    parents: dict[str, set[str]] = {}
    for child, parent in rows:
        parents.setdefault(child, set()).add(parent)

    owned = {"workspaces"}
    changed = True
    while changed:                      # transitive closure
        changed = False
        for child, ps in parents.items():
            if child not in owned and (ps & owned):
                owned.add(child)
                changed = True
    return {t for t in owned if t not in _NON_TENANT_TABLES}


def test_export_covers_every_workspace_owned_table_from_the_fk_graph(client: TestClient):
    """(2-corrective, hardened) The export must have a key for EVERY workspace-owned table as
    derived from the LIVE DATABASE FK graph -- not from a list copied out of the implementation.

    The previous version of this test enumerated the same 22 entity keys the export itself
    declared, so five genuinely-missing tables (authorization_scopes, evidence,
    vulnerability_evidence, roles, role_permissions) passed it. Deriving the expected set from
    information_schema makes that class of omission impossible to miss."""
    owner = _register(client)
    ws = _workspace(client, _auth(owner), "FkGraph")
    exp = client.get(f"/api/v1/workspaces/{ws}/export", headers=_auth(owner)).json()

    owned = asyncio.run(_workspace_owned_tables())
    assert owned, "FK-graph derivation returned nothing -- the check would be vacuous"

    unmapped = sorted(t for t in owned if t not in _TABLE_TO_EXPORT_KEY)
    assert not unmapped, (
        f"workspace-owned table(s) with no export mapping: {unmapped}. "
        "Add them to the export (and to _TABLE_TO_EXPORT_KEY), or to _NON_TENANT_TABLES if they "
        "are genuinely platform-level."
    )
    missing = sorted(_TABLE_TO_EXPORT_KEY[t] for t in owned if _TABLE_TO_EXPORT_KEY[t] not in exp)
    assert not missing, f"export payload is missing key(s) for workspace-owned data: {missing}"


def test_export_includes_the_five_previously_missing_entities(client: TestClient):
    """Explicit regression guard: the five entities the earlier export silently omitted are
    present AND populated (not merely present-but-empty keys)."""
    owner = _register(client)
    ws = _workspace(client, _auth(owner), "FiveNew")
    ids = asyncio.run(_seed(ws, owner["id"]))
    exp = client.get(f"/api/v1/workspaces/{ws}/export", headers=_auth(owner)).json()

    assert {a["id"] for a in exp["authorization_scopes"]} == {ids["authz_scope"]}
    assert {e["id"] for e in exp["evidence"]} == {ids["evidence"]}
    assert {r["id"] for r in exp["roles"]} == {ids["role"]}
    assert len(exp["vulnerability_evidence"]) == 1
    assert len(exp["role_permissions"]) == 1

    summary = exp["summary"]
    assert summary["authorization_scope_count"] == 1
    assert summary["evidence_count"] == 1
    assert summary["vulnerability_evidence_count"] == 1
    assert summary["role_count"] == 1
    assert summary["role_permission_count"] == 1


def test_export_preserves_vulnerability_evidence_relationships(client: TestClient):
    """The vulnerability <-> evidence <-> tool_run chain must stay reconstructable from the
    export alone: every join row must point at an exported vulnerability, evidence and tool_run."""
    owner = _register(client)
    ws = _workspace(client, _auth(owner), "EvidenceChain")
    ids = asyncio.run(_seed(ws, owner["id"]))
    exp = client.get(f"/api/v1/workspaces/{ws}/export", headers=_auth(owner)).json()

    vuln_ids = {v["id"] for v in exp["vulnerabilities"]}
    evidence_ids = {e["id"] for e in exp["evidence"]}
    tool_run_ids = {t["id"] for t in exp["tool_runs"]}

    assert exp["vulnerability_evidence"], "seeded join row missing from the export"
    for link in exp["vulnerability_evidence"]:
        assert link["vulnerability_id"] in vuln_ids
        assert link["evidence_id"] in evidence_ids
        assert link["tool_run_id"] in tool_run_ids

    # the specific seeded association survived intact
    assert {(x["vulnerability_id"], x["evidence_id"]) for x in exp["vulnerability_evidence"]} == {
        (ids["vuln"], ids["evidence"])
    }
    # evidence links back to the exported tool_run
    assert {e["tool_run_id"] for e in exp["evidence"]} == {ids["tool_run"]}


def test_export_new_entities_are_workspace_isolated(client: TestClient):
    """W1's export must contain none of W2's authorization scopes / evidence / join rows /
    custom roles -- these reach the workspace only through FK chains, so a missing anchor would
    leak the whole table."""
    owner = _register(client)
    ws1 = _workspace(client, _auth(owner), "IsoOne")
    ws2 = _workspace(client, _auth(owner), "IsoTwo")
    ids1 = asyncio.run(_seed(ws1, owner["id"]))
    ids2 = asyncio.run(_seed(ws2, owner["id"]))

    exp1 = client.get(f"/api/v1/workspaces/{ws1}/export", headers=_auth(owner)).json()

    assert {a["id"] for a in exp1["authorization_scopes"]} == {ids1["authz_scope"]}
    assert ids2["authz_scope"] not in {a["id"] for a in exp1["authorization_scopes"]}
    assert {e["id"] for e in exp1["evidence"]} == {ids1["evidence"]}
    assert ids2["evidence"] not in {e["id"] for e in exp1["evidence"]}
    assert {r["id"] for r in exp1["roles"]} == {ids1["role"]}
    assert ids2["role"] not in {r["id"] for r in exp1["roles"]}
    assert {x["vulnerability_id"] for x in exp1["vulnerability_evidence"]} == {ids1["vuln"]}
    assert {rp["role_id"] for rp in exp1["role_permissions"]} == {ids1["role"]}


def test_export_roles_excludes_global_system_roles(client: TestClient):
    """roles.workspace_id is NULLABLE and NULL means a GLOBAL/system role (owner/admin/member)
    shared across all tenants. Those are platform data and must never appear in a tenant export,
    even though the member list still names the role a member holds."""
    owner = _register(client)
    ws = _workspace(client, _auth(owner), "NoSystemRoles")
    ids = asyncio.run(_seed(ws, owner["id"]))

    async def _system_role_names() -> set[str]:
        eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        try:
            async with eng.connect() as c:
                rows = (await c.execute(
                    text("SELECT name FROM roles WHERE workspace_id IS NULL"))).fetchall()
                return {r[0] for r in rows}
        finally:
            await eng.dispose()

    system_names = asyncio.run(_system_role_names())
    assert system_names, "expected seeded global system roles to exist"

    exp = client.get(f"/api/v1/workspaces/{ws}/export", headers=_auth(owner)).json()
    exported_role_names = {r["name"] for r in exp["roles"]}

    assert exported_role_names == {"custom-auditor"}
    assert not (exported_role_names & system_names), (
        f"global system role(s) leaked into the tenant export: {exported_role_names & system_names}"
    )
    # the owner's system role is still recorded on the member record (by name), which is fine.
    assert exp["members"][0]["role_name"] in system_names
    assert ids["role"] in {r["id"] for r in exp["roles"]}


def test_export_excludes_secrets(client: TestClient):
    """(13) No password hash / mfa secret / api-key hash / token appears anywhere in the export."""
    owner = _register(client)
    ws = _workspace(client, _auth(owner))
    client.post(f"/api/v1/workspaces/{ws}/api-keys", headers=_auth(owner), json={"name": "k"})
    body = client.get(f"/api/v1/workspaces/{ws}/export", headers=_auth(owner)).text.lower()
    for forbidden in ("password_hash", "key_hash", "mfa_secret", "token_hash", "execution_token",
                      "hashed_password", "jwt_secret"):
        assert forbidden not in body
    # api-key metadata present but never the secret hash
    exp = client.get(f"/api/v1/workspaces/{ws}/export", headers=_auth(owner)).json()
    assert exp["api_keys"][0]["name"] == "k"
    assert "key_hash" not in exp["api_keys"][0]


def test_export_new_entities_carry_no_secret_material(client: TestClient):
    """The five newly exported entities must not introduce secret material. Checks both the
    field names AND the actual stored secret VALUES (password hash, MFA secret, api-key hash),
    so a renamed column cannot smuggle a secret past a name-only assertion."""
    owner = _register(client)
    ws = _workspace(client, _auth(owner), "NewSecrets")
    asyncio.run(_seed(ws, owner["id"]))
    client.post(f"/api/v1/workspaces/{ws}/api-keys", headers=_auth(owner), json={"name": "sk"})

    async def _real_secret_values() -> list[str]:
        eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        try:
            async with eng.connect() as c:
                rows = (await c.execute(
                    text("SELECT password_hash, mfa_secret_encrypted FROM users WHERE id=:u"),
                    {"u": owner["id"]})).fetchone()
                keys = (await c.execute(
                    text("SELECT key_hash FROM api_keys WHERE workspace_id=:w"), {"w": ws})).fetchall()
            return [v for v in [*(rows or []), *(k[0] for k in keys)] if v]
        finally:
            await eng.dispose()

    exp = client.get(f"/api/v1/workspaces/{ws}/export", headers=_auth(owner)).json()
    body = client.get(f"/api/v1/workspaces/{ws}/export", headers=_auth(owner)).text

    # no real secret VALUE is anywhere in the payload
    for secret in asyncio.run(_real_secret_values()):
        assert secret not in body, "a real stored secret value leaked into the export"

    # and no secret-ish field name on the new entities
    forbidden = ("password", "secret", "hash", "token", "credential", "key_hash")
    for key in ("authorization_scopes", "evidence", "vulnerability_evidence", "roles",
                "role_permissions"):
        for row in exp[key]:
            for field in row:
                # `checksum` is an artifact integrity digest, not a credential; `*_id` are keys.
                if field in ("checksum",) or field.endswith("_id"):
                    continue
                assert not any(f in field.lower() for f in forbidden), (
                    f"suspicious field {key}.{field} in export"
                )

    # evidence exports a REFERENCE, never bytes
    for ev in exp["evidence"]:
        assert ev["storage_uri"].startswith("s3://")
        assert "content" not in ev and "bytes" not in ev and "raw" not in ev


def test_export_rls_exempt_tables_are_workspace_filtered(client: TestClient):
    """(14) scans + api_keys are RLS-EXEMPT; export must still return ONLY this workspace's rows."""
    owner = _register(client)
    ws1 = _workspace(client, _auth(owner), "A")
    ws2 = _workspace(client, _auth(owner), "B")
    asyncio.run(_seed(ws1, owner["id"]))
    asyncio.run(_seed(ws2, owner["id"]))
    client.post(f"/api/v1/workspaces/{ws1}/api-keys", headers=_auth(owner), json={"name": "a-key"})
    exp2 = client.get(f"/api/v1/workspaces/{ws2}/export", headers=_auth(owner)).json()
    assert exp2["summary"]["scan_count"] == 1                       # only ws2's scan
    assert all(s["project_id"] for s in exp2["scans"])
    assert exp2["summary"]["api_key_count"] == 0                    # a-key belongs to ws1, not ws2


# --- deletion: completeness / isolation / object cleanup / idempotency / audit -------------

def test_deletion_completeness_and_other_workspace_untouched(client: TestClient):
    """(1) all rows for the workspace are gone; (2) a sibling workspace is untouched."""
    owner = _register(client)
    ws_del = _workspace(client, _auth(owner), "Doomed")
    ws_keep = _workspace(client, _auth(owner), "Kept")
    asyncio.run(_seed(ws_del, owner["id"]))
    keep_ids = asyncio.run(_seed(ws_keep, owner["id"]))

    deleted, _ = asyncio.run(_delete(ws_del, owner["id"]))
    assert deleted is True

    gone = asyncio.run(_count(ws_del))
    assert gone == {"workspace": 0, "projects": 0, "scans": 0, "vulns": 0, "reports": 0, "members": 0}

    kept = asyncio.run(_count(ws_keep))
    assert kept["workspace"] == 1 and kept["projects"] == 1 and kept["scans"] == 1
    assert kept["vulns"] == 1 and kept["reports"] == 1 and keep_ids["project"]


def test_deletion_captures_object_targets_for_cleanup(client: TestClient):
    """(3) tool-run ids + report uris are captured for cleanup; (4) they belong ONLY to the
    deleted workspace."""
    owner = _register(client)
    ws_del = _workspace(client, _auth(owner), "Doomed2")
    ws_keep = _workspace(client, _auth(owner), "Kept2")
    del_ids = asyncio.run(_seed(ws_del, owner["id"]))
    keep_ids = asyncio.run(_seed(ws_keep, owner["id"]))

    _, captured = asyncio.run(_delete(ws_del, owner["id"]))
    assert len(captured) == 1
    targets = captured[0]
    tool_run_ids = {str(t) for t in targets.tool_run_ids}
    assert del_ids["tool_run"] in tool_run_ids
    assert keep_ids["tool_run"] not in tool_run_ids          # never the sibling's objects
    assert any(del_ids["report"] in uri for uri in targets.report_uris)
    assert not any(keep_ids["report"] in uri for uri in targets.report_uris)


def test_deletion_is_idempotent_on_retry(client: TestClient):
    """(5) A second run after the workspace is already gone converges (returns False, no error)."""
    owner = _register(client)
    ws = _workspace(client, _auth(owner), "Retry")
    asyncio.run(_seed(ws, owner["id"]))
    first, _ = asyncio.run(_delete(ws, owner["id"]))
    second, _ = asyncio.run(_delete(ws, owner["id"]))
    assert first is True
    assert second is False
    assert asyncio.run(_count(ws))["workspace"] == 0


def test_deletion_audit_survives_workspace_deletion(client: TestClient, caplog):
    """(10) The tenant.delete.completed record is emitted on the NON-cascading security logger,
    so it exists after the workspace (and its audit_events) are gone."""
    import logging

    owner = _register(client)
    ws = _workspace(client, _auth(owner), "Audited")
    asyncio.run(_seed(ws, owner["id"]))
    with caplog.at_level(logging.INFO, logger="mbs.security"):
        asyncio.run(_delete(ws, owner["id"]))
    assert any(r.message == "tenant.delete.completed" and getattr(r, "workspace_id", None) == ws
               for r in caplog.records)


async def _platform_audit_events(workspace_id: str) -> list[str]:
    eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    try:
        async with eng.connect() as c:
            rows = await c.execute(
                text("SELECT event FROM platform_audit_events WHERE workspace_id=:w ORDER BY created_at"),
                {"w": workspace_id})
            return [r[0] for r in rows.fetchall()]
    finally:
        await eng.dispose()


def test_durable_audit_record_survives_hard_deletion(client: TestClient):
    """(1-corrective) A DURABLE, queryable platform_audit_events row for tenant.delete.completed
    exists AFTER the workspace is hard-deleted -- proving the audit is not merely a log line and
    is not cascaded away with the workspace."""
    owner = _register(client)
    ws = _workspace(client, _auth(owner), "Durable")
    asyncio.run(_seed(ws, owner["id"]))
    deleted, _ = asyncio.run(_delete(ws, owner["id"]))
    assert deleted is True
    # workspace row is gone...
    assert asyncio.run(_count(ws))["workspace"] == 0
    # ...but the durable audit record persists and is queryable.
    events = asyncio.run(_platform_audit_events(ws))
    assert "tenant.delete.completed" in events


def test_durable_audit_requested_written_on_request(client: TestClient):
    """The request path writes a durable tenant.delete.requested row (committed with the status
    flip). We flip via the service request path, mocking the Celery dispatch."""
    from apps.api.modules.workspaces import tenant_service

    owner = _register(client)
    ws = _workspace(client, _auth(owner), "ReqAudit")

    async def _request():
        from sqlalchemy.ext.asyncio import async_sessionmaker
        eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        Session = async_sessionmaker(eng, expire_on_commit=False)
        try:
            with tenancy.admin_bypass():
                # stub the celery dispatch so nothing runs
                orig = tenant_service.__dict__.get("delete_workspace_task", None)
                import apps.api.celery_app.tasks.tenant_tasks as tt

                class _Stub:
                    def delay(self, *a, **k):
                        return None
                tt.delete_workspace_task = _Stub()
                try:
                    async with Session() as s:
                        from apps.api.modules.users.models import User
                        actor = await s.get(User, uuid.UUID(owner["id"]))
                        await tenant_service.request_workspace_deletion(s, uuid.UUID(ws), actor, "ReqAudit")
                finally:
                    if orig is not None:
                        tt.delete_workspace_task = orig
        finally:
            await eng.dispose()
    asyncio.run(_request())
    events = asyncio.run(_platform_audit_events(ws))
    assert "tenant.delete.requested" in events


# --- queued-relay + schedule deleting-workspace race ---------------------------------------

def test_queued_relay_skips_deleting_workspace(client: TestClient):
    """(3-corrective) A queued scan whose workspace is `deleting` is NOT selected by the relay
    query -- the explicit workspace-status guard, not just the FK cascade, protects it."""
    from apps.api.modules.scans.service import Scan  # noqa: F401  (ensure model import)

    owner = _register(client)
    ws = _workspace(client, _auth(owner), "RelayGate")
    ids = asyncio.run(_seed(ws, owner["id"]))

    async def _setup_and_query() -> list[str]:
        from datetime import datetime, timedelta, timezone
        eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        try:
            async with eng.begin() as c:
                # a relay-eligible scan: queued, no celery_task_id, old enough
                old = datetime.now(timezone.utc) - timedelta(hours=1)
                await c.execute(text(
                    "UPDATE scans SET status='queued', celery_task_id=NULL, queued_at=:o, created_at=:o "
                    "WHERE id=:s"), {"o": old, "s": ids["scan"]})
                await c.execute(text("UPDATE workspaces SET status='deleting' WHERE id=:w"), {"w": ws})
            # run the exact relay SELECT (guarded)
            async with eng.connect() as c:
                cutoff = datetime.now(timezone.utc) - timedelta(seconds=1)
                rows = await c.execute(text(
                    "SELECT s.id FROM scans s JOIN workspaces w ON w.id = s.workspace_id "
                    "WHERE s.status='queued' AND s.celery_task_id IS NULL AND w.status <> 'deleting' "
                    "AND coalesce(s.queued_at, s.created_at) < :cutoff"), {"cutoff": cutoff})
                return [str(r[0]) for r in rows.fetchall()]
        finally:
            await eng.dispose()
    eligible = asyncio.run(_setup_and_query())
    assert ids["scan"] not in eligible          # guarded out because workspace is deleting

    # sanity: with the workspace active, the same scan IS eligible (guard is the only difference)
    async def _flip_active_and_query() -> list[str]:
        from datetime import datetime, timedelta, timezone
        eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        try:
            async with eng.begin() as c:
                await c.execute(text("UPDATE workspaces SET status='active' WHERE id=:w"), {"w": ws})
            async with eng.connect() as c:
                cutoff = datetime.now(timezone.utc) - timedelta(seconds=1)
                rows = await c.execute(text(
                    "SELECT s.id FROM scans s JOIN workspaces w ON w.id = s.workspace_id "
                    "WHERE s.status='queued' AND s.celery_task_id IS NULL AND w.status <> 'deleting' "
                    "AND coalesce(s.queued_at, s.created_at) < :cutoff"), {"cutoff": cutoff})
                return [str(r[0]) for r in rows.fetchall()]
        finally:
            await eng.dispose()
    assert ids["scan"] in asyncio.run(_flip_active_and_query())


def test_schedule_dispatch_skips_deleting_workspace(client: TestClient):
    """(3-corrective) run_due_schedules must not pick up a schedule whose workspace is deleting."""
    from apps.api.modules.schedules.service import run_due_schedules

    owner = _register(client)
    ws = _workspace(client, _auth(owner), "SchedGate")
    ids = asyncio.run(_seed(ws, owner["id"]))

    async def _make_due_schedule_and_run() -> int:
        from datetime import datetime, timedelta, timezone
        from sqlalchemy.ext.asyncio import async_sessionmaker
        eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        Session = async_sessionmaker(eng, expire_on_commit=False)
        sid = str(uuid.uuid4())
        try:
            async with eng.begin() as c:
                tenancy.bind_workspace(ws)
                due = datetime.now(timezone.utc) - timedelta(minutes=1)
                await c.execute(text(
                    "INSERT INTO scan_schedules (id, workspace_id, project_id, target_id, created_by, "
                    "scan_type, requested_modules, use_ai_planner, interval_minutes, enabled, next_run_at, created_at) "
                    "VALUES (:id,:w,:p,:t,:u,'recon','[]',0,60,1,:due, now())"),
                    {"id": sid, "w": ws, "p": ids["project"], "t": ids["target"], "u": owner["id"], "due": due})
                await c.execute(text("UPDATE workspaces SET status='deleting' WHERE id=:w"), {"w": ws})
            with tenancy.admin_bypass():
                async with Session() as s:
                    return await run_due_schedules(s)
        finally:
            await eng.dispose()
    launched = asyncio.run(_make_due_schedule_and_run())
    assert launched == 0            # the deleting workspace's due schedule was skipped


# --- deletion: authorization + confirmation + IDOR -----------------------------------------

def test_delete_requires_owner_and_matching_name(client: TestClient):
    """(8/9) Non-owner is 403; wrong confirm-name is 400; only the true owner with the exact
    name can flip the workspace to deleting."""
    owner = _register(client)
    ws = _workspace(client, _auth(owner), "Secure")

    # wrong confirmation name -> 400 (owner, but name mismatch)
    bad = client.request("DELETE", f"/api/v1/workspaces/{ws}", headers=_auth(owner),
                         json={"confirm_name": "not-the-name"})
    assert bad.status_code == 400, bad.text

    # a different user who is not even a member -> 403
    other = _register(client)
    forbidden = client.request("DELETE", f"/api/v1/workspaces/{ws}", headers=_auth(other),
                               json={"confirm_name": "Secure"})
    assert forbidden.status_code == 403, forbidden.text


def test_delete_gate_blocks_new_mutations_while_deleting(client: TestClient, monkeypatch):
    """(7) Once a workspace is `deleting`, new mutating operations are rejected (409). We flip the
    status directly (the async task would do this) and prove a create is blocked while a read
    still works."""
    owner = _register(client)
    ws = _workspace(client, _auth(owner), "Gated")

    async def _set_deleting():
        eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        try:
            async with eng.begin() as c:
                await c.execute(text("UPDATE workspaces SET status='deleting' WHERE id=:w"), {"w": ws})
        finally:
            await eng.dispose()
    asyncio.run(_set_deleting())

    # a mutating op (create project) is blocked with 409
    blocked = client.post(f"/api/v1/workspaces/{ws}/projects", headers=_auth(owner),
                          json={"name": "nope"})
    assert blocked.status_code == 409, blocked.text
    # a read still works
    assert client.get(f"/api/v1/workspaces/{ws}/members", headers=_auth(owner)).status_code == 200
