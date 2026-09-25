"""The ISOLATED SCANNER PATH must actually persist what it scans.

WHY THIS FILE EXISTS

`/v1/tool-results` authorized the worker, logged a line, committed an EMPTY transaction and
returned `{"ok": true}`. It wrote nothing. The isolated worker holds no database credential
by design, so the manager is the only component that CAN write -- and with it a no-op, every
remote scan lost its entire tool history, its evidence rows and every vulnerability it found.
Measured on the live database: `tool_runs`, `evidence` and `vulnerabilities` all stopped
gaining rows on the same afternoon, while scans kept completing and reporting success.

The whole suite stayed green through all of it. `test_scanner_manager_http.py` had 22 tests
covering this boundary and every one asserted a REFUSAL -- 403 for another tenant, 400 for a
bad digest. Not one asserted that an AUTHORIZED submission stored anything, so a handler that
persisted nothing satisfied all of them. A rejection test proves an endpoint says no; only a
persistence test proves it ever says yes.

So these are functional-first: each one submits as a legitimate worker would and then reads
the database back. The security cases are here too, but they are the second half.
"""
import asyncio
import base64
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.core.db import get_db
from apps.api.modules.assets.models import Asset
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scanner_workers import service as workers_service
from apps.api.modules.scanner_workers.models import ScannerWorker
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.vulnerabilities.models import Vulnerability
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.models import Evidence, ToolRun
from apps.api.scanner_manager.app import app as manager_app

# The 12 the failing scan requested, so the counts here mean what they meant in production.
REQUESTED_MODULES = [
    "subfinder", "amass", "dnsx", "httpx", "whatweb", "naabu",
    "nmap", "katana", "ffuf", "arjun", "nuclei", "nuclei-dast",
]

# One real nuclei JSONL line. Parsed by the REGISTRY's own parser server-side, which is the
# point: the worker sends bytes, never conclusions.
NUCLEI_LINE = (
    '{"template-id":"exposed-git-config","info":{"name":"Exposed .git/config",'
    '"severity":"high","tags":["exposure"],"description":"git config is readable"},'
    '"matched-at":"https://t.example.com/.git/config","type":"http"}'
)


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _seed(session, label, *, public=True):
    """One tenant with a scan that is RUNNING and holds a live execution token.

    `public=True` (no site) keeps the common case simple; the isolation test seeds a second
    tenant so cross-tenant writes have somewhere to be refused from.
    """
    user = User(email=f"{label}-{uuid.uuid4()}@t.local", password_hash="x", full_name=label)
    session.add(user)
    await session.flush()
    ws = Workspace(name=f"{label}-{uuid.uuid4().hex[:8]}", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    project = Project(id=uuid.uuid4(), workspace_id=ws.id, name=f"{label}-p", created_by=user.id)
    session.add(project)
    await session.flush()
    target = Target(id=uuid.uuid4(), project_id=project.id, type="domain",
                    value="t.example.com", added_by=user.id, criticality="high")
    session.add(target)
    await session.flush()
    token = uuid.uuid4()
    scan = Scan(
        id=uuid.uuid4(), workspace_id=ws.id, project_id=project.id, target_id=target.id,
        initiated_by=user.id, scan_type="web", status="running",
        config={"requested_modules": list(REQUESTED_MODULES)},
        execution_token=token,
    )
    session.add(scan)
    worker_token = workers_service.generate_worker_token()
    worker = ScannerWorker(
        id=uuid.uuid4(), worker_id=f"wk-{label}-{uuid.uuid4().hex[:6]}",
        pool_id=f"pool-{label}", site_id=None, workspace_id=ws.id, status="active",
        token_hash=workers_service.hash_worker_token(worker_token),
    )
    session.add(worker)
    await session.flush()
    return {
        "ws": ws.id, "project_id": project.id, "target_id": target.id,
        "scan_id": scan.id, "execution_token": token,
        "worker_id": worker.worker_id, "token": worker_token,
    }


@pytest.fixture
def env():
    """Manager TestClient + two tenants. Engine-per-loop for the same reason
    test_scanner_manager_http.py does it: TestClient runs the app on its own event loop and
    an AsyncEngine's pooled connections belong to the loop that made them."""
    state = {}

    async def seed():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    state["a"] = await _seed(s, "alpha")
                    state["b"] = await _seed(s, "bravo")
                    await s.commit()
        finally:
            await engine.dispose()

    asyncio.run(seed())

    async def _override_db():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    yield s
        finally:
            await engine.dispose()

    manager_app.dependency_overrides[get_db] = _override_db
    client = TestClient(manager_app)
    try:
        yield client, state
    finally:
        manager_app.dependency_overrides.clear()


def _auth(entry):
    return {"X-Worker-Id": entry["worker_id"], "Authorization": f"Bearer {entry['token']}"}


def _result_payload(entry, *, tool_name="httpx", tool_run_id=None, status="completed",
                    findings=None, token=None):
    return {
        "scan_id": str(entry["scan_id"]),
        "tool_run_id": str(tool_run_id or uuid.uuid4()),
        "tool_name": tool_name,
        "execution_token": str(token or entry["execution_token"]),
        "status": status,
        "findings": findings or [],
    }


def _evidence_payload(entry, *, tool_run_id, content: bytes, tool_name=None, token=None):
    return {
        "scan_id": str(entry["scan_id"]),
        "tool_run_id": str(tool_run_id),
        "content_type": "text/plain",
        "content_b64": base64.b64encode(content).decode(),
        "execution_token": str(token or entry["execution_token"]),
        "tool_name": tool_name,
    }


def _query(coro_factory):
    """Read the database back on a fresh engine/loop, outside the request."""
    async def run():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    return await coro_factory(s)
        finally:
            await engine.dispose()
    return asyncio.run(run())


# ---------------------------------------------------------------------------------------
# 1-3. PERSISTENCE -- the half that was missing entirely
# ---------------------------------------------------------------------------------------

def test_a_submitted_tool_result_is_actually_stored(env):
    """THE regression test. This exact call used to return 200 and write nothing."""
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    r = client.post("/v1/tool-results", headers=_auth(a),
                    json=_result_payload(a, tool_name="nuclei", tool_run_id=run_id))
    assert r.status_code == 200, r.text

    row = _query(lambda s: s.get(ToolRun, run_id))
    assert row is not None, "the endpoint returned 200 but stored no ToolRun"
    assert str(row.scan_id) == str(a["scan_id"])
    assert row.tool_name == "nuclei"
    assert row.status == "completed"
    assert row.completed_at is not None


def test_tool_version_comes_from_the_registry_not_the_worker(env):
    """The version describes the image the CONTROL PLANE published. A worker must not be
    able to attribute its output to a version it did not run."""
    from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY

    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    payload = _result_payload(a, tool_name="nuclei", tool_run_id=run_id)
    payload["tool_version"] = "99.9-forged"      # ignored: not part of the schema
    assert client.post("/v1/tool-results", headers=_auth(a), json=payload).status_code == 200

    row = _query(lambda s: s.get(ToolRun, run_id))
    assert row.tool_version == (getattr(TOOL_REGISTRY["nuclei"], "version", "") or "")
    assert "forged" not in (row.tool_version or "")


def test_twelve_executed_tools_produce_twelve_tool_runs(env):
    """The scan that exposed this ran 12 tools and the UI showed 12 rows of 'queued',
    because `tool_runs` held none of them."""
    client, state = env
    a = state["a"]
    for tool in REQUESTED_MODULES:
        r = client.post("/v1/tool-results", headers=_auth(a),
                        json=_result_payload(a, tool_name=tool))
        assert r.status_code == 200, f"{tool}: {r.text}"

    rows = _query(lambda s: s.execute(
        select(ToolRun).where(ToolRun.scan_id == a["scan_id"])
    ))
    names = sorted(r[0].tool_name for r in rows.all())
    assert names == sorted(REQUESTED_MODULES), f"expected 12 tool runs, got {len(names)}"


def test_inventory_findings_become_assets(env):
    """`findings` on a tool result are inventory (discovered assets) and go through the same
    upsert the in-process path uses."""
    client, state = env
    a = state["a"]
    findings = [
        {"asset_type": "subdomain", "value": "api.t.example.com", "metadata": {"src": "test"}},
        {"asset_type": "subdomain", "value": "www.t.example.com", "metadata": {}},
    ]
    r = client.post("/v1/tool-results", headers=_auth(a),
                    json=_result_payload(a, tool_name="subfinder", findings=findings))
    assert r.status_code == 200, r.text
    assert r.json()["assets"] == 2

    rows = _query(lambda s: s.execute(
        select(Asset).where(Asset.target_id == a["target_id"],
                            Asset.asset_type == "subdomain")
    ))
    values = {row[0].value for row in rows.all()}
    assert {"api.t.example.com", "www.t.example.com"} <= values


# ---------------------------------------------------------------------------------------
# 4. EVIDENCE -- the DB row AND the object
# ---------------------------------------------------------------------------------------

def test_evidence_creates_both_a_database_row_and_a_stored_object(env):
    """The bytes were reaching object storage all along; what vanished was the ROW that
    points at them, so nothing in the database could cite any of it."""
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    client.post("/v1/tool-results", headers=_auth(a),
                json=_result_payload(a, tool_name="httpx", tool_run_id=run_id))

    r = client.post("/v1/evidence", headers=_auth(a),
                    json=_evidence_payload(a, tool_run_id=run_id, content=b"https://t.example.com"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sha256"] and body["uri"], "no object was stored"

    rows = _query(lambda s: s.execute(
        select(Evidence).where(Evidence.tool_run_id == run_id)
    ))
    evidence = [row[0] for row in rows.all()]
    assert len(evidence) == 1, "evidence row missing (or duplicated)"
    assert evidence[0].checksum == body["sha256"], "row and object disagree on the digest"
    assert evidence[0].storage_uri == body["uri"]

    run = _query(lambda s: s.get(ToolRun, run_id))
    assert run.raw_output_ref == body["uri"], "the tool run does not point at its raw output"


# ---------------------------------------------------------------------------------------
# 5. IDEMPOTENCY -- acks_late, lease redelivery and plain HTTP retries
# ---------------------------------------------------------------------------------------

def test_resubmitting_the_same_tool_run_does_not_duplicate_it(env):
    """`tool_run_id` is the PRIMARY KEY and the worker chooses it, so a retry updates the
    existing row. Three identical POSTs must leave exactly one."""
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    for _ in range(3):
        r = client.post("/v1/tool-results", headers=_auth(a),
                        json=_result_payload(a, tool_name="nmap", tool_run_id=run_id))
        assert r.status_code == 200, r.text

    rows = _query(lambda s: s.execute(
        select(ToolRun).where(ToolRun.scan_id == a["scan_id"])
    ))
    assert len([row for row in rows.all()]) == 1


def test_resubmitting_the_same_evidence_does_not_duplicate_the_row(env):
    """Keyed on (tool_run_id, checksum): the same bytes re-sent are the same evidence."""
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    client.post("/v1/tool-results", headers=_auth(a),
                json=_result_payload(a, tool_name="httpx", tool_run_id=run_id))
    for _ in range(3):
        r = client.post("/v1/evidence", headers=_auth(a),
                        json=_evidence_payload(a, tool_run_id=run_id, content=b"same bytes"))
        assert r.status_code == 200, r.text

    rows = _query(lambda s: s.execute(
        select(Evidence).where(Evidence.tool_run_id == run_id)
    ))
    assert len([row for row in rows.all()]) == 1


def test_a_retried_result_updates_status_rather_than_appending(env):
    """Same status resubmitted (a genuine retry reports the SAME outcome it reported
    before) must update the existing row in place, once -- not append a second one."""
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    client.post("/v1/tool-results", headers=_auth(a),
                json=_result_payload(a, tool_name="ffuf", tool_run_id=run_id, status="partial"))
    client.post("/v1/tool-results", headers=_auth(a),
                json=_result_payload(a, tool_name="ffuf", tool_run_id=run_id, status="partial"))

    rows = _query(lambda s: s.execute(
        select(ToolRun).where(ToolRun.scan_id == a["scan_id"])
    ))
    runs = [row[0] for row in rows.all()]
    assert len(runs) == 1
    assert runs[0].status == "partial"


def test_a_retry_reporting_a_different_terminal_status_is_ignored(env):
    """The first terminal status wins: a resubmission for the same tool_run_id that reports
    a DIFFERENT status from the one already recorded must not overwrite it. Guards against a
    buggy or adversarial retry silently altering an already-recorded outcome (the worker
    computes and submits status exactly once per tool_run_id -- see F2-09 -- so a genuine
    retry reports the SAME status, not a different one)."""
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    client.post("/v1/tool-results", headers=_auth(a),
                json=_result_payload(a, tool_name="ffuf", tool_run_id=run_id, status="completed"))
    r = client.post("/v1/tool-results", headers=_auth(a),
                    json=_result_payload(a, tool_name="ffuf", tool_run_id=run_id, status="failed"))
    assert r.status_code == 200, r.text  # fail-soft: not an error, just ignored

    rows = _query(lambda s: s.execute(
        select(ToolRun).where(ToolRun.scan_id == a["scan_id"])
    ))
    runs = [row[0] for row in rows.all()]
    assert len(runs) == 1
    assert runs[0].status == "completed"


def test_a_first_result_after_tool_started_still_writes_its_status(env):
    """A row opened by /v1/tool-started (status='running') is not yet terminal, so the
    FIRST /v1/tool-results for it must still write its reported status normally."""
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    client.post("/v1/tool-started", headers=_auth(a),
                json=_started_payload(a, tool_name="ffuf", tool_run_id=run_id))
    r = client.post("/v1/tool-results", headers=_auth(a),
                    json=_result_payload(a, tool_name="ffuf", tool_run_id=run_id, status="partial"))
    assert r.status_code == 200, r.text

    rows = _query(lambda s: s.execute(
        select(ToolRun).where(ToolRun.scan_id == a["scan_id"])
    ))
    runs = [row[0] for row in rows.all()]
    assert len(runs) == 1
    assert runs[0].status == "partial"


# ---------------------------------------------------------------------------------------
# 6-8. VULNERABILITIES through THE pipeline (not a parallel one)
# ---------------------------------------------------------------------------------------

def test_raw_output_is_parsed_server_side_into_vulnerabilities(env):
    """`vulnerabilities` gained NO rows at all after the cutover: the remote executor never
    called `parse_vulnerabilities()` and nothing downstream did either.

    The parse now happens in the control plane, from the bytes it just stored and
    checksummed -- so a worker cannot fabricate a finding no tool emitted, nor hide one by
    omitting it from a summary."""
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    client.post("/v1/tool-results", headers=_auth(a),
                json=_result_payload(a, tool_name="nuclei", tool_run_id=run_id))

    r = client.post("/v1/evidence", headers=_auth(a), json=_evidence_payload(
        a, tool_run_id=run_id, content=NUCLEI_LINE.encode(), tool_name="nuclei",
    ))
    assert r.status_code == 200, r.text
    assert r.json()["vulnerabilities"] == 1, "the raw output was not parsed"

    rows = _query(lambda s: s.execute(
        select(Vulnerability).where(Vulnerability.project_id == a["project_id"])
    ))
    vulns = [row[0] for row in rows.all()]
    assert len(vulns) == 1
    assert vulns[0].severity == "high"
    assert "git" in (vulns[0].title or "").lower()


def test_ingested_vulnerabilities_get_risk_compliance_and_attack_mappings(env):
    """The reason the shared pipeline is shared. Writing vulnerability rows straight from
    the endpoint would have produced findings with no risk score and no mappings -- rows
    that look ingested while silently skipping four engines."""
    from apps.api.modules.attack.models import AttackMapping
    from apps.api.modules.compliance.models import ComplianceMapping
    from apps.api.modules.risk.models import RiskScore

    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    client.post("/v1/tool-results", headers=_auth(a),
                json=_result_payload(a, tool_name="nuclei", tool_run_id=run_id))
    client.post("/v1/evidence", headers=_auth(a), json=_evidence_payload(
        a, tool_run_id=run_id, content=NUCLEI_LINE.encode(), tool_name="nuclei"))

    def _load(s):
        return s.execute(select(Vulnerability).where(
            Vulnerability.project_id == a["project_id"]))
    vuln = [row[0] for row in _query(_load).all()][0]

    risk = _query(lambda s: s.execute(
        select(RiskScore).where(RiskScore.vulnerability_id == vuln.id)))
    assert [r[0] for r in risk.all()], "no risk score -- the Risk Engine was skipped"

    # Compliance and ATT&CK mapping counts depend on the finding's CATEGORY and the
    # catalogue, so a category with no catalogue entry legitimately yields zero rows. What
    # must never happen is the engines being skipped, which is what writing vulnerability
    # rows directly from the endpoint would have done. Assert against the in-process path's
    # own answer for this category: the two paths must agree exactly.
    from apps.api.modules.compliance.catalog import controls_for_category

    comp = [r[0] for r in _query(lambda s: s.execute(select(ComplianceMapping).where(
        ComplianceMapping.vulnerability_id == vuln.id))).all()]
    att = [r[0] for r in _query(lambda s: s.execute(select(AttackMapping).where(
        AttackMapping.vulnerability_id == vuln.id))).all()]
    # Compliance rows are a pure function of the category, so this is an exact check
    # against the same catalogue the in-process path consults.
    assert len(comp) == len(controls_for_category(vuln.category)),         "compliance mapping diverged from the in-process path"
    # ATT&CK deliberately yields nothing for some categories (a technology DETECTION must
    # not inherit techniques via a generic CWE), so the invariant is that the engine RAN
    # and produced well-formed rows -- not that it produced any.
    for row in att:
        assert row.technique_id.startswith("T") and row.tactic_id.startswith("TA")


def test_reparsing_the_same_output_does_not_duplicate_vulnerabilities(env):
    """Dedup is the Vulnerability Engine's job (fingerprint), and it still applies when the
    same evidence is retried."""
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    client.post("/v1/tool-results", headers=_auth(a),
                json=_result_payload(a, tool_name="nuclei", tool_run_id=run_id))
    for _ in range(3):
        client.post("/v1/evidence", headers=_auth(a), json=_evidence_payload(
            a, tool_run_id=run_id, content=NUCLEI_LINE.encode(), tool_name="nuclei"))

    rows = _query(lambda s: s.execute(
        select(Vulnerability).where(Vulnerability.project_id == a["project_id"])))
    assert len([r for r in rows.all()]) == 1


def test_a_failed_tool_runs_output_is_not_ingested(env):
    """Same rule the in-process path applies: don't trust output from a failed run."""
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    client.post("/v1/tool-results", headers=_auth(a), json=_result_payload(
        a, tool_name="nuclei", tool_run_id=run_id, status="failed"))
    r = client.post("/v1/evidence", headers=_auth(a), json=_evidence_payload(
        a, tool_run_id=run_id, content=NUCLEI_LINE.encode(), tool_name="nuclei"))
    assert r.status_code == 200, r.text
    assert r.json()["vulnerabilities"] == 0

    rows = _query(lambda s: s.execute(
        select(Vulnerability).where(Vulnerability.project_id == a["project_id"])))
    assert not [r for r in rows.all()]


# ---------------------------------------------------------------------------------------
# 9-10. tool_name is CONSTRAINED, not trusted
# ---------------------------------------------------------------------------------------

def test_an_unregistered_tool_name_is_refused(env):
    """Free text would land verbatim in the UI and in customer reports."""
    client, state = env
    a = state["a"]
    payload = _result_payload(a, tool_name="'; DROP TABLE tool_runs; --")
    r = client.post("/v1/tool-results", headers=_auth(a), json=payload)
    assert r.status_code == 400, r.text
    assert r.json()["detail"] in {"TOOL_NOT_REQUESTED_FOR_SCAN", "UNKNOWN_TOOL_NAME"}


def test_a_tool_the_scan_never_requested_is_refused(env):
    """`nuclei-dast` is a REAL registered tool, but this scan did not ask for it -- so a
    worker may not file a result claiming it ran."""
    client, state = env
    a = state["a"]

    async def narrow(s):
        scan = await s.get(Scan, a["scan_id"])
        scan.config = {**(scan.config or {}), "requested_modules": ["httpx"]}
        await s.commit()
    _query(narrow)

    r = client.post("/v1/tool-results", headers=_auth(a),
                    json=_result_payload(a, tool_name="nuclei-dast"))
    assert r.status_code == 400, r.text
    assert r.json()["detail"] == "TOOL_NOT_REQUESTED_FOR_SCAN"


def test_an_invented_tool_status_is_refused(env):
    """Same rule as the terminal scan status: a worker cannot invent a lifecycle state."""
    client, state = env
    a = state["a"]
    r = client.post("/v1/tool-results", headers=_auth(a),
                    json=_result_payload(a, status="totally-fine"))
    assert r.status_code == 400
    assert r.json()["detail"] == "INVALID_TOOL_STATUS"


def test_tool_name_is_mandatory(env):
    """It is NOT NULL in the schema and cannot be derived: a lease covers a whole scan, and
    the executor skips modules that do not apply to the target type, so position in
    `requested_modules` does not identify the tool."""
    client, state = env
    a = state["a"]
    payload = _result_payload(a)
    del payload["tool_name"]
    assert client.post("/v1/tool-results", headers=_auth(a), json=payload).status_code == 422


# ---------------------------------------------------------------------------------------
# 11-15. FENCING, IDENTITY AND ISOLATION
# ---------------------------------------------------------------------------------------

def test_a_stale_execution_token_cannot_write_results(env):
    """A worker whose lease was superseded -- requeued on shutdown, reclaimed by the orphan
    reaper, cancelled -- must not append to the execution that replaced it."""
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    r = client.post("/v1/tool-results", headers=_auth(a), json=_result_payload(
        a, tool_run_id=run_id, token=uuid.uuid4()))
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "EXECUTION_SUPERSEDED"
    assert _query(lambda s: s.get(ToolRun, run_id)) is None, "a fenced-out write still landed"


def test_a_stale_execution_token_cannot_write_evidence(env):
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    r = client.post("/v1/evidence", headers=_auth(a), json=_evidence_payload(
        a, tool_run_id=run_id, content=b"late", token=uuid.uuid4()))
    assert r.status_code == 409
    rows = _query(lambda s: s.execute(
        select(Evidence).where(Evidence.tool_run_id == run_id)))
    assert not [r for r in rows.all()]


def test_a_reclaimed_scan_rejects_the_previous_owners_results(env):
    """The realistic sequence: the orphan reaper re-claims the scan with a NEW token, then
    the original worker -- still alive -- reports its results."""
    client, state = env
    a = state["a"]
    old_token = a["execution_token"]

    async def reclaim(s):
        scan = await s.get(Scan, a["scan_id"])
        scan.execution_token = uuid.uuid4()
        await s.commit()
    _query(reclaim)

    r = client.post("/v1/tool-results", headers=_auth(a),
                    json=_result_payload(a, token=old_token))
    assert r.status_code == 409
    assert r.json()["detail"] == "EXECUTION_SUPERSEDED"


def test_a_worker_cannot_hijack_another_scans_tool_run(env):
    """`tool_run_id` is a PRIMARY KEY the worker chooses, so it could otherwise name an id
    that already belongs to a different scan and overwrite it. A ToolRun never moves."""
    client, state = env
    a, b = state["a"], state["b"]
    run_id = uuid.uuid4()
    assert client.post("/v1/tool-results", headers=_auth(b),
                       json=_result_payload(b, tool_run_id=run_id)).status_code == 200

    r = client.post("/v1/tool-results", headers=_auth(a),
                    json=_result_payload(a, tool_run_id=run_id))
    assert r.status_code == 403, r.text
    assert r.json()["detail"] == "TOOL_RUN_BELONGS_TO_ANOTHER_SCAN"

    row = _query(lambda s: s.get(ToolRun, run_id))
    assert str(row.scan_id) == str(b["scan_id"]), "tenant B's tool run was re-parented"


def test_cross_tenant_result_submission_writes_nothing(env):
    """The pre-existing test asserted the 403. It could not assert the absence of a row,
    because no submission wrote one. Now both halves are checked."""
    client, state = env
    a, b = state["a"], state["b"]
    run_id = uuid.uuid4()
    r = client.post("/v1/tool-results", headers=_auth(a), json={
        "scan_id": str(b["scan_id"]), "tool_run_id": str(run_id),
        "tool_name": "nuclei", "execution_token": str(b["execution_token"]),
        "status": "completed", "findings": [],
    })
    assert r.status_code == 403
    assert _query(lambda s: s.get(ToolRun, run_id)) is None


def test_a_revoked_worker_cannot_write(env):
    """Revocation must take effect on the WRITE endpoints, not only on leasing."""
    client, state = env
    a = state["a"]

    async def revoke(s):
        row = await s.scalar(select(ScannerWorker).where(
            ScannerWorker.worker_id == a["worker_id"]))
        row.status = "revoked"
        await s.commit()
    _query(revoke)

    run_id = uuid.uuid4()
    r = client.post("/v1/tool-results", headers=_auth(a),
                    json=_result_payload(a, tool_run_id=run_id))
    assert r.status_code in (401, 403), r.text
    assert _query(lambda s: s.get(ToolRun, run_id)) is None


def test_an_unauthenticated_request_writes_nothing(env):
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    r = client.post("/v1/tool-results", json=_result_payload(a, tool_run_id=run_id))
    assert r.status_code in (401, 403)
    assert _query(lambda s: s.get(ToolRun, run_id)) is None


# ---------------------------------------------------------------------------------------
# 16. END-TO-END through execute_leased_job -- a path NOTHING covered before
# ---------------------------------------------------------------------------------------

def test_execute_leased_job_persists_runs_findings_and_vulnerabilities(env):
    """The full remote path in one test: executor -> reporter -> manager -> database.

    Audit found ZERO tests exercising `execute_leased_job`, which is how a path that
    persisted nothing stayed green. The tool runners are stubbed (no binaries in the test
    environment) but everything after them is real: the real reporter, the real HTTP
    endpoints, the real registry parser and the real ingestion pipeline.

    It also pins the parse bug this fix included: the executor read
    `getattr(raw, "findings", None)` from a RawToolOutput that has no such attribute, so
    inventory findings were ALWAYS empty and each tool received none of the previous tool's
    output.
    """
    from apps.api.scanner_engine.tool_runners.base import RawToolOutput
    from apps.api.scanner_worker import executor as executor_mod

    client, state = env
    a = state["a"]

    class _StubRunner:
        name = "nuclei"
        version = "3.0-stub"
        phase = 5
        applicable_target_types = None

        async def run(self, target_value, config, prior):
            return RawToolOutput(command="nuclei -u x", stdout=NUCLEI_LINE,
                                 stderr="", exit_code=0)

        def parse(self, raw):
            from apps.api.scanner_engine.tool_runners.base import CommonFinding
            return [CommonFinding(asset_type="http_service",
                                  value="https://t.example.com", metadata={})]

        def parse_vulnerabilities(self, raw):
            from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY
            return TOOL_REGISTRY["nuclei"]().parse_vulnerabilities(raw)

        def hard_failure(self, raw):
            return False

        benign_exit_codes = ()

    class _Sink:
        """Routes the worker's submissions through the REAL HTTP endpoints."""
        async def submit_tool_started(self, *, scan_id, tool_run_id, tool_name,
                                      execution_token=None, started_at=None):
            r = client.post("/v1/tool-started", headers=_auth(a), json={
                "scan_id": str(scan_id), "tool_run_id": str(tool_run_id),
                "tool_name": tool_name, "execution_token": str(execution_token),
                "started_at": started_at.isoformat() if started_at is not None else None,
            })
            assert r.status_code == 200, r.text
            return r.json()

        async def submit_tool_result(self, *, scan_id, tool_run_id, status, findings,
                                     tool_name=None, execution_token=None,
                                     exit_code=None, error_message=None,
                                     started_at=None, effective_command=None,
                                     timed_out=None):
            r = client.post("/v1/tool-results", headers=_auth(a), json={
                "scan_id": str(scan_id), "tool_run_id": str(tool_run_id),
                "tool_name": tool_name, "execution_token": str(execution_token),
                "status": status, "findings": findings, "exit_code": exit_code,
                "error_message": error_message,
                "started_at": started_at.isoformat() if started_at is not None else None,
                "effective_command": effective_command,
                "timed_out": timed_out,
            })
            assert r.status_code == 200, r.text
            return r.json()

        async def submit_evidence(self, *, scan_id, tool_run_id, content,
                                  content_type="text/plain", finding_id=None,
                                  execution_token=None, tool_name=None,
                                  fingerprint=None):
            # `fingerprint` mirrors the real ResultSink signature: the execution plane
            # cannot resolve a vulnerability id, so a screenshot names the finding by its
            # stable identity and the manager performs the association.
            r = client.post("/v1/evidence", headers=_auth(a), json={
                "scan_id": str(scan_id),
                "tool_run_id": str(tool_run_id) if tool_run_id else None,
                "content_type": content_type,
                "content_b64": base64.b64encode(content).decode(),
                "execution_token": str(execution_token), "tool_name": tool_name,
                "fingerprint": fingerprint,
            })
            assert r.status_code == 200, r.text
            return r.json()

    job = {
        "scan_id": str(a["scan_id"]),
        "execution_token": str(a["execution_token"]),
        "target": {"id": str(a["target_id"]), "type": "domain", "value": "t.example.com"},
        "requested_modules": ["nuclei"],
        "config": {},
    }
    reporter = executor_mod.ManagerResultReporter(_Sink())
    outcome = asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=reporter, registry={"nuclei": _StubRunner},
    ))
    assert outcome == "completed", outcome

    runs = [r[0] for r in _query(lambda s: s.execute(
        select(ToolRun).where(ToolRun.scan_id == a["scan_id"]))).all()]
    assert len(runs) == 1, "the executed tool produced no ToolRun"
    assert runs[0].tool_name == "nuclei"
    assert runs[0].status == "completed"

    evidence = [r[0] for r in _query(lambda s: s.execute(
        select(Evidence).where(Evidence.tool_run_id == runs[0].id))).all()]
    assert len(evidence) == 1, "no evidence row for the executed tool"

    assets = [r[0] for r in _query(lambda s: s.execute(
        select(Asset).where(Asset.target_id == a["target_id"]))).all()]
    assert assets, "runner.parse() output was dropped -- the raw.findings bug is back"

    vulns = [r[0] for r in _query(lambda s: s.execute(
        select(Vulnerability).where(Vulnerability.project_id == a["project_id"]))).all()]
    assert len(vulns) == 1, "a completed remote scan produced no vulnerabilities"
    assert vulns[0].severity == "high"

# ---------------------------------------------------------------------------------------
# TOOL RUN DURATION -- the `0s` defect
#
# Symptom: every completed tool on the remote path displayed "0s" in the scan-progress UI.
# Cause: the ToolRun row is created when the RESULT arrives, and `started_at` was never
# supplied, so it fell back to the column default (CURRENT_TIMESTAMP at insert) while
# `completed_at` was computed in Python microseconds EARLIER. Measured on the live database:
# all 127 rows written by this path had a duration <= 0 (subfinder -0.0022s, dnsx -0.0204s),
# against 0 of the 349 rows written by the in-process orchestrator, which inserts its row
# before launching the tool. `round(-0.0022, 1)` is `-0.0`, which JavaScript stringifies as
# "0" -- so an impossible negative duration reached the user as a plausible "0s".
# ---------------------------------------------------------------------------------------

def _duration_of(row) -> float | None:
    """Duration exactly as the read API computes it (modules/scans/schemas.py).

    None while the tool is still running -- `duration_seconds` is derived from
    `completed_at`, which a running row deliberately leaves null.
    """
    from apps.api.modules.scans.schemas import ToolRunRead

    return ToolRunRead.model_validate(row).duration_seconds


def test_a_reported_started_at_produces_a_real_duration(env):
    """12 seconds of work must be stored and reported as ~12 seconds, not as 0s."""
    from datetime import datetime, timedelta, timezone

    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    started = datetime.now(timezone.utc) - timedelta(seconds=12)

    payload = _result_payload(a, tool_name="nuclei", tool_run_id=run_id)
    payload["started_at"] = started.isoformat()
    r = client.post("/v1/tool-results", headers=_auth(a), json=payload)
    assert r.status_code == 200, r.text

    row = _query(lambda s: s.get(ToolRun, run_id))
    assert row is not None
    duration = _duration_of(row)
    # A window, not an equality: `completed_at` is stamped when the request is handled, so
    # the measured value is 12s plus the request's own latency.
    assert 11.5 <= duration <= 14.0, f"expected ~12s, got {duration}s"


def test_a_result_without_started_at_never_stores_a_negative_duration(env):
    """THE regression test for `0s`.

    An older worker submits no `started_at`. That must stay accepted -- refusing it would
    lose a whole scan's tool history over a cosmetic field -- but it must never again
    produce the inverted row that the CURRENT_TIMESTAMP default produced.
    """
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()

    payload = _result_payload(a, tool_name="nuclei", tool_run_id=run_id)
    assert "started_at" not in payload
    r = client.post("/v1/tool-results", headers=_auth(a), json=payload)
    assert r.status_code == 200, r.text

    row = _query(lambda s: s.get(ToolRun, run_id))
    assert row is not None, "backward compatibility broke: an old worker result was lost"
    assert row.started_at is not None
    assert _duration_of(row) >= 0.0, "the negative-duration defect is back"


def test_a_future_started_at_is_discarded_rather_than_stored(env):
    """`started_at` is UNTRUSTED worker input. A value in the future would store a negative
    duration -- the exact defect this field exists to fix -- so it is dropped and the row
    falls back to a 0s duration instead."""
    from datetime import datetime, timedelta, timezone

    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()

    payload = _result_payload(a, tool_name="nuclei", tool_run_id=run_id)
    payload["started_at"] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    r = client.post("/v1/tool-results", headers=_auth(a), json=payload)
    # Accepted, not refused: the RESULT is legitimate, only its clock is wrong, and
    # discarding a scan's tool history over clock skew is the worse failure.
    assert r.status_code == 200, r.text

    row = _query(lambda s: s.get(ToolRun, run_id))
    assert row is not None
    assert _duration_of(row) >= 0.0, "a future started_at was stored and inverted the row"


def test_a_started_at_within_clock_skew_tolerance_is_clamped_not_inverted(env):
    """A worker clock a fraction ahead of the manager is ordinary NTP drift between two
    hosts, not an attack. The value is clamped to `completed_at` so the row reports 0s
    rather than a negative duration."""
    from datetime import datetime, timedelta, timezone

    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()

    payload = _result_payload(a, tool_name="nuclei", tool_run_id=run_id)
    payload["started_at"] = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()
    r = client.post("/v1/tool-results", headers=_auth(a), json=payload)
    assert r.status_code == 200, r.text

    row = _query(lambda s: s.get(ToolRun, run_id))
    assert _duration_of(row) >= 0.0


def test_a_naive_started_at_is_read_as_utc(env):
    """A worker that serializes without an offset must not shift by the manager local
    offset -- this codebase stores "naive == UTC" (core/db_types.py), and a mixed-awareness
    comparison would otherwise raise TypeError inside the handler."""
    from datetime import datetime, timedelta, timezone

    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()

    naive = (datetime.now(timezone.utc) - timedelta(seconds=30)).replace(tzinfo=None)
    payload = _result_payload(a, tool_name="nuclei", tool_run_id=run_id)
    payload["started_at"] = naive.isoformat()
    r = client.post("/v1/tool-results", headers=_auth(a), json=payload)
    assert r.status_code == 200, r.text

    row = _query(lambda s: s.get(ToolRun, run_id))
    assert 29.0 <= _duration_of(row) <= 32.0, "a naive started_at was not read as UTC"


def test_a_retried_result_keeps_the_original_start_time(env):
    """A lease redelivery / acks_late retry re-POSTs the same `tool_run_id`. That must
    refresh the outcome without stretching the duration by the retry delay.

    Asserts the DURATION is unchanged, not merely non-negative. The weaker `>= 0` form of
    this test passed against code that charged the whole retry gap to the tool, because
    both POSTs went out microseconds apart and no gap could manifest -- hence the real
    sleep below.
    """
    import time
    from datetime import datetime, timedelta, timezone

    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    started = datetime.now(timezone.utc) - timedelta(seconds=20)

    payload = _result_payload(a, tool_name="nuclei", tool_run_id=run_id)
    payload["started_at"] = started.isoformat()
    assert client.post("/v1/tool-results", headers=_auth(a), json=payload).status_code == 200
    first_row = _query(lambda s: s.get(ToolRun, run_id))
    first_start = first_row.started_at
    first_completed = first_row.completed_at
    first_duration = _duration_of(first_row)

    time.sleep(2)

    # The retry reports the same start, as the worker would.
    assert client.post("/v1/tool-results", headers=_auth(a), json=payload).status_code == 200
    row = _query(lambda s: s.get(ToolRun, run_id))
    assert row.started_at == first_start, "a retry moved the start time"
    assert row.completed_at == first_completed, "a retry moved the completion time"
    assert abs(_duration_of(row) - first_duration) <= 0.05, (
        f"the retry gap was charged to the tool: {first_duration}s -> {_duration_of(row)}s"
    )


def test_every_tool_run_of_a_simulated_remote_scan_has_a_sane_duration(env):
    """The invariant, over the whole path rather than one endpoint: no completed ToolRun
    may have `completed_at` before `started_at`."""
    client, state = env
    a = state["a"]

    run_id = uuid.uuid4()
    r = client.post("/v1/tool-results", headers=_auth(a),
                    json=_result_payload(a, tool_name="nuclei", tool_run_id=run_id))
    assert r.status_code == 200, r.text

    runs = [row[0] for row in _query(lambda s: s.execute(
        select(ToolRun).where(ToolRun.scan_id == a["scan_id"]))).all()]
    assert runs
    for row in runs:
        if row.completed_at is None:
            continue
        assert row.completed_at >= row.started_at, (
            f"{row.tool_name}: completed_at {row.completed_at} precedes "
            f"started_at {row.started_at}"
        )



def test_a_retry_does_not_count_the_redelivery_gap(env):
    """THE invariant: resubmitting the same `tool_run_id` after a delay must leave
    `duration_seconds` unchanged.

    Measured against the deployed build before this fix: a tool that ran 3s, re-POSTed 6s
    later, recorded 9.0s -- `started_at` was correctly frozen but `completed_at` was
    re-stamped with "now", so the redelivery gap was charged to the tool. One ToolRun row
    is ONE execution attempt (`tool_run_id` is minted per execution in executor.py), so a
    resubmission is the same attempt reported twice and its end time cannot move.
    """
    import time
    from datetime import datetime, timedelta, timezone

    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    # A tool that genuinely ran for ~3 seconds.
    started = datetime.now(timezone.utc) - timedelta(seconds=3)

    payload = _result_payload(a, tool_name="nuclei", tool_run_id=run_id)
    payload["started_at"] = started.isoformat()
    assert client.post("/v1/tool-results", headers=_auth(a), json=payload).status_code == 200
    first_duration = _duration_of(_query(lambda s: s.get(ToolRun, run_id)))
    assert 2.5 <= first_duration <= 5.0, f"setup wrong: first duration {first_duration}s"

    # The redelivery gap. Longer than the tolerance below, so an inflated duration cannot
    # hide inside it.
    time.sleep(2.5)

    assert client.post("/v1/tool-results", headers=_auth(a), json=payload).status_code == 200
    second_duration = _duration_of(_query(lambda s: s.get(ToolRun, run_id)))

    assert abs(second_duration - first_duration) <= 0.05, (
        f"the {2.5}s redelivery gap was counted as execution time: "
        f"{first_duration}s -> {second_duration}s"
    )


def test_a_retry_repairs_an_inverted_completed_at(env):
    """Freezing `completed_at` must still REPAIR a broken row, not cement it.

    The 144 rows written before the started_at fix have `completed_at` BEFORE `started_at`
    (a negative duration, which the UI rendered as "0s"). A guard that only ever froze the
    value would preserve that forever, so the condition is "missing OR inverted" -- the
    same shape as the `started_at` guard beside it.
    """
    from datetime import datetime, timedelta, timezone

    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()

    payload = _result_payload(a, tool_name="nuclei", tool_run_id=run_id)
    assert client.post("/v1/tool-results", headers=_auth(a), json=payload).status_code == 200

    # Reproduce a pre-fix row directly: completed_at 5s BEFORE started_at.
    async def _invert(sess):
        row = await sess.get(ToolRun, run_id)
        row.started_at = datetime.now(timezone.utc)
        row.completed_at = row.started_at - timedelta(seconds=5)
        await sess.commit()

    _query(_invert)
    broken = _query(lambda s: s.get(ToolRun, run_id))
    assert broken.completed_at < broken.started_at, "setup did not produce an inverted row"
    assert _duration_of(broken) < 0, "setup did not produce a negative duration"

    # A retry touching this row must heal it rather than leave it inverted.
    assert client.post("/v1/tool-results", headers=_auth(a), json=payload).status_code == 200
    row = _query(lambda s: s.get(ToolRun, run_id))
    assert row.completed_at >= row.started_at, "an inverted row survived a retry"
    assert _duration_of(row) >= 0.0


# ---------------------------------------------------------------------------------------
# TOOL START ANNOUNCEMENT (/v1/tool-started) -- the live elapsed counter
#
# On the remote path a ToolRun row existed only once the tool FINISHED, so the scan-progress
# UI went straight from "waiting" to "completed" and a ten-minute katana/nuclei run looked
# frozen the whole time. The frontend already renders a live counter from a running row's
# `started_at` (useLiveElapsed in ScanProgress.tsx); it simply never received such a row.
# These pin the row that makes it work, and that opening it cannot damage the terminal write.
# ---------------------------------------------------------------------------------------

def _started_payload(entry, *, tool_name="nuclei", tool_run_id=None, token=None,
                     started_at=None):
    body = {
        "scan_id": str(entry["scan_id"]),
        "tool_run_id": str(tool_run_id or uuid.uuid4()),
        "tool_name": tool_name,
        "execution_token": str(token or entry["execution_token"]),
    }
    if started_at is not None:
        body["started_at"] = started_at.isoformat()
    return body


def test_tool_started_creates_exactly_one_running_toolrun(env):
    """The row the UI needs: exactly one, status running, no completion yet."""
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()

    r = client.post("/v1/tool-started", headers=_auth(a),
                    json=_started_payload(a, tool_name="nuclei", tool_run_id=run_id))
    assert r.status_code == 200, r.text

    rows = [row[0] for row in _query(lambda s: s.execute(
        select(ToolRun).where(ToolRun.scan_id == a["scan_id"]))).all()]
    assert len(rows) == 1, f"expected exactly one ToolRun, got {len(rows)}"
    assert rows[0].status == "running"
    assert rows[0].tool_name == "nuclei"


def test_tool_started_uses_the_worker_reported_started_at(env):
    """The counter must tick from the tool's REAL start, not from when the row was written."""
    from datetime import datetime, timedelta, timezone

    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    started = datetime.now(timezone.utc) - timedelta(seconds=30)

    r = client.post("/v1/tool-started", headers=_auth(a),
                    json=_started_payload(a, tool_run_id=run_id, started_at=started))
    assert r.status_code == 200, r.text

    row = _query(lambda s: s.get(ToolRun, run_id))
    # UTCDateTime hands back tz-aware values, so this compares like-for-like.
    elapsed = (datetime.now(timezone.utc) - row.started_at).total_seconds()
    assert 29.0 <= elapsed <= 33.0, f"started_at was not the worker's value (elapsed {elapsed}s)"


def test_tool_started_leaves_completed_at_null(env):
    """`duration_seconds` is derived from `completed_at`; it MUST stay null while running,
    otherwise the UI would render a finished duration for a tool still executing."""
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()

    assert client.post("/v1/tool-started", headers=_auth(a),
                       json=_started_payload(a, tool_run_id=run_id)).status_code == 200

    row = _query(lambda s: s.get(ToolRun, run_id))
    assert row.completed_at is None, "a running tool must not carry a completion time"
    assert _duration_of(row) is None, "duration must be null while the tool runs"


def test_start_then_complete_reuses_one_row_and_preserves_the_start(env):
    """The whole lifecycle: announce, run, complete. ONE row, original start preserved,
    completion stamped once -- so the counter's elapsed value and the final duration agree."""
    import time
    from datetime import datetime, timedelta, timezone

    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    started = datetime.now(timezone.utc) - timedelta(seconds=4)

    assert client.post("/v1/tool-started", headers=_auth(a),
                       json=_started_payload(a, tool_run_id=run_id,
                                             started_at=started)).status_code == 200
    open_row = _query(lambda s: s.get(ToolRun, run_id))
    assert open_row.status == "running"
    announced_start = open_row.started_at

    time.sleep(1)

    payload = _result_payload(a, tool_name="nuclei", tool_run_id=run_id, status="completed")
    payload["started_at"] = started.isoformat()
    assert client.post("/v1/tool-results", headers=_auth(a), json=payload).status_code == 200

    rows = [row[0] for row in _query(lambda s: s.execute(
        select(ToolRun).where(ToolRun.scan_id == a["scan_id"]))).all()]
    assert len(rows) == 1, "start + result produced two rows for one execution"
    row = rows[0]
    assert row.status == "completed"
    assert row.started_at == announced_start, "the result moved the announced start time"
    assert row.completed_at is not None, "the result did not close the running row"
    assert row.completed_at >= row.started_at
    # ~4s of real work, plus the 1s sleep is NOT added to it (the start is what anchors it).
    assert 3.5 <= _duration_of(row) <= 7.0, f"implausible duration {_duration_of(row)}s"


def test_a_re_announcement_does_not_reopen_a_finished_run(env):
    """A redelivered start announcement arriving after the result must not erase the
    terminal status -- that would make a completed tool look like it is running again."""
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()

    assert client.post("/v1/tool-started", headers=_auth(a),
                       json=_started_payload(a, tool_run_id=run_id)).status_code == 200
    assert client.post("/v1/tool-results", headers=_auth(a),
                       json=_result_payload(a, tool_name="nuclei", tool_run_id=run_id,
                                            status="completed")).status_code == 200
    finished = _query(lambda s: s.get(ToolRun, run_id))
    assert finished.status == "completed"

    # The late re-announcement.
    assert client.post("/v1/tool-started", headers=_auth(a),
                       json=_started_payload(a, tool_run_id=run_id)).status_code == 200

    row = _query(lambda s: s.get(ToolRun, run_id))
    assert row.status == "completed", "a late start announcement reopened a finished run"
    assert row.completed_at == finished.completed_at
    assert row.started_at == finished.started_at


# -- security parity with /v1/tool-results ------------------------------------------------

def test_tool_started_refuses_a_stale_execution_token(env):
    """A superseded lease must not be able to open rows on a scan it no longer owns."""
    client, state = env
    a = state["a"]
    r = client.post("/v1/tool-started", headers=_auth(a),
                    json=_started_payload(a, token=uuid.uuid4()))
    assert r.status_code == 409, r.text

    rows = [row[0] for row in _query(lambda s: s.execute(
        select(ToolRun).where(ToolRun.scan_id == a["scan_id"]))).all()]
    assert rows == [], "a stale token still wrote a ToolRun"


def test_tool_started_refuses_a_tool_the_scan_never_requested(env):
    """Same allow-list as the result path: a worker cannot invent a tool for this scan."""
    client, state = env
    a = state["a"]
    r = client.post("/v1/tool-started", headers=_auth(a),
                    json=_started_payload(a, tool_name="sqlmap"))
    assert r.status_code in (400, 403), r.text

    rows = [row[0] for row in _query(lambda s: s.execute(
        select(ToolRun).where(ToolRun.scan_id == a["scan_id"]))).all()]
    assert rows == [], "an unauthorized tool name still wrote a ToolRun"


def test_cross_tenant_tool_started_writes_nothing(env):
    """Tenant isolation: bravo's credential must not open a row on alpha's scan."""
    client, state = env
    a, b = state["a"], state["b"]
    r = client.post("/v1/tool-started", headers=_auth(b), json=_started_payload(a))
    assert r.status_code in (403, 404), r.text

    rows = [row[0] for row in _query(lambda s: s.execute(
        select(ToolRun).where(ToolRun.scan_id == a["scan_id"]))).all()]
    assert rows == [], "a cross-tenant announcement wrote into another tenant's scan"


def test_tool_started_refuses_a_run_belonging_to_another_scan(env):
    """`tool_run_id` is a worker-chosen PRIMARY KEY; it must never be re-parented."""
    client, state = env
    a, b = state["a"], state["b"]
    run_id = uuid.uuid4()

    assert client.post("/v1/tool-started", headers=_auth(b),
                       json=_started_payload(b, tool_run_id=run_id)).status_code == 200
    r = client.post("/v1/tool-started", headers=_auth(a),
                    json=_started_payload(a, tool_run_id=run_id))
    assert r.status_code == 403, r.text

    row = _query(lambda s: s.get(ToolRun, run_id))
    assert str(row.scan_id) == str(b["scan_id"]), "a ToolRun was re-parented to another scan"


def test_an_unauthenticated_tool_started_writes_nothing(env):
    client, state = env
    a = state["a"]
    r = client.post("/v1/tool-started", json=_started_payload(a))
    assert r.status_code in (401, 403, 422), r.text

    rows = [row[0] for row in _query(lambda s: s.execute(
        select(ToolRun).where(ToolRun.scan_id == a["scan_id"]))).all()]
    assert rows == [], "an unauthenticated announcement wrote a ToolRun"

# ---------------------------------------------------------------------------------------
# WORKER SIDE of the duration fix.
#
# The worker is the ONLY component that knows when a tool actually started: the manager
# creates the row when the result arrives, long after. These pin that the timestamp is
# captured before the tool runs and reported on BOTH outcomes -- the failure path is easy
# to miss, and a failed tool showing "0s" hides how long it hung before dying.
# ---------------------------------------------------------------------------------------

def _stub_runner(name="nuclei", *, raises=None):
    from apps.api.scanner_engine.tool_runners.base import RawToolOutput

    class _R:
        applicable_target_types = None
        phase = 5
        version = "3.0-stub"

        def __init__(self):
            self.name = name

        async def run(self, target_value, config, prior):
            import asyncio as _a
            # A measurable amount of work, so "captured before the run" is provable rather
            # than indistinguishable from "captured after".
            await _a.sleep(0.05)
            if raises is not None:
                raise raises
            return RawToolOutput(command=f"{name} -u x", stdout="", stderr="", exit_code=0)

        def parse(self, raw):
            return []

        def parse_vulnerabilities(self, raw):
            return []

        def hard_failure(self, raw):
            return False

        benign_exit_codes = ()

    _R.name = name
    return _R


class _RecordingSink:
    """Captures the kwargs the executor submits, without any HTTP or database."""

    def __init__(self):
        self.results = []
        self.started = []

    async def submit_tool_started(self, **kwargs):
        self.started.append(kwargs)
        return {}

    async def submit_tool_result(self, **kwargs):
        self.results.append(kwargs)
        return {}

    async def submit_evidence(self, **kwargs):
        return {}


def _run_job(runner_cls, sink):
    from apps.api.scanner_worker import executor as executor_mod

    job = {
        "scan_id": str(uuid.uuid4()),
        "execution_token": str(uuid.uuid4()),
        "target": {"id": str(uuid.uuid4()), "type": "domain", "value": "t.example.com"},
        "requested_modules": ["nuclei"],
        "config": {},
    }
    reporter = executor_mod.ManagerResultReporter(sink)
    return asyncio.run(executor_mod.execute_leased_job(
        job, policy=None, reporter=reporter, registry={"nuclei": runner_cls},
    ))


def test_worker_reports_started_at_on_the_success_path():
    from datetime import datetime, timezone

    sink = _RecordingSink()
    before = datetime.now(timezone.utc)
    _run_job(_stub_runner(), sink)
    after = datetime.now(timezone.utc)

    assert len(sink.results) == 1
    started = sink.results[0].get("started_at")
    assert started is not None, "the worker submitted no started_at -- duration is unmeasurable"
    assert before <= started <= after
    # Captured BEFORE the runner, not after it: the tool slept 50ms, so a timestamp taken
    # afterwards would land within a hair of `after` instead of near `before`.
    assert (after - started).total_seconds() >= 0.05


def test_worker_reports_started_at_on_the_exception_path():
    """A tool that raises must still report when it began -- otherwise a tool that hung for
    ten minutes and then failed is indistinguishable from one that failed instantly."""
    from datetime import datetime, timezone

    sink = _RecordingSink()
    before = datetime.now(timezone.utc)
    _run_job(_stub_runner(raises=RuntimeError("boom")), sink)
    after = datetime.now(timezone.utc)

    assert len(sink.results) == 1
    assert sink.results[0]["status"] == "failed"
    started = sink.results[0].get("started_at")
    assert started is not None, "the failure path dropped started_at"
    assert before <= started <= after
    assert (after - started).total_seconds() >= 0.05


# -- worker side of the start announcement ------------------------------------------------

class _OrderRecordingSink:
    """Records the ORDER of announcements, runs and results -- no HTTP, no database."""

    def __init__(self, *, start_raises=None):
        self.events = []
        self._start_raises = start_raises

    async def submit_tool_started(self, **kwargs):
        self.events.append(("started", kwargs))
        if self._start_raises is not None:
            raise self._start_raises
        return {}

    async def submit_tool_result(self, **kwargs):
        self.events.append(("result", kwargs))
        return {}

    async def submit_evidence(self, **kwargs):
        return {}


def _runner_recording_into(sink, name="nuclei", *, raises=None):
    """A stub runner that logs its own execution into the SAME event list, so the
    announcement can be proven to happen BEFORE the tool runs rather than merely
    alongside it."""
    from apps.api.scanner_engine.tool_runners.base import RawToolOutput

    class _R:
        applicable_target_types = None
        phase = 5
        version = "3.0-stub"

        def __init__(self):
            self.name = name

        async def run(self, target_value, config, prior):
            sink.events.append(("run", {}))
            if raises is not None:
                raise raises
            return RawToolOutput(command=f"{name} -u x", stdout="", stderr="", exit_code=0)

        def parse(self, raw):
            return []

        def parse_vulnerabilities(self, raw):
            return []

        def hard_failure(self, raw):
            return False

        benign_exit_codes = ()

    _R.name = name
    return _R


def test_worker_announces_the_start_before_running_the_tool():
    """THE ordering guarantee. An announcement sent after the tool ran would be useless --
    the row would appear only once there was nothing left to count."""
    sink = _OrderRecordingSink()
    runner_cls = _runner_recording_into(sink)
    outcome = _run_job(runner_cls, sink)

    assert outcome == "completed", outcome
    kinds = [k for k, _ in sink.events]
    assert kinds == ["started", "run", "result"], f"wrong lifecycle order: {kinds}"

    start_kwargs = sink.events[0][1]
    assert start_kwargs["tool_name"] == "nuclei"
    assert start_kwargs["started_at"] is not None
    # Same row the result closes -- otherwise the UI would show two entries per tool.
    assert start_kwargs["tool_run_id"] == sink.events[2][1]["tool_run_id"]
    assert start_kwargs["execution_token"] is not None


def test_a_failed_start_announcement_is_fail_soft():
    """Progress reporting is cosmetic. If the announcement cannot be delivered the tool
    must still run and its RESULT must still be submitted -- trading a real scan result for
    a display detail would be the worse failure."""
    sink = _OrderRecordingSink(start_raises=RuntimeError("manager unreachable"))
    runner_cls = _runner_recording_into(sink)

    outcome = _run_job(runner_cls, sink)

    assert outcome == "completed", f"a failed announcement aborted the scan: {outcome}"
    kinds = [k for k, _ in sink.events]
    assert kinds == ["started", "run", "result"], f"tool did not run/report: {kinds}"


def test_the_start_announcement_is_sent_for_a_tool_that_then_fails():
    """A tool that crashes must still have been announced, so the UI counts up while it
    hangs rather than showing nothing until it dies."""
    sink = _OrderRecordingSink()
    runner_cls = _runner_recording_into(sink, raises=RuntimeError("boom"))

    _run_job(runner_cls, sink)

    kinds = [k for k, _ in sink.events]
    assert kinds == ["started", "run", "result"], f"wrong lifecycle order: {kinds}"
    assert sink.events[2][1]["status"] == "failed"
    assert sink.events[0][1]["tool_run_id"] == sink.events[2][1]["tool_run_id"]


# ---------------------------------------------------------------------------------------
# 17. SCREENSHOT EVIDENCE across the manager boundary
#
# The execution plane holds no database credential, so it cannot resolve a vulnerability id
# and cannot write an Evidence row. It sends PNG bytes plus the finding FINGERPRINT; the
# manager resolves that against the vulnerabilities IT parsed and owns the association.
#
# The regression these pin: screenshots stored as `log_excerpt` would satisfy every
# existing evidence test and STILL render no image, because reports/data.py routes purely
# on `evidence_type`.
# ---------------------------------------------------------------------------------------

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"screenshot-under-test"


def _screenshot_payload(entry, *, tool_run_id, fingerprint, content=PNG_BYTES, token=None):
    return {
        "scan_id": str(entry["scan_id"]),
        "tool_run_id": str(tool_run_id),
        "content_type": "image/png",
        "content_b64": base64.b64encode(content).decode(),
        "execution_token": str(token or entry["execution_token"]),
        # A PNG names no parser: it is not parseable output.
        "tool_name": None,
        "fingerprint": fingerprint,
    }


def _ingest_one_vulnerability(client, entry, *, tool_run_id):
    """Drive the REAL path that creates the vulnerability a screenshot attaches to."""
    r = client.post("/v1/tool-results", headers=_auth(entry),
                    json=_result_payload(entry, tool_name="nuclei", tool_run_id=tool_run_id))
    assert r.status_code == 200, r.text
    r = client.post("/v1/evidence", headers=_auth(entry),
                    json=_evidence_payload(entry, tool_run_id=tool_run_id,
                                           content=NUCLEI_LINE.encode(), tool_name="nuclei"))
    assert r.status_code == 200, r.text
    assert r.json()["vulnerabilities"] == 1, r.text
    vulns = [row[0] for row in _query(lambda s: s.execute(
        select(Vulnerability).where(Vulnerability.project_id == entry["project_id"]))).all()]
    assert len(vulns) == 1
    return vulns[0]


def test_screenshot_is_persisted_as_evidence_type_screenshot(env):
    """Requirement 7. `log_excerpt` here would store the bytes and render NO image."""
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    vuln = _ingest_one_vulnerability(client, a, tool_run_id=run_id)

    r = client.post("/v1/evidence", headers=_auth(a),
                    json=_screenshot_payload(a, tool_run_id=run_id,
                                             fingerprint=vuln.fingerprint))
    assert r.status_code == 200, r.text

    rows = [row[0] for row in _query(lambda s: s.execute(
        select(Evidence).where(Evidence.tool_run_id == run_id))).all()]
    kinds = sorted(e.evidence_type for e in rows)
    assert kinds == ["log_excerpt", "screenshot"], kinds

    shot = next(e for e in rows if e.evidence_type == "screenshot")
    # store_screenshot(), not store_raw_output(): a PNG written to the fixed
    # `raw-output.txt` key would overwrite the tool log with image bytes.
    assert shot.storage_uri.endswith(".png"), shot.storage_uri
    assert "raw-output.txt" not in shot.storage_uri


def test_screenshot_is_associated_with_the_correct_vulnerability(env):
    """Requirement 4. An image attached to nothing is invisible to the report."""
    from apps.api.modules.vulnerabilities.models import VulnerabilityEvidence

    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    vuln = _ingest_one_vulnerability(client, a, tool_run_id=run_id)

    r = client.post("/v1/evidence", headers=_auth(a),
                    json=_screenshot_payload(a, tool_run_id=run_id,
                                             fingerprint=vuln.fingerprint))
    assert r.status_code == 200, r.text

    links = [row[0] for row in _query(lambda s: s.execute(
        select(VulnerabilityEvidence).where(
            VulnerabilityEvidence.vulnerability_id == vuln.id))).all()]
    shot_ids = {
        e.id for e in [row[0] for row in _query(lambda s: s.execute(
            select(Evidence).where(Evidence.tool_run_id == run_id))).all()]
        if e.evidence_type == "screenshot"
    }
    assert shot_ids, "no screenshot row was written"
    assert shot_ids <= {link.evidence_id for link in links}, \
        "the screenshot was stored but never linked to its finding"


def test_report_pipeline_sees_the_screenshot(env):
    """Requirement: the EXISTING report layer consumes these rows with no modification.

    Calls the real `gather_report_data` -- the same function the PDF renderer uses -- and
    asserts the image reaches `VulnRow.screenshots`, which is what the technical report
    embeds. This is the end the whole restoration exists to serve.
    """
    from apps.api.modules.reports.data import gather_report_data

    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    vuln = _ingest_one_vulnerability(client, a, tool_run_id=run_id)
    r = client.post("/v1/evidence", headers=_auth(a),
                    json=_screenshot_payload(a, tool_run_id=run_id,
                                             fingerprint=vuln.fingerprint))
    assert r.status_code == 200, r.text

    data = _query(lambda s: gather_report_data(s, a["project_id"]))
    row = next(v for v in data.vulns if v.id == vuln.id)
    assert row.screenshots, "the report layer received no screenshot for this finding"
    uri, checksum = row.screenshots[0]
    assert uri.endswith(".png") and len(checksum) == 64
    # The raw tool log must still be listed separately -- a screenshot does not replace it.
    assert any(t != "screenshot" for t, _ in row.evidence_items), row.evidence_items


def test_resubmitting_the_same_screenshot_is_idempotent(env):
    """Requirement 8. A re-scan recaptures an unchanged page -> same bytes, same checksum."""
    from apps.api.modules.vulnerabilities.models import VulnerabilityEvidence

    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    vuln = _ingest_one_vulnerability(client, a, tool_run_id=run_id)
    payload = _screenshot_payload(a, tool_run_id=run_id, fingerprint=vuln.fingerprint)

    for _ in range(3):
        assert client.post("/v1/evidence", headers=_auth(a), json=payload).status_code == 200

    rows = [row[0] for row in _query(lambda s: s.execute(
        select(Evidence).where(Evidence.tool_run_id == run_id))).all()]
    shots = [e for e in rows if e.evidence_type == "screenshot"]
    assert len(shots) == 1, f"duplicate screenshot rows: {len(shots)}"

    links = [row[0] for row in _query(lambda s: s.execute(
        select(VulnerabilityEvidence).where(
            VulnerabilityEvidence.evidence_id == shots[0].id))).all()]
    assert len(links) == 1, f"duplicate association rows: {len(links)}"


def test_unknown_fingerprint_attaches_to_nothing(env):
    """A worker cannot file evidence against a finding the manager never derived.

    The bytes are still stored (they are already checksummed and paid for), but no
    association is invented -- there is no vulnerability for them to point at.
    """
    from apps.api.modules.vulnerabilities.models import VulnerabilityEvidence

    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    _ingest_one_vulnerability(client, a, tool_run_id=run_id)

    r = client.post("/v1/evidence", headers=_auth(a),
                    json=_screenshot_payload(a, tool_run_id=run_id,
                                             fingerprint="fabricated@never-parsed"))
    assert r.status_code == 200, r.text

    rows = [row[0] for row in _query(lambda s: s.execute(
        select(Evidence).where(Evidence.tool_run_id == run_id))).all()]
    shots = [e for e in rows if e.evidence_type == "screenshot"]
    assert len(shots) == 1, "the bytes should still be stored"

    links = [row[0] for row in _query(lambda s: s.execute(
        select(VulnerabilityEvidence).where(
            VulnerabilityEvidence.evidence_id == shots[0].id))).all()]
    assert links == [], "an unmatched fingerprint must not be attached to any finding"


def test_a_screenshot_cannot_cross_a_tenant_boundary(env):
    """Tenant B submits B's screenshot naming A's fingerprint: it must not reach A.

    The project is read from the AUTHORIZED scan row, never from the payload, so the
    fingerprint lookup is confined to the submitting tenant.
    """
    from apps.api.modules.vulnerabilities.models import VulnerabilityEvidence

    client, state = env
    a, b = state["a"], state["b"]
    a_run = uuid.uuid4()
    a_vuln = _ingest_one_vulnerability(client, a, tool_run_id=a_run)

    b_run = uuid.uuid4()
    assert client.post("/v1/tool-results", headers=_auth(b),
                       json=_result_payload(b, tool_name="nuclei",
                                            tool_run_id=b_run)).status_code == 200
    r = client.post("/v1/evidence", headers=_auth(b),
                    json=_screenshot_payload(b, tool_run_id=b_run,
                                             fingerprint=a_vuln.fingerprint))
    assert r.status_code == 200, r.text

    links = [row[0] for row in _query(lambda s: s.execute(
        select(VulnerabilityEvidence).where(
            VulnerabilityEvidence.vulnerability_id == a_vuln.id))).all()]
    b_evidence = {e.id for e in [row[0] for row in _query(lambda s: s.execute(
        select(Evidence).where(Evidence.tool_run_id == b_run))).all()]}
    assert not (b_evidence & {link.evidence_id for link in links}), \
        "another tenant's screenshot was attached to this finding"


def test_text_evidence_is_still_stored_as_log_excerpt(env):
    """The raw-output path is untouched -- no regression from the type split."""
    client, state = env
    a = state["a"]
    run_id = uuid.uuid4()
    assert client.post("/v1/tool-results", headers=_auth(a),
                       json=_result_payload(a, tool_name="nuclei",
                                            tool_run_id=run_id)).status_code == 200
    assert client.post("/v1/evidence", headers=_auth(a),
                       json=_evidence_payload(a, tool_run_id=run_id,
                                              content=b"plain tool output")).status_code == 200
    rows = [row[0] for row in _query(lambda s: s.execute(
        select(Evidence).where(Evidence.tool_run_id == run_id))).all()]
    assert [e.evidence_type for e in rows] == ["log_excerpt"]
    assert rows[0].storage_uri.endswith("raw-output.txt")
