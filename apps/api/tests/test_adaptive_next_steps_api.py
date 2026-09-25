"""Prompt 21 -- adaptive next-steps endpoint end-to-end against a REAL DB.

Seeds real assets + tool_runs, then asserts the Adaptive Detection Engine's candidates via the
API: evidence-driven selection, provenance, coverage/auth awareness, tenancy + scope isolation,
and the candidate!=finding separation. This is the DB/tenancy counterpart to the pure unit
tests in test_adaptive_engine.py.
"""
import asyncio
import uuid

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.assets.service import upsert_asset
from apps.api.scanner_engine.models import ToolRun
from apps.api.tests.test_scans import _auth, _register, _verify_target


def _make_target_with_value(client, headers):
    """Like test_scans._make_target but also returns the target's domain value, so seeded
    hosts can be made genuinely in-scope (the targets collection has no individual GET)."""
    ws = client.post("/api/v1/workspaces", headers=headers, json={"name": "Scan WS"}).json()["id"]
    proj = client.post(f"/api/v1/workspaces/{ws}/projects", headers=headers, json={"name": "P"}).json()["id"]
    value = f"{uuid.uuid4()}.test"
    tgt = client.post(
        f"/api/v1/workspaces/{ws}/projects/{proj}/targets",
        headers=headers, json={"type": "domain", "value": value},
    ).json()["id"]
    return ws, proj, tgt, value


async def _seed(ws, proj, tgt, scan_id, target_value):
    settings = get_settings()
    engine = create_async_engine(settings.database_url, poolclass=StaticPool)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    host = target_value
    try:
        async with maker() as s:
            tenancy.bind_workspace(ws)
            # A live web service (crawled) + a param-bearing API endpoint (arjun not yet run)
            # + a protected endpoint (must NOT become a candidate).
            await upsert_asset(s, project_id=uuid.UUID(proj), target_id=uuid.UUID(tgt),
                               asset_type="http_service", value=f"http://{host}/",
                               metadata={"in_scope": True, "host": host, "source": "httpx"})
            await upsert_asset(s, project_id=uuid.UUID(proj), target_id=uuid.UUID(tgt),
                               asset_type="url", value=f"http://{host}/api/orders?id=1",
                               metadata={"in_scope": True, "host": host, "source": "katana",
                                         "is_api": True, "api_kind": "rest", "params": ["id"]})
            await upsert_asset(s, project_id=uuid.UUID(proj), target_id=uuid.UUID(tgt),
                               asset_type="http_service", value=f"http://{host}/admin",
                               metadata={"in_scope": True, "host": host, "source": "httpx",
                                         "auth_state": "protected"})
            # katana completed (so the live service is covered -> not a candidate), arjun/dast
            # have NOT run (so the API endpoint IS a dast candidate).
            s.add(ToolRun(scan_id=uuid.UUID(scan_id), tool_name="httpx", tool_version="1",
                          status="completed", command_hash="x"))
            s.add(ToolRun(scan_id=uuid.UUID(scan_id), tool_name="katana", tool_version="1",
                          status="completed", command_hash="x"))
            await s.commit()
    finally:
        await engine.dispose()


def _make_scan(client, headers, ws, proj, tgt) -> str:
    r = client.post(
        f"/api/v1/workspaces/{ws}/projects/{proj}/scans", headers=headers,
        json={"target_id": tgt, "scan_type": "web", "requested_modules": ["httpx"]},
    )
    assert r.status_code in (201, 202), r.text
    return r.json()["id"]


def test_next_steps_endpoint_is_evidence_driven_and_tenant_isolated(client, no_celery_dispatch):
    owner = _auth(_register(client, "AdaptOwner"))
    ws, proj, tgt, target_value = _make_target_with_value(client, owner)
    # Active testing must be allowed for a DAST candidate to be eligible.
    base = f"/api/v1/workspaces/{ws}/projects/{proj}/targets/{tgt}/authorization-scope"
    client.post(base, headers=owner, json={"proof_type": "dns_txt", "proof_reference": "x"})
    client.post(f"{base}/verify", headers=owner, json={"active_testing_allowed": True})

    scan_id = _make_scan(client, owner, ws, proj, tgt)
    asyncio.run(_seed(ws, proj, tgt, scan_id, target_value))

    url = f"/api/v1/workspaces/{ws}/projects/{proj}/scans/{scan_id}/next-steps"
    r = client.get(url, headers=owner)
    assert r.status_code == 200, r.text
    body = r.json()

    by_target = {c["target"]: c for c in body["candidates"]}
    api_ep = f"http://{target_value}/api/orders?id=1"
    # The param-bearing API endpoint IS a DAST candidate, with evidence-backed reasons...
    assert api_ep in by_target
    cand = by_target[api_ep]
    assert cand["capability"] == "dast_fuzzing" and cand["tool"] == "nuclei-dast"
    assert "discovered_parameter" in cand["reasons"] and "api_surface" in cand["reasons"]
    assert cand["provenance"]["source"] == "katana" and cand["provenance"]["params"] == ["id"]
    # ...the crawled live service is COVERED -> not a candidate...
    assert f"http://{target_value}/" not in by_target
    # ...and the PROTECTED endpoint is never a candidate (Invariant 6: not clean, no creds).
    assert f"http://{target_value}/admin" not in by_target

    # candidate != finding: nothing here is a vulnerability row.
    assert all("severity" not in c and "verified" not in c for c in body["candidates"])

    # --- cross-tenant isolation (Invariant 2) ---
    other = _auth(_register(client, "AdaptIntruder"))
    assert client.get(url, headers=other).status_code in (403, 404)
    # --- unauthenticated ---
    assert client.get(url).status_code in (401, 403)


def test_next_steps_empty_without_active_testing_scope(client, no_celery_dispatch):
    """A verified-but-not-active-testing scope must not surface DAST/arjun candidates (the
    registry gate is re-applied): the endpoint returns an empty, valid result, never an error."""
    owner = _auth(_register(client, "AdaptPassive"))
    ws, proj, tgt, target_value = _make_target_with_value(client, owner)
    _verify_target(client, owner, ws, proj, tgt)  # active_testing_allowed=False
    scan_id = _make_scan(client, owner, ws, proj, tgt)
    asyncio.run(_seed(ws, proj, tgt, scan_id, target_value))

    url = f"/api/v1/workspaces/{ws}/projects/{proj}/scans/{scan_id}/next-steps"
    r = client.get(url, headers=owner)
    assert r.status_code == 200, r.text
    # No active-testing => arjun (parameter_discovery) and nuclei-dast (dast_fuzzing) are both
    # ineligible; the API endpoint therefore yields no candidate.
    api_ep = f"http://{target_value}/api/orders?id=1"
    assert api_ep not in {c["target"] for c in r.json()["candidates"]}
