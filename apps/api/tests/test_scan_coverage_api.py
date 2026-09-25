"""Prompt 14 -- coverage endpoint end-to-end against a REAL DB.

Seeds real assets + tool_runs for a scan, then asserts the coverage projection:
  * an in-scope http_service that no crawl ever reached is coverage DEBT (false-confidence
    guard: the scan can be 'completed' while this surface is untested),
  * cross-tenant isolation (another tenant cannot read the coverage),
  * out-of-scope assets never appear as debt.

This is the runtime/integration counterpart to the pure unit tests in
test_coverage_projection.py -- it proves the DB adapter + tenancy scoping, not just the math.
"""
import asyncio
import uuid

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.assets.service import upsert_asset
from apps.api.scanner_engine.models import ToolRun
from apps.api.tests.test_scans import (
    _auth,
    _make_target,
    _register,
    _verify_target,
)


async def _seed_coverage(ws_id: str, project_id: str, target_id: str, scan_id: str):
    """A discovered subdomain (probed by httpx=completed) + a live http_service that NO crawl
    reached, plus an out-of-scope subdomain. Only the http_service is real coverage debt."""
    settings = get_settings()
    engine = create_async_engine(settings.database_url, poolclass=StaticPool)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as s:
            tenancy.bind_workspace(ws_id)
            await upsert_asset(
                s, project_id=uuid.UUID(project_id), target_id=uuid.UUID(target_id),
                asset_type="subdomain", value="api.cov.example.com", metadata={"in_scope": True},
            )
            await upsert_asset(
                s, project_id=uuid.UUID(project_id), target_id=uuid.UUID(target_id),
                asset_type="http_service", value="http://api.cov.example.com/", metadata={"in_scope": True},
            )
            await upsert_asset(
                s, project_id=uuid.UUID(project_id), target_id=uuid.UUID(target_id),
                asset_type="subdomain", value="evil.cov.example.com", metadata={"in_scope": False},
            )
            # httpx ran and completed (subdomain covered); katana (web_crawling) NEVER ran.
            s.add(ToolRun(scan_id=uuid.UUID(scan_id), tool_name="httpx", tool_version="1",
                          status="completed", command_hash="x"))
            await s.commit()
    finally:
        await engine.dispose()


def _make_scan(client, headers, ws, proj, tgt) -> str:
    r = client.post(
        f"/api/v1/workspaces/{ws}/projects/{proj}/scans", headers=headers,
        json={"target_id": tgt, "scan_type": "network", "requested_modules": ["httpx"]},
    )
    assert r.status_code in (201, 202), r.text
    return r.json()["id"]


def test_coverage_endpoint_reports_debt_and_isolates_tenants(client, no_celery_dispatch):
    owner = _auth(_register(client, "CovOwner"))
    ws, proj, tgt = _make_target(client, owner)
    _verify_target(client, owner, ws, proj, tgt)
    scan_id = _make_scan(client, owner, ws, proj, tgt)
    asyncio.run(_seed_coverage(ws, proj, tgt, scan_id))

    url = f"/api/v1/workspaces/{ws}/projects/{proj}/scans/{scan_id}/coverage"

    r = client.get(url, headers=owner)
    assert r.status_code == 200, r.text
    body = r.json()

    debt_vals = {d["value"] for d in body["debt"]}
    # The live web service that no crawler reached IS debt...
    assert "http://api.cov.example.com/" in debt_vals
    assert body["has_debt"] is True
    assert "web_crawling" in body["debt_summary"]
    # ...the probed subdomain is NOT (httpx completed against it)...
    assert "api.cov.example.com" not in debt_vals
    # ...and the out-of-scope host is never debt.
    assert "evil.cov.example.com" not in debt_vals
    states = {s["value"]: s["state"] for s in body["surfaces"]}
    assert states["evil.cov.example.com"] == "out_of_scope"
    assert states["api.cov.example.com"] == "covered"

    # --- cross-tenant isolation ---
    other = _auth(_register(client, "CovIntruder"))
    assert client.get(url, headers=other).status_code in (403, 404)

    # --- unauthenticated ---
    assert client.get(url).status_code in (401, 403)
