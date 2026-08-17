"""M4.4.5 -- read-only attack-graph API: authorization, RLS/workspace isolation,
response shape, and the no-write guarantee. Exercises the REAL endpoint through the
app (TestClient) with the platform's normal auth/RBAC/RLS, reusing the scans test
helpers. The persisted graph is seeded directly into engagement_state (RLS GUC set)
to avoid running a live scan; the API must return that ACTUAL persisted graph."""
import asyncio
import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core.config import get_settings
from apps.api.modules.agent.models import EngagementState
# Reuse the established API helpers from the scans tests (no_celery_dispatch is a conftest fixture).
from apps.api.tests.test_scans import (
    _auth,
    _make_target,
    _register,
    _verify_target,
)

_SAMPLE_GRAPH = {
    "nodes": [
        {"id": "asset:203.0.113.7", "type": "asset", "label": "203.0.113.7",
         "provenance": {"tool": "nmap", "source": "derived", "confidence": 0.9,
                        "first_seen": "2026-08-05T00:00:00+00:00", "last_seen": "2026-08-05T00:00:00+00:00"},
         "attributes": {"kind": "host"}},
    ],
    "edges": [],
    "counts": {"asset": 1},
    "updated_at": "2026-08-05T00:00:00+00:00",
}


async def _seed_engagement(ws_id: str, scan_id: str, graph: dict) -> None:
    settings = get_settings()
    engine = create_async_engine(settings.database_url, poolclass=StaticPool)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as s:
            await s.execute(
                text("SELECT set_config('app.current_workspace_id', :w, false)"), {"w": ws_id}
            )
            s.add(EngagementState(
                workspace_id=uuid.UUID(ws_id), scan_id=uuid.UUID(scan_id),
                status="completed", current_phase="reconnaissance",
                objective="assess host", attack_graph=graph,
            ))
            await s.commit()
    finally:
        await engine.dispose()


def _make_scan(client, headers, ws, proj, tgt) -> str:
    resp = client.post(
        f"/api/v1/workspaces/{ws}/projects/{proj}/scans",
        headers=headers,
        json={"target_id": tgt, "scan_type": "network", "requested_modules": ["nmap"]},
    )
    assert resp.status_code in (201, 202), resp.text
    return resp.json()["id"]


def test_attack_graph_api_authorization_shape_and_readonly(client, no_celery_dispatch):
    owner = _register(client, "GraphOwner")
    headers = _auth(owner)
    ws, proj, tgt = _make_target(client, headers)
    _verify_target(client, headers, ws, proj, tgt)
    scan_id = _make_scan(client, headers, ws, proj, tgt)
    url = f"/api/v1/workspaces/{ws}/projects/{proj}/scans/{scan_id}/attack-graph"

    # 1. Non-agent scan (no engagement) -> empty graph, 200 (backward compatible).
    r = client.get(url, headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["has_engagement"] is False and body["graph"] == {}

    # 2. Seed a persisted graph -> the API returns the ACTUAL persisted graph, unchanged.
    asyncio.run(_seed_engagement(ws, scan_id, _SAMPLE_GRAPH))
    r2 = client.get(url, headers=headers)
    assert r2.status_code == 200
    b2 = r2.json()
    assert b2["has_engagement"] is True
    assert b2["status"] == "completed" and b2["current_phase"] == "reconnaissance"
    assert b2["graph"]["nodes"][0]["id"] == "asset:203.0.113.7"
    assert b2["graph"]["nodes"][0]["provenance"]["tool"] == "nmap"   # provenance preserved
    assert b2["graph"]["counts"] == {"asset": 1}

    # 3. Cross-workspace isolation: a different user cannot read this scan's graph.
    other = _register(client, "Intruder")
    r3 = client.get(url, headers=_auth(other))
    assert r3.status_code in (403, 404)   # denied by workspace membership / scope, no leak

    # 4. Read-only: there is no write path to the graph via the API.
    assert client.post(url, headers=headers, json={"graph": {}}).status_code == 405
    assert client.put(url, headers=headers, json={"graph": {}}).status_code == 405
    assert client.delete(url, headers=headers).status_code == 405

    # 5. Unauthenticated requests are rejected.
    assert client.get(url).status_code in (401, 403)


def test_report_aggregates_attack_graph(client, no_celery_dispatch):
    # M4.4.6: the project report aggregates the persisted engagement graph -- node
    # counts + confirmed access with evidence-backed state (no invented priv-esc).
    import uuid as _uuid

    from apps.api.modules.reports.data import gather_report_data

    owner = _register(client, "ReportOwner")
    headers = _auth(owner)
    ws, proj, tgt = _make_target(client, headers)
    _verify_target(client, headers, ws, proj, tgt)
    scan_id = _make_scan(client, headers, ws, proj, tgt)

    graph = {
        "nodes": [
            {"id": "asset:203.0.113.9", "type": "asset", "label": "203.0.113.9", "provenance": {}, "attributes": {}},
            {"id": "service:203.0.113.9:80", "type": "service", "label": "svc", "provenance": {}, "attributes": {}},
            {"id": "access:203.0.113.9:rce_proof", "type": "access", "label": "rce_proof",
             "provenance": {"source": "exploitation"},
             "attributes": {"module": "known_cve", "access_type": "rce_proof", "access_state": "access_obtained"}},
        ],
        "edges": [],
        "counts": {"asset": 1, "service": 1, "access": 1},
    }
    asyncio.run(_seed_engagement(ws, scan_id, graph))

    async def _gather():
        settings = get_settings()
        engine = create_async_engine(settings.database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                await s.execute(text("SELECT set_config('app.current_workspace_id', :w, false)"), {"w": ws})
                return await gather_report_data(s, _uuid.UUID(proj))
        finally:
            await engine.dispose()

    data = asyncio.run(_gather())
    ag = data.attack_graph
    assert ag["has_data"] is True and ag["engagement_count"] == 1
    assert ag["node_counts"]["access"] == 1 and ag["node_counts"]["service"] == 1
    assert ag["confirmed_access"][0]["access_state"] == "access_obtained"
    assert ag["confirmed_access"][0]["module"] == "known_cve"
    assert ag["confirmed_access"][0]["target"] == "203.0.113.9"
