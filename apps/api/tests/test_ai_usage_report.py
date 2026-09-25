"""AI-2.2B-2 -- AI cost reporting endpoint (GET /workspaces/{id}/ai-usage).

Verifies totals + breakdowns, tenant isolation, authorization, date-range filtering, and that the
report exposes metadata only. Seeds ai_usage directly (no live AI calls).
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings

_PW = "correct horse battery staple"


def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    r = client.post("/api/v1/auth/register", json={"email": email, "password": _PW, "full_name": "Cost User"})
    assert r.status_code == 201, r.text
    tokens = r.json()
    me = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    return {"email": email, "id": me.json()["id"], **tokens}


def _auth(t: dict) -> dict:
    return {"Authorization": f"Bearer {t['access_token']}"}


def _workspace(client: TestClient, headers: dict, name: str = "Acme") -> str:
    return client.post("/api/v1/workspaces", headers=headers, json={"name": name}).json()["id"]


async def _seed_usage(workspace_id: str, specs: list[dict]) -> None:
    eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    try:
        async with eng.begin() as c:
            tenancy.bind_workspace(workspace_id)  # Phase 0 MySQL cutover: was Postgres set_config; see apps.api.core.tenancy
            for s in specs:
                # Phase 0 MySQL cutover: make_interval() has no MySQL equivalent; the
                # created_at timestamp is computed in Python instead (same fix as the other
                # seed helpers in this suite -- see test_queued_relay.py/_seed_scan).
                created_at = datetime.now(timezone.utc) - timedelta(days=s["days_ago"])
                await c.execute(
                    text(
                        "INSERT INTO ai_usage (id, workspace_id, provider, model, agent_role, "
                        "prompt_tokens, completion_tokens, estimated_cost_usd, created_at) "
                        "VALUES (:id,:w,'openrouter',:model,:role,:pt,:ct,:cost,:created_at)"
                    ),
                    {"id": str(uuid.uuid4()), "w": workspace_id, "model": s["model"], "role": s["role"],
                     "pt": s["pt"], "ct": s["ct"], "cost": s["cost"], "created_at": created_at},
                )
    finally:
        await eng.dispose()


def _url(ws: str) -> str:
    return f"/api/v1/workspaces/{ws}/ai-usage"


# --- totals + breakdowns --------------------------------------------------------------------

def test_report_totals_and_breakdowns(client: TestClient) -> None:
    u = _register(client)
    h = _auth(u)
    ws = _workspace(client, h)
    asyncio.run(_seed_usage(ws, [
        {"model": "claude-opus", "role": "agent", "pt": 100, "ct": 50, "cost": 0.01, "days_ago": 0},
        {"model": "claude-opus", "role": "remediation", "pt": 200, "ct": 100, "cost": 0.02, "days_ago": 1},
        {"model": "deepseek-chat", "role": "agent", "pt": 50, "ct": 50, "cost": 0.001, "days_ago": 2},
    ]))
    data = client.get(_url(ws), headers=h).json()

    assert data["total_calls"] == 3
    assert data["total_prompt_tokens"] == 350
    assert data["total_completion_tokens"] == 200
    assert data["total_cost_usd"] == pytest.approx(0.031)

    by_model = {b["key"]: b for b in data["by_model"]}
    assert by_model["claude-opus"]["calls"] == 2 and by_model["claude-opus"]["cost_usd"] == pytest.approx(0.03)
    assert by_model["deepseek-chat"]["calls"] == 1
    by_role = {b["key"]: b["calls"] for b in data["by_agent_role"]}
    assert by_role == {"agent": 2, "remediation": 1}
    assert len(data["by_day"]) == 3


def test_empty_workspace_is_zero(client: TestClient) -> None:
    u = _register(client)
    h = _auth(u)
    ws = _workspace(client, h)
    data = client.get(_url(ws), headers=h).json()
    assert data["total_calls"] == 0 and data["total_cost_usd"] == 0.0
    assert data["by_day"] == [] and data["by_model"] == [] and data["by_agent_role"] == []


# --- tenant isolation -----------------------------------------------------------------------

def test_report_is_tenant_isolated(client: TestClient) -> None:
    a = _register(client)
    ws_a = _workspace(client, _auth(a), "A-space")
    asyncio.run(_seed_usage(ws_a, [{"model": "opus", "role": "agent", "pt": 10, "ct": 10, "cost": 0.05, "days_ago": 0}]))

    b = _register(client)
    ws_b = _workspace(client, _auth(b), "B-space")
    asyncio.run(_seed_usage(ws_b, [{"model": "opus", "role": "agent", "pt": 10, "ct": 10, "cost": 0.99, "days_ago": 0}]))

    data_a = client.get(_url(ws_a), headers=_auth(a)).json()
    assert data_a["total_cost_usd"] == pytest.approx(0.05)   # only A's spend, never B's 0.99


# --- authorization --------------------------------------------------------------------------

def test_report_requires_auth(client: TestClient) -> None:
    u = _register(client)
    ws = _workspace(client, _auth(u))
    assert client.get(_url(ws)).status_code == 401


def test_report_rejects_non_member(client: TestClient) -> None:
    a = _register(client)
    ws_a = _workspace(client, _auth(a))
    b = _register(client)                                    # not a member of ws_a
    assert client.get(_url(ws_a), headers=_auth(b)).status_code == 403


# --- date range -----------------------------------------------------------------------------

def test_date_range_filter(client: TestClient) -> None:
    u = _register(client)
    h = _auth(u)
    ws = _workspace(client, h)
    asyncio.run(_seed_usage(ws, [
        {"model": "opus", "role": "agent", "pt": 1, "ct": 1, "cost": 0.01, "days_ago": 0},
        {"model": "opus", "role": "agent", "pt": 1, "ct": 1, "cost": 0.02, "days_ago": 60},   # outside default 30d
    ]))
    default = client.get(_url(ws), headers=h).json()
    assert default["total_cost_usd"] == pytest.approx(0.01)   # 60-day-old row excluded

    frm = (datetime.now(timezone.utc).date() - timedelta(days=65)).isoformat()
    widened = client.get(_url(ws), headers=h, params={"from": frm}).json()
    assert widened["total_cost_usd"] == pytest.approx(0.03)   # now includes the old row


# --- metadata-only --------------------------------------------------------------------------

def test_report_exposes_metadata_only(client: TestClient) -> None:
    u = _register(client)
    h = _auth(u)
    ws = _workspace(client, h)
    asyncio.run(_seed_usage(ws, [{"model": "opus", "role": "agent", "pt": 1, "ct": 1, "cost": 0.01, "days_ago": 0}]))
    data = client.get(_url(ws), headers=h).json()
    assert set(data) == {
        "from_date", "to_date", "total_calls", "total_prompt_tokens", "total_completion_tokens",
        "total_cost_usd", "by_day", "by_model", "by_agent_role",
    }
    assert set(data["by_model"][0]) == {"key", "calls", "prompt_tokens", "completion_tokens", "cost_usd"}
