"""M4.5 integration tests -- derived-target authorization enforcement (G9) through the
REAL orchestrator enforcement point (`_run_single_tool`), against real Postgres.

Proves the required security behavior for a DOMAIN engagement:
  (a) in-scope derived assets ARE handed to the active tool,
  (b) out-of-scope derived assets are recorded but BLOCKED from the active tool,
  (c) findings with no determinable host are recorded but BLOCKED (fail closed).

Only the tool subprocess boundary is mocked; the scope filter, tagging, ingestion and
storage are the real code paths. RLS stays enabled (workspace GUC set).
"""
import asyncio
import uuid

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core.config import get_settings
from apps.api.modules.assets.models import Asset
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.orchestrator import _run_single_tool
from apps.api.scanner_engine.tool_runners.base import CommonFinding, RawToolOutput
from apps.api.scanner_engine.tool_runners.httpx_runner import HttpxRunner
from apps.api.scanner_engine.tool_runners.subfinder_runner import SubfinderRunner

DOMAIN = "example.com"


async def _set_guc(session, ws_id):
    await session.execute(
        text("SELECT set_config('app.current_workspace_id', :wid, false)"), {"wid": str(ws_id)}
    )


async def _seed_domain(session):
    user = User(email=f"scope-{uuid.uuid4()}@test.local", password_hash="x", full_name="Scope Tester")
    session.add(user)
    await session.flush()
    ws = Workspace(name="scope-ws", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    await _set_guc(session, ws.id)
    project = Project(workspace_id=ws.id, name="scope-proj", created_by=user.id)
    session.add(project)
    await session.flush()
    target = Target(project_id=project.id, type="domain", value=DOMAIN, criticality="medium", added_by=user.id)
    session.add(target)
    await session.flush()
    scan = Scan(
        workspace_id=ws.id, project_id=project.id, target_id=target.id, initiated_by=user.id,
        scan_type="web", status="running", config={},
    )
    session.add(scan)
    await session.flush()
    return ws.id, scan, project.id, target.id


def test_active_tool_receives_only_in_scope_derived_hosts(monkeypatch):
    """(a)+(b)+(c): the filter at the enforcement point hands the active tool ONLY the
    in-scope derived host; the out-of-scope subdomain and the no-host finding are
    dropped from active probing (fail closed)."""
    captured: dict = {}

    async def _capture_run(self, target_value, config, prior_findings):
        captured["prior"] = list(prior_findings)
        return RawToolOutput(command="httpx (mock)", stdout="", stderr="", exit_code=0)

    monkeypatch.setattr(HttpxRunner, "run", _capture_run)

    prior = [
        CommonFinding("subdomain", "api.example.com", {"source": "subfinder"}),   # in scope
        CommonFinding("subdomain", "evil.attacker.com", {"source": "subfinder"}),  # OUT of scope
        CommonFinding("weird", "", {}),                                            # no host -> fail closed
    ]

    async def scenario():
        settings = get_settings()
        engine = create_async_engine(settings.database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                _ws, scan, _proj, _tgt = await _seed_domain(s)
                await _run_single_tool(s, scan, HttpxRunner(), DOMAIN, prior, "medium", "domain")
                await s.commit()
        finally:
            await engine.dispose()

    asyncio.run(scenario())

    handed = [f.value for f in captured["prior"]]
    assert handed == ["api.example.com"]            # ONLY the in-scope subdomain reaches the tool
    assert "evil.attacker.com" not in handed         # out-of-scope blocked
    assert "" not in handed                          # no-host finding blocked (fail closed)


def test_out_of_scope_discovery_is_recorded_as_observation(monkeypatch):
    """Out-of-scope discoveries are STORED (assets) with an in_scope=False observation
    flag -- recorded, not hidden -- while an in-scope discovery is flagged True."""
    async def _subfinder_run(self, target_value, config, prior_findings):
        stdout = (
            '{"host":"api.example.com","source":"crtsh"}\n'
            '{"host":"evil.attacker.com","source":"crtsh"}\n'
        )
        return RawToolOutput(command="subfinder (mock)", stdout=stdout, stderr="", exit_code=0)

    monkeypatch.setattr(SubfinderRunner, "run", _subfinder_run)

    async def scenario():
        settings = get_settings()
        engine = create_async_engine(settings.database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                ws, scan, _proj, target_id = await _seed_domain(s)
                findings, status = await _run_single_tool(s, scan, SubfinderRunner(), DOMAIN, [], "medium", "domain")
                await s.commit()
            async with maker() as v:
                await _set_guc(v, ws)
                assets = list(await v.scalars(select(Asset).where(Asset.target_id == target_id)))
            return findings, status, assets
        finally:
            await engine.dispose()

    findings, status, assets = asyncio.run(scenario())

    # Both discovered subdomains were ingested (recorded as observations).
    by_value = {a.value: a for a in assets}
    assert set(by_value) == {"api.example.com", "evil.attacker.com"}
    # Scope decision recorded on each stored asset.
    assert by_value["api.example.com"].metadata_["in_scope"] is True
    assert by_value["evil.attacker.com"].metadata_["in_scope"] is False
    # The returned findings carry the same tags (they flow into the graph downstream).
    tags = {f.value: f.metadata.get("in_scope") for f in findings}
    assert tags == {"api.example.com": True, "evil.attacker.com": False}
