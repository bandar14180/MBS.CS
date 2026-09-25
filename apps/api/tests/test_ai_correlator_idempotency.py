"""F3.2 -- AI Correlator idempotency.

A scan re-run (Celery F2 transient retry, reaper reclaim, DLQ replay) must NOT re-invoke the AI
correlator when an attack_narrative already exists for the scan: no duplicate AI charge / usage.
Real Postgres (attack_narratives + vulnerabilities are FORCE-RLS, so the workspace GUC is set);
the AICorrelator is replaced with a spy that records whether it was called.
"""
import asyncio
import types
import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.attack.models import AttackNarrative
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.vulnerabilities.models import Vulnerability
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.orchestrator import _synthesize_attack_narrative


class _SpyCorrelator:
    """Stand-in for AICorrelator that records each correlate() call (i.e. an AI call)."""

    calls: list = []

    def __init__(self, client=None):
        pass

    def correlate(self, findings):
        _SpyCorrelator.calls.append(findings)
        # shape mirrors CorrelationResult: the orchestrator reads groups + model/prompt version.
        return types.SimpleNamespace(groups=[], model_version="spy-model", prompt_version="spy-v")


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


async def _set_ws(session, wid):
    # Phase 0 MySQL cutover: was a Postgres set_config GUC call; tenancy.bind_workspace is the
    # app-layer replacement (a plain ContextVar set) -- see apps.api.core.tenancy.
    tenancy.bind_workspace(wid)


async def _seed(session):
    user = User(email=f"corr-{uuid.uuid4()}@t.local", password_hash="x", full_name="Corr Tester")
    session.add(user)
    await session.flush()
    ws = Workspace(name="corr-ws", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    await _set_ws(session, ws.id)
    proj = Project(workspace_id=ws.id, name="p", created_by=user.id)
    session.add(proj)
    await session.flush()
    tgt = Target(project_id=proj.id, type="domain", value="example.com", criticality="low", added_by=user.id)
    session.add(tgt)
    await session.flush()
    scan = Scan(workspace_id=ws.id, project_id=proj.id, target_id=tgt.id, initiated_by=user.id,
                scan_type="network", status="running", config={})
    session.add(scan)
    await session.flush()
    # one finding attributed to this scan so the correlator would otherwise run
    session.add(Vulnerability(project_id=proj.id, fingerprint=f"fp-{uuid.uuid4()}", title="XSS",
                              severity="high", last_seen_scan_id=scan.id))
    await session.commit()
    return ws.id, scan


async def _narrative_count(session, scan_id):
    return int(await session.scalar(
        text("SELECT count(*) FROM attack_narratives WHERE scan_id = :s"), {"s": str(scan_id)}) or 0)


def _patch(monkeypatch):
    import apps.api.ai_agent.correlator as correlator_mod
    import apps.api.ai_agent.providers.factory as factory_mod

    _SpyCorrelator.calls = []
    monkeypatch.setattr(correlator_mod, "AICorrelator", _SpyCorrelator)
    monkeypatch.setattr(factory_mod, "get_ai_client", lambda *a, **k: object())


def test_correlator_skipped_when_narrative_exists(monkeypatch):
    _patch(monkeypatch)

    async def scenario():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                ws, scan = await _seed(s)
                await _set_ws(s, ws)
                s.add(AttackNarrative(workspace_id=ws, scan_id=scan.id, summary="prior", steps=[]))
                await s.commit()
                await _synthesize_attack_narrative(s, scan)   # re-run
                return list(_SpyCorrelator.calls), await _narrative_count(s, scan.id)
        finally:
            await eng.dispose()

    calls, narratives = asyncio.run(scenario())
    assert calls == []        # the AI correlator was NOT called on the re-run
    assert narratives == 1    # still exactly one narrative (no duplicate)


def test_correlator_runs_when_no_narrative_exists(monkeypatch):
    """First run (no prior narrative) is unchanged: the correlator IS invoked and a narrative saved."""
    _patch(monkeypatch)

    async def scenario():
        eng = _engine()
        try:
            async with async_sessionmaker(eng, expire_on_commit=False)() as s:
                ws, scan = await _seed(s)
                await _set_ws(s, ws)
                await _synthesize_attack_narrative(s, scan)
                return list(_SpyCorrelator.calls), await _narrative_count(s, scan.id)
        finally:
            await eng.dispose()

    calls, narratives = asyncio.run(scenario())
    assert len(calls) == 1    # correlator invoked once (unchanged first-run behavior)
    assert narratives == 1    # narrative persisted
