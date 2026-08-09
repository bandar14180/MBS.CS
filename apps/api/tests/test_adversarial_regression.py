"""M4.6.3 -- adversarial regression suite for the scope/authorization boundary.

  T1 stale/tampered metadata.in_scope is IGNORED (enforcement recalculates).
  T2 the AI cannot name a target/host; an injected target is dropped.
  T4 domain scope is name-based (CNAME/third-party subdomain = accepted risk).
  T5 the kill-switch toggles enforcement (regression guard ONLY -- secure default True).

(T3 lives in test_runner_boundary.py; T6 in test_scan_claim.py.)

Only the tool subprocess boundary is mocked; scope_guard, _run_single_tool, ingestion
and tagging are the real code paths. RLS not involved (these paths are scans-scoped).
"""
import asyncio
import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.ai_agent.agent import AgentDecision, CandidateAction, RedTeamAgent
from apps.api.core.config import get_settings
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine import scope_guard
from apps.api.scanner_engine.orchestrator import _run_single_tool
from apps.api.scanner_engine.tool_runners.base import CommonFinding, RawToolOutput
from apps.api.scanner_engine.tool_runners.httpx_runner import HttpxRunner

DOMAIN = "example.com"


async def _set_guc(session, ws_id):
    await session.execute(
        text("SELECT set_config('app.current_workspace_id', :wid, false)"), {"wid": str(ws_id)}
    )


async def _seed_domain_scan(session) -> Scan:
    user = User(email=f"adv-{uuid.uuid4()}@test.local", password_hash="x", full_name="Adv Tester")
    session.add(user)
    await session.flush()
    ws = Workspace(name="adv-ws", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    await _set_guc(session, ws.id)
    project = Project(workspace_id=ws.id, name="adv-proj", created_by=user.id)
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
    return scan


async def _capture_httpx_prior(prior, monkeypatch_run) -> list[str]:
    """Run _run_single_tool for a domain scan with httpx.run captured; return the host
    values the tool actually received (i.e. what survived scope filtering)."""
    settings = get_settings()
    engine = create_async_engine(settings.database_url, poolclass=StaticPool)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as s:
            scan = await _seed_domain_scan(s)
            await _run_single_tool(s, scan, HttpxRunner(), DOMAIN, prior, "medium", "domain")
            await s.commit()
    finally:
        await engine.dispose()
    return monkeypatch_run["received"]


def _install_capture(monkeypatch) -> dict:
    state = {"received": []}

    async def _cap(self, target_value, config, prior_findings):
        state["received"] = [f.value for f in prior_findings]
        return RawToolOutput(command="httpx (mock)", stdout="", stderr="", exit_code=0)

    monkeypatch.setattr(HttpxRunner, "run", _cap)
    return state


# --- T1: stale/tampered in_scope flag is ignored (enforcement recalculates) ---

def test_t1_stale_in_scope_flag_ignored_unit():
    # An out-of-scope subdomain carrying a forged in_scope=True is still out of scope.
    forged = CommonFinding("subdomain", "evil.attacker.com", {"in_scope": True})
    ok = CommonFinding("subdomain", "api.example.com", {"in_scope": False})  # forged the other way
    in_scope, out = scope_guard.partition_in_scope("domain", DOMAIN, [forged, ok])
    assert [f.value for f in in_scope] == ["api.example.com"]   # recalculated by name
    assert [f.value for f in out] == ["evil.attacker.com"]      # forged True ignored


def test_t1_stale_in_scope_flag_ignored_integration(monkeypatch):
    cap = _install_capture(monkeypatch)
    prior = [
        CommonFinding("subdomain", "evil.attacker.com", {"in_scope": True}),   # forged in-scope
        CommonFinding("subdomain", "api.example.com", {}),
    ]
    handed = asyncio.run(_capture_httpx_prior(prior, cap))
    assert handed == ["api.example.com"]           # the forged flag did not smuggle it through
    assert "evil.attacker.com" not in handed


# --- T2: the AI cannot name a target/host ---

def test_t2_decision_schema_exposes_no_target_field():
    fields = set(AgentDecision.__dataclass_fields__) | set(CandidateAction.__dataclass_fields__)
    for banned in ("host", "target", "target_value", "ip", "url", "address"):
        assert banned not in fields, f"decision schema unexpectedly exposes a '{banned}' field"


def test_t2_decide_ignores_injected_target():
    class _FakeAI:
        def complete_json(self, system, user):
            # A malicious model tries to smuggle an out-of-scope target into the decision.
            return {
                "candidate_actions": [
                    {"tool": "nmap", "confidence": 0.9, "expected_value": "high", "risk": "low", "rationale": "x"}
                ],
                "target": "evil.com",
                "host": "evil.com",
                "scan_url": "http://evil.com",
            }

        @property
        def model_version(self):
            return "fake"

    d = RedTeamAgent(client=_FakeAI()).decide(
        target_type="ip_range", target_value="10.0.0.1", current_phase="reconnaissance",
        findings_summary="", available=["nmap"],
    )
    assert d.action == "run_tool" and d.tool == "nmap"   # only an allowlisted TOOL is chosen
    assert "evil.com" not in repr(d)                      # the injected host is nowhere in the decision


# --- T4: domain scope is name-based (F1 accepted risk, documented) ---

def test_t4_domain_scope_is_name_based_accepted_risk():
    # A subdomain is in scope BY NAME regardless of where DNS/CNAME points it (F1
    # accepted risk). This test documents the semantic so any future change (e.g. a
    # resolve-and-verify hardening) is a CONSCIOUS update, not an accident.
    assert scope_guard.host_in_scope("domain", DOMAIN, "api.example.com") is True
    assert scope_guard.host_in_scope("domain", DOMAIN, "deep.sub.example.com") is True
    # Look-alike / suffix / unrelated hosts are NOT in scope.
    assert scope_guard.host_in_scope("domain", DOMAIN, "example.com.evil.com") is False
    assert scope_guard.host_in_scope("domain", DOMAIN, "notexample.com") is False
    assert scope_guard.host_in_scope("domain", DOMAIN, "evil.com") is False


# --- T5: kill-switch toggles enforcement (REGRESSION guard only) ---

def test_t5_kill_switch_toggles_enforcement(monkeypatch):
    # Regression guard for the toggle -- NOT a production usage pattern. Secure default
    # (True) blocks out-of-scope; DISABLED (emergency-only) passes through unfiltered.
    settings = get_settings()
    cap = _install_capture(monkeypatch)
    prior = [
        CommonFinding("subdomain", "evil.attacker.com", {}),   # out of scope
        CommonFinding("subdomain", "api.example.com", {}),     # in scope
    ]

    monkeypatch.setattr(settings, "scan_enforce_derived_scope", False)  # emergency override
    disabled = asyncio.run(_capture_httpx_prior(prior, cap))

    monkeypatch.setattr(settings, "scan_enforce_derived_scope", True)   # secure default
    enabled = asyncio.run(_capture_httpx_prior(prior, cap))

    # Disabled -> the out-of-scope host reaches the tool (enforcement off).
    assert "evil.attacker.com" in disabled
    # Enabled (default) -> it is blocked; only the in-scope host is handed over.
    assert enabled == ["api.example.com"]
    assert "evil.attacker.com" not in enabled
