"""PHASE 3 -- quota enforcement on NON-HTTP execution paths.

The obvious quota bypass is not a clever payload -- it is an alternate code path that reaches
the same billable operation without passing the check. This file proves the two that exist in
this codebase are covered:

  1. THE SCHEDULER. `run_due_schedules()` launches scans from a Celery-beat tick, with no HTTP
     request and no `WorkspaceContextDep`. It must still consume quota, and it must take the
     workspace from the TRUSTED schedule row -- never from anything a client supplied.

  2. THE WORKER. `run_scan_task` executes scans. If it could CREATE one, a tenant could mint
     scans past their cap by going through Celery. It cannot -- it only claims and executes a
     row the API already created (and therefore already charged for). That is asserted
     structurally here so a future refactor cannot quietly introduce a worker-side insert.

Also asserted: the call graph is CLOSED. There are exactly three places that insert a
Project/Target/Scan in production code, all inside the quota-enforcing services -- so a new
bypass would have to add a fourth, which this file's structural test fails on.
"""
from __future__ import annotations

import ast
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from apps.api.modules.billing.plans import PLANS

REPO_ROOT = Path(__file__).resolve().parents[3]
API_ROOT = REPO_ROOT / "apps" / "api"

# The ONLY production functions permitted to construct these entities. Each one calls the
# corresponding billing.enforce_*_quota before inserting.
ALLOWED_INSERT_SITES = {
    "Project": {"apps/api/modules/projects/service.py"},
    "Target": {"apps/api/modules/projects/service.py"},
    "Scan": {"apps/api/modules/scans/service.py"},
}


def _production_sources():
    for path in sorted(API_ROOT.rglob("*.py")):
        if {"tests", "__pycache__"} & set(path.parts):
            continue
        yield path


# --------------------------------------------------------------------------------------------
# STRUCTURAL: the call graph is closed.
# --------------------------------------------------------------------------------------------

def test_only_the_quota_enforcing_services_construct_billable_entities():
    """THE BYPASS LOCK. A new `Scan(...)` anywhere else is, by construction, a quota bypass --
    the enforcement lives in the service, not in the model."""
    offenders: list[str] = []
    for path in _production_sources():
        rel = path.relative_to(REPO_ROOT).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            name = node.func.id
            if name in ALLOWED_INSERT_SITES and rel not in ALLOWED_INSERT_SITES[name]:
                offenders.append(f"{rel}:{node.lineno}: constructs {name}()")
    assert not offenders, (
        "a billable entity is constructed outside the quota-enforcing service -- this is a "
        "quota bypass by construction:\n" + "\n".join(offenders)
    )


def test_each_creation_service_calls_its_quota_enforcer():
    """The enforcement must actually be present in each creating function, not merely imported
    somewhere in the module."""
    expected = {
        ("apps/api/modules/projects/service.py", "create_project"): "enforce_project_quota",
        ("apps/api/modules/projects/service.py", "create_target"): "enforce_target_quota",
        ("apps/api/modules/scans/service.py", "create_scan"): "enforce_scan_quota",
    }
    for (rel, func_name), enforcer in expected.items():
        tree = ast.parse((REPO_ROOT / rel).read_text(encoding="utf-8"))
        fn = next(
            (n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == func_name),
            None,
        )
        assert fn is not None, f"{rel}: {func_name} not found"
        calls = {
            n.func.attr for n in ast.walk(fn)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        }
        assert enforcer in calls, f"{rel}:{func_name} does not call {enforcer}"


def test_worker_and_celery_tasks_never_create_billable_entities():
    """The worker executes scans; it must never mint one. If it could, Celery would be a
    quota-free scan factory."""
    offenders: list[str] = []
    for sub in ("celery_app", "scanner_engine"):
        root = API_ROOT / sub
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            src = path.read_text(encoding="utf-8")
            try:
                tree = ast.parse(src)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ALLOWED_INSERT_SITES:
                    offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}:{node.lineno}: {node.func.id}()")
                # also catch a direct call to the creating service from worker code
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "create_scan":
                    offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}:{node.lineno}: create_scan()")
    assert not offenders, "worker/scanner code creates billable entities:\n" + "\n".join(offenders)


def test_scheduler_launches_through_the_quota_enforcing_service():
    """The scheduler must reuse create_scan (which enforces quota), not insert a Scan itself."""
    src = (API_ROOT / "modules" / "schedules" / "service.py").read_text(encoding="utf-8")
    assert "from apps.api.modules.scans.service import create_scan" in src
    assert "Scan(" not in src.replace("create_scan(", ""), "the scheduler constructs a Scan directly"


def test_creation_routers_take_workspace_from_context_not_the_body():
    """A forged `workspace_id` in the request body must be impossible to honour: every creating
    router passes `ctx.workspace_id`."""
    for rel in ("apps/api/modules/projects/router.py", "apps/api/modules/scans/router.py"):
        src = (REPO_ROOT / rel).read_text(encoding="utf-8")
        for call in ("service.create_project(", "service.create_target(", "service.create_scan("):
            if call in src:
                window = src[src.index(call): src.index(call) + 400]
                assert "ctx.workspace_id" in window, f"{rel}: {call} does not use ctx.workspace_id"
                assert "payload.workspace_id" not in window, f"{rel}: {call} reads workspace from the body"


# --------------------------------------------------------------------------------------------
# RUNTIME: the scheduler actually consumes quota.
# --------------------------------------------------------------------------------------------

def test_scheduled_scan_is_refused_when_the_workspace_is_over_quota(client: TestClient, monkeypatch):
    """END-TO-END on the beat path: a workspace already at its monthly scan cap must not gain
    extra scans by scheduling them.

    The whole DB interaction runs inside ONE event loop, matching how celery-beat actually
    calls `run_due_schedules`. (Splitting it across several `asyncio.run()` calls while a
    schedule object is still attached to another loop's session raises MissingGreenlet -- an
    artifact of the test harness, not of the scheduler.)
    """
    import asyncio

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core.config import get_settings
    from apps.api.modules.schedules.service import run_due_schedules
    from apps.api.tests.test_schedule_dispatch import _make_due, _patch_delay, _setup_schedule
    from apps.api.tests.test_scans import _auth, _register

    _patch_delay(monkeypatch)
    headers = _auth(_register(client, "Sched Quota"))
    ws, project, target, sid = _setup_schedule(client, headers)

    assert client.patch(
        f"/api/v1/workspaces/{ws}/billing/plan", headers=headers, json={"tier": "free"}
    ).status_code == 200

    limit = PLANS["free"].max_scans_per_month
    assert limit is not None, "the FREE plan must define a monthly scan cap"

    async def _scenario() -> tuple[int, int, int]:
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                count_sql = text("SELECT COUNT(*) FROM scans WHERE workspace_id = :ws")
                current = int((await s.execute(count_sql, {"ws": ws})).scalar() or 0)
                # Seed to the cap with valid rows (initiated_by is NOT NULL -> take the
                # schedule's creator, so every FK stays satisfied).
                for _ in range(max(0, limit - current)):
                    await s.execute(
                        text(
                            "INSERT INTO scans (id, workspace_id, project_id, target_id, "
                            "initiated_by, scan_type, status, config, created_at) "
                            "SELECT :id, :ws, :proj, :tgt, created_by, 'network', 'completed', "
                            "'{}', UTC_TIMESTAMP() FROM scan_schedules WHERE id = :sid"
                        ),
                        {"id": str(uuid.uuid4()), "ws": ws, "proj": project, "tgt": target, "sid": sid},
                    )
                await s.commit()
                before = int((await s.execute(count_sql, {"ws": ws})).scalar() or 0)
                launched = await run_due_schedules(s)
                after = int((await s.execute(count_sql, {"ws": ws})).scalar() or 0)
                return before, launched, after
        finally:
            await engine.dispose()

    _make_due(sid)
    before, launched, after = asyncio.run(_scenario())

    assert before >= limit, f"failed to seed the workspace to its cap ({before} < {limit})"
    assert launched == 0, "the scheduler launched a scan for an over-quota workspace"
    assert after == before, (
        f"scan quota bypassed via the scheduler: {before} -> {after} (FREE cap {limit})"
    )


def test_scheduler_uses_the_schedules_own_workspace(client: TestClient):
    """The beat path has no request context, so the workspace comes from the schedule ROW.
    That row was created through an authorized, workspace-scoped endpoint."""
    src = (API_ROOT / "modules" / "schedules" / "service.py").read_text(encoding="utf-8")
    window = src[src.index("create_scan("): src.index("create_scan(") + 300]
    assert "sched.workspace_id" in window, (
        "the scheduler must pass the schedule row's own workspace_id to create_scan"
    )
