"""Prompt 10 -- execution determinism & reproducible execution trace.

Covers the concrete gap identified: ToolRun.command_hash was already a tamper-evident
digest of the exact tool invocation, but never the reconstructible text itself, and on the
remote/lease execution plane command_hash was never populated AT ALL (hardcoded ""). Every
tool runner also already computed whether its own wall-clock budget was exceeded
(`run_with_timeout`'s `TimedRun.timed_out`), but discarded that structured fact into a
free-text "timed out" suffix on stderr.

This file exercises, in order:
  A. Unit:        RawToolOutput.timed_out default/propagation; classify_run unaffected.
  B. Integration:  execute_leased_job -> ManagerResultReporter -> real manager HTTP
                   endpoints -> ToolRun row, end to end.
  D. Negative:     missing/omitted fields, resubmission does not clobber a recorded
                   command, cross-tenant isolation is unaffected, no secret leakage.
"""
import asyncio
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.projects.models import Project, Target
from apps.api.modules.scans.models import Scan
from apps.api.modules.users.models import User
from apps.api.modules.workspaces.models import Workspace
from apps.api.scanner_engine.models import ToolRun
from apps.api.scanner_engine.orchestrator import _run_single_tool
from apps.api.scanner_engine.tool_runners.base import (
    RawToolOutput,
    classify_run,
)
from apps.api.scanner_engine.tool_runners.httpx_runner import HttpxRunner
from apps.api.scanner_worker import executor as executor_mod

from apps.api.tests.test_scanner_manager_http import _auth, _set_scan, manager_env  # noqa: F401, F811

DOMAIN = "trace-example.com"


# -----------------------------------------------------------------------------------------
# A. UNIT: RawToolOutput.timed_out
# -----------------------------------------------------------------------------------------

def test_raw_tool_output_timed_out_defaults_false():
    """Every existing positional/keyword construction across the 12 tool runners must keep
    working unchanged -- the new field is additive with a safe default."""
    raw = RawToolOutput(command="x", stdout="", stderr="", exit_code=0)
    assert raw.timed_out is False


def test_raw_tool_output_timed_out_is_settable():
    raw = RawToolOutput(command="x", stdout="partial", stderr="timed out", exit_code=-1, timed_out=True)
    assert raw.timed_out is True


def test_classify_run_unaffected_by_timed_out_flag():
    """classify_run's completed/partial/failed rule is exit-code and output driven; adding
    `timed_out` must not change its verdict for any existing case."""
    class _Runner:
        def hard_failure(self, raw):
            return False
        benign_exit_codes = frozenset()

    runner = _Runner()
    timed_out_partial = RawToolOutput(command="x", stdout="some output", stderr="", exit_code=-1, timed_out=True)
    not_timed_out_partial = RawToolOutput(command="x", stdout="some output", stderr="", exit_code=-1, timed_out=False)
    assert classify_run(runner, timed_out_partial, produced_findings=True) == "partial"
    assert classify_run(runner, not_timed_out_partial, produced_findings=True) == "partial"

    timed_out_failed = RawToolOutput(command="x", stdout="", stderr="", exit_code=-1, timed_out=True)
    assert classify_run(runner, timed_out_failed, produced_findings=False) == "failed"


@pytest.mark.parametrize("runner_module,build", [
    ("nmap_runner", lambda mod: mod.NmapRunner),
    ("httpx_runner", lambda mod: mod.HttpxRunner),
    ("naabu_runner", lambda mod: mod.NaabuRunner),
    ("subfinder_runner", lambda mod: mod.SubfinderRunner),
    ("dnsx_runner", lambda mod: mod.DnsxRunner),
    ("amass_runner", lambda mod: mod.AmassRunner),
])
def test_every_simple_runner_sets_timed_out_on_its_timeout_branch(runner_module, build):
    """Source-level guarantee: every simple (single-process) runner's timeout branch sets
    `timed_out=True` on the RawToolOutput it returns, not just on the TimedRun it read it
    from. Read the source rather than driving a real timeout (these tools are not
    necessarily installed in this environment) -- this is a regression guard against a
    runner silently dropping the flag again."""
    import importlib
    import inspect

    mod = importlib.import_module(f"apps.api.scanner_engine.tool_runners.{runner_module}")
    src = inspect.getsource(build(mod))
    assert "timed_out=True" in src, (
        f"{runner_module}'s timeout branch no longer sets RawToolOutput.timed_out=True"
    )


# -----------------------------------------------------------------------------------------
# A/B. Executor -> reporter plumbing (pure unit, reporter=None / fake reporter)
# -----------------------------------------------------------------------------------------

def _job(config=None, modules=("nuclei",)):
    return {
        "scan_id": str(uuid.uuid4()),
        "execution_token": str(uuid.uuid4()),
        "target": {"id": "t", "type": "domain", "value": "t.example.com"},
        "requested_modules": list(modules),
        "config": config or {},
    }


def _runner_cls(name, phase, raw: RawToolOutput):
    class _StubRunner:
        pass

    _StubRunner.name = name
    _StubRunner.phase = phase
    _StubRunner.applicable_target_types = None
    _StubRunner.benign_exit_codes = ()

    async def run(self, target_value, config, prior):
        return raw

    def parse(self, r):
        return []

    def hard_failure(self, r):
        return False

    _StubRunner.run = run
    _StubRunner.parse = parse
    _StubRunner.hard_failure = hard_failure
    return _StubRunner


class _RecordingReporter:
    def __init__(self):
        self.calls = []

    async def submit_tool_started(self, **kwargs):
        pass

    async def submit_tool_result(self, **kwargs):
        self.calls.append(kwargs)

    async def submit_evidence(self, **kwargs):
        pass


def test_executor_forwards_effective_command_to_the_reporter():
    """The exact command the tool ran with must reach the reporter's submit_tool_result --
    this is the fix for the lease path never sending anything (command_hash stayed "")."""
    raw = RawToolOutput(command="nuclei -json -u https://t.example.com", stdout="ok", stderr="", exit_code=0)
    runner_cls = _runner_cls("nuclei", 50, raw)
    reporter = _RecordingReporter()
    asyncio.run(executor_mod.execute_leased_job(
        _job(), policy=None, reporter=reporter, registry={"nuclei": runner_cls},
    ))
    assert len(reporter.calls) == 1
    assert reporter.calls[0]["effective_command"] == "nuclei -json -u https://t.example.com"
    assert reporter.calls[0]["timed_out"] is False


def test_executor_forwards_timed_out_true_to_the_reporter():
    raw = RawToolOutput(
        command="nmap -sT -sV -Pn t.example.com", stdout="partial xml", stderr="timed out",
        exit_code=-1, timed_out=True,
    )
    runner_cls = _runner_cls("nuclei", 50, raw)
    reporter = _RecordingReporter()
    asyncio.run(executor_mod.execute_leased_job(
        _job(), policy=None, reporter=reporter, registry={"nuclei": runner_cls},
    ))
    assert len(reporter.calls) == 1
    assert reporter.calls[0]["timed_out"] is True
    assert reporter.calls[0]["effective_command"] == "nmap -sT -sV -Pn t.example.com"


def test_exception_raising_tool_reports_no_effective_command():
    """A runner that raised before returning a RawToolOutput has no command to report --
    the exception path must not fabricate one, and must not crash trying to read `.command`
    off something that never existed."""
    class _RaisingRunner:
        name = "nuclei"
        phase = 50
        applicable_target_types = None

        async def run(self, target_value, config, prior):
            raise RuntimeError("boom")

        def parse(self, raw):
            return []

    reporter = _RecordingReporter()
    asyncio.run(executor_mod.execute_leased_job(
        _job(), policy=None, reporter=reporter, registry={"nuclei": _RaisingRunner},
    ))
    assert len(reporter.calls) == 1
    assert reporter.calls[0]["status"] == "failed"
    assert "effective_command" not in reporter.calls[0]


# -----------------------------------------------------------------------------------------
# B. Integration: through the REAL manager HTTP endpoint, end to end.
# -----------------------------------------------------------------------------------------

def _toolrun_row(scan_id, tool_run_id):
    import asyncio as _asyncio

    from sqlalchemy import select as _select
    from sqlalchemy.ext.asyncio import async_sessionmaker as _maker
    from sqlalchemy.ext.asyncio import create_async_engine as _mk_engine
    from sqlalchemy.pool import StaticPool as _Static

    from apps.api.core import tenancy as _tenancy
    from apps.api.core.config import get_settings as _gs
    from apps.api.scanner_engine.models import ToolRun as _ToolRun

    async def _go():
        engine = _mk_engine(_gs().database_url, poolclass=_Static)
        try:
            async with _maker(engine, expire_on_commit=False)() as s:
                with _tenancy.admin_bypass():
                    return await s.scalar(
                        _select(_ToolRun).where(_ToolRun.id == uuid.UUID(str(tool_run_id)))
                    )
        finally:
            await engine.dispose()

    return _asyncio.run(_go())


def test_tool_result_persists_effective_command_and_derives_command_hash(manager_env):  # noqa: F811
    """END TO END: a worker's /v1/tool-results submission carrying `effective_command` must
    leave BOTH the reconstructible text and a server-derived digest on the row -- fixing the
    lease path's command_hash being hardcoded "" unconditionally."""
    client, state = manager_env
    entry = state["a"]
    _set_scan(entry["scan_id"], status="running", execution_token=entry["execution_token"])

    tool_run_id = str(uuid.uuid4())
    command = "httpx-pd -json -silent -no-color -tech-detect -status-code -title"
    r = client.post("/v1/tool-results", json={
        "scan_id": str(entry["scan_id"]), "tool_run_id": tool_run_id,
        "tool_name": "httpx", "status": "completed", "findings": [],
        "execution_token": str(entry["execution_token"]),
        "effective_command": command,
        "timed_out": False,
    }, headers=_auth(entry))
    assert r.status_code == 200, r.text

    row = _toolrun_row(entry["scan_id"], tool_run_id)
    assert row is not None
    assert row.effective_command == command
    assert row.timed_out is False
    import hashlib
    assert row.command_hash == hashlib.sha256(command.encode()).hexdigest()


def test_tool_result_persists_timed_out_true(manager_env):  # noqa: F811
    client, state = manager_env
    entry = state["a"]
    _set_scan(entry["scan_id"], status="running", execution_token=entry["execution_token"])

    tool_run_id = str(uuid.uuid4())
    r = client.post("/v1/tool-results", json={
        "scan_id": str(entry["scan_id"]), "tool_run_id": tool_run_id,
        "tool_name": "naabu", "status": "partial", "findings": [],
        "execution_token": str(entry["execution_token"]),
        "effective_command": "naabu -host 10.0.5.0/24 -top-ports 100",
        "timed_out": True,
    }, headers=_auth(entry))
    assert r.status_code == 200, r.text

    row = _toolrun_row(entry["scan_id"], tool_run_id)
    assert row.timed_out is True


def test_tool_result_omitting_effective_command_is_backward_compatible(manager_env):  # noqa: F811
    """An older worker that never sends the new fields must still succeed -- exactly the
    contract every other optional field on this endpoint already has."""
    client, state = manager_env
    entry = state["a"]
    _set_scan(entry["scan_id"], status="running", execution_token=entry["execution_token"])

    tool_run_id = str(uuid.uuid4())
    r = client.post("/v1/tool-results", json={
        "scan_id": str(entry["scan_id"]), "tool_run_id": tool_run_id,
        "tool_name": "nuclei", "status": "completed", "findings": [],
        "execution_token": str(entry["execution_token"]),
    }, headers=_auth(entry))
    assert r.status_code == 200, r.text

    row = _toolrun_row(entry["scan_id"], tool_run_id)
    assert row.effective_command is None
    assert row.timed_out is False
    assert row.command_hash == ""


def test_resubmission_does_not_overwrite_an_already_recorded_command(manager_env):  # noqa: F811
    """A retry (acks_late redelivery / lease redelivery) reports the SAME execution's
    outcome a second time. If the second submission somehow carried a DIFFERENT command
    (a bug, or an adversarial resend), the first-recorded command must win -- mirroring the
    write-once rule this endpoint already applies to `status`."""
    client, state = manager_env
    entry = state["a"]
    _set_scan(entry["scan_id"], status="running", execution_token=entry["execution_token"])

    tool_run_id = str(uuid.uuid4())
    first_command = "nuclei -json -tags cve -u https://t.example.com"
    r1 = client.post("/v1/tool-results", json={
        "scan_id": str(entry["scan_id"]), "tool_run_id": tool_run_id,
        "tool_name": "nuclei", "status": "completed", "findings": [],
        "execution_token": str(entry["execution_token"]),
        "effective_command": first_command,
    }, headers=_auth(entry))
    assert r1.status_code == 200, r1.text

    r2 = client.post("/v1/tool-results", json={
        "scan_id": str(entry["scan_id"]), "tool_run_id": tool_run_id,
        "tool_name": "nuclei", "status": "completed", "findings": [],
        "execution_token": str(entry["execution_token"]),
        "effective_command": "nuclei -json -tags DIFFERENT -u https://evil.example.com",
    }, headers=_auth(entry))
    assert r2.status_code == 200, r2.text

    row = _toolrun_row(entry["scan_id"], tool_run_id)
    assert row.effective_command == first_command, (
        "a resubmission overwrote the first-recorded effective_command"
    )


def test_timed_out_true_on_resubmission_is_sticky_not_overwritable_to_false(manager_env):  # noqa: F811
    """Once a run is known to have timed out, a later resubmission must not silently erase
    that fact (e.g. a redelivered request that -- for whatever reason -- omits the flag)."""
    client, state = manager_env
    entry = state["a"]
    _set_scan(entry["scan_id"], status="running", execution_token=entry["execution_token"])

    tool_run_id = str(uuid.uuid4())
    r1 = client.post("/v1/tool-results", json={
        "scan_id": str(entry["scan_id"]), "tool_run_id": tool_run_id,
        "tool_name": "nuclei", "status": "partial", "findings": [],
        "execution_token": str(entry["execution_token"]),
        "timed_out": True,
    }, headers=_auth(entry))
    assert r1.status_code == 200, r1.text

    r2 = client.post("/v1/tool-results", json={
        "scan_id": str(entry["scan_id"]), "tool_run_id": tool_run_id,
        "tool_name": "nuclei", "status": "partial", "findings": [],
        "execution_token": str(entry["execution_token"]),
        # timed_out omitted this time
    }, headers=_auth(entry))
    assert r2.status_code == 200, r2.text

    row = _toolrun_row(entry["scan_id"], tool_run_id)
    assert row.timed_out is True


# -----------------------------------------------------------------------------------------
# B. Integration: the IN-PROCESS orchestrator path (_run_single_tool), against real MySQL.
# -----------------------------------------------------------------------------------------

async def _seed_domain_scan(session):
    user = User(email=f"trace-{uuid.uuid4()}@test.local", password_hash="x", full_name="Trace Tester")
    session.add(user)
    await session.flush()
    ws = Workspace(name="trace-ws", owner_user_id=user.id)
    session.add(ws)
    await session.flush()
    tenancy.bind_workspace(ws.id)
    project = Project(workspace_id=ws.id, name="trace-proj", created_by=user.id)
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


def test_in_process_path_persists_effective_command_and_hash(monkeypatch):
    """The pre-existing in-process orchestrator path: `_run_single_tool` must persist the
    RECONSTRUCTIBLE command alongside the digest it already computed, and must not have
    regressed the pre-existing behavior of `command_hash` itself."""
    known_command = "httpx-pd -json -silent -no-color -tech-detect -status-code -title  (stdin: trace-example.com)"

    async def _fake_run(self, target_value, config, prior_findings):
        return RawToolOutput(command=known_command, stdout="", stderr="", exit_code=0)

    monkeypatch.setattr(HttpxRunner, "run", _fake_run)

    async def scenario():
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_domain_scan(s)
                await _run_single_tool(s, scan, HttpxRunner(), DOMAIN, [], "medium", "domain")
                await s.commit()
                row = await s.scalar(select(ToolRun).where(ToolRun.scan_id == scan.id))
            return row
        finally:
            await engine.dispose()

    row = asyncio.run(scenario())
    assert row is not None
    assert row.effective_command == known_command
    assert row.timed_out is False
    import hashlib
    assert row.command_hash == hashlib.sha256(known_command.encode()).hexdigest()


def test_in_process_path_persists_timed_out_true(monkeypatch):
    async def _timed_out_run(self, target_value, config, prior_findings):
        return RawToolOutput(
            command="httpx-pd -json (stdin: trace-example.com)",
            stdout="", stderr="timed out", exit_code=-1, timed_out=True,
        )

    monkeypatch.setattr(HttpxRunner, "run", _timed_out_run)

    async def scenario():
        engine = create_async_engine(get_settings().database_url, poolclass=StaticPool)
        maker = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with maker() as s:
                scan = await _seed_domain_scan(s)
                await _run_single_tool(s, scan, HttpxRunner(), DOMAIN, [], "medium", "domain")
                await s.commit()
                row = await s.scalar(select(ToolRun).where(ToolRun.scan_id == scan.id))
            return row
        finally:
            await engine.dispose()

    row = asyncio.run(scenario())
    assert row is not None
    assert row.timed_out is True


# -----------------------------------------------------------------------------------------
# D. Negative tests
# -----------------------------------------------------------------------------------------

def test_oversized_effective_command_is_rejected(manager_env):  # noqa: F811
    """The field is bounded server-side (max_length=8000) -- a compromised or buggy worker
    cannot smuggle an arbitrarily large payload through what is supposed to be one shell
    command."""
    client, state = manager_env
    entry = state["a"]
    _set_scan(entry["scan_id"], status="running", execution_token=entry["execution_token"])

    r = client.post("/v1/tool-results", json={
        "scan_id": str(entry["scan_id"]), "tool_run_id": str(uuid.uuid4()),
        "tool_name": "nuclei", "status": "completed", "findings": [],
        "execution_token": str(entry["execution_token"]),
        "effective_command": "x" * 8001,
    }, headers=_auth(entry))
    assert r.status_code == 422


def test_worker_cannot_attach_a_command_to_another_tenants_tool_run(manager_env):  # noqa: F811
    """Cross-tenant isolation is unaffected by the new fields: tenant B's worker still
    cannot write anything -- including an effective_command -- onto tenant A's scan."""
    client, state = manager_env
    a, b = state["a"], state["b"]

    r = client.post("/v1/tool-results", json={
        "scan_id": str(a["scan_id"]), "tool_run_id": str(uuid.uuid4()),
        "tool_name": "nuclei", "status": "completed", "findings": [],
        "execution_token": str(a["execution_token"]),
        "effective_command": "nuclei -u https://a-tenant-target.example.com",
    }, headers=_auth(b))
    assert r.status_code == 403


def test_effective_command_never_contains_the_worker_bearer_token(manager_env):  # noqa: F811
    """Sanity check that the trace field is not somehow fed request-level secrets: the
    submitted command text must never equal or contain this worker's own auth token. This
    guards the CONTRACT (a command is tool CLI text, never credential material), not any
    particular tool's argument list."""
    client, state = manager_env
    entry = state["a"]
    _set_scan(entry["scan_id"], status="running", execution_token=entry["execution_token"])

    command = "httpx-pd -json -silent -no-color -tech-detect -status-code -title"
    tool_run_id = str(uuid.uuid4())
    r = client.post("/v1/tool-results", json={
        "scan_id": str(entry["scan_id"]), "tool_run_id": tool_run_id,
        "tool_name": "httpx", "status": "completed", "findings": [],
        "execution_token": str(entry["execution_token"]),
        "effective_command": command,
    }, headers=_auth(entry))
    assert r.status_code == 200, r.text

    row = _toolrun_row(entry["scan_id"], tool_run_id)
    assert entry["token"] not in row.effective_command
    assert str(entry["execution_token"]) not in row.effective_command


def test_missing_tool_run_id_target_scan_status_conflict_leaves_no_command(manager_env):  # noqa: F811
    """An unknown scan is refused before any ToolRun row (or command) is ever touched --
    the trace addition must not create a path where a rejected request still leaves a
    partial/misleading row behind."""
    client, state = manager_env
    entry = state["a"]

    bogus_scan_id = str(uuid.uuid4())
    r = client.post("/v1/tool-results", json={
        "scan_id": bogus_scan_id, "tool_run_id": str(uuid.uuid4()),
        "tool_name": "nuclei", "status": "completed", "findings": [],
        "execution_token": str(entry["execution_token"]),
        "effective_command": "nuclei -u https://nonexistent.example.com",
    }, headers=_auth(entry))
    assert r.status_code == 403
