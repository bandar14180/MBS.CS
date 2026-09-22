"""MBS.SC PHASE 8 (P8-F) -- the uptime anchor's IMPORT LIFECYCLE.

WHY THIS FILE EXISTS, AND WHY THE EXISTING COLD-START TESTS WERE NOT ENOUGH
--------------------------------------------------------------------------
`test_p8f_reaper_cold_start.py` pins the gate's BEHAVIOUR by patching
`platform_uptime.time.monotonic` directly. That is the right way to test boundary
arithmetic deterministically -- but it patches the clock AFTER the module is imported, so it
cannot see WHEN the module was imported. The first shipped version of this fix imported
`platform_uptime` lazily, inside `reap_stale_workers()`, and all 23 of those tests passed
against it.

Runtime validation on 2026-09-17 found what they could not. Celery's `worker-default` runs
`concurrency: 12 (prefork)` with `worker_max_tasks_per_child = 50`. With a lazy import the
module was first executed inside a forked CHILD, on that child's first sweep, so each child
started its own `_PROCESS_START_MONOTONIC`:

    11:17:27  ForkPoolWorker-1  reap_skipped_startup_grace uptime=0.0s grace=600.0s
    11:22:27  ForkPoolWorker-8  reap_skipped_startup_grace uptime=0.0s grace=600.0s

300 seconds apart, both reporting zero. The 600s grace could never expire: stale-worker
detection was disabled outright -- strictly worse than the incident it was written to fix,
and invisible, because the gate's log line looks identical either way.

WHAT THESE TESTS PIN
--------------------
The LIFECYCLE, not the arithmetic:

  * the anchor is initialised in the MainProcess, at the point Celery actually boots, BEFORE
    any fork (test 1);
  * forked children inherit that one anchor rather than creating their own (test 2);
  * uptime therefore ADVANCES between sweeps instead of resetting to 0 (test 3);
  * a RECYCLED child (worker_max_tasks_per_child) still inherits the original anchor (test 4).

Tests 5-9 re-pin the behavioural contract through the real import path, and test 10 is the
anti-regression guard for the lazy import itself.

These use real `fork` where the platform provides it. On a non-fork platform the
inheritance tests skip rather than assert something the OS does not do -- the deployed
target is Linux/fork (asserted in test 2).
"""
import asyncio
import importlib
import inspect
import multiprocessing as mp
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.scanner_workers import service as workers_service
from apps.api.modules.scanner_workers.models import ScannerWorker

STALE = 600

# The module the Celery MainProcess loads at boot via the app's `include=` list. This is the
# module whose IMPORT must establish the anchor, so it is named once here.
TASK_MODULE = "apps.api.celery_app.tasks.scan_tasks"
UPTIME_MODULE = "apps.api.core.platform_uptime"

_HAS_FORK = hasattr(os, "fork") and "fork" in mp.get_all_start_methods()
_needs_fork = pytest.mark.skipif(not _HAS_FORK, reason="requires a fork start method")


# =========================================================================================
# helpers
# =========================================================================================

def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


def _worker(**kw) -> ScannerWorker:
    return ScannerWorker(
        id=uuid.uuid4(),
        worker_id=kw.get("worker_id", f"lz-{uuid.uuid4().hex[:10]}"),
        pool_id=kw.get("pool_id", "public-default"),
        site_id=kw.get("site_id"),
        workspace_id=kw.get("workspace_id"),
        status=kw.get("status", "active"),
        health_state=kw.get("health_state", "healthy"),
        last_seen_at=kw.get("last_seen_at", datetime.now(timezone.utc) - timedelta(seconds=9999)),
        revoked_at=kw.get("revoked_at"),
    )


async def _run(rows, *, stale=STALE, grace=0.0):
    engine = _engine()
    Session = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with Session() as s:
            with tenancy.admin_bypass():
                for r in rows:
                    s.add(r)
                await s.commit()
                suspended = await workers_service.reap_stale_workers(
                    s, stale, startup_grace_seconds=grace
                )
                out = {}
                for r in rows:
                    got = await s.scalar(select(ScannerWorker).where(ScannerWorker.id == r.id))
                    await s.refresh(got)
                    out[got.worker_id] = got
                return suspended, out
    finally:
        await engine.dispose()


def _uptime(monkeypatch, seconds: float):
    """Pin apparent uptime by patching the CLOCK, leaving the anchor and the real boundary
    arithmetic in place."""
    from apps.api.core import platform_uptime

    monkeypatch.setattr(
        platform_uptime.time, "monotonic",
        lambda: platform_uptime._PROCESS_START_MONOTONIC + seconds,
    )


# --- subprocess bodies (module-level so they are picklable under any start method) -------

def _child_reports_anchor(conn):
    """Runs in a forked child. Imports the module the way production code does."""
    from apps.api.core import platform_uptime as pu

    conn.send((os.getpid(), pu._PROCESS_START_MONOTONIC, pu.process_uptime_seconds()))
    conn.close()


def _boot_like_celery_mainprocess(conn):
    """Reproduce the MainProcess boot sequence in a clean interpreter, then report whether
    the anchor module was loaded as a RESULT of that boot -- not by this test importing it.

    `import_default_modules()` is the call Celery's worker bootstep makes at startup to load
    the app's `include=` list. It is the real pre-fork boundary.
    """
    loaded_before = UPTIME_MODULE in sys.modules
    from apps.api.celery_app.worker import celery_app

    loaded_after_app_import = UPTIME_MODULE in sys.modules
    celery_app.loader.import_default_modules()
    loaded_after_boot = UPTIME_MODULE in sys.modules
    task_loaded = TASK_MODULE in sys.modules
    conn.send({
        "before": loaded_before,
        "after_app_import": loaded_after_app_import,
        "after_boot": loaded_after_boot,
        "task_module_loaded": task_loaded,
    })
    conn.close()


# =========================================================================================
# TEST 1 -- PARENT INITIALIZATION (anchor exists in MainProcess, before any fork)
# =========================================================================================

@_needs_fork
def test_celery_mainprocess_boot_loads_the_uptime_anchor_before_fork():
    """THE CORE LIFECYCLE ASSERTION.

    Runs Celery's real boot sequence in a CLEAN interpreter (a fresh process, so this test
    file's own imports cannot mask the result) and asserts the anchor module is loaded as a
    consequence of that boot. Under the lazy import this returned after_boot=False, which is
    exactly the defect.
    """
    ctx = mp.get_context("fork")
    parent_conn, child_conn = ctx.Pipe()
    p = ctx.Process(target=_boot_like_celery_mainprocess, args=(child_conn,))
    p.start()
    result = parent_conn.recv()
    p.join(60)

    assert result["task_module_loaded"] is True, (
        "scan_tasks must be loaded by the MainProcess boot (it is in the app's include= list)"
    )
    assert result["after_boot"] is True, (
        "REGRESSION: platform_uptime was NOT loaded during MainProcess boot. The anchor will "
        "then be created inside a forked child on its first sweep, every child gets its own "
        "origin, uptime stays 0.0s and the startup grace never expires."
    )


def test_the_task_module_imports_the_anchor_at_module_scope():
    """The mechanism behind test 1: the import must be at module scope in the module Celery
    loads at boot. A function-local import would still satisfy 'the name is used somewhere'
    but would NOT run before fork."""
    mod = importlib.import_module(TASK_MODULE)
    src = inspect.getsource(mod)
    head = src.split("def ", 1)[0]  # module preamble, before the first function definition
    assert "from apps.api.core import platform_uptime" in head, (
        "platform_uptime must be imported at MODULE scope in scan_tasks.py so the anchor is "
        "established during MainProcess boot, before prefork."
    )


# =========================================================================================
# TEST 2 -- CHILDREN INHERIT THE SAME ANCHOR
# =========================================================================================

@_needs_fork
def test_forked_children_all_inherit_the_parent_anchor():
    """parent anchor = X  ->  child1 = X, child2 = X, child3 = X.

    NOT child1=A, child2=B, child3=C (independent anchors), and NOT 'anchor = first task
    execution time'. Real fork, three children, exact float equality.
    """
    from apps.api.core import platform_uptime as pu

    parent_anchor = pu._PROCESS_START_MONOTONIC
    ctx = mp.get_context("fork")

    time.sleep(0.25)  # let real time pass, so a re-initialised anchor would differ visibly

    seen = []
    for _ in range(3):
        parent_conn, child_conn = ctx.Pipe()
        p = ctx.Process(target=_child_reports_anchor, args=(child_conn,))
        p.start()
        seen.append(parent_conn.recv())
        p.join(30)

    pids = {pid for pid, _, _ in seen}
    assert len(pids) == 3, f"expected three distinct children, got {pids}"

    for pid, anchor, uptime in seen:
        assert anchor == parent_anchor, (
            f"child {pid} created its OWN anchor ({anchor}) instead of inheriting the "
            f"parent's ({parent_anchor}) -- this is the lazy-import defect."
        )
        assert uptime > 0.0, (
            f"child {pid} reported uptime={uptime}; a child inheriting the parent's anchor "
            f"must measure real elapsed time, never 0.0"
        )


@_needs_fork
def test_the_fork_start_method_is_the_default_where_it_exists():
    """The inheritance argument above depends on `fork`, which is what the DEPLOYED target
    (Linux container, `concurrency: 12 (prefork)`) provides.

    Skipped on a platform without fork -- notably the Windows dev host, which offers only
    `spawn`. That skip is honest rather than a weakened assertion: on spawn a child would
    re-import and reset the anchor, so the inheritance tests genuinely cannot be evaluated
    there, and asserting otherwise would be asserting something the OS does not do. The
    Linux behaviour is verified by running this suite inside the worker image.
    """
    assert mp.get_start_method(allow_none=False) == "fork", (
        "where fork is available it must be the default, since platform_uptime's "
        "inheritance guarantee depends on it"
    )


# =========================================================================================
# TEST 3 -- THE ANCHOR DOES NOT RESET BETWEEN REAPER CALLS
# =========================================================================================

def test_uptime_advances_between_successive_reaper_calls():
    """first execution uptime > 0, later execution LARGER. Never 0 -> 0.

    Uses the real clock (no patching) so nothing can mask a reset: it calls the gate twice
    with a real delay and asserts monotonic growth.
    """
    from apps.api.core.platform_uptime import process_uptime_seconds

    first = process_uptime_seconds()
    time.sleep(0.2)
    second = process_uptime_seconds()

    assert first > 0.0, "uptime must be measured from process start, not from this call"
    assert second > first, f"uptime did not advance: {first} -> {second}"


@_needs_fork
def test_uptime_advances_across_two_sweeps_in_the_same_child():
    """The runtime symptom, reproduced end-to-end: two sweeps in ONE child must report
    increasing uptime. Under the lazy import both reported 0.0s."""
    ctx = mp.get_context("fork")
    parent_conn, child_conn = ctx.Pipe()

    def _two_sweeps(conn):
        from apps.api.core import platform_uptime as pu

        a = pu.process_uptime_seconds()
        time.sleep(0.2)
        b = pu.process_uptime_seconds()
        conn.send((a, b))
        conn.close()

    p = ctx.Process(target=_two_sweeps, args=(child_conn,))
    p.start()
    a, b = parent_conn.recv()
    p.join(30)

    assert a > 0.0 and b > a, f"uptime must advance within a child, got {a} -> {b}"


# =========================================================================================
# TEST 4 -- CHILD RECYCLING (worker_max_tasks_per_child = 50)
# =========================================================================================

@_needs_fork
def test_a_recycled_child_still_inherits_the_original_anchor():
    """MainProcess anchor = X; child A starts (inherits X), exits; child B starts LATER and
    must still inherit X -- a replacement child is forked from the same parent.

    This is what makes `worker_max_tasks_per_child = 50` safe: without it, every 50 tasks
    would re-arm the 600s grace and the reaper would never run again.
    """
    from apps.api.core import platform_uptime as pu

    parent_anchor = pu._PROCESS_START_MONOTONIC
    ctx = mp.get_context("fork")

    # Child A -- the one that "reaches its task limit" and exits.
    conn_a, child_a = ctx.Pipe()
    pa = ctx.Process(target=_child_reports_anchor, args=(child_a,))
    pa.start()
    pid_a, anchor_a, uptime_a = conn_a.recv()
    pa.join(30)
    assert not pa.is_alive(), "child A should have exited (simulating recycling)"

    time.sleep(0.3)  # real time passes between the recycle and the replacement

    # Child B -- the replacement forked after A died.
    conn_b, child_b = ctx.Pipe()
    pb = ctx.Process(target=_child_reports_anchor, args=(child_b,))
    pb.start()
    pid_b, anchor_b, uptime_b = conn_b.recv()
    pb.join(30)

    assert pid_a != pid_b, "the replacement must be a different process"
    assert anchor_a == parent_anchor, "child A did not inherit the parent anchor"
    assert anchor_b == parent_anchor, (
        "REGRESSION: the RECYCLED child created a fresh anchor. Child recycling would then "
        "re-arm the startup grace every 50 tasks and permanently disable stale detection."
    )
    assert uptime_b > uptime_a, (
        f"the replacement child must see MORE uptime than its predecessor "
        f"({uptime_b} vs {uptime_a}), not a reset"
    )


# =========================================================================================
# TEST 5 -- GRACE EXPIRES (exclusive boundary at exactly 600)
# =========================================================================================

def test_below_the_grace_the_sweep_is_skipped(monkeypatch):
    _uptime(monkeypatch, STALE - 1)
    w = _worker(status="active")
    n, rows = asyncio.run(_run([w], grace=STALE))
    assert n == 0
    assert rows[w.worker_id].status == "active"


def test_at_exactly_the_grace_normal_evaluation_resumes(monkeypatch):
    """Boundary is EXCLUSIVE (`uptime < grace`), so at exactly 600 the reaper evaluates."""
    _uptime(monkeypatch, STALE)
    w = _worker(status="active")
    n, rows = asyncio.run(_run([w], grace=STALE))
    assert n == 1
    assert rows[w.worker_id].status == "suspended"


def test_the_boundary_semantics_are_strictly_less_than(monkeypatch):
    from apps.api.core.platform_uptime import within_startup_grace

    _uptime(monkeypatch, STALE - 0.001)
    assert within_startup_grace(STALE) is True
    _uptime(monkeypatch, STALE)
    assert within_startup_grace(STALE) is False
    _uptime(monkeypatch, STALE + 0.001)
    assert within_startup_grace(STALE) is False


# =========================================================================================
# TEST 6 -- A REAL STALE WORKER STILL SUSPENDS AFTER THE GRACE
# =========================================================================================

def test_a_genuinely_stale_worker_is_suspended_after_the_grace(monkeypatch):
    """Not merely 'the gate expired' -- the reaper must actually do its job: active ->
    suspended, with the audit reason it always recorded."""
    _uptime(monkeypatch, STALE * 10)
    w = _worker(status="active",
                last_seen_at=datetime.now(timezone.utc) - timedelta(seconds=STALE + 30))
    n, rows = asyncio.run(_run([w], grace=STALE))
    assert n == 1
    got = rows[w.worker_id]
    assert got.status == "suspended"
    assert got.revoked_at is None
    assert "stale: no worker heartbeat" in (got.last_health_detail or "")


# =========================================================================================
# TEST 7 -- COLD START IS STILL PROTECTED
# =========================================================================================

def test_cold_start_with_an_old_heartbeat_suspends_nothing(monkeypatch):
    """Fresh process + old heartbeat + uptime < 600 -> return 0, no UPDATE, no audit row."""
    _uptime(monkeypatch, 13.0)
    w = _worker(status="active",
                last_seen_at=datetime.now(timezone.utc) - timedelta(seconds=703))
    n, rows = asyncio.run(_run([w], grace=STALE))
    assert n == 0
    got = rows[w.worker_id]
    assert got.status == "active"
    assert got.last_health_detail is None  # proves no UPDATE ran


def test_a_gated_sweep_writes_no_audit_row(monkeypatch):
    from apps.api.modules.audit import scanner_ops

    calls = []

    async def _spy(*a, **kw):
        calls.append(kw)

    monkeypatch.setattr(scanner_ops, "record_worker_reaped_stale", _spy)
    _uptime(monkeypatch, 13.0)
    n, _ = asyncio.run(_run([_worker(status="active")], grace=STALE))
    assert n == 0
    assert calls == []


# =========================================================================================
# TEST 8 -- BEAT RACE (deterministic, no real waiting)
# =========================================================================================

def test_dispatch_immediately_after_worker_start_is_gated(monkeypatch):
    """Beat's persisted `last_run_at` makes the task due ~163ms after Beat restarts, so no
    scheduling delay protects anything. Deterministic: uptime is pinned, nothing sleeps."""
    _uptime(monkeypatch, 0.163)
    w = _worker(status="active")
    n, rows = asyncio.run(_run([w], grace=STALE))
    assert n == 0
    assert rows[w.worker_id].status == "active"


def test_the_celery_task_opts_in_with_the_existing_threshold():
    from apps.api.celery_app.tasks import scan_tasks

    src = inspect.getsource(scan_tasks._reap_stale_workers)
    assert "startup_grace_seconds=" in src
    assert "worker_stale_after_seconds" in src


# =========================================================================================
# TEST 9 -- NO FALSE PERMANENT DISABLE (kills `if True: return 0`)
# =========================================================================================

def test_the_gate_cannot_be_permanently_on(monkeypatch):
    """Designed to kill a mutation that makes the gate unconditional. At a large uptime the
    gate MUST be open and a stale worker MUST be suspended."""
    from apps.api.core.platform_uptime import within_startup_grace

    _uptime(monkeypatch, STALE * 100)
    assert within_startup_grace(STALE) is False, "the gate must open once uptime exceeds it"

    w = _worker(status="active")
    n, rows = asyncio.run(_run([w], grace=STALE))
    assert n == 1, "a permanently-closed gate would leave this worker active"
    assert rows[w.worker_id].status == "suspended"


def test_the_default_grace_is_off_so_other_callers_are_unaffected(monkeypatch):
    _uptime(monkeypatch, 0.0)
    w = _worker(status="active")
    n, rows = asyncio.run(_run([w]))  # no grace -> 0.0
    assert n == 1
    assert rows[w.worker_id].status == "suspended"


# =========================================================================================
# TEST 10 -- NO LAZY IMPORT (the anti-regression guard)
# =========================================================================================

def test_the_reaper_does_not_lazily_import_the_anchor():
    """LIFECYCLE GUARD, not a text search for a name.

    `reap_stale_workers` must NOT contain an import of platform_uptime in its own body: such
    an import re-executes in each forked child and restarts the anchor. The names must come
    from module scope instead, which is asserted positively below.
    """
    src = inspect.getsource(workers_service.reap_stale_workers)
    body = src.split('"""', 2)[-1]  # exclude the docstring, which discusses the defect
    assert "import platform_uptime" not in body
    assert "from apps.api.core.platform_uptime import" not in body, (
        "REGRESSION: platform_uptime is imported inside reap_stale_workers(). Each forked "
        "child would re-execute it and start its own anchor -- uptime would stay 0.0s and "
        "the startup grace would never expire."
    )


def test_the_service_module_binds_the_gate_names_at_module_scope():
    """The positive half of test 10: the names must be resolvable as module globals, which
    is only true if the import happened at module scope."""
    assert hasattr(workers_service, "within_startup_grace")
    assert hasattr(workers_service, "process_uptime_seconds")
    assert workers_service.within_startup_grace.__module__ == UPTIME_MODULE


def test_importing_the_service_module_is_enough_to_establish_the_anchor():
    """Whichever module first pulls in the service, the anchor must already exist -- no
    deferred initialisation left anywhere on the reaper's path."""
    mod = importlib.import_module(UPTIME_MODULE)
    assert isinstance(mod._PROCESS_START_MONOTONIC, float)
    assert mod.process_uptime_seconds() > 0.0


# =========================================================================================
# the production invariants this fix must not have disturbed
# =========================================================================================

def test_the_stale_predicate_and_transition_are_unchanged():
    src = inspect.getsource(workers_service.reap_stale_workers)
    assert "WHERE status = 'active' " in src
    assert "AND revoked_at IS NULL " in src
    assert "AND COALESCE(last_seen_at, created_at) < :cutoff" in src
    assert "SET status = 'suspended'" in src
    assert "SET status = 'active'" not in src


@pytest.mark.parametrize("status", ["draining", "suspended", "pending", "revoked"])
@pytest.mark.parametrize("uptime", [13.0, STALE * 10], ids=["during_grace", "established"])
def test_non_active_statuses_are_untouched(monkeypatch, status, uptime):
    _uptime(monkeypatch, uptime)
    kw = {"status": status}
    if status == "revoked":
        kw["revoked_at"] = datetime.now(timezone.utc) - timedelta(seconds=9999)
    w = _worker(**kw)
    n, rows = asyncio.run(_run([w], grace=STALE))
    assert n == 0
    assert rows[w.worker_id].status == status


def test_the_configured_thresholds_are_unchanged():
    s = get_settings()
    assert s.worker_stale_after_seconds == 600
    assert s.worker_stale_reaper_interval_seconds == 300


def test_the_gate_still_uses_a_monotonic_clock():
    from apps.api.core import platform_uptime

    src = inspect.getsource(platform_uptime)
    assert "time.monotonic()" in src
    assert "time.time()" not in src
    assert "datetime.now" not in src


def test_the_sweep_remains_idempotent_after_the_grace(monkeypatch):
    _uptime(monkeypatch, STALE * 10)
    w = _worker(status="active")
    engine = _engine()
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async def scenario():
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    s.add(w)
                    await s.commit()
                    first = await workers_service.reap_stale_workers(
                        s, STALE, startup_grace_seconds=STALE)
                    second = await workers_service.reap_stale_workers(
                        s, STALE, startup_grace_seconds=STALE)
                    got = await s.scalar(
                        select(ScannerWorker).where(ScannerWorker.id == w.id))
                    await s.refresh(got)
                    return first, second, got
        finally:
            await engine.dispose()

    first, second, got = asyncio.run(scenario())
    assert (first, second) == (1, 0)
    assert got.status == "suspended"
