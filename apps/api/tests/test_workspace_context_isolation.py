"""AUDIT-004 -- workspace context must never leak past the scope that bound it.

THE BUG
-------
`tenancy.bind_workspace(ws)` sets a ContextVar for the REST OF THE TASK and returns a Token
the caller is expected to hand back to `clear_workspace()`. Several call sites took the
binding and dropped the token on the floor. The worst was `persist_ai_usage()`, which loops
over a list of usage records whose `workspace_id`s may DIFFER:

    for r in records:
        tenancy.bind_workspace(r.workspace_id)      # never reset
        ...insert...

so record N+1 began with record N's workspace bound, and -- because the function swallows all
exceptions -- whatever workspace the LAST record carried stayed bound to the caller's Task
after the call returned. Any subsequent ORM query in that Task was then silently auto-filtered
to a workspace the caller never established. `tenancy.workspace_scope()` exists precisely for
this and restores the previous value in a `finally`.

The same shape existed in the retention sweep, the schedule dispatcher, and the GDPR export --
all of which loop over EVERY tenant, making the leaked value effectively arbitrary.

WHAT IS DELIBERATELY *NOT* CHANGED
----------------------------------
Three sites bind without a scope ON PURPOSE and are asserted as such below: `core/deps.py`
(a request dependency -- the binding must cover the whole request), `workspaces/service.py`
(binds the just-created workspace for the rest of the handler), and the scan orchestrator
(entry point of a one-workspace Celery task). Each is confined to its own Task/Context.
"""
from __future__ import annotations

import ast
import asyncio
import uuid
from pathlib import Path

import pytest

from apps.api.core import tenancy

REPO_ROOT = Path(__file__).resolve().parents[3]

WS_A = uuid.uuid4()
WS_B = uuid.uuid4()
WS_C = uuid.uuid4()


@pytest.fixture(autouse=True)
def _clean_context():
    """Every test starts and ends with no workspace bound, so a leak in ONE test cannot make
    another test pass."""
    tenancy.clear_workspace()
    yield
    tenancy.clear_workspace()


# --------------------------------------------------------------------------------------------
# The scope primitive itself: A -> B -> restore A, on every exit path.
# --------------------------------------------------------------------------------------------

def test_scope_restores_previous_workspace():
    """A -> B -> after B, A is restored."""
    with tenancy.workspace_scope(WS_A):
        assert tenancy.current_workspace_id() == WS_A
        with tenancy.workspace_scope(WS_B):
            assert tenancy.current_workspace_id() == WS_B
        assert tenancy.current_workspace_id() == WS_A, "B leaked past its scope"
    assert tenancy.current_workspace_id() is None


def test_scope_restores_previous_workspace_on_exception():
    """A -> B -> raise -> A is still restored. The exception path is the one that matters:
    persist_ai_usage swallows exceptions, so a leak there became permanent."""
    with tenancy.workspace_scope(WS_A):
        with pytest.raises(RuntimeError):
            with tenancy.workspace_scope(WS_B):
                assert tenancy.current_workspace_id() == WS_B
                raise RuntimeError("boom")
        assert tenancy.current_workspace_id() == WS_A, "B leaked out of a raising scope"


def test_nested_scopes_unwind_in_order():
    """A -> B -> C -> B -> A."""
    with tenancy.workspace_scope(WS_A):
        assert tenancy.current_workspace_id() == WS_A
        with tenancy.workspace_scope(WS_B):
            assert tenancy.current_workspace_id() == WS_B
            with tenancy.workspace_scope(WS_C):
                assert tenancy.current_workspace_id() == WS_C
            assert tenancy.current_workspace_id() == WS_B
        assert tenancy.current_workspace_id() == WS_A
    assert tenancy.current_workspace_id() is None


def test_scope_restores_across_await_boundary():
    """The context must survive an await and still unwind correctly -- the real call sites are
    all async."""
    async def _inner():
        with tenancy.workspace_scope(WS_A):
            await asyncio.sleep(0)
            with tenancy.workspace_scope(WS_B):
                await asyncio.sleep(0)
                assert tenancy.current_workspace_id() == WS_B
            await asyncio.sleep(0)
            assert tenancy.current_workspace_id() == WS_A
        assert tenancy.current_workspace_id() is None

    asyncio.run(_inner())


def test_scope_restores_on_async_failure():
    """A failing coroutine inside the scope must still restore the outer workspace."""
    async def _inner():
        with tenancy.workspace_scope(WS_A):
            with pytest.raises(ValueError):
                with tenancy.workspace_scope(WS_B):
                    await asyncio.sleep(0)
                    raise ValueError("async boom")
            assert tenancy.current_workspace_id() == WS_A

    asyncio.run(_inner())


def test_bare_bind_demonstrably_leaks():
    """Characterisation of the DEFECT, so the reason the scope is required stays visible.
    A bare bind does NOT restore -- which is why no loop may use it."""
    with tenancy.workspace_scope(WS_A):
        tenancy.bind_workspace(WS_B)
        assert tenancy.current_workspace_id() == WS_B
    # leaving the outer scope resets to the value captured on entry (None)
    assert tenancy.current_workspace_id() is None


# --------------------------------------------------------------------------------------------
# persist_ai_usage -- the site the finding named.
# --------------------------------------------------------------------------------------------

def test_persist_ai_usage_does_not_leak_workspace_to_caller(monkeypatch):
    """THE AUDIT-004 REGRESSION LOCK.

    Records carrying two DIFFERENT workspaces are persisted; afterwards the caller's context
    must be exactly what it was before the call. Before the fix, WS_B (the last record's
    workspace) stayed bound.
    """
    from apps.api.ai_agent import usage_repo
    from apps.api.ai_agent.providers.usage import AIUsage

    seen: list[uuid.UUID | None] = []

    class _FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def begin(self):
            return self

        def add(self, _row):
            # the workspace bound at INSERT time is what attributes the row
            seen.append(tenancy.current_workspace_id())

    monkeypatch.setattr(usage_repo, "SessionLocal", lambda: _FakeSession())

    records = [
        AIUsage(workspace_id=str(WS_A), scan_id=None, provider="p", model="m", agent_role="r",
                prompt_tokens=1, completion_tokens=1, estimated_cost_usd=0.0,
                correlation_id=None, prompt_version=None),
        AIUsage(workspace_id=str(WS_B), scan_id=None, provider="p", model="m", agent_role="r",
                prompt_tokens=1, completion_tokens=1, estimated_cost_usd=0.0,
                correlation_id=None, prompt_version=None),
    ]

    async def _run():
        assert tenancy.current_workspace_id() is None
        await usage_repo.persist_ai_usage(records)
        return tenancy.current_workspace_id()

    after = asyncio.run(_run())
    assert after is None, f"persist_ai_usage leaked workspace {after} to its caller"
    # each row was attributed to ITS OWN workspace, not to a carried-over one
    assert seen == [WS_A, WS_B], f"rows were attributed to the wrong workspaces: {seen}"


def test_persist_ai_usage_restores_caller_context_it_did_not_own(monkeypatch):
    """If the caller already had a workspace bound, that exact workspace must survive."""
    from apps.api.ai_agent import usage_repo
    from apps.api.ai_agent.providers.usage import AIUsage

    class _FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def begin(self):
            return self

        def add(self, _row):
            pass

    monkeypatch.setattr(usage_repo, "SessionLocal", lambda: _FakeSession())
    records = [
        AIUsage(workspace_id=str(WS_B), scan_id=None, provider="p", model="m", agent_role="r",
                prompt_tokens=1, completion_tokens=1, estimated_cost_usd=0.0,
                correlation_id=None, prompt_version=None),
    ]

    async def _run():
        with tenancy.workspace_scope(WS_A):
            await usage_repo.persist_ai_usage(records)
            return tenancy.current_workspace_id()

    assert asyncio.run(_run()) == WS_A, "the caller's own workspace was overwritten"


def test_persist_ai_usage_does_not_leak_when_the_insert_fails(monkeypatch):
    """persist_ai_usage swallows every exception by design. That must not turn a failed row
    into a permanently leaked context."""
    from apps.api.ai_agent import usage_repo
    from apps.api.ai_agent.providers.usage import AIUsage

    class _ExplodingSession:
        async def __aenter__(self):
            raise RuntimeError("db down")

        async def __aexit__(self, *a):
            return False

    monkeypatch.setattr(usage_repo, "SessionLocal", lambda: _ExplodingSession())
    records = [
        AIUsage(workspace_id=str(WS_B), scan_id=None, provider="p", model="m", agent_role="r",
                prompt_tokens=1, completion_tokens=1, estimated_cost_usd=0.0,
                correlation_id=None, prompt_version=None),
    ]

    async def _run():
        await usage_repo.persist_ai_usage(records)   # must not raise
        return tenancy.current_workspace_id()

    assert asyncio.run(_run()) is None, "a failed insert leaked its workspace"


# --------------------------------------------------------------------------------------------
# Repository-wide sweep: every bind_workspace() call site is accounted for.
# --------------------------------------------------------------------------------------------

# The ONLY production sites permitted to call bind_workspace() without a surrounding scope.
# Each is a context-establishing entry point whose binding must outlive the call, and each is
# confined to its own asyncio Task / contextvars Context. Adding to this set is a review
# decision, which is the point of pinning it here.
INTENTIONALLY_PERSISTENT = {
    "apps/api/core/deps.py",                       # FastAPI request dependency
    "apps/api/modules/workspaces/service.py",      # binds the just-created workspace
    "apps/api/scanner_engine/orchestrator.py",     # entry point of a one-workspace task
    "apps/api/core/tenancy.py",                    # the primitive itself (workspace_scope)
}


def _bind_call_sites() -> dict[str, list[int]]:
    """Every production call to tenancy.bind_workspace(), by file and line."""
    api_root = REPO_ROOT / "apps" / "api"
    sites: dict[str, list[int]] = {}
    for path in sorted(api_root.rglob("*.py")):
        if "tests" in path.parts or "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
            if name == "bind_workspace":
                rel = path.relative_to(REPO_ROOT).as_posix()
                sites.setdefault(rel, []).append(node.lineno)
    return sites


def test_no_unreviewed_bare_bind_workspace_sites():
    """THE SWEEP. Any NEW bare bind_workspace() must be justified and added to
    INTENTIONALLY_PERSISTENT deliberately -- it cannot appear by accident."""
    if not (REPO_ROOT / "apps" / "api" / "core" / "tenancy.py").is_file():
        pytest.skip("application tree not bind-mounted")
    unexpected = {f: lines for f, lines in _bind_call_sites().items()
                  if f not in INTENTIONALLY_PERSISTENT}
    assert not unexpected, (
        "bare tenancy.bind_workspace() at an unreviewed site -- use tenancy.workspace_scope() "
        f"unless the binding must genuinely outlive the call: {unexpected}"
    )


def test_the_fixed_loop_sites_no_longer_bind_bare():
    """Explicit lock on the four sites this remediation converted, so a revert is caught."""
    converted = [
        "apps/api/ai_agent/usage_repo.py",
        "apps/api/retention/repo.py",
        "apps/api/modules/schedules/service.py",
        "apps/api/modules/users/service.py",
    ]
    if not (REPO_ROOT / "apps" / "api" / "core" / "tenancy.py").is_file():
        pytest.skip("application tree not bind-mounted")
    sites = _bind_call_sites()
    for f in converted:
        assert f not in sites, (
            f"{f} calls bind_workspace() again -- it loops over tenants and must use "
            "tenancy.workspace_scope()"
        )
