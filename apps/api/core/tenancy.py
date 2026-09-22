"""Application-layer workspace (tenant) isolation.

MySQL migration note (Phase 0): every table below used to be protected by a
Postgres Row-Level Security policy — `ALTER TABLE ... FORCE ROW LEVEL
SECURITY` + `CREATE POLICY workspace_isolation ON ... USING (...)` — set up
across 15 Alembic migrations. MySQL has no equivalent feature (verified: no
native RLS in MySQL 8, and MariaDB's RLS request, MDEV-27301, is still
unimplemented). This module is the deliberate, reviewed replacement.

WHAT CHANGES, CONCRETELY:
  - Before: even a raw, buggy SQL query against `vulnerabilities` could not
    return another workspace's rows — Postgres refused them at the storage
    layer, unconditionally, regardless of what the application code did.
  - After: every ORM query (SELECT/UPDATE/DELETE) against a table in
    `_DIRECT`/`_VIA` below is *automatically* rewritten to add the same
    workspace filter the old SQL policy encoded, via SQLAlchemy's
    `with_loader_criteria` + `do_orm_execute` hook (`install()` below).
    A query issued through the ORM cannot practically forget the filter.
  - The one real gap: **raw `text()` SQL** (this codebase uses it for the
    atomic scan-claim/fencing statements, and a few reporting queries)
    bypasses the ORM entirely and is therefore NOT covered by this module.
    Every raw-SQL call site was (or must be) individually audited and given
    an explicit `WHERE workspace_id = :wid` — see
    docs/architecture/mysql-migration-phase0.md for the tracked list.

FAIL-CLOSED, ARGUABLY STRICTER THAN THE ORIGINAL: the old Postgres policy,
when no session var was set, made every row invisible (`workspace_id = NULL`
matches nothing) — a silent empty result. This module instead *raises*
`TenancyNotBoundError` for that case. An empty result set from a missing
bootstrap call is easy to misread as "this workspace has no data"; a raised
exception is not. Code that legitimately must run across workspaces (the
retention sweep, the schedule dispatcher) already loops workspace-by-workspace
and binds each one explicitly — see `apps/api/retention/repo.py` and
`apps/api/modules/schedules/service.py`. A true cross-tenant admin path, if
one is ever needed, should use `admin_bypass()` below and must be reviewed
like any other change to this file.

WHY A CONTEXTVAR IS SAFE HERE (no explicit reset needed at most call sites):
`contextvars.ContextVar` is not shared global state — an `asyncio.Task`
receives a *copy* of the context at creation time, and a `.set()` inside one
task is invisible to any other task, sibling or subsequent. Every Celery task
in this codebase runs its own top-level `asyncio.run(...)` (see
`celery_app/tasks/scan_tasks.py`), and every FastAPI request is dispatched as
its own `asyncio.Task` by Starlette — so `bind_workspace()` calls in the
orchestrator, the retention repo, and `core/deps.py` are naturally isolated
per scan / per request with no cross-talk, matching (and for concurrent
requests on one connection, improving on) the old `SET LOCAL` behavior. Use
the `workspace_scope()` context manager instead of a bare `bind_workspace()`
wherever a function's control flow makes an explicit reset easy — it costs
nothing and removes any doubt.
"""

from __future__ import annotations

import contextlib
import contextvars
import uuid
from collections.abc import Iterator
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import ORMExecuteState, Session, with_loader_criteria

_current_workspace_id: contextvars.ContextVar[uuid.UUID | None] = contextvars.ContextVar(
    "mbs_current_workspace_id", default=None
)
_bypass: contextvars.ContextVar[bool] = contextvars.ContextVar("mbs_tenancy_bypass", default=False)


class TenancyNotBoundError(RuntimeError):
    """A workspace-scoped table was queried with no workspace bound and no
    explicit admin_bypass() in effect. Almost always means a request/task
    forgot to call bind_workspace() / workspace_scope() — fix the call site,
    do not reach for admin_bypass() to silence this."""


def bind_workspace(workspace_id: uuid.UUID | str) -> contextvars.Token:
    """Bind the workspace for the remainder of the current asyncio Task.
    Returns a Token; pass it to clear_workspace() to reset explicitly, or
    just let the Task end (see module docstring for why that's safe here)."""
    if not isinstance(workspace_id, uuid.UUID):
        workspace_id = uuid.UUID(str(workspace_id))
    return _current_workspace_id.set(workspace_id)


def clear_workspace(token: contextvars.Token | None = None) -> None:
    if token is not None:
        try:
            _current_workspace_id.reset(token)
            return
        except ValueError:
            pass  # token belongs to a different Context (defensive only) -- hard clear below
    _current_workspace_id.set(None)


def current_workspace_id() -> uuid.UUID | None:
    return _current_workspace_id.get()


@contextlib.contextmanager
def workspace_scope(workspace_id: uuid.UUID | str) -> Iterator[None]:
    """Preferred entry point wherever the call site's control flow allows
    `with`: binds for the block, always resets after, no reliance on
    Task-boundary reasoning."""
    token = bind_workspace(workspace_id)
    try:
        yield
    finally:
        clear_workspace(token)


@contextlib.contextmanager
def admin_bypass() -> Iterator[None]:
    """Explicit, auditable escape hatch for a genuine cross-workspace system
    query. Every use of this should have a comment justifying it, the same
    bar as the pre-cutover migrations held raw isolation-bypassing SQL to. Grep for
    `admin_bypass` in code review the same way `FORCE ROW LEVEL SECURITY` was
    grepped for under the old PostgreSQL design."""
    token = _bypass.set(True)
    try:
        yield
    finally:
        _bypass.reset(token)


# --------------------------------------------------------------------------
# Registry: table name -> how it's scoped. This is the single file that
# answers "which tables are tenant-isolated and how" -- mirroring how the
# PostgreSQL-era policies used to be auditable with one `grep CREATE POLICY`
# across the migrations. Keep it that way: don't scatter scoping logic into individual
# models or services.
# --------------------------------------------------------------------------

# Has a workspace_id column but is DELIBERATELY not auto-filtered, same as
# the original migrations left it unprotected by RLS -- not an oversight.
#   scans          -- the Celery worker reads this by trusted internal scan_id
#                      BEFORE it knows the workspace, to bootstrap tenancy
#                      itself (see orchestrator.run_scan). App-layer service
#                      code filters by workspace_id explicitly wherever a scan
#                      is looked up on behalf of a request.
#   api_keys       -- looked up by raw key hash during auth, before the
#                      caller's workspace is known.
#   scan_schedules -- Celery beat iterates ALL due schedules across every
#                      workspace by design (run_due_schedules).
#   scanner_workers -- MBS.SC. Authenticated by credential BEFORE any workspace is
#                      known (exactly the api_keys case): the manager is handed a worker
#                      credential and must resolve it to a row to discover which
#                      workspace, pool and site that worker is bound to. It is ALSO
#                      legitimately cross-tenant: a shared PUBLIC worker has
#                      workspace_id = NULL and serves many tenants, so a direct
#                      auto-filter would hide every public worker from every workspace
#                      and no scan could ever be leased.
#                      This exemption is NOT a weakening: modules/scanner_workers/
#                      service.py performs the explicit authorization instead --
#                      authenticate_worker() -> assert_worker_may_serve_site() ->
#                      assert_worker_may_take_scan(), each of which compares the SERVER's
#                      row against the requested work and fails closed. The regression
#                      tests in test_scanner_manager_authz.py cover the cross-tenant,
#                      wrong-pool, wrong-site and revoked cases directly.
EXEMPT_TABLES = frozenset({"scans", "api_keys", "scan_schedules", "scanner_workers"})

# Tables with a workspace_id column that IS auto-filtered directly.
_DIRECT_TABLES = frozenset(
    {
        "workspace_members",
        "projects",
        "attack_narratives",
        "agent_decisions",
        "notifications",
        "audit_events",
        "ai_usage",
        "engagement_state",
        "agent_steps",
        # --- Remediation / assessment subsystem -------------------------------------------
        # All DIRECT (own workspace_id column) rather than VIA, deliberately. remediation_items
        # alone could be a 2-hop VIA table (project -> workspace), but remediation_events,
        # remediation_evidence and verification_requests hang off remediation_items, which puts
        # them THREE hops from workspaces -- more than the 1-or-2-hop limit asserted below.
        # Rather than special-case a deeper chain, every table in this subsystem carries its own
        # workspace_id, which is also what makes the retention sweep and the tenant export able
        # to reach them with a single explicit filter.
        "remediation_items",
        "remediation_events",
        "remediation_evidence",
        "verification_requests",
        "risk_acceptances",
        "risk_assessments",
        "risk_assessment_findings",
        # MBS.SC: a private site belongs to EXACTLY ONE workspace (non-nullable
        # workspace_id), so it auto-filters directly. This is what makes
        # "tenant A cannot read/lease/scan tenant B's site" true at the ORM layer
        # in addition to the explicit manager-side checks.
        "private_sites",
    }
)

# Tables scoped through a foreign-key chain (no workspace_id column of their
# own). Each value is an ordered tuple of (fk_column, target_table) hops;
# the final table in the chain is assumed to carry a direct `workspace_id`
# column (true for every case below: projects and scans both do).
_VIA_TABLES: dict[str, tuple[tuple[str, str], ...]] = {
    "targets": (("project_id", "projects"),),
    "assets": (("project_id", "projects"),),
    "vulnerabilities": (("project_id", "projects"),),
    "reports": (("project_id", "projects"),),
    "tool_runs": (("scan_id", "scans"),),
    "ai_plans": (("scan_id", "scans"),),
    # NOTE: `evidence.tool_run_id` is now NULLABLE (remediation proof uploaded by a human has
    # no tool run to attribute it to -- fabricating one would be a lie in the evidence chain).
    # A NULL fk makes `tool_run_id IN (<subquery>)` evaluate to NULL, i.e. NOT TRUE, so a
    # remediation-proof row would be invisible to EVERY workspace under the plain VIA chain --
    # fail-closed, but uselessly so. `_evidence_criterion` below therefore ORs in the
    # remediation_evidence link (which carries its own workspace_id) for exactly those rows.
    # The tool-run branch is untouched, so scanner evidence keeps its existing behaviour.
    "evidence": (("tool_run_id", "tool_runs"), ("scan_id", "scans")),
    "authorization_scopes": (("target_id", "targets"), ("project_id", "projects")),
    "vulnerability_evidence": (("vulnerability_id", "vulnerabilities"), ("project_id", "projects")),
    "vulnerability_lineage": (("new_vulnerability_id", "vulnerabilities"), ("project_id", "projects")),
    "vulnerability_history": (("vulnerability_id", "vulnerabilities"), ("project_id", "projects")),
    "remediations": (("vulnerability_id", "vulnerabilities"), ("project_id", "projects")),
    "attack_mappings": (("vulnerability_id", "vulnerabilities"), ("project_id", "projects")),
    "risk_scores": (("vulnerability_id", "vulnerabilities"), ("project_id", "projects")),
    "compliance_mappings": (("vulnerability_id", "vulnerabilities"), ("project_id", "projects")),
}

# --------------------------------------------------------------------------
# CANONICAL TABLE CLASSIFICATION
# --------------------------------------------------------------------------
# Every table in the mapper registry MUST appear in exactly one bucket below.
# This is the single source of truth that tenancy enforcement, the tenancy
# tests, and docs/architecture/mysql-migration-phase0.md all read -- so the
# three can never drift apart (test_tenancy_isolation asserts the partition is
# total and disjoint, so a NEW table added without classifying it FAILS the
# suite rather than silently defaulting to "unprotected").
#
# TENANT_SCOPED   -- holds Workspace-owned data. Either carries workspace_id
#                    directly (_DIRECT_TABLES) or reaches it through a
#                    deterministic FK chain (_VIA_TABLES). Auto-filtered on
#                    SELECT/UPDATE/DELETE, and guarded on INSERT (see
#                    _assert_insert_allowed).
# SYSTEM_SCOPED   -- Workspace-owned, but deliberately NOT auto-filtered
#                    because a trusted internal path must read the row BEFORE
#                    the workspace is known (== EXEMPT_TABLES). Each of these
#                    is filtered explicitly at its call sites; see the comment
#                    on EXEMPT_TABLES for the per-table justification.
# USER_SCOPED     -- keyed by user identity, not by workspace. A user exists
#                    across workspaces, so workspace filtering is meaningless
#                    here; access control is by authenticated identity.
# GLOBAL_SCOPED   -- platform-wide reference/config data with no tenant owner.
#                    `roles` appears here because roles.workspace_id is
#                    NULLABLE: NULL == a built-in system role shared by every
#                    workspace. Auto-filtering it would hide those system roles
#                    from every tenant and break login, so its call sites filter
#                    explicitly (`Role.workspace_id.is_(None)` for system roles,
#                    `== workspace_id` for custom ones).
USER_SCOPED_TABLES = frozenset({"users", "refresh_tokens", "mfa_recovery_codes"})
GLOBAL_SCOPED_TABLES = frozenset(
    {"workspaces", "roles", "permissions", "role_permissions", "platform_audit_events"}
)


def table_scope(table: str) -> str:
    """The canonical classification of one table. Raises KeyError for an
    unclassified table -- fail closed, so an unregistered table is a loud error
    rather than a silently unprotected one."""
    if table in _DIRECT_TABLES or table in _VIA_TABLES:
        return "TENANT_SCOPED"
    if table in EXEMPT_TABLES:
        return "SYSTEM_SCOPED"
    if table in USER_SCOPED_TABLES:
        return "USER_SCOPED"
    if table in GLOBAL_SCOPED_TABLES:
        return "GLOBAL_SCOPED"
    raise KeyError(
        f"table '{table}' is not classified in apps/api/core/tenancy.py. Add it to exactly one "
        "of _DIRECT_TABLES / _VIA_TABLES / EXEMPT_TABLES / USER_SCOPED_TABLES / "
        "GLOBAL_SCOPED_TABLES and document it in docs/architecture/mysql-migration-phase0.md."
    )

# Every VIA chain in this codebase is 1 or 2 hops deep (verified against the
# original RLS USING clauses). Assert that stays true so a 3-hop entry added
# later doesn't silently fall through the two hand-written builders below.
for _table, _chain in _VIA_TABLES.items():
    assert len(_chain) in (1, 2), f"{_table}: only 1- or 2-hop VIA chains are supported, got {len(_chain)}"


def workspace_criterion(model: type) -> Any | None:
    """The workspace predicate for `model`, or None if the model is not tenant-scoped.

    PUBLIC counterpart to the criteria `install()` injects automatically. It exists because
    SQLAlchemy's `with_loader_criteria` only attaches to statements that LOAD a mapped
    entity: every AGGREGATE shape (count/max over a mapped column, with or without
    select_from, with or without with_only_columns) escapes the auto-filter entirely --
    verified empirically against SQLAlchemy 2.0.35, all shapes returning the GLOBAL row
    count while a workspace owning one row was bound.

    Any code that aggregates over a tenant-scoped table must therefore apply this
    explicitly. `core/pagination.paginate` does exactly that for its COUNT, so a paginated
    total can never describe a wider population than its items.

    Raises TenancyNotBoundError for a tenant-scoped model with no workspace bound -- the
    same fail-closed contract as the auto-filter, so an unbound aggregate is a loud error
    rather than a silent global number. Returns None under admin_bypass(), matching the
    auto-filter's behaviour there."""
    table = getattr(model, "__tablename__", None)
    if table is None:
        return None
    try:
        if table_scope(table) != "TENANT_SCOPED":
            return None
    except KeyError:
        # Unclassified: fail closed the same way table_scope() does for the auto-filter.
        raise

    if _bypass.get():
        return None

    ws_id = current_workspace_id()
    if ws_id is None:
        raise TenancyNotBoundError(
            f"Aggregate over workspace-scoped table '{table}' with no workspace bound. "
            "Call tenancy.bind_workspace()/workspace_scope() first, or wrap a genuine "
            "cross-workspace system query in tenancy.admin_bypass()."
        )

    if table in _DIRECT_TABLES:
        return _direct_criterion(model, ws_id)
    if table == "evidence":
        return _evidence_criterion(model, _VIA_TABLES[table], ws_id)
    return _via_criterion(model, _VIA_TABLES[table], ws_id)


_model_by_table: dict[str, type] | None = None


def _load_model_registry() -> dict[str, type]:
    """Lazily import every model module and index by __tablename__. Deferred
    (not a module-level import) specifically to avoid a circular import:
    this module is imported by app/worker *startup* code, which by that
    point has already imported apps.api.core.models_all -- importing model
    modules here directly, at import time, would race that and risk a
    partially-initialized apps.api.core.db.Base."""
    global _model_by_table
    if _model_by_table is not None:
        return _model_by_table

    import apps.api.core.models_all  # noqa: F401  (populates Base.metadata / mapper registry)
    from apps.api.core.db import Base

    registry: dict[str, type] = {}
    for mapper in Base.registry.mappers:
        cls = mapper.class_
        table = getattr(cls, "__tablename__", None)
        if table:
            registry[table] = cls
    _model_by_table = registry
    return registry


def _direct_criterion(model: type, ws_id: uuid.UUID) -> Any:
    return getattr(model, "workspace_id") == ws_id


def _evidence_criterion(model: type, chain: tuple[tuple[str, str], ...], ws_id: uuid.UUID) -> Any:
    """`evidence` is scoped by EITHER of two disjoint paths, because one table now holds two
    kinds of artifact:

      1. SCANNER evidence -- tool_run_id -> tool_runs -> scans.workspace_id (the original,
         unchanged 2-hop VIA chain);
      2. REMEDIATION PROOF -- tool_run_id IS NULL, reached instead through the
         `remediation_evidence` join row, which carries its own workspace_id.

    The two branches are mutually exclusive by construction (branch 2 only matches rows with a
    remediation_evidence link), so this is a widening of REACHABILITY, not of ACCESS: a row
    still has exactly one owning workspace, and a row belonging to neither path -- an orphaned
    evidence row with a NULL tool_run and no remediation link -- remains invisible to every
    workspace, which is the correct fail-closed answer for an artifact with no owner."""
    from_tool_run = _via_criterion(model, chain, ws_id)
    models = _load_model_registry()
    link = models["remediation_evidence"]
    via_remediation = getattr(model, "id").in_(
        select(link.evidence_id).where(link.workspace_id == ws_id)
    )
    return from_tool_run | via_remediation


def _via_criterion(model: type, chain: tuple[tuple[str, str], ...], ws_id: uuid.UUID) -> Any:
    models = _load_model_registry()
    if len(chain) == 1:
        (fk_col, target_table) = chain[0]
        target = models[target_table]
        subq = select(target.id).where(target.workspace_id == ws_id)
        return getattr(model, fk_col).in_(subq)

    # 2-hop: origin.fk1 -> mid.id, mid.fk2 -> final.id, final.workspace_id == ws
    (fk1, mid_table), (fk2, final_table) = chain
    mid = models[mid_table]
    final = models[final_table]
    inner = select(final.id).where(final.workspace_id == ws_id)
    outer = select(mid.id).where(getattr(mid, fk2).in_(inner))
    return getattr(model, fk1).in_(outer)


# --------------------------------------------------------------------------
# INSERT enforcement
# --------------------------------------------------------------------------
# WHY A SEPARATE MECHANISM: the `do_orm_execute` hook that filters
# SELECT/UPDATE/DELETE does NOT fire for an ORM flush INSERT. SQLAlchemy's
# unit of work persists `session.add()`-ed objects through its persistence
# layer, not through `session.execute()`, so `ORMExecuteState` never sees them
# (verified empirically against this project's MySQL 8.0: do_orm_execute fired
# 0 times for a flush INSERT while `before_flush` fired once). Postgres's
# `FORCE ROW LEVEL SECURITY` covered INSERT via its WITH CHECK clause; losing
# that is the one enforcement gap the MySQL cutover opened, and this closes it.
#
# WHAT IT ENFORCES, on every TENANT_SCOPED row about to be INSERTed:
#   1. a workspace MUST be bound            -> else TenancyNotBoundError;
#   2. a _DIRECT table's workspace_id MUST equal the bound workspace
#                                           -> else CrossTenantWriteError.
#
#   3. a _VIA table's parent, WHEN THE PARENT IS ALREADY IN THE SESSION, must
#      belong to the bound workspace -> else CrossTenantWriteError.
#
# ON (3) -- THE VIA-TABLE PARENT CHAIN (audit Phase 14).
# Originally this hook validated only _DIRECT rows, on the reasoning that a
# full parent check would need a SELECT per pending row on every flush -- a
# real cost on the scanner's bulk finding ingest. That reasoning still holds,
# so this does NOT issue any query: it consults the Session's IDENTITY MAP and
# its pending set, both already in memory. The ordinary ORM path
# (`project = await get_project(...)`, then `session.add(Target(project_id=
# project.id))`) has the parent loaded, so the check is free and exact. When
# the parent is NOT resident -- a caller that fabricated a UUID it never read
# -- the hook stays silent rather than paying for a lookup, exactly as before.
#
# So this is a strictly-additive backstop, not a complete boundary:
#   * it CANNOT regress performance (no I/O added), and
#   * it now catches the realistic ORM mistake -- code that legitimately loaded
#     tenant B's parent under an admin_bypass() or from another context and
#     then wrote a child row while tenant A was bound.
# The AUTHORITATIVE control for a fabricated parent id remains the service
# layer's explicit ownership check (verified: an HTTP attempt by tenant A to
# create a target under tenant B's project returns 404/403). That division is
# documented in docs/architecture/mysql-migration-phase0.md and asserted by
# apps/api/tests/test_via_table_tenancy.py, which exercises BOTH layers.
#
# Non-tenant rows (USER/GLOBAL/SYSTEM scoped) are untouched, so login,
# registration, system-role seeding and the Celery scan bootstrap all keep
# working with no workspace bound.


class CrossTenantWriteError(RuntimeError):
    """An INSERT tried to write a row into a workspace other than the bound one."""


def _assert_insert_allowed(instances, session=None) -> None:
    """Validate every pending NEW object in a flush. Pure and side-effect free
    apart from raising; safe to call from `before_flush`.

    `session` is optional so existing direct callers keep working; when supplied it enables
    the VIA-table parent check, which reads only in-memory state (never a query)."""
    if _bypass.get():
        return
    for obj in instances:
        table = getattr(type(obj), "__tablename__", None)
        if table is None:
            continue
        # Unclassified tables raise KeyError from table_scope() -- fail closed,
        # matching the registry-completeness guarantee.
        if table_scope(table) != "TENANT_SCOPED":
            continue

        ws_id = current_workspace_id()
        if ws_id is None:
            raise TenancyNotBoundError(
                f"INSERT into workspace-scoped table '{table}' with no workspace bound. "
                "Call tenancy.bind_workspace()/workspace_scope() before writing, or wrap a "
                "genuine cross-workspace system write in tenancy.admin_bypass() with a "
                "comment explaining why."
            )

        if table in _DIRECT_TABLES:
            row_ws = getattr(obj, "workspace_id", None)
            # None is left to the column's own NOT NULL constraint rather than
            # being silently back-filled: quietly stamping the bound workspace
            # onto a row whose caller forgot it would hide the bug this exists
            # to surface.
            if row_ws is not None and row_ws != ws_id:
                raise CrossTenantWriteError(
                    f"INSERT into '{table}' targets workspace {row_ws}, but the bound "
                    f"workspace is {ws_id}. Cross-tenant writes are refused."
                )
        elif table in _VIA_TABLES and session is not None:
            _assert_via_parent_allowed(session, obj, table, ws_id)


def _resident_parent(session, parent_table: str, parent_id):
    """The parent object for `parent_id`, but ONLY if it is already in memory.

    Looks in the Session's identity map (rows loaded in this session) and its pending set
    (rows added in this same flush). Returns None when the parent is not resident -- the
    caller then skips the check rather than issuing a query, which is what keeps this hook
    free of I/O (see the design note above).
    """
    if parent_id is None:
        return None
    for state_obj in list(getattr(session, "identity_map", {}).values()) + list(session.new):
        if getattr(type(state_obj), "__tablename__", None) != parent_table:
            continue
        if getattr(state_obj, "id", None) == parent_id:
            return state_obj
    return None


def _assert_via_parent_allowed(session, obj, table: str, ws_id) -> None:
    """Phase 14 backstop: reject a VIA-table INSERT whose (already-loaded) parent belongs to
    another workspace. Issues NO queries -- see the design note above for why."""
    for fk_attr, parent_table in _VIA_TABLES[table]:
        parent_id = getattr(obj, fk_attr, None)
        parent = _resident_parent(session, parent_table, parent_id)
        if parent is None:
            continue  # not loaded -> service layer owns this case; do not pay for a SELECT

        # A DIRECT parent carries workspace_id itself; a VIA parent (targets -> projects)
        # does not, so only the directly-scoped hop is conclusive here.
        parent_ws = getattr(parent, "workspace_id", None)
        if parent_ws is not None and parent_ws != ws_id:
            raise CrossTenantWriteError(
                f"INSERT into '{table}' links to {parent_table} {parent_id}, which belongs to "
                f"workspace {parent_ws}, but the bound workspace is {ws_id}. Cross-tenant "
                "relationships are refused."
            )
        return  # first resident hop decided it


_installed = False


def is_installed() -> bool:
    return _installed


def install() -> None:
    """Register the global ORM filter. Call exactly once, after
    apps.api.core.models_all has been imported -- from apps/api/main.py's
    startup path and from celery_app/worker.py's worker startup path (both
    already exist as the app's two process entry points). Idempotent.

    IMPLEMENTATION NOTE, hard-won: `with_loader_criteria`'s callable form
    (`with_loader_criteria(Model, lambda cls: ...)`) is NOT a plain Python
    callback -- SQLAlchemy runs it through its "lambda SQL" caching system,
    which statically analyzes the function and forbids calling out to
    ordinary Python functions from inside it (verified empirically: even a
    `list.append()` in the lambda body raises `InvalidRequestError`, "Can't
    invoke Python callable ... inside of lambda expression argument"). So
    this deliberately does NOT pass a lambda. It computes the concrete
    boolean expression eagerly, per statement, using the plain Python
    registry/contextvar lookups above, and hands `with_loader_criteria` the
    already-built expression object. Verified against SQLAlchemy 2.0.35: a
    pre-built expression filters 1-hop and 2-hop VIA chains correctly, on
    both SELECT and ORM-enabled UPDATE, and attaching it for tables a given
    statement doesn't touch is a no-op (no error, no effect) -- see the
    scratch reproduction this comment's author ran before trusting this."""
    global _installed
    if _installed:
        return

    models = _load_model_registry()
    scoped_tables = _DIRECT_TABLES | set(_VIA_TABLES)
    unknown = scoped_tables - set(models)
    if unknown:
        raise RuntimeError(f"tenancy registry references unknown table(s): {sorted(unknown)}")

    from sqlalchemy import event

    @event.listens_for(Session, "do_orm_execute")
    def _scope_by_workspace(orm_execute_state: ORMExecuteState) -> None:
        if not (orm_execute_state.is_select or orm_execute_state.is_update or orm_execute_state.is_delete):
            return
        if _bypass.get():
            return

        touched = {mapper.class_ for mapper in orm_execute_state.all_mappers}
        touched_scoped = [
            (table, model) for table, model in models.items() if table in scoped_tables and model in touched
        ]
        if not touched_scoped:
            return

        ws_id = current_workspace_id()
        if ws_id is None:
            names = ", ".join(t for t, _ in touched_scoped)
            raise TenancyNotBoundError(
                f"Query touches workspace-scoped table(s) [{names}] with no workspace bound. "
                "Call tenancy.bind_workspace()/workspace_scope() before querying, or wrap a "
                "genuine cross-workspace system query in tenancy.admin_bypass() with a comment "
                "explaining why."
            )

        for table, model in touched_scoped:
            if table in _DIRECT_TABLES:
                expr = _direct_criterion(model, ws_id)
            elif table == "evidence":
                # Two-path scoping -- see _evidence_criterion.
                expr = _evidence_criterion(model, _VIA_TABLES[table], ws_id)
            else:
                expr = _via_criterion(model, _VIA_TABLES[table], ws_id)
            orm_execute_state.statement = orm_execute_state.statement.options(
                with_loader_criteria(model, expr, include_aliases=True)
            )

    @event.listens_for(Session, "before_flush")
    def _guard_inserts(session: Session, flush_context, instances) -> None:
        """INSERT-side counterpart to the filter above -- see
        _assert_insert_allowed for why a separate hook is required.

        Only `session.new` is inspected: `session.dirty` (UPDATE) and
        `session.deleted` (DELETE) already go through do_orm_execute's
        auto-filter, which restricts them to rows the bound workspace can
        see, so re-validating them here would be redundant."""
        _assert_insert_allowed(session.new, session)

    _installed = True
