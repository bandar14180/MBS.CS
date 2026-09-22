# MySQL Migration — Phase 0: Workspace Isolation Without RLS

**Status:** implemented
**Scope:** the tenant-isolation control only. Everything else in the PostgreSQL→MySQL cutover (dialect fixes, `RETURNING`→`rowcount`, `JSONB`→`JSON`, UUID storage) is out of scope here.
**Authoritative code:** [`apps/api/core/tenancy.py`](../../apps/api/core/tenancy.py)
**Authoritative tests:** [`apps/api/tests/test_tenancy_isolation.py`](../../apps/api/tests/test_tenancy_isolation.py)

This document is referenced from `tenancy.py` as the tracked list of raw-SQL call sites and the procedure for adding a table. It is meant to be verifiable: every claim below corresponds to code or a named test.

---

## 1. Why we moved

The platform moved from PostgreSQL to MySQL 8.0 for operational reasons (hosting/tooling standardisation). MySQL has **no equivalent of Row-Level Security** — verified: MySQL 8 has no native RLS, and MariaDB's request (MDEV-27301) is unimplemented. The previous isolation model was 15 Alembic migrations' worth of `ALTER TABLE … FORCE ROW LEVEL SECURITY` + `CREATE POLICY workspace_isolation …`, so it could not be carried across. `apps/api/core/tenancy.py` is the deliberate, reviewed replacement.

## 2. What actually changed

| | PostgreSQL (before) | MySQL (now) |
|---|---|---|
| Enforcement point | Storage engine | Application (SQLAlchemy ORM hooks) |
| Scope of guarantee | **Any** SQL, including raw | ORM statements only; raw SQL is filtered by hand |
| SELECT / UPDATE / DELETE | `USING` clause | `with_loader_criteria` via `do_orm_execute` |
| INSERT | `WITH CHECK` clause | `before_flush` guard (§6) |
| Missing tenant context | Silent empty result (`workspace_id = NULL` matches nothing) | **Raises `TenancyNotBoundError`** |
| Auditable by | `grep CREATE POLICY` over migrations | `grep` this one module |

Two honest observations:

* **This is a weaker guarantee than RLS.** A forgotten `bind_workspace()` is now a Python-level responsibility. It is mitigated by failing closed and by the tests in §10, not eliminated.
* **In one respect it is stricter.** The old policy returned an empty set when no context was bound, which is easy to misread as "this tenant has no data". This module raises instead.

## 3. Canonical table classification

`tenancy.table_scope(table)` is the single source of truth. Enforcement, the tests, and this document all read it. It raises `KeyError` for an unclassified table — fail closed.

`test_every_mapped_table_is_classified` asserts the partition is **total** (every mapped table classified) and `test_classification_buckets_are_disjoint` asserts it is **disjoint**. A new model that nobody classified therefore fails the suite rather than silently defaulting to unprotected.

### TENANT_SCOPED — 29 tables

Workspace-owned. Auto-filtered on SELECT/UPDATE/DELETE and guarded on INSERT.

*Direct* (own `workspace_id` column) — `_DIRECT_TABLES`:
`workspace_members`, `projects`, `attack_narratives`, `agent_decisions`, `notifications`, `audit_events`, `ai_usage`, `engagement_state`, `agent_steps`, `remediation_items`, `remediation_events`, `remediation_evidence`, `verification_requests`, `risk_acceptances`, `risk_assessments`, `risk_assessment_findings`

The seven remediation/assessment tables are **all** Direct, deliberately, even though
`remediation_items` alone could have been a 2-hop Via table (`→ projects`). The other six
hang off `remediation_items`, which would put them **three** hops from `workspaces` — past
the 1-or-2-hop limit the module-level `assert` enforces. Giving every table in the
subsystem its own `workspace_id` is one rule instead of a mix, and it is what lets the
retention sweep's raw SQL and the tenant export reach each of them with a single explicit
`workspace_id = :wid` predicate.

*Via FK chain* (no `workspace_id` of their own) — `_VIA_TABLES`:

| Table | Chain to `workspace_id` |
|---|---|
| `targets`, `assets`, `vulnerabilities`, `reports` | → `projects` |
| `tool_runs`, `ai_plans` | → `scans` |
| `evidence` | → `tool_runs` → `scans` **OR** → `remediation_evidence.workspace_id` (see note) |
| `authorization_scopes` | → `targets` → `projects` |
| `vulnerability_evidence`, `remediations`, `attack_mappings`, `risk_scores`, `compliance_mappings`, `vulnerability_lineage`, `vulnerability_history` | → `vulnerabilities` → `projects` |

Chains are 1 or 2 hops; a module-level `assert` rejects a 3-hop entry, because only two builders exist (`_via_criterion`).

**`evidence` is the one two-path table.** `evidence.tool_run_id` became NULLABLE when
human-uploaded remediation proof was introduced — such an artifact has no tool run, and
fabricating one would put a false claim into the evidence chain. A NULL FK makes
`tool_run_id IN (<subquery>)` evaluate to NULL (i.e. NOT TRUE), so a proof row would be
invisible to *every* workspace under the plain chain. `_evidence_criterion` therefore ORs
in the `remediation_evidence` link, which carries its own `workspace_id`. The two branches
are mutually exclusive by construction, so this widens **reachability**, not access: a row
still has exactly one owning workspace, and an orphan (NULL tool run, no remediation link)
stays invisible to everyone — the correct fail-closed answer for an artifact with no owner.
`test_remediation_tenancy.py` pins both directions.

### SYSTEM_SCOPED — 3 tables (`EXEMPT_TABLES`)

Workspace-owned but **deliberately not auto-filtered**, each because a trusted internal path must read the row *before* the workspace is known. Same tables the original migrations left outside RLS — not an oversight.

| Table | Why exempt | Compensating control |
|---|---|---|
| `scans` | The Celery worker loads a scan by trusted internal `scan_id` to bootstrap tenancy (`orchestrator.run_scan` → `bind_workspace(scan.workspace_id)`) | Request-path service code filters by `workspace_id` explicitly |
| `api_keys` | Looked up by key hash during authentication, before any workspace is known | `get_workspace_context` rejects a key used outside its own workspace (`deps.py`) |
| `scan_schedules` | Celery beat iterates **all** due schedules across every workspace by design | `run_due_schedules` binds each schedule's workspace before doing tenant work |

### USER_SCOPED — 3 tables

`users`, `refresh_tokens`, `mfa_recovery_codes` — keyed by user identity. A user exists across workspaces, so workspace filtering is meaningless; access control is by authenticated identity.

### GLOBAL_SCOPED — 4 tables

`workspaces`, `roles`, `permissions`, `role_permissions` — platform-wide reference/config data.

`roles` deserves a note, since it *has* a `workspace_id` column: it is **nullable**, and `NULL` means a built-in system role shared by every workspace. Auto-filtering it would hide system roles from every tenant and break login. Its call sites filter explicitly — `Role.workspace_id.is_(None)` for system roles, `== workspace_id` for custom ones (`workspaces/service.py`, `workspaces/tenant_service.py`).

## 4. Workspace binding

```python
bind_workspace(ws_id)      # bind for the rest of the current asyncio Task
workspace_scope(ws_id)     # preferred: context manager, always resets
clear_workspace(token)     # explicit reset
admin_bypass()             # audited escape hatch for genuine cross-tenant work
current_workspace_id()     # read the binding
```

Binding happens at exactly four kinds of entry point:

| Entry point | Site |
|---|---|
| HTTP request | `core/deps.py:92` — in `get_workspace_context`, **before** the membership lookup |
| Scan execution | `scanner_engine/orchestrator.py:298` — from the trusted `scan.workspace_id` |
| Scheduled scans | `modules/schedules/service.py:176` — per schedule, inside the dispatch loop |
| Retention sweep | `retention/repo.py:69` — per workspace, inside the tenant loop |

Plus `ai_agent/usage_repo.py` (per usage row) and `modules/users/service.py` / `modules/workspaces/service.py` (workspace creation and cross-workspace listings, which use `admin_bypass` where genuinely cross-tenant).

## 5. SELECT / UPDATE / DELETE enforcement

`install()` registers a `do_orm_execute` listener. For any SELECT/UPDATE/DELETE touching a TENANT_SCOPED mapper it:

1. returns immediately if `admin_bypass()` is active;
2. raises `TenancyNotBoundError` if no workspace is bound;
3. otherwise attaches `with_loader_criteria(model, expr, include_aliases=True)` — `workspace_id == ws` for direct tables, or an `IN (subquery)` chain for VIA tables.

Implementation note (hard-won, kept from the original): the criteria are built **eagerly as expression objects**, never as `with_loader_criteria`'s lambda form. SQLAlchemy runs that lambda through its "lambda SQL" caching system, which statically analyses the body and forbids calling ordinary Python functions from inside it.

## 6. INSERT enforcement

**This is the gap the cutover opened, and it is now closed.**

`do_orm_execute` does **not** fire for an ORM flush INSERT. SQLAlchemy's unit of work persists `session.add()`-ed objects through its persistence layer, not through `session.execute()`. Measured against this project's MySQL 8.0: a flush INSERT fires `do_orm_execute` **0** times and `before_flush` **1** time. Postgres's `FORCE ROW LEVEL SECURITY` covered INSERT via `WITH CHECK`; losing that was a real regression.

`install()` therefore also registers a `before_flush` listener calling `_assert_insert_allowed(session.new)`, which for every pending TENANT_SCOPED row:

1. skips everything if `admin_bypass()` is active;
2. raises `TenancyNotBoundError` if no workspace is bound;
3. raises `CrossTenantWriteError` if a *direct* table's `workspace_id` ≠ the bound workspace.

Only `session.new` is inspected: `session.dirty` and `session.deleted` already pass through the auto-filter, which restricts them to rows the bound workspace can see.

A `workspace_id` of `None` is left to the column's own `NOT NULL` constraint rather than being back-filled — quietly stamping the bound workspace onto a row whose caller forgot it would hide the bug the guard exists to surface.

### Known limitation (deliberate)

The guard validates a VIA table's parent chain **only when the parent is already resident in the session** (identity map or pending set). It issues **no queries** to do so — a `SELECT` per pending row on every flush would be a real cost on the scanner's bulk finding ingest, and `apps/api/tests/test_via_table_tenancy.py::test_guard_does_not_query` asserts no SELECT is emitted.

*Audit Phase 14 update.* The check previously did not exist at all. It now catches the realistic ORM mistake: code that legitimately loaded another tenant's parent (under `admin_bypass()`, or from a system task) and then writes a child row while a different workspace is bound — that raises `CrossTenantWriteError`. **The residual gap is unchanged and deliberate:** a caller that fabricates a parent UUID it never read leaves the parent non-resident, so the hook stays silent rather than paying for a lookup.

For that case the control is the **service layer**, which is the only surface a real caller can reach and which resolves every parent through an explicit ownership check. Measured empirically: tenant A posting a target under tenant B's project returns **404**; addressing B's workspace directly returns **403**; creating a scan or schedule against B's project is refused. Both layers — including the documented gap — are asserted by `apps/api/tests/test_via_table_tenancy.py`.

## 7. Raw SQL policy

Raw `text()` bypasses the ORM entirely and is therefore **not** covered. Policy: every raw statement touching tenant data carries its own explicit workspace predicate, and the complete inventory is tracked here.

**The inventory is now machine-verified — see `docs/architecture/raw-sql-inventory.yml`.**

This section used to carry a hand-maintained table claiming a "complete inventory — 9 sites".
It drifted: the tree actually held **26** production raw-SQL statements. Section 11 of this
document predicted exactly that failure ("a new `text()` call site could be added without
updating this section. No automated gate today — this is the weakest link"), so the manual
table has been replaced by a gate rather than corrected in place.

**How it works.** `scripts/raw_sql_inventory.py` parses the AST of every production module
under `apps/api` and reports each call to `text(...)` or `.exec_driver_sql(...)`. Calls that
are the value of a `server_default=` / `onupdate=` / `default=` keyword are excluded: those are
schema DDL applied by the migration engine, not runtime queries, and they account for ~47 of
the raw `text(` occurrences — a substring grep drowns the real statements in them (and also
matches `context(`, `ciphertext(`, `read_text(`, and prose in docstrings). Tests, Alembic
migrations, and vendored code are excluded deliberately; the reasons are documented at the top
of the script.

The discovered set is compared against `raw-sql-inventory.yml`, which records every site with a
classification (TENANT_SCOPED / SYSTEM_SCOPED / GLOBAL / INFRASTRUCTURE) and a one-line reason.

**What fails the build:**
* a raw statement that is not registered — a new one, or a registered one that *moved*;
* an inventory entry pointing at a location that no longer holds raw SQL.

Because line numbers are the identifier, movement and in-place edits both surface as drift.
That is intentional: a content hash would survive a refactor but would also let a statement be
rewritten without review. The cost is a one-line inventory update when code shifts — which is
the prompt to re-read the statement.

**Run it:** `python scripts/raw_sql_inventory.py` (report) or `--check` (gate). CI runs the
gate in the `supply-chain` job, and `apps/api/tests/test_supply_chain_config.py` runs the same
scanner so drift also fails locally.

**Adding raw SQL:** prefer the ORM. If raw SQL is genuinely required, give any tenant-scoped
statement an explicit workspace predicate (or document what else scopes it), then register it
in `raw-sql-inventory.yml` with a classification and a reason.

`retention/repo.py` additionally hard-codes `_WORKSPACE_FILTER: dict[str, str]` per table and interpolates it into the CTE. That dict lookup raises `KeyError` for an unregistered table — fail closed.

**Rule for new raw SQL:** either add an explicit `workspace_id` predicate and a row in this table, or use the ORM.

## 8. Celery, background jobs, and ContextVar lifecycle

`_current_workspace_id` is a `contextvars.ContextVar`, not global state. An `asyncio.Task` receives a **copy** of the context at creation, and a `.set()` inside one task is invisible to any other.

* **FastAPI** dispatches each request as its own `asyncio.Task`, so concurrent requests on one connection cannot see each other's binding. Pinned by `test_concurrent_workspaces_do_not_bleed_context`.
* **Celery** tasks each run their own top-level `asyncio.run(...)` (`celery_app/tasks/scan_tasks.py`), so a binding cannot survive into the next task. Pinned by `test_celery_style_task_does_not_inherit_previous_task_context`.
* **`workspace_scope()`** always resets in a `finally`. Pinned by `test_workspace_scope_resets_context_on_exit`.

This is an improvement on the old `SET LOCAL` GUC, which was per-*connection* and could be observed by a concurrent request sharing that connection.

## 9. Fail-closed behaviour

| Situation | Result |
|---|---|
| Query a TENANT_SCOPED table, nothing bound | `TenancyNotBoundError` |
| INSERT a TENANT_SCOPED row, nothing bound | `TenancyNotBoundError` |
| INSERT stamped for another workspace | `CrossTenantWriteError` |
| Unclassified table passed to `table_scope()` | `KeyError` |
| Unregistered table in `_WORKSPACE_FILTER` | `KeyError` |
| `install()` referencing an unknown table | `RuntimeError` at startup |

`install()` is called from both process entry points — `main.py:74` (API) and `celery_app/worker.py:19` (worker) — and is idempotent.

## 10. Test coverage

`apps/api/tests/test_tenancy_isolation.py` — **19 tests, all passing against MySQL 8.0 `mbs_test`**:

* fail-closed on unbound SELECT
* DIRECT and VIA cross-workspace SELECT isolation
* cross-workspace UPDATE and DELETE isolation (dedicated tests)
* INSERT: valid PASS · no-context DENY · cross-workspace DENY · VIA no-context DENY · non-tenant tables still PASS
* `admin_bypass()` behaves as documented
* concurrent interleaved workspaces do not bleed context
* `workspace_scope` resets on exit; Celery-style tasks do not inherit context
* registry completeness: total partition, disjoint buckets, enforcement/classification agreement, unknown table raises

## 11. Risks and rollback

**Residual risks (accepted, with mitigations):**

1. *Raw SQL is not covered by the ORM filter.* Mitigation: **26 sites, machine-verified** — `scripts/raw_sql_inventory.py --check` rediscovers them from the AST and fails CI on any unregistered or moved statement (§7). Each is classified in `raw-sql-inventory.yml`.
2. *VIA-table parent chains are validated on INSERT only when the parent is already loaded* (§6, Phase 14). A fabricated, never-read parent UUID is not caught by the ORM hook — by design, to keep the flush query-free. Mitigation: service-layer ownership checks, verified end-to-end (404/403) in `test_via_table_tenancy.py`.
3. ~~*A new `text()` call site could be added without updating §7.* No automated gate today — this is the weakest link.~~ **CLOSED:** the gate described in §7 now runs in CI (`supply-chain` job) and in the test suite. This risk is what the hand-maintained table's drift (9 documented vs 26 actual) demonstrated in practice.

**Rollback:** the PostgreSQL RLS migrations are preserved under `db/migrations/archived_postgres/` (22 files). Rolling back means restoring those and reverting the dialect changes; it is a full migration, not a flag.

## 12. Procedure for adding a new table

1. Add the model.
2. **Classify it** in `apps/api/core/tenancy.py` — exactly one of `_DIRECT_TABLES`, `_VIA_TABLES`, `EXEMPT_TABLES`, `USER_SCOPED_TABLES`, `GLOBAL_SCOPED_TABLES`. Skipping this fails `test_every_mapped_table_is_classified`.
3. For a VIA table, give the FK chain (1–2 hops, ending at a table with `workspace_id`).
4. For an `EXEMPT_TABLES` entry, document *why* and name the compensating control — add it to §3 here.
5. Add it to the table lists in this document.
6. If it needs raw SQL, add the call site to §7 with its explicit workspace predicate.
7. Run `pytest apps/api/tests/test_tenancy_isolation.py` against MySQL `mbs_test`.

## 13. How to prove there is no cross-tenant access

```bash
# against a MySQL database whose name ends in _test
DATABASE_URL="mysql+aiomysql://<user>:<pw>@127.0.0.1:3307/mbs_test" \
  python -m pytest apps/api/tests/test_tenancy_isolation.py -v
```

Then review, in order: the classification in `tenancy.py` (§3), the two listeners in `install()` (§5, §6), and the raw-SQL inventory (§7). Those three are the entire trust surface.
