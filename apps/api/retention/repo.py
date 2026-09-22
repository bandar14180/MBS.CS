"""Phase 5.3.2 -- retention SQL layer.

ALL raw SQL and the per-workspace tenancy bootstrap live here so service.py stays
orchestration only.

Phase 0 MySQL cutover -- READ THIS BEFORE TOUCHING THIS FILE: every query in this module
is raw `text()` SQL, which `apps/api/core/tenancy.py`'s ORM-level auto-filter does NOT
see (it hooks `do_orm_execute`, which raw SQL never goes through -- see that module's
docstring). Under the old Postgres RLS design that was fine: `set_workspace()` set a
session GUC and the `workspace_isolation` policy scoped every query to it regardless of
what SQL the query text contained. That mechanism is gone. Every query below that touches
a workspace-scoped table (reports, ai_usage, notifications, audit_events) now carries an
EXPLICIT `WHERE workspace_id = :wid` (or, for `reports`, a join through `projects` -- see
`_WORKSPACE_FILTER`) written directly into the SQL text. `delete_by_ids` is the one
exception: it deletes by a specific id list that was already produced by a
workspace-scoped SELECT, so re-filtering there would be redundant, not protective -- but
if you ever call it with an id list from anywhere else, add the filter there too. `scans`
stays scoped by an explicit `workspace_id = :wid` in its own dedicated queries below, same
as before (it was never RLS-protected -- see tenancy.EXEMPT_TABLES).

`set_workspace()` still runs per-tenant (now binding tenancy.py's context instead of a
Postgres GUC) because the ORM-level operations elsewhere in the retention flow (audit
event writes, etc.) DO go through the auto-filter and still need it bound.

Table/column identifiers here are internal constants (never user input); id lists use
expanding bindparams. Eligibility = older than `cutoff` AND not among the newest `min_keep`
(ranked by timestamp), capped at `batch` for deletion.
"""
import contextlib
import json
import uuid

from sqlalchemy import bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core import tenancy

# Resources deleted by age directly: resource -> (table, timestamp column).
RESOURCE_TABLE: dict[str, tuple[str, str]] = {
    "report": ("reports", "generated_at"),
    "ai_usage": ("ai_usage", "created_at"),
    "notification": ("notifications", "created_at"),
    "audit": ("audit_events", "created_at"),
    # Remediation workflow history. The only new table with unbounded growth (one row per
    # workflow action, kept forever); the remediation ITEMS themselves are deliberately not
    # aged off by time -- see config.retention_remediation_event_days.
    "remediation_event": ("remediation_events", "created_at"),
    # ISSUED client assessments. Longest window of anything here: a client may request a prior
    # period's assessment years later, and the frozen snapshot IS the record.
    "risk_assessment": ("risk_assessments", "created_at"),
}

# How each RESOURCE_TABLE entry is scoped to a workspace, now that it must be written into
# the SQL explicitly (see module docstring). Mirrors apps/api/core/tenancy.py's registry:
# ai_usage/notifications/audit_events carry workspace_id directly; reports is scoped via
# project_id -> projects.workspace_id (one hop), same chain tenancy.py uses for the ORM.
_WORKSPACE_FILTER: dict[str, str] = {
    "reports": "project_id IN (SELECT id FROM projects WHERE workspace_id = :wid)",
    "ai_usage": "workspace_id = :wid",
    "notifications": "workspace_id = :wid",
    "audit_events": "workspace_id = :wid",
    # Both new tables carry workspace_id DIRECTLY (they are _DIRECT_TABLES in tenancy.py), so
    # the explicit filter this raw SQL needs is a plain equality -- no join through projects.
    "remediation_events": "workspace_id = :wid",
    # `status = 'issued'` is a RETENTION-SCOPE restriction, not just a filter: a DRAFT
    # assessment must never be aged off by this sweep (it is unfinished work someone is still
    # editing, and it holds no frozen record worth a retention window). Only the immutable,
    # already-delivered snapshots are eligible.
    "risk_assessments": "workspace_id = :wid AND status = 'issued'",
}

# Terminal scan states -- only finished scans are ever eligible (never queued/running).
_SCAN_TERMINAL = ("completed", "completed_with_errors", "failed", "cancelled")


async def list_workspace_ids(session: AsyncSession) -> list[uuid.UUID]:
    """Enumerate tenants from the `workspaces` anchor (drives the per-tenant loop)."""
    rows = await session.execute(text("SELECT id FROM workspaces ORDER BY created_at, id"))
    return [r[0] for r in rows.fetchall()]


@contextlib.contextmanager
def workspace_scope(workspace_id: uuid.UUID):
    """Bind workspace-isolation context (apps/api/core/tenancy.py) for ONE tenant, restoring
    the previous context on exit -- including when the per-tenant purge raises.

    AUDIT-004: this replaces a bare `set_workspace()` that called `tenancy.bind_workspace()`
    and never reset. The retention sweep loops over EVERY workspace, so the bare form left the
    last tenant in the list bound to the worker Task after the sweep finished, and an exception
    mid-loop left some arbitrary tenant bound for whatever ran next on that Task.

    Does NOT by itself scope the raw-SQL queries below -- see the module docstring; those carry
    their own explicit workspace predicates.
    """
    with tenancy.workspace_scope(workspace_id):
        yield


# --- generic table eligibility (report / ai_usage / notification / audit) -------------------

def _ranked_cte(table: str, ts: str) -> str:
    # Rows ranked newest-first so `rn > :min_keep` always spares the newest min_keep.
    # No explicit NULLS LAST: unlike Postgres (whose DESC default is NULLS FIRST, hence the
    # original explicit override), MySQL sorts NULL as the lowest value, so a bare `DESC`
    # already puts NULLs last -- the behavior this needs, with no clause required.
    return (
        f"WITH ranked AS (SELECT id, {ts} AS ts, "
        f"row_number() OVER (ORDER BY {ts} DESC, id DESC) AS rn FROM {table} "
        f"WHERE {_WORKSPACE_FILTER[table]}) "
    )


async def count_eligible_generic(
    session: AsyncSession, table: str, ts: str, cutoff, min_keep: int, workspace_id: uuid.UUID
) -> int:
    sql = _ranked_cte(table, ts) + (
        "SELECT count(*) FROM ranked WHERE rn > :min_keep AND ts IS NOT NULL AND ts < :cutoff"
    )
    return int(
        await session.scalar(
            text(sql), {"min_keep": min_keep, "cutoff": cutoff, "wid": str(workspace_id)}
        )
        or 0
    )


async def select_eligible_generic(
    session: AsyncSession, table: str, ts: str, cutoff, min_keep: int, batch: int, workspace_id: uuid.UUID
) -> list[uuid.UUID]:
    sql = _ranked_cte(table, ts) + (
        "SELECT id FROM ranked WHERE rn > :min_keep AND ts IS NOT NULL AND ts < :cutoff "
        "ORDER BY ts ASC, id ASC LIMIT :batch"
    )
    rows = await session.execute(
        text(sql), {"min_keep": min_keep, "cutoff": cutoff, "batch": batch, "wid": str(workspace_id)}
    )
    return [r[0] for r in rows.fetchall()]


async def delete_by_ids(session: AsyncSession, table: str, ids: list[uuid.UUID]) -> int:
    """No workspace filter here BY DESIGN, not by omission: `ids` must already come from a
    workspace-scoped SELECT (select_eligible_generic / select_eligible_scans) -- re-filtering
    an already-scoped id list is redundant, not protective. If a future caller ever passes an
    id list that ISN'T already workspace-scoped, add the filter here rather than assuming
    this function will catch it."""
    if not ids:
        return 0
    stmt = text(f"DELETE FROM {table} WHERE id IN :ids").bindparams(
        bindparam("ids", expanding=True)
    )
    result = await session.execute(stmt, {"ids": ids})
    return result.rowcount or 0


# --- scans (in tenancy.EXEMPT_TABLES: scope by workspace_id + terminal status) --------------

_SCAN_RANK = (
    "WITH ranked AS (SELECT id, COALESCE(completed_at, created_at) AS ts, "
    "row_number() OVER (ORDER BY COALESCE(completed_at, created_at) DESC, id DESC) AS rn "
    "FROM scans WHERE workspace_id = :wid AND status IN :states) "
)


def _scan_stmt(tail: str):
    return text(_SCAN_RANK + tail).bindparams(bindparam("states", expanding=True))


async def count_eligible_scans(
    session: AsyncSession, workspace_id: uuid.UUID, cutoff, min_keep: int
) -> int:
    stmt = _scan_stmt("SELECT count(*) FROM ranked WHERE rn > :min_keep AND ts < :cutoff")
    return int(
        await session.scalar(
            stmt, {"wid": str(workspace_id), "states": list(_SCAN_TERMINAL),
                    "min_keep": min_keep, "cutoff": cutoff}
        ) or 0
    )


async def select_eligible_scans(
    session: AsyncSession, workspace_id: uuid.UUID, cutoff, min_keep: int, batch: int
) -> list[uuid.UUID]:
    stmt = _scan_stmt(
        "SELECT id FROM ranked WHERE rn > :min_keep AND ts < :cutoff ORDER BY ts ASC, id ASC LIMIT :batch"
    )
    rows = await session.execute(
        stmt, {"wid": str(workspace_id), "states": list(_SCAN_TERMINAL),
                "min_keep": min_keep, "cutoff": cutoff, "batch": batch}
    )
    return [r[0] for r in rows.fetchall()]


async def capture_tool_run_ids(session: AsyncSession, scan_ids: list[uuid.UUID]) -> list[uuid.UUID]:
    """MUST run BEFORE deleting the scans: the scan cascade destroys tool_runs, and the
    evidence object keys are `tool-runs/{tool_run_id}/...` -- lose the ids and the objects
    can't be located. No workspace filter needed: `scan_ids` already came from
    select_eligible_scans, which filters by workspace_id explicitly."""
    if not scan_ids:
        return []
    stmt = text("SELECT id FROM tool_runs WHERE scan_id IN :ids").bindparams(
        bindparam("ids", expanding=True)
    )
    rows = await session.execute(stmt, {"ids": scan_ids})
    return [r[0] for r in rows.fetchall()]


async def capture_evidence_uris(session: AsyncSession, tool_run_ids: list[uuid.UUID]) -> list[str]:
    """P1-1: evidence object URIs for the given tool runs, captured BEFORE the scan cascade
    deletes the rows.

    MUST run before delete_scans: the cascade removes `evidence`, and a screenshot's key is
    `vulnerabilities/{vuln_id}/screenshot-*.png` -- NOT under the `tool-runs/{id}/` prefix the
    caller deletes separately -- so losing the row means losing the only pointer to the object.

    No workspace filter needed: `tool_run_ids` already came from capture_tool_run_ids, which
    is driven by a workspace-scoped scan selection."""
    if not tool_run_ids:
        return []
    stmt = text(
        "SELECT storage_uri FROM evidence WHERE tool_run_id IN :ids AND storage_uri IS NOT NULL"
    ).bindparams(bindparam("ids", expanding=True))
    rows = await session.execute(stmt, {"ids": tool_run_ids})
    return [r[0] for r in rows.fetchall()]


async def mark_reports_with_purged_scans(
    session: AsyncSession, wid: uuid.UUID, scan_ids: list[uuid.UUID]
) -> int:
    """Prompt 13, Finding #8: flip `scans_purged` on every report in this workspace whose
    (never-rewritten) `scan_ids` JSON list names at least one of the scans about to be
    deleted. MUST run BEFORE delete_scans, in the SAME transaction, so the flag and the
    deletion are atomic -- a report can never observably exist with a stale, un-flagged
    reference even for one committed instant.

    Deliberately fetches candidate reports and checks overlap in PYTHON rather than with a SQL
    JSON function: `JSON_OVERLAPS`/`JSON_CONTAINS` semantics and availability differ between
    MySQL 8.0.17+ and MariaDB (this codebase targets both -- see this file's own module
    docstring), and a workspace's report count is small and this runs on a periodic background
    sweep, not a request path, so the portability is worth the extra round trip. Only reports
    that are NOT already flagged are candidates, so a report already marked stays marked
    (idempotent) without a redundant UPDATE.

    No workspace filter needed on the scan_ids themselves: `scan_ids` (the parameter) already
    came from select_eligible_scans, which is workspace-scoped; the `WHERE workspace_id`
    predicate below is on `reports` via its `projects` join (the same `_WORKSPACE_FILTER` join
    shape `count_eligible_generic`/`select_eligible_generic` use for `reports`), so a report
    from a DIFFERENT workspace can never be flagged even if a scan id collision were somehow
    possible."""
    if not scan_ids:
        return 0
    scan_id_strs = {str(s) for s in scan_ids}
    stmt = text(
        "SELECT r.id, r.scan_ids FROM reports r "
        "JOIN projects p ON p.id = r.project_id "
        "WHERE p.workspace_id = :wid AND r.scans_purged = 0"
    )
    rows = (await session.execute(stmt, {"wid": str(wid)})).fetchall()
    to_flag: list[uuid.UUID] = []
    for report_id, report_scan_ids_raw in rows:
        # A raw `text()` SELECT returns the JSON column as its serialized STRING form, not a
        # parsed Python list (unlike ORM attribute access, which deserializes automatically) --
        # confirmed against a real MySQL 8 server: iterating the string directly would walk its
        # CHARACTERS, never matching a real UUID. Parse it explicitly here.
        if isinstance(report_scan_ids_raw, str):
            try:
                report_scan_ids = json.loads(report_scan_ids_raw)
            except (TypeError, ValueError):
                report_scan_ids = []
        else:
            report_scan_ids = report_scan_ids_raw or []
        cited = {str(s) for s in report_scan_ids}
        if cited & scan_id_strs:
            to_flag.append(report_id)
    if not to_flag:
        return 0
    upd = text("UPDATE reports SET scans_purged = 1 WHERE id IN :ids").bindparams(
        bindparam("ids", expanding=True)
    )
    result = await session.execute(upd, {"ids": to_flag})
    return result.rowcount or 0


async def delete_scans(session: AsyncSession, scan_ids: list[uuid.UUID]) -> int:
    if not scan_ids:
        return 0
    # EXEMPT table (not auto-filtered); cascade removes tool_runs/evidence/ai_usage/agent/attack subtree and
    # SET NULLs vulnerabilities.first/last_scan_id (findings survive).
    stmt = text("DELETE FROM scans WHERE id IN :ids").bindparams(bindparam("ids", expanding=True))
    result = await session.execute(stmt, {"ids": scan_ids})
    return result.rowcount or 0


# --- report object capture (before row delete) ---------------------------------------------

async def capture_report_uris(session: AsyncSession, report_ids: list[uuid.UUID]) -> list[str]:
    """Capture report storage URIs BEFORE deleting the rows. No workspace filter needed:
    `report_ids` already came from select_eligible_generic, which is workspace-scoped.
    Non-s3 / NULL URIs are returned as-is; the caller filters them out before touching storage."""
    if not report_ids:
        return []
    stmt = text(
        "SELECT storage_uri FROM reports WHERE id IN :ids AND storage_uri IS NOT NULL"
    ).bindparams(bindparam("ids", expanding=True))
    rows = await session.execute(stmt, {"ids": report_ids})
    return [r[0] for r in rows.fetchall()]
