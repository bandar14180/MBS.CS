"""Phase 5.3.2 -- retention SQL / RLS layer.

ALL raw SQL and the per-workspace RLS bootstrap live here so service.py stays orchestration
only. Every operation on a FORCE-RLS table (reports, ai_usage, notifications, audit_events,
tool_runs, evidence) runs AFTER `set_workspace()` so the `workspace_isolation` policy scopes
it to exactly one tenant -- an unset/wrong GUC would make an RLS DELETE a silent no-op, so the
per-workspace loop in service.py must always call set_workspace first. `scans` is RLS-exempt
(worker bootstrap) so its queries filter by workspace_id explicitly.

Table/column identifiers here are internal constants (never user input); id lists use
expanding bindparams. Eligibility = older than `cutoff` AND not among the newest `min_keep`
(ranked by timestamp), capped at `batch` for deletion.
"""
import uuid

from sqlalchemy import bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession

# RLS resources deleted by age directly: resource -> (table, timestamp column).
RESOURCE_TABLE: dict[str, tuple[str, str]] = {
    "report": ("reports", "generated_at"),
    "ai_usage": ("ai_usage", "created_at"),
    "notification": ("notifications", "created_at"),
    "audit": ("audit_events", "created_at"),
}

# Terminal scan states -- only finished scans are ever eligible (never queued/running).
_SCAN_TERMINAL = ("completed", "completed_with_errors", "failed", "cancelled")


async def list_workspace_ids(session: AsyncSession) -> list[uuid.UUID]:
    """Enumerate tenants from the NON-RLS `workspaces` anchor (drives the per-tenant loop)."""
    rows = await session.execute(text("SELECT id FROM workspaces ORDER BY created_at, id"))
    return [r[0] for r in rows.fetchall()]


async def set_workspace(session: AsyncSession, workspace_id: uuid.UUID) -> None:
    """Bootstrap RLS for this tenant. Session-scoped (is_local=false), matching the
    orchestrator / schedule jobs that run under a reused StaticPool connection."""
    await session.execute(
        text("SELECT set_config('app.current_workspace_id', :wid, false)"),
        {"wid": str(workspace_id)},
    )


# --- generic RLS-table eligibility (report / ai_usage / notification / audit) ---------------

def _ranked_cte(table: str, ts: str) -> str:
    # Rows ranked newest-first so `rn > :min_keep` always spares the newest min_keep.
    return (
        f"WITH ranked AS (SELECT id, {ts} AS ts, "
        f"row_number() OVER (ORDER BY {ts} DESC NULLS LAST, id DESC) AS rn FROM {table}) "
    )


async def count_eligible_generic(
    session: AsyncSession, table: str, ts: str, cutoff, min_keep: int
) -> int:
    sql = _ranked_cte(table, ts) + (
        "SELECT count(*) FROM ranked WHERE rn > :min_keep AND ts IS NOT NULL AND ts < :cutoff"
    )
    return int(await session.scalar(text(sql), {"min_keep": min_keep, "cutoff": cutoff}) or 0)


async def select_eligible_generic(
    session: AsyncSession, table: str, ts: str, cutoff, min_keep: int, batch: int
) -> list[uuid.UUID]:
    sql = _ranked_cte(table, ts) + (
        "SELECT id FROM ranked WHERE rn > :min_keep AND ts IS NOT NULL AND ts < :cutoff "
        "ORDER BY ts ASC, id ASC LIMIT :batch"
    )
    rows = await session.execute(
        text(sql), {"min_keep": min_keep, "cutoff": cutoff, "batch": batch}
    )
    return [r[0] for r in rows.fetchall()]


async def delete_by_ids(session: AsyncSession, table: str, ids: list[uuid.UUID]) -> int:
    if not ids:
        return 0
    stmt = text(f"DELETE FROM {table} WHERE id IN :ids").bindparams(
        bindparam("ids", expanding=True)
    )
    result = await session.execute(stmt, {"ids": ids})
    return result.rowcount or 0


# --- scans (NON-RLS: scope by workspace_id + terminal status) -------------------------------

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
    can't be located. (tool_runs is RLS-visible under the workspace GUC set by the caller.)"""
    if not scan_ids:
        return []
    stmt = text("SELECT id FROM tool_runs WHERE scan_id IN :ids").bindparams(
        bindparam("ids", expanding=True)
    )
    rows = await session.execute(stmt, {"ids": scan_ids})
    return [r[0] for r in rows.fetchall()]


async def delete_scans(session: AsyncSession, scan_ids: list[uuid.UUID]) -> int:
    if not scan_ids:
        return 0
    # NON-RLS table; cascade removes tool_runs/evidence/ai_usage/agent/attack subtree and
    # SET NULLs vulnerabilities.first/last_scan_id (findings survive).
    stmt = text("DELETE FROM scans WHERE id IN :ids").bindparams(bindparam("ids", expanding=True))
    result = await session.execute(stmt, {"ids": scan_ids})
    return result.rowcount or 0


# --- report object capture (before row delete) ---------------------------------------------

async def capture_report_uris(session: AsyncSession, report_ids: list[uuid.UUID]) -> list[str]:
    """Capture report storage URIs BEFORE deleting the rows (RLS-visible under the GUC).
    Non-s3 / NULL URIs are returned as-is; the caller filters them out before touching storage."""
    if not report_ids:
        return []
    stmt = text(
        "SELECT storage_uri FROM reports WHERE id IN :ids AND storage_uri IS NOT NULL"
    ).bindparams(bindparam("ids", expanding=True))
    rows = await session.execute(stmt, {"ids": report_ids})
    return [r[0] for r in rows.fetchall()]
