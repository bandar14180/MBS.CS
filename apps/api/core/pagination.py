"""Shared pagination (P1-3).

All list endpoints are bounded to avoid unbounded reads (a cheap DoS + memory
risk). Kept backward compatible: responses stay bare JSON arrays; the pagination
metadata (total / limit / offset / has_more) is returned in response headers, so
existing clients are unaffected while new clients can page.

FastAPI validates the bounds for us (limit 1..MAX_LIMIT, offset >= 0), so negative
or huge values are rejected with 422 automatically. Every paginated query must
apply a deterministic ORDER BY so pages are stable.
"""
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Query
from starlette.responses import Response

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


@dataclass
class Pagination:
    limit: int
    offset: int


def pagination_params(
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT, description="Max items to return (1..200)."),
    offset: int = Query(0, ge=0, description="Items to skip."),
) -> Pagination:
    return Pagination(limit=limit, offset=offset)


PaginationDep = Annotated[Pagination, Depends(pagination_params)]


def set_page_headers(response: Response, *, total: int, page: Pagination) -> None:
    """Attach pagination metadata as headers (body stays a bare array)."""
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Limit"] = str(page.limit)
    response.headers["X-Offset"] = str(page.offset)
    response.headers["X-Has-More"] = "true" if page.offset + page.limit < total else "false"


async def paginate(db, query, page: Pagination):
    """Run a (tenant-scoped, ORDER BY'd) query with limit/offset and also compute
    the total for the same filter. Returns (items, total). One extra COUNT query --
    not N+1. The query must already be ordered for stable pages.

    TENANCY (P1-2). The workspace predicate is applied to the COUNT **explicitly**, via
    `tenancy.workspace_criterion`, rather than being left to the automatic filter.

    The automatic filter cannot do it. `apps/api/core/tenancy.py` injects its predicate with
    `with_loader_criteria`, which SQLAlchemy applies only to statements that LOAD a mapped
    entity. Measured against SQLAlchemy 2.0.35, bound to a workspace owning ONE of two rows,
    EVERY aggregate shape returned the global count of 2:

        select(func.count()).select_from(query.subquery())                   -> 2  (the bug)
        select(func.count(Entity.id))                                        -> 2
        select(func.count(Entity.id)).select_from(Entity)                    -> 2
        query.with_only_columns(func.count(pk), maintain_column_froms=True)  -> 2

    So no reshaping of the count query fixes this -- the criterion has to be added by hand.
    The result was that the total silently described the GLOBAL population while the items
    described one workspace. (No endpoint leaked at the time, because every call site happened
    to carry its own explicit workspace_id/project_id predicate; the point of this fix is that
    the safety net now holds when a future caller does not.)

    The criterion is applied to the INNER query, before it becomes a subquery: it refers to
    the entity's own columns, so attaching it to the outer count -- whose FROM is an anonymous
    subquery -- would resolve those names against the wrong scope.

    A SYSTEM_SCOPED/exempt table (scans, api_keys, scan_schedules) is unaffected:
    `workspace_criterion` returns None for those, so their counts are unfiltered exactly as
    before and their call sites keep their own explicit workspace_id predicates. A
    tenant-scoped entity with NO workspace bound raises TenancyNotBoundError -- the same
    fail-closed contract the items query is already held to."""
    from sqlalchemy import func, select

    from apps.api.core.tenancy import workspace_criterion

    # The COUNT is scoped EXPLICITLY, not by the auto-filter. Measured against SQLAlchemy
    # 2.0.35, `with_loader_criteria` attaches only to statements that LOAD a mapped entity,
    # so every aggregate shape escaped it -- each of these returned the GLOBAL count while a
    # workspace owning ONE row was bound:
    #     select(func.count()).select_from(query.subquery())     <- the original bug
    #     select(func.count(Entity.id))
    #     select(func.count(Entity.id)).select_from(Entity)
    #     query.with_only_columns(func.count(pk), maintain_column_froms=True)
    # Reshaping the query therefore cannot fix this; the predicate must be added by hand.
    entity = _counted_entity(query)
    counted = query.order_by(None)
    if entity is not None:
        # Raises TenancyNotBoundError for a tenant-scoped entity with no workspace bound --
        # the same fail-closed contract the entity query itself is held to. Returns None for
        # SYSTEM/USER/GLOBAL-scoped tables and under admin_bypass(), leaving those counts
        # exactly as they were.
        criterion = workspace_criterion(entity)
        if criterion is not None:
            # Applied to the INNER query, before it becomes a subquery. The criterion refers
            # to the entity's own columns, so attaching it to the OUTER count -- whose FROM is
            # an anonymous subquery -- would resolve those names against the wrong scope.
            counted = counted.where(criterion)
    total = await db.scalar(select(func.count()).select_from(counted.subquery()))
    items = list(await db.scalars(query.limit(page.limit).offset(page.offset)))
    return items, int(total or 0)


def _counted_entity(query):
    """The single mapped entity a SELECT loads, or None.

    Identifies WHICH model's workspace predicate `paginate` must apply to its COUNT (see
    `tenancy.workspace_criterion`). Returns None for anything that is not exactly one mapped
    entity -- a column-only or multi-entity select -- so the caller leaves such a count
    unscoped rather than guessing at the wrong model. Those queries are not covered by the
    ORM auto-filter either, so this is no worse than the pre-existing behaviour."""
    try:
        descriptions = query.column_descriptions
    except Exception:  # noqa: BLE001 -- not an ORM-entity select; caller falls back
        return None
    entities = {d.get("entity") for d in descriptions if d.get("entity") is not None}
    if len(entities) != 1:
        return None
    return entities.pop()
