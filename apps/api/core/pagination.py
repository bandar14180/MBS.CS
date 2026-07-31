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
    not N+1. The query must already be ordered for stable pages."""
    from sqlalchemy import func, select

    total = await db.scalar(select(func.count()).select_from(query.order_by(None).subquery()))
    items = list(await db.scalars(query.limit(page.limit).offset(page.offset)))
    return items, int(total or 0)
