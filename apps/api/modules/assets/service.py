import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.pagination import MAX_LIMIT, Pagination, paginate
from apps.api.modules.assets.models import Asset


async def upsert_asset(
    db: AsyncSession,
    project_id: uuid.UUID,
    target_id: uuid.UUID,
    asset_type: str,
    value: str,
    metadata: dict,
) -> None:
    """Insert-or-touch: assets outlive individual scans (blueprint §3), so a
    re-scan that re-discovers the same asset updates last_seen/metadata rather
    than creating a duplicate. Keyed on the (target_id, asset_type, value)
    unique constraint."""
    now = datetime.now(timezone.utc)
    # Target Asset.__table__, not the mapped class: on the declarative class the
    # name `metadata` is SQLAlchemy's MetaData object (the column's ORM attr is
    # metadata_), so pg_insert(Asset).values(metadata=...) grabs the wrong thing
    # ("'MetaData' object has no attribute '_bulk_update_tuples'"). Against the
    # Table, keys are physical column names -- so "metadata" is the column.
    stmt = pg_insert(Asset.__table__).values(
        project_id=project_id,
        target_id=target_id,
        asset_type=asset_type,
        value=value,
        metadata=metadata,
        first_seen=now,
        last_seen=now,
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_assets_target_type_value",
        set_={"last_seen": now, "metadata": metadata},
    )
    await db.execute(stmt)


async def list_assets(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, page: Pagination | None = None
) -> tuple[list[Asset], int]:
    query = select(Asset).where(Asset.project_id == project_id).order_by(Asset.first_seen, Asset.id)
    return await paginate(db, query, page or Pagination(limit=MAX_LIMIT, offset=0))


async def get_asset(db: AsyncSession, workspace_id: uuid.UUID, asset_id: uuid.UUID) -> Asset:
    asset = await db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    return asset
