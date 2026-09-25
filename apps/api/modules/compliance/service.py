import uuid

from sqlalchemy import select
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.compliance.catalog import controls_for_category
from apps.api.modules.compliance.models import ComplianceMapping


async def sync_mappings(db: AsyncSession, vulnerability_id: uuid.UUID, category: str | None) -> None:
    """Map a vulnerability's category to framework controls and persist them.
    Idempotent: uses the (vuln, framework, control) unique key with
    do-nothing-on-conflict, so re-detection doesn't duplicate rows."""
    controls = controls_for_category(category)
    if not controls:
        return
    rows = [
        {
            "vulnerability_id": vulnerability_id,
            "framework": framework,
            "control_id": control_id,
            "control_description": description,
        }
        for framework, control_id, description in controls
    ]
    stmt = mysql_insert(ComplianceMapping.__table__).values(rows)
    # Phase 0 MySQL cutover: MySQL has no on_conflict_do_nothing. The standard SQLAlchemy
    # idiom for a true no-op ON DUPLICATE KEY UPDATE is to set the table's own PK column to
    # itself via VALUES() -- it satisfies "must SET something" while changing nothing, which
    # is exactly do-nothing-on-conflict's contract. (INSERT IGNORE was deliberately NOT used
    # here: it silently swallows every warning-level error, not just this specific duplicate
    # key, which is broader than what this call site wants.)
    stmt = stmt.on_duplicate_key_update(id=stmt.inserted.id)
    await db.execute(stmt)


async def list_mappings(db: AsyncSession, vulnerability_id: uuid.UUID) -> list[ComplianceMapping]:
    result = await db.scalars(
        select(ComplianceMapping)
        .where(ComplianceMapping.vulnerability_id == vulnerability_id)
        .order_by(ComplianceMapping.framework, ComplianceMapping.control_id)
    )
    return list(result)
