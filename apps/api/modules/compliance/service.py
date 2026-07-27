import uuid

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
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
    stmt = pg_insert(ComplianceMapping.__table__).values(rows)
    stmt = stmt.on_conflict_do_nothing(constraint="uq_compliance_vuln_framework_control")
    await db.execute(stmt)


async def list_mappings(db: AsyncSession, vulnerability_id: uuid.UUID) -> list[ComplianceMapping]:
    result = await db.scalars(
        select(ComplianceMapping)
        .where(ComplianceMapping.vulnerability_id == vulnerability_id)
        .order_by(ComplianceMapping.framework, ComplianceMapping.control_id)
    )
    return list(result)
