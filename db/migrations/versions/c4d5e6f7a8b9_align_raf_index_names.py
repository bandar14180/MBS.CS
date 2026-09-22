"""align risk_assessment_findings index names with the model metadata (AUDIT-009)

Revision ID: c4d5e6f7a8b9
Revises: b2c3d4e5f6a7
Create Date: 2026-09-03 00:00:00.000000

AUDIT-009 -- index-name drift. `b2c3d4e5f6a7` created the two single-column indexes on
`risk_assessment_findings` as `ix_raf_workspace_id` / `ix_raf_assessment_id`, but the model
declares them with `index=True` on the columns, which SQLAlchemy auto-names
`ix_risk_assessment_findings_<column>` -- the convention every other table in this repo follows
(see the op.f('ix_...') calls throughout 417cf2df2299_mysql_baseline_schema.py). The mismatch made
`alembic check` report a permanent phantom diff (drop the ix_raf_* pair, add the canonical pair)
on a schema that was in fact structurally correct, which is exactly the noise that trains people
to ignore the migration gate.

b2c3d4e5f6a7 has been corrected to emit the canonical names for databases built from scratch.
This migration fixes databases that ALREADY applied the old one. It RENAMES rather than
drop/create so the index is never absent -- no table scan, no window without the index, and no
data is touched. It is idempotent and checks the live catalog first, so it is a no-op on a
database created after the b2c3d4e5f6a7 correction (where the canonical names already exist).

`ix_raf_assessment_severity` is deliberately NOT renamed: it is declared explicitly in the
model's __table_args__ under that exact name, so the short form IS canonical there and metadata
and migration already agree.
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'c4d5e6f7a8b9'
down_revision: Union[str, None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLE = "risk_assessment_findings"
# (legacy name, canonical name)
RENAMES = (
    ("ix_raf_workspace_id", "ix_risk_assessment_findings_workspace_id"),
    ("ix_raf_assessment_id", "ix_risk_assessment_findings_assessment_id"),
)


def _existing_indexes() -> set[str]:
    bind = op.get_bind()
    return {row[0] for row in bind.exec_driver_sql(
        "SELECT DISTINCT index_name FROM information_schema.statistics "
        "WHERE table_schema = DATABASE() AND table_name = %s",
        (TABLE,),
    )}


def _rename(pairs) -> None:
    """RENAME INDEX for every pair whose source exists and whose destination does not.

    Guarding on the live catalog keeps this safe in both directions and on partially-migrated
    databases: a DB built after the b2c3d4e5f6a7 fix already has the canonical names and gets a
    clean no-op instead of an 'unknown index' error.
    """
    present = _existing_indexes()
    for src, dst in pairs:
        if src in present and dst not in present:
            op.execute(f"ALTER TABLE `{TABLE}` RENAME INDEX `{src}` TO `{dst}`")


def upgrade() -> None:
    _rename(RENAMES)


def downgrade() -> None:
    _rename(tuple((dst, src) for src, dst in RENAMES))
