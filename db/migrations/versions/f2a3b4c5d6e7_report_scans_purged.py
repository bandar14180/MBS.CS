"""reports.scans_purged (Prompt 13, Finding #8)

Purely ADDITIVE: one new column on `reports`, no change to any existing column/index/
constraint, no data migration -- every existing report reads as `scans_purged=False`, which is
the true historical fact for a row created before retention could have purged anything it cites
(the flag is only ever set going forward, by the retention sweep itself; see
apps/api/retention/repo.py `mark_reports_with_purged_scans`).

WHY: `Report.scan_ids` is a JSON list, validated against the `scans` table only at CREATE time
(reports/service.py create_report). It is not a relational FK, so a cited scan can later be
retention-purged (scans have their own, typically SHORTER retention window --
retention_scan_days defaults to 180 vs retention_report_days's 365) with nothing making that
explicit on the report itself. This column is that explicit, queryable signal: it is set (never
`scan_ids` itself, which stays the historically accurate record of what was included at
generation time) by the retention sweep's scan-purge step, in the SAME transaction as the
deletion, so the flag and the deletion are atomic.

MySQL notes:
  * `NOT NULL DEFAULT 0` is safe to add to a live table with existing rows in one statement --
    no separate backfill needed (unlike a JSON column, MySQL's BOOLEAN/TINYINT(1) supports a
    literal server default directly).

Revision ID: f2a3b4c5d6e7
Revises: e1f2a3b4c5d6
Create Date: 2026-09-19 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "f2a3b4c5d6e7"
down_revision: Union[str, None] = "e1f2a3b4c5d6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "reports",
        sa.Column("scans_purged", sa.Boolean(), nullable=False, server_default=sa.text("0")),
    )


def downgrade() -> None:
    op.drop_column("reports", "scans_purged")
