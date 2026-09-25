"""verification_requests.baseline_locations (Prompt 13, Finding #3)

Purely ADDITIVE: one new nullable-then-backfilled JSON column on `verification_requests`, no
change to any existing column/index/constraint, no data loss.

WHY: `complete_verification()` previously derived PASS/FAIL only from which locations the
RETEST scan happened to re-touch (`Vulnerability.last_seen_scan_id == scan_id`) -- a location
the retest scan never revisited silently dropped out of consideration instead of blocking the
verdict, so a retest with narrower coverage than the original scan could report `passed` without
ever re-examining every original location. `baseline_locations` snapshots the issue's distinct
scorable locations at the moment verification is REQUESTED (before any retest runs), giving
`complete_verification()` a fixed reference set to check retest coverage against
(apps/api/modules/remediation/verification.py: `_scorable_locations`/`_retest_had_usable_
detection_coverage`), instead of only ever seeing whatever the retest scan happened to produce.

Also widens `verification_requests.result` from String(16) to String(24): the new third
outcome `incomplete_coverage` (19 characters) does not fit the old width. `passed`/`failed`
(the only values ever written before this change) are unaffected by a widen.

MySQL notes:
  * Added NULLABLE with no server default (MySQL's JSON column type does not portably support a
    literal-list SQL DEFAULT across the 5.7/8.0/MariaDB matrix this project targets -- see
    apps/api/core/db_types.JSONType, a plain SQLAlchemy JSON column), then backfilled to `[]`
    for every existing row in a single UPDATE, then altered to NOT NULL. This is the same
    add-nullable / backfill / tighten sequence used for a live table with existing rows
    elsewhere in this project's Postgres-era migrations, adapted for MySQL's ALTER syntax.
  * Widening `result` is a plain MODIFY COLUMN -- VARCHAR(16) -> VARCHAR(24) never truncates or
    reinterprets existing data.
  * `[]` is the CORRECT backfill value for every pre-existing row: a VerificationRequest created
    before this column existed has no captured baseline, which is honestly represented as "no
    locations were snapshotted" rather than fabricating one after the fact. Application code
    (`_retest_had_usable_detection_coverage`) does not depend on baseline_locations being
    non-empty to function -- an empty baseline against a covered retest still correctly returns
    PASSED when count_live_locations is 0, matching this column's pre-Finding-#3 behavior
    exactly for historical rows.
  * The ORM model (`VerificationRequest.baseline_locations`) declares `nullable=False,
    default=list`, matching the NOT NULL this migration lands on.

Revision ID: d0e1f2a3b4c5
Revises: c9d0e1f2a3b4
Create Date: 2026-09-19 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from apps.api.core.db_types import JSONType


# revision identifiers, used by Alembic.
revision: str = "d0e1f2a3b4c5"
down_revision: Union[str, None] = "c9d0e1f2a3b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "verification_requests", sa.Column("baseline_locations", JSONType(), nullable=True)
    )
    op.execute(
        "UPDATE verification_requests SET baseline_locations = JSON_ARRAY() "
        "WHERE baseline_locations IS NULL"
    )
    with op.batch_alter_table("verification_requests") as batch_op:
        batch_op.alter_column("baseline_locations", existing_type=JSONType(), nullable=False)
        batch_op.alter_column(
            "result", existing_type=sa.String(length=16), type_=sa.String(length=24),
            existing_nullable=True,
        )


def downgrade() -> None:
    op.execute(
        "UPDATE verification_requests SET result = NULL WHERE result NOT IN ('passed', 'failed')"
    )
    with op.batch_alter_table("verification_requests") as batch_op:
        batch_op.alter_column(
            "result", existing_type=sa.String(length=24), type_=sa.String(length=16),
            existing_nullable=True,
        )
    op.drop_column("verification_requests", "baseline_locations")
