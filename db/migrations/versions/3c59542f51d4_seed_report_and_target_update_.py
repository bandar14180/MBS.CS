"""seed report and target update permissions

Revision ID: 3c59542f51d4
Revises: bbcddc51e96a
Create Date: 2026-08-21 15:21:39.161776

RECOVERED SEED DATA, not a new feature. The Phase 0 MySQL cutover squashed 21 pure-DDL
Postgres migrations into the single 417cf2df2299 baseline (see that migration's docstring)
and archived the originals. Two of those 21 were NOT pure DDL, despite their "add X table"
names: c0ecf2f76c48_add_reports_table.py also seeded the report:create/report:read
permissions in the same upgrade(), and ccf0f32c1190_add_risk_scores_compliance_mappings_.py
also seeded target:update -- both inline alongside the CREATE TABLE/RLS statements for the
feature that motivated the migration. Archiving them as DDL-only silently dropped that seed
data: application code checks for all three permissions (grep across apps/api/modules
confirms report:create, report:read, and target:update are real permission-gate checks, not
dead strings), but nothing in the new baseline or the 4 rechained seed migrations recreated
them -- caught empirically when report-generation and target-update endpoints started
returning 403 "Missing permission" against the rebuilt MySQL test database, not by
inspection. This migration seeds exactly what those two archived migrations seeded, using
the same role grants, so the permission set matches what the pre-cutover Postgres schema
actually had.
"""
import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import column, table

from apps.api.core.db_types import GUID


# revision identifiers, used by Alembic.
revision: str = '3c59542f51d4'
down_revision: Union[str, None] = 'bbcddc51e96a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

permissions_table = table(
    "permissions",
    column("id", GUID()),
    column("key", sa.String()),
    column("description", sa.Text()),
)
role_permissions_table = table(
    "role_permissions",
    column("role_id", GUID()),
    column("permission_id", GUID()),
)

NEW_PERMISSIONS: list[tuple[str, str]] = [
    ("report:create", "Generate reports"),
    ("report:read", "View and download reports"),
    ("target:update", "Update a target's business criticality"),
]

# Matches the original archived migrations exactly: report:read for everyone, report:create
# for owner/admin only (an export/deliverable action); target:update on the same footing as
# target:create -- owner/admin/member.
ROLE_PERMISSION_NAMES: dict[str, list[str]] = {
    "report:create": ["owner", "admin"],
    "report:read": ["owner", "admin", "member"],
    "target:update": ["owner", "admin", "member"],
}


def upgrade() -> None:
    bind = op.get_bind()

    permission_ids = {key: uuid.uuid4() for key, _ in NEW_PERMISSIONS}
    op.bulk_insert(
        permissions_table,
        [{"id": permission_ids[key], "key": key, "description": desc} for key, desc in NEW_PERMISSIONS],
    )

    role_rows = bind.execute(sa.text("SELECT id, name FROM roles WHERE workspace_id IS NULL")).fetchall()
    # Same PyMySQL str-vs-uuid.UUID normalization as the other seed migrations in this chain
    # (see baf7c3543732's comment for the full empirical explanation).
    role_ids = {name: uuid.UUID(str(role_id)) for role_id, name in role_rows}

    op.bulk_insert(
        role_permissions_table,
        [
            {"role_id": role_ids[role_name], "permission_id": permission_ids[perm_key]}
            for perm_key, role_names in ROLE_PERMISSION_NAMES.items()
            for role_name in role_names
            if role_name in role_ids
        ],
    )


def downgrade() -> None:
    keys = ", ".join(f"'{key}'" for key, _ in NEW_PERMISSIONS)
    op.execute(
        f"DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE `key` IN ({keys}))"
    )
    op.execute(f"DELETE FROM permissions WHERE `key` IN ({keys})")
