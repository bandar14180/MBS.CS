"""seed scan and asset permissions

Revision ID: baf7c3543732
Revises: eaf57eef76d7
Create Date: 2026-07-27 04:13:25.877154

"""
# Phase 0 MySQL cutover: re-chained to follow the new squashed MySQL baseline
# (417cf2df2299) instead of the old Postgres migration it used to sit after (now
# archived, not deleted -- see docs/architecture). down_revision updated accordingly.
#
# Also: the ad-hoc `table()` column types below were switched from the generic sa.UUID()
# to this codebase's own GUID type (apps.api.core.db_types) -- caught empirically by
# actually running this migration against MySQL, not by inspection. SQLAlchemy's generic
# Uuid type has NO native-MySQL representation, so on bind it falls back to `.hex` (a
# 32-char string with no dashes), while the REAL `roles`/`permissions`/etc. columns (CHAR(36)
# via GUID, created by the baseline migration) store the canonical 36-char DASHED form --
# the same form the ORM/runtime binds via GUID everywhere else. Seeding with sa.UUID() wrote
# rows whose primary keys didn't match what any later dashed-string lookup (FK insert, ORM
# query) would ever produce -- not a crash at migration time, but a silent, permanent
# integrity mismatch that then broke every FK insert into these seeded rows (workspace
# creation, membership, etc.) with a 'foreign key constraint fails' error. On Postgres this
# was never visible: its native UUID type round-trips correctly regardless of which generic
# SQLAlchemy UUID spelling was used to bind it.
import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import column, table

from apps.api.core.db_types import GUID


# revision identifiers, used by Alembic.
revision: str = 'baf7c3543732'
down_revision: Union[str, None] = 'eaf57eef76d7'
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
    ("scan:create", "Create/cancel scans"),
    ("scan:read", "View scans, tool runs, and evidence"),
    ("asset:read", "View discovered assets"),
]

# scan:create follows the same footing as project:create -- all three roles can
# kick off scans (the authorization-scope gate, not the role, is what actually
# controls whether a scan is allowed to run against a given target).
ROLE_PERMISSION_NAMES: dict[str, list[str]] = {
    "scan:create": ["owner", "admin", "member"],
    "scan:read": ["owner", "admin", "member"],
    "asset:read": ["owner", "admin", "member"],
}


def upgrade() -> None:
    bind = op.get_bind()

    permission_ids = {key: uuid.uuid4() for key, _ in NEW_PERMISSIONS}
    op.bulk_insert(
        permissions_table,
        [{"id": permission_ids[key], "key": key, "description": desc} for key, desc in NEW_PERMISSIONS],
    )

    role_rows = bind.execute(sa.text("SELECT id, name FROM roles WHERE workspace_id IS NULL")).fetchall()
    # Phase 0 MySQL cutover: on Postgres, psycopg2 auto-adapted a UUID column's raw SELECT
    # result into a Python uuid.UUID transparently, so `role_id` here was already the right
    # type for op.bulk_insert's sa.UUID() column below. PyMySQL has no such adaptation --
    # our GUID storage (CHAR(36)) comes back as a plain str -- and sa.UUID()'s bind processor
    # unconditionally calls `.hex` on the value, so a raw str blows up with 'str' object has
    # no attribute 'hex' (caught by actually running this migration against MySQL). Wrapping
    # in uuid.UUID(...) here makes the type explicit regardless of what the driver handed back.
    role_ids = {name: uuid.UUID(str(role_id)) for role_id, name in role_rows}

    op.bulk_insert(
        role_permissions_table,
        [
            {"role_id": role_ids[role_name], "permission_id": permission_ids[perm_key]}
            for perm_key, role_names in ROLE_PERMISSION_NAMES.items()
            for role_name in role_names
        ],
    )


def downgrade() -> None:
    # `key` is a MySQL reserved word and must be backtick-quoted in raw SQL.
    keys = ", ".join(f"'{key}'" for key, _ in NEW_PERMISSIONS)
    op.execute(
        f"DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE `key` IN ({keys}))"
    )
    op.execute(f"DELETE FROM permissions WHERE `key` IN ({keys})")
