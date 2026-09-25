"""seed rbac defaults: system permissions and owner/admin/member roles

Revision ID: 6a99a2128bba
Revises: 417cf2df2299
Create Date: 2026-07-24 09:16:31.835283

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
revision: str = '6a99a2128bba'
down_revision: Union[str, None] = '417cf2df2299'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

permissions_table = table(
    "permissions",
    column("id", GUID()),
    column("key", sa.String()),
    column("description", sa.Text()),
)
roles_table = table(
    "roles",
    column("id", GUID()),
    column("workspace_id", GUID()),
    column("name", sa.String()),
    column("description", sa.Text()),
)
role_permissions_table = table(
    "role_permissions",
    column("role_id", GUID()),
    column("permission_id", GUID()),
)

# Deliberately small: only what's needed for workspaces/projects/targets (step 2).
# Extend this list as later modules (scans, vulnerabilities, reports, ...) land,
# following the same "<resource>:<action>" key convention.
PERMISSIONS: list[tuple[str, str]] = [
    ("workspace:view", "View workspace details and members"),
    ("workspace:manage", "Invite/remove members and change member roles"),
    ("project:create", "Create projects"),
    ("project:read", "View projects"),
    ("project:update", "Update project details"),
    ("project:delete", "Delete projects"),
    ("target:create", "Add targets to a project"),
    ("target:read", "View targets"),
    ("target:delete", "Remove targets"),
]

ROLES: dict[str, str] = {
    "owner": "Full control over the workspace, including membership",
    "admin": "Manages projects and targets; cannot manage workspace membership",
    "member": "Can create and view projects/targets; read-only on workspace membership",
}

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "owner": {key for key, _ in PERMISSIONS},
    "admin": {key for key, _ in PERMISSIONS if key != "workspace:manage"},
    "member": {"workspace:view", "project:create", "project:read", "target:create", "target:read"},
}


def upgrade() -> None:
    permission_ids = {key: uuid.uuid4() for key, _ in PERMISSIONS}
    op.bulk_insert(
        permissions_table,
        [{"id": permission_ids[key], "key": key, "description": desc} for key, desc in PERMISSIONS],
    )

    role_ids = {name: uuid.uuid4() for name in ROLES}
    op.bulk_insert(
        roles_table,
        [
            {"id": role_ids[name], "workspace_id": None, "name": name, "description": desc}
            for name, desc in ROLES.items()
        ],
    )

    op.bulk_insert(
        role_permissions_table,
        [
            {"role_id": role_ids[role_name], "permission_id": permission_ids[perm_key]}
            for role_name, perm_keys in ROLE_PERMISSIONS.items()
            for perm_key in perm_keys
        ],
    )


def downgrade() -> None:
    op.execute("DELETE FROM role_permissions")
    op.execute("DELETE FROM roles WHERE workspace_id IS NULL AND name IN ('owner', 'admin', 'member')")
    op.execute(
        # `key` is a MySQL reserved word and must be backtick-quoted in raw SQL (SQLAlchemy
        # Core auto-quotes it when going through a Table/Column construct, as the upgrade()
        # above does via bulk_insert, but this raw op.execute() string does not).
        "DELETE FROM permissions WHERE `key` IN ("
        + ", ".join(f"'{key}'" for key, _ in PERMISSIONS)
        + ")"
    )
