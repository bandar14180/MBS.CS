"""add workspaces.status + seed tenant delete/export permissions

Revision ID: a1b2c3d4e5f6
Revises: 20d9114ac4ed
Create Date: 2026-08-30 00:00:00.000000

Adds the `workspaces.status` lifecycle column (active -> deleting; the row is hard-removed on
completion) that gates tenant deletion, the durable NON-cascading `platform_audit_events` table
(no FK to workspaces, so the deletion record survives the tenant), and seeds two owner/admin
permissions: `workspace:delete` and `workspace:export`. Mirrors the existing seed-permission
migrations (GUID column types, uuid.UUID() wrapping of raw role ids for PyMySQL, backtick `key`).
"""
import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql
from sqlalchemy.sql import column, table

from apps.api.core.db_types import GUID


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = '20d9114ac4ed'
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
    ("workspace:delete", "Permanently delete an entire workspace and all its data"),
    ("workspace:export", "Export all of a workspace's data"),
]

# Both are high-trust, workspace-wide operations: owner + admin only, never plain members.
ROLE_PERMISSION_NAMES: dict[str, list[str]] = {
    "workspace:delete": ["owner", "admin"],
    "workspace:export": ["owner", "admin"],
}


def upgrade() -> None:
    bind = op.get_bind()

    # 1) workspaces.status. server_default 'active' backfills every existing row.
    op.add_column(
        "workspaces",
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
    )

    # 1b) durable, NON-cascading platform audit for destructive tenant ops. No FK to workspaces,
    # so a tenant.delete.* record OUTLIVES the workspace hard deletion. Queryable from the DB.
    op.create_table(
        "platform_audit_events",
        sa.Column("id", GUID(), nullable=False),
        sa.Column("workspace_id", GUID(), nullable=False),
        sa.Column("actor_user_id", GUID(), nullable=True),
        sa.Column("event", sa.String(length=64), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", mysql.DATETIME(fsp=6), server_default=sa.text("CURRENT_TIMESTAMP(6)"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_platform_audit_events_workspace_id", "platform_audit_events", ["workspace_id"])
    op.create_index("ix_platform_audit_events_event", "platform_audit_events", ["event"])
    op.create_index("ix_platform_audit_events_created_at", "platform_audit_events", ["created_at"])

    # 2) seed the two permissions + grant them to owner/admin system roles.
    permission_ids = {key: uuid.uuid4() for key, _ in NEW_PERMISSIONS}
    op.bulk_insert(
        permissions_table,
        [{"id": permission_ids[key], "key": key, "description": desc} for key, desc in NEW_PERMISSIONS],
    )

    role_rows = bind.execute(sa.text("SELECT id, name FROM roles WHERE workspace_id IS NULL")).fetchall()
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
    op.drop_index("ix_platform_audit_events_created_at", table_name="platform_audit_events")
    op.drop_index("ix_platform_audit_events_event", table_name="platform_audit_events")
    op.drop_index("ix_platform_audit_events_workspace_id", table_name="platform_audit_events")
    op.drop_table("platform_audit_events")
    op.drop_column("workspaces", "status")
