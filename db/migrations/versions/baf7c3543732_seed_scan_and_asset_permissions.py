"""seed scan and asset permissions

Revision ID: baf7c3543732
Revises: 35da883cdec8
Create Date: 2026-07-27 04:13:25.877154

"""
import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import column, table


# revision identifiers, used by Alembic.
revision: str = 'baf7c3543732'
down_revision: Union[str, None] = '35da883cdec8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

permissions_table = table(
    "permissions",
    column("id", sa.UUID()),
    column("key", sa.String()),
    column("description", sa.Text()),
)
role_permissions_table = table(
    "role_permissions",
    column("role_id", sa.UUID()),
    column("permission_id", sa.UUID()),
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
    role_ids = {name: role_id for role_id, name in role_rows}

    op.bulk_insert(
        role_permissions_table,
        [
            {"role_id": role_ids[role_name], "permission_id": permission_ids[perm_key]}
            for perm_key, role_names in ROLE_PERMISSION_NAMES.items()
            for role_name in role_names
        ],
    )


def downgrade() -> None:
    keys = ", ".join(f"'{key}'" for key, _ in NEW_PERMISSIONS)
    op.execute(
        f"DELETE FROM role_permissions WHERE permission_id IN (SELECT id FROM permissions WHERE key IN ({keys}))"
    )
    op.execute(f"DELETE FROM permissions WHERE key IN ({keys})")
