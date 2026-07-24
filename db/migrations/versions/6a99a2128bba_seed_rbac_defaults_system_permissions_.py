"""seed rbac defaults: system permissions and owner/admin/member roles

Revision ID: 6a99a2128bba
Revises: 87ca3d89a924
Create Date: 2026-07-24 09:16:31.835283

"""
import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import column, table


# revision identifiers, used by Alembic.
revision: str = '6a99a2128bba'
down_revision: Union[str, None] = '87ca3d89a924'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

permissions_table = table(
    "permissions",
    column("id", sa.UUID()),
    column("key", sa.String()),
    column("description", sa.Text()),
)
roles_table = table(
    "roles",
    column("id", sa.UUID()),
    column("workspace_id", sa.UUID()),
    column("name", sa.String()),
    column("description", sa.Text()),
)
role_permissions_table = table(
    "role_permissions",
    column("role_id", sa.UUID()),
    column("permission_id", sa.UUID()),
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
        "DELETE FROM permissions WHERE key IN ("
        + ", ".join(f"'{key}'" for key, _ in PERMISSIONS)
        + ")"
    )
