"""seed authorization_scope permissions

Revision ID: eaf57eef76d7
Revises: 90c242a2cfe1
Create Date: 2026-07-24 10:54:13.781228

"""
import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import column, table


# revision identifiers, used by Alembic.
revision: str = 'eaf57eef76d7'
down_revision: Union[str, None] = '90c242a2cfe1'
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
    ("authorization_scope:submit", "Submit ownership/authorization proof for a target"),
    (
        "authorization_scope:verify",
        "Review and verify a target's authorization proof, and set whether active testing is allowed",
    ),
]

# authorization_scope:verify is deliberately owner-only: the same person who
# submitted proof of ownership shouldn't also be the one certifying it. This
# is a known-imperfect stopgap (the owner can still self-certify) until either
# automated proof checking (DNS/file/cloud) or an independent reviewer role
# exists -- see the "Step 3" note in docs/architecture/blueprint.md.
ROLE_PERMISSION_NAMES: dict[str, list[str]] = {
    "authorization_scope:submit": ["owner", "admin", "member"],
    "authorization_scope:verify": ["owner"],
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
    op.execute(
        "DELETE FROM role_permissions WHERE permission_id IN ("
        "SELECT id FROM permissions WHERE key IN "
        "('authorization_scope:submit', 'authorization_scope:verify'))"
    )
    op.execute(
        "DELETE FROM permissions WHERE key IN "
        "('authorization_scope:submit', 'authorization_scope:verify')"
    )
