"""add users.mfa_enabled_at (MFA Sprint 1, Step 2)

Revision ID: c9d0e1f2a3b4
Revises: b7c8d9e0f1a2
Create Date: 2026-08-09

Additive, nullable column recording when MFA was activated (mfa_enabled / mfa_secret_encrypted
already exist from the initial schema). Nullable -> existing users are unaffected and remain MFA
disabled. Backward compatible; no data migration.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "c9d0e1f2a3b4"
down_revision: Union[str, None] = "b7c8d9e0f1a2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_enabled_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "mfa_enabled_at")
