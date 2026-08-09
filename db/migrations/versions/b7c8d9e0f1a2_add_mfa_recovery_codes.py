"""add mfa_recovery_codes (MFA Sprint 1, Step 1)

Revision ID: b7c8d9e0f1a2
Revises: f3a4b1c2d3e4
Create Date: 2026-08-09

One-time MFA recovery codes, stored HASHED. User-scoped like refresh_tokens (deliberately NOT
workspace-RLS -- auth precedes any workspace context). code_hash is a unique index for O(1)
redemption lookup. Additive foundation: no login/API behavior depends on this yet.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "b7c8d9e0f1a2"
down_revision: Union[str, None] = "f3a4b1c2d3e4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_mfa_recovery_codes_code_hash"), "mfa_recovery_codes", ["code_hash"], unique=True)
    op.create_index(op.f("ix_mfa_recovery_codes_user_id"), "mfa_recovery_codes", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_mfa_recovery_codes_user_id"), table_name="mfa_recovery_codes")
    op.drop_index(op.f("ix_mfa_recovery_codes_code_hash"), table_name="mfa_recovery_codes")
    op.drop_table("mfa_recovery_codes")
