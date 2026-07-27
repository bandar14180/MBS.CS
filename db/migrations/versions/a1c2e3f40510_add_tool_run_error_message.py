"""add tool_runs.error_message

Stores the exact failure text for a tool run (exception message or a tail of
the tool's stderr) so failures are visible in the API/UI, not just a status
flag. Nullable -- only populated when a run fails.

Revision ID: a1c2e3f40510
Revises: 023ad0eb9823
Create Date: 2026-07-27 20:05:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'a1c2e3f40510'
down_revision: Union[str, None] = '023ad0eb9823'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("tool_runs", sa.Column("error_message", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("tool_runs", "error_message")
