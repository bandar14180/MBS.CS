"""add ai_usage table

Per-call AI token/cost accounting (Task 1 usage logging + Task 15 cost tracking).
Tenant-scoped with ENABLE + FORCE RLS on workspace_id (direct column, like
notifications). Rows are written best-effort in an independent transaction that
sets app.current_workspace_id, so the INSERT satisfies the FORCE-RLS check.

Revision ID: f1a2b3c4d5e6
Revises: e6a8c0d2f248
Create Date: 2026-07-28 22:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "f1a2b3c4d5e6"
down_revision: Union[str, None] = "e6a8c0d2f248"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ai_usage",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "workspace_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("agent_role", sa.String(64), nullable=True),
        sa.Column("prompt_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completion_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("estimated_cost_usd", sa.Numeric(12, 6), nullable=False, server_default="0"),
        sa.Column("correlation_id", sa.String(64), nullable=True),
        sa.Column("prompt_version", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_ai_usage_workspace_id", "ai_usage", ["workspace_id"])
    op.create_index("ix_ai_usage_scan_id", "ai_usage", ["scan_id"])
    op.create_index("ix_ai_usage_created_at", "ai_usage", ["created_at"])

    op.execute("ALTER TABLE ai_usage ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE ai_usage FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY workspace_isolation ON ai_usage USING ("
        "workspace_id = current_setting('app.current_workspace_id', true)::uuid)"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS workspace_isolation ON ai_usage")
    op.drop_index("ix_ai_usage_created_at", table_name="ai_usage")
    op.drop_index("ix_ai_usage_scan_id", table_name="ai_usage")
    op.drop_index("ix_ai_usage_workspace_id", table_name="ai_usage")
    op.drop_table("ai_usage")
