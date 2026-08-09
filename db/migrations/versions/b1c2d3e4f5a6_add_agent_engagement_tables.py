"""add engagement_state and agent_steps tables

Autonomous red-team agent (M1): per-scan engagement state machine + immutable
audit log of every agent decision/action/safety-verdict. Both tenant-scoped by
their own workspace_id with ENABLE + FORCE RLS (scans are RLS-exempt), same
pattern as ai_usage / attack_narratives.

Revision ID: b1c2d3e4f5a6
Revises: a7b8c9d0e1f2
Create Date: 2026-08-02 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "b1c2d3e4f5a6"
down_revision: Union[str, None] = "a7b8c9d0e1f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "engagement_state",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "workspace_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "scan_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("status", sa.String(32), nullable=False, server_default="running"),
        sa.Column("current_phase", sa.String(32), nullable=False, server_default="reconnaissance"),
        sa.Column("objective", sa.Text(), nullable=True),
        sa.Column("approval_state", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("attack_graph", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("scan_id", name="uq_engagement_state_scan"),
    )
    op.create_index("ix_engagement_state_workspace_id", "engagement_state", ["workspace_id"])
    op.create_index("ix_engagement_state_scan_id", "engagement_state", ["scan_id"])

    op.create_table(
        "agent_steps",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "workspace_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "scan_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("step_no", sa.Integer(), nullable=False),
        sa.Column("phase", sa.String(32), nullable=False),
        sa.Column("action_type", sa.String(32), nullable=False),
        sa.Column("tool_or_module", sa.String(64), nullable=True),
        sa.Column("safety_tier", sa.String(16), nullable=True),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("result_summary", sa.Text(), nullable=True),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="executed"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_agent_steps_workspace_id", "agent_steps", ["workspace_id"])
    op.create_index("ix_agent_steps_scan_id", "agent_steps", ["scan_id"])

    # RLS: own workspace_id (ENABLE + FORCE), same as ai_usage / attack_narratives.
    for tbl in ("engagement_state", "agent_steps"):
        op.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY workspace_isolation ON {tbl} USING ("
            "workspace_id = current_setting('app.current_workspace_id', true)::uuid)"
        )


def downgrade() -> None:
    for tbl in ("agent_steps", "engagement_state"):
        op.execute(f"DROP POLICY IF EXISTS workspace_isolation ON {tbl}")
    op.drop_index("ix_agent_steps_scan_id", table_name="agent_steps")
    op.drop_index("ix_agent_steps_workspace_id", table_name="agent_steps")
    op.drop_table("agent_steps")
    op.drop_index("ix_engagement_state_scan_id", table_name="engagement_state")
    op.drop_index("ix_engagement_state_workspace_id", table_name="engagement_state")
    op.drop_table("engagement_state")
