"""add agent_decisions table

Autonomous red-team agent (M4.4): structured reasoning audit -- one row per
`decide()` cycle capturing the evidence tiers (observations/inferences/hypotheses),
the ranked candidate set, the code-selected action, the stop reason and the budget
snapshot. Complements (never replaces) agent_steps: agent_steps stays the immutable
chronological ACTION audit; this is the structured REASONING audit, correlated by
(scan_id, step_no) + a nullable agent_step_id FK. agent_steps is NOT modified.

Tenant-scoped by its own workspace_id with ENABLE + FORCE RLS, same pattern as
agent_steps / attack_narratives / ai_usage. Additive only.

Revision ID: c3d5e7f9a2b4
Revises: b1c2d3e4f5a6
Create Date: 2026-08-05 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "c3d5e7f9a2b4"
down_revision: Union[str, None] = "b1c2d3e4f5a6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agent_decisions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "workspace_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "scan_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False,
        ),
        # Hard link to the chronological audit row; SET NULL never touches agent_steps.
        sa.Column(
            "agent_step_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("agent_steps.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("step_no", sa.Integer(), nullable=False),
        sa.Column("phase", sa.String(32), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("observations", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("inferences", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("hypotheses", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("candidates", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("selected_tool", sa.String(64), nullable=True),
        sa.Column("selected_confidence", sa.Float(), nullable=True),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("stop_reason", sa.String(64), nullable=True),
        sa.Column("budget_state", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("model_version", sa.String(128), nullable=True),
        sa.Column("prompt_version", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("scan_id", "step_no", name="uq_agent_decisions_scan_step"),
    )
    op.create_index("ix_agent_decisions_workspace_id", "agent_decisions", ["workspace_id"])
    op.create_index("ix_agent_decisions_scan_id", "agent_decisions", ["scan_id"])

    # RLS: own workspace_id (ENABLE + FORCE), same as agent_steps / attack_narratives.
    op.execute("ALTER TABLE agent_decisions ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE agent_decisions FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY workspace_isolation ON agent_decisions USING ("
        "workspace_id = current_setting('app.current_workspace_id', true)::uuid)"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS workspace_isolation ON agent_decisions")
    op.drop_index("ix_agent_decisions_scan_id", table_name="agent_decisions")
    op.drop_index("ix_agent_decisions_workspace_id", table_name="agent_decisions")
    op.drop_table("agent_decisions")
