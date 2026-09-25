"""add scan_schedules

Recurring scans. Like `scans`, this table is intentionally NOT RLS-protected:
the Celery-beat scheduler has no workspace context and must read due schedules
across workspaces, then bootstrap RLS per-schedule from the trusted workspace_id.

Revision ID: b2d4f6a8c012
Revises: a1c2e3f40510
Create Date: 2026-07-28 20:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "b2d4f6a8c012"
down_revision: Union[str, None] = "a1c2e3f40510"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_schedules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "workspace_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "project_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "target_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("targets.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column(
            "created_by", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False,
        ),
        sa.Column("scan_type", sa.String(32), nullable=False),
        sa.Column("requested_modules", postgresql.JSONB(), nullable=False),
        sa.Column("use_ai_planner", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("last_error", sa.String(1000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_scan_schedules_workspace_id", "scan_schedules", ["workspace_id"])
    op.create_index("ix_scan_schedules_project_id", "scan_schedules", ["project_id"])
    op.create_index("ix_scan_schedules_next_run_at", "scan_schedules", ["next_run_at"])


def downgrade() -> None:
    op.drop_index("ix_scan_schedules_next_run_at", table_name="scan_schedules")
    op.drop_index("ix_scan_schedules_project_id", table_name="scan_schedules")
    op.drop_index("ix_scan_schedules_workspace_id", table_name="scan_schedules")
    op.drop_table("scan_schedules")
