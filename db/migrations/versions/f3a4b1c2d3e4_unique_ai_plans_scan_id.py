"""unique ai_plans.scan_id (F3.4)

Revision ID: f3a4b1c2d3e4
Revises: c3d5e7f9a2b4
Create Date: 2026-08-09

F3.4: enforce one AI plan per scan (uq_ai_plans_scan) -- the DB backstop to the F3.1
planner-reuse guard. Scan re-runs BEFORE F3.1 shipped could have inserted duplicate ai_plans
rows, so dedup (keep the newest row per scan_id) before adding the constraint.

RLS note: ai_plans is FORCE RLS and this migration runs as the app role with no
app.current_workspace_id set, so a plain DELETE would be RLS-filtered to zero rows -- while the
UNIQUE-constraint DDL (not RLS-filtered) would then fail on any surviving duplicate. So the dedup
runs under NO FORCE (the table owner then bypasses RLS and sees every row), after which FORCE is
restored. Alembic wraps the migration in a single transaction, so an abort can never leave the
table with RLS disabled.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "f3a4b1c2d3e4"
down_revision: Union[str, None] = "c3d5e7f9a2b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()

    # (1) Verify + log the surplus (duplicate) count BEFORE deleting anything.
    surplus = conn.execute(
        sa.text("SELECT count(*) - count(DISTINCT scan_id) FROM ai_plans")
    ).scalar() or 0
    print(f"[F3.4] ai_plans surplus (duplicate) rows to remove before adding uq_ai_plans_scan: {surplus}")

    # (2) Dedup must bypass FORCE RLS: NO FORCE lets the table owner see every row (a plain DELETE
    #     under FORCE + no workspace GUC would match zero rows).
    op.execute("ALTER TABLE ai_plans NO FORCE ROW LEVEL SECURITY")

    # (3) Keep the NEWEST row per scan_id (created_at, tie-break on id); delete the rest.
    op.execute(
        """
        DELETE FROM ai_plans a USING ai_plans b
        WHERE a.scan_id = b.scan_id
          AND (a.created_at < b.created_at
               OR (a.created_at = b.created_at AND a.id < b.id))
        """
    )

    # (4) Restore the tenant-isolation invariant.
    op.execute("ALTER TABLE ai_plans FORCE ROW LEVEL SECURITY")

    # (5) One plan per scan. ix_ai_plans_scan_id is intentionally LEFT IN PLACE.
    op.create_unique_constraint("uq_ai_plans_scan", "ai_plans", ["scan_id"])


def downgrade() -> None:
    # Only remove the constraint; ix_ai_plans_scan_id was never touched in upgrade().
    op.drop_constraint("uq_ai_plans_scan", "ai_plans", type_="unique")
