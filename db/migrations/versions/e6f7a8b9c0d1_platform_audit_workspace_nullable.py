"""MBS.SC P8-G: allow platform-scoped audit events (workspace_id NULL)

WHY
---
`platform_audit_events` was introduced for destructive TENANT operations
(tenant.delete.requested/completed/failed), so `workspace_id` was NOT NULL -- every such
event names a workspace by construction.

Phase 8 adds operator actions that are genuinely PLATFORM-SCOPED and have no workspace at
all:

  * the private-scanning emergency kill switch (P8-D) is platform-wide by definition;
  * revoking or reaping a SHARED PUBLIC scanner worker, whose `scanner_workers.workspace_id`
    is already NULL because it serves many tenants.

Without this change those actions could not be audited at all, which is the gap P8-G exists
to close.

WHY NULL AND NOT A SENTINEL UUID
--------------------------------
This repository already expresses "not workspace-scoped" as a NULL `workspace_id`, and it
does so in exactly the two places that needed it:

    roles.workspace_id            NULL = system/global role   (all 4 seeded roles)
    scanner_workers.workspace_id  NULL = shared public worker (documented on the model)

There is no sentinel/reserved-UUID convention anywhere in the codebase -- no named constant,
no all-zero UUID literal in production code, and no reserved workspace row. Inventing one
here would have created a value that looks like a foreign key but references nothing, and
would have contradicted the project's own convention. So this follows the convention instead.

SCOPE -- ONE COLUMN'S NULLABILITY, NOTHING ELSE
-----------------------------------------------
No foreign key is added, altered or dropped (this table deliberately has NO FK to
`workspaces`, so the record survives a tenant's hard deletion -- see platform_models.py).
No index is touched. No other column on this table or any other is modified. No data is
rewritten.

EXISTING ROWS REMAIN VALID. Relaxing NOT NULL -> NULL widens what is accepted and rejects
nothing that was previously stored: every existing row still has its non-null workspace_id
and still reads back identically. The downgrade is only safe while no platform-scoped row
exists, which is why it asserts that before re-tightening rather than silently failing or
deleting audit history.

Revision ID: e6f7a8b9c0d1
Revises: d5e6f7a8b9c0
Create Date: 2026-09-12 00:00:00.000000

"""
import sqlalchemy as sa
from alembic import op

from apps.api.core.db_types import GUID

revision = "e6f7a8b9c0d1"
down_revision = "d5e6f7a8b9c0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # existing_* are supplied because MySQL's MODIFY COLUMN rewrites the whole definition:
    # omitting them would silently drop the type or re-add a default.
    op.alter_column(
        "platform_audit_events",
        "workspace_id",
        existing_type=GUID(),
        nullable=True,
        existing_nullable=False,
    )


def downgrade() -> None:
    # Re-tightening would fail on -- or worse, silently require destroying -- any
    # platform-scoped row written since the upgrade. Fail loudly with an actionable message
    # instead: audit history must never be discarded to make a downgrade succeed.
    bind = op.get_bind()
    orphaned = bind.execute(
        sa.text("SELECT COUNT(*) FROM platform_audit_events WHERE workspace_id IS NULL")
    ).scalar()
    if orphaned:
        raise RuntimeError(
            f"Refusing to downgrade: {orphaned} platform-scoped audit event(s) have "
            f"workspace_id IS NULL (emergency-flag transitions, public-worker revocations). "
            f"Re-applying NOT NULL would require deleting them, and audit history must not "
            f"be destroyed by a schema downgrade. Archive and remove those rows deliberately "
            f"first if you genuinely intend to downgrade."
        )
    op.alter_column(
        "platform_audit_events",
        "workspace_id",
        existing_type=GUID(),
        nullable=False,
        existing_nullable=True,
    )
