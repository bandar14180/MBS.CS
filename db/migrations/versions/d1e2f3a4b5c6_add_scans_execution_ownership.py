"""add scans.execution_token + scans.queued_at (P1-1 P3 race -- execution ownership + relay timing)

Revision ID: d1e2f3a4b5c6
Revises: c9d0e1f2a3b4
Create Date: 2026-08-19

Two additive, nullable columns. Both exist to make a graceful-shutdown requeue safe.

execution_token -- WHICH execution currently owns a running scan.
    `status='running'` alone could not say that, so an executor whose scan had been requeued
    by the shutdown hook could not tell it had lost ownership: its terminal
    `UPDATE ... WHERE status='running'` matched 0 rows and the outcome was silently
    discarded, leaving a redispatchable row while that executor was still running (the P3
    duplicate-scan race). `_claim_scan` now stamps a fresh token and every ownership-
    sensitive write is conditional on it. NULL = nobody owns this scan (queued/terminal),
    which is exactly the state the requeue writes.

queued_at -- WHEN the scan entered the queue, which is what the queued relay must age off.
    The relay previously aged rows off `created_at`. A scan being requeued was created long
    before it ran, so it became relay-eligible IMMEDIATELY on requeue -- the relay could
    redispatch it inside the container's stop_grace_period, while the old executor was still
    alive. Ageing off `queued_at` (set on creation AND refreshed by the requeue) makes the
    earliest possible redispatch `requeue + scan_queued_relay_seconds`, which is well after
    the old worker has been SIGKILLed.

`queued_at` is added in THREE steps on purpose. Adding it directly as
`DEFAULT now()` would not leave existing rows NULL: PostgreSQL 11+ applies the default to
every pre-existing row (`now()` is STABLE, so the fast-default path stores one migration-time
value), which would RESET the relay clock of every scan already sitting in the queue and delay
its recovery by up to `scan_queued_relay_seconds`. So the column is added with NO default,
existing rows are explicitly backfilled from `created_at` (preserving their real queue age),
and only then is the default set for future inserts.

Backward compatible: no row loses its queue age, and future inserts get `now()` from the
database default, matching the `server_default` declared on the ORM model. The relay's
`coalesce(queued_at, created_at)` is a defensive fallback for unexpected NULLs, not the
mechanism that preserves pre-migration behaviour -- the backfill is. A scan already 'running'
at deploy time is handled by the pre-existing orphan reaper.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "d1e2f3a4b5c6"
down_revision: Union[str, None] = "c9d0e1f2a3b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("execution_token", postgresql.UUID(as_uuid=True), nullable=True),
    )
    # Step 1 -- add with NO default, so PostgreSQL does not stamp every existing row with the
    # migration timestamp (which would reset the relay clock of everything already queued).
    op.add_column("scans", sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True))
    # Step 2 -- preserve the real queue age of rows that predate this column.
    op.execute("UPDATE scans SET queued_at = created_at WHERE queued_at IS NULL")
    # Step 3 -- now make future inserts default to now(), matching the ORM's server_default.
    op.alter_column(
        "scans",
        "queued_at",
        existing_type=sa.DateTime(timezone=True),
        existing_nullable=True,
        server_default=sa.text("now()"),
    )


def downgrade() -> None:
    op.drop_column("scans", "queued_at")
    op.drop_column("scans", "execution_token")
