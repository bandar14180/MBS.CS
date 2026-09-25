"""Prompt 34: audit outcome + correlation id

WHY
---
The audit tables recorded actor / tenant / action / timestamp / resource, but two of the
fields the audit requirements call for had nowhere to live:

  * OUTCOME -- whether the recorded action succeeded, failed, or was denied. Previously this
    was either absent or buried in free-text `detail` prose, so "user attempted X" and "user
    did X" were indistinguishable to any query. That distinction is the whole point of an
    audit log during an incident.
  * CORRELATION ID -- the request/task id that the middleware already generates, returns as
    X-Request-ID, and attaches to every log line (apps/api/core/observability.py). Without it
    on the row, an audit event could not be joined to the request that produced it or to the
    surrounding application logs.

SCOPE -- ADDITIVE ONLY
----------------------
Three nullable columns and two indexes. No column is altered, dropped, or retyped; no data
is rewritten; no foreign key or constraint is touched.

WHY NULLABLE, NOT DEFAULTED
---------------------------
Rows written before this migration genuinely have no recorded outcome and no captured
correlation id. Back-filling them with "success" would FABRICATE audit content -- it would
assert an outcome nobody observed. NULL states the truth: not recorded. For the same reason
the application normalizes the correlation contextvar's "-" placeholder to NULL rather than
storing a literal dash that looks like an id.

`correlation_id` is indexed on both tables because its only real query pattern is the lookup
"show me every audit event for request X" during an investigation. `outcome` is left
unindexed: it has three values over a table already filtered by workspace, so an index would
not be selective enough to earn its write cost.

Revision ID: a7b8c9d0e1f2
Revises: f2a3b4c5d6e7
Create Date: 2026-09-20 00:00:00.000000

"""
import sqlalchemy as sa
from alembic import op

revision: str = "a7b8c9d0e1f2"
down_revision: str | None = "f2a3b4c5d6e7"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("audit_events", sa.Column("outcome", sa.String(length=16), nullable=True))
    op.add_column("audit_events", sa.Column("correlation_id", sa.String(length=64), nullable=True))
    op.create_index("ix_audit_events_correlation_id", "audit_events", ["correlation_id"])

    op.add_column(
        "platform_audit_events", sa.Column("correlation_id", sa.String(length=64), nullable=True)
    )
    op.create_index(
        "ix_platform_audit_events_correlation_id", "platform_audit_events", ["correlation_id"]
    )


def downgrade() -> None:
    # Dropping these columns discards recorded outcome/correlation data. That is acceptable
    # here in a way that dropping audit ROWS never would be: the events themselves (actor,
    # tenant, action, resource, timestamp, detail) survive intact, and these two fields did
    # not exist before this revision.
    op.drop_index("ix_platform_audit_events_correlation_id", table_name="platform_audit_events")
    op.drop_column("platform_audit_events", "correlation_id")

    op.drop_index("ix_audit_events_correlation_id", table_name="audit_events")
    op.drop_column("audit_events", "correlation_id")
    op.drop_column("audit_events", "outcome")
