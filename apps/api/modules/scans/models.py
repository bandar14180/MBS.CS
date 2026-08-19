import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Denormalized on purpose: the Celery worker that executes this scan has
    # no HTTP request/{workspace_id} path param to bootstrap RLS from, and
    # `projects`/`targets` are FORCE RLS-protected -- it can't even read
    # those tables to *discover* the workspace without already knowing it.
    # Scans itself is deliberately NOT RLS-protected (see blueprint "Step 4"
    # notes): the worker is handed a trusted, internally-generated scan_id,
    # never a client-supplied workspace_id, so reading this one row by id is
    # exactly the bootstrap it needs -- then it can SET the RLS session var
    # itself before touching anything else.
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    initiated_by: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    # NOTE: no ai_plan_id yet -- the ai_plans table doesn't exist until Phase 3
    # (AI Layer v1). requested_modules lives in `config` in the meantime.
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    celery_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # EXECUTION OWNERSHIP FENCE (P1-1 P3). `status='running'` alone cannot say WHICH
    # execution owns the scan, so an executor whose row was requeued by the graceful-
    # shutdown hook could not tell it had been revoked -- it kept running and its terminal
    # write silently matched 0 rows. `_claim_scan` stamps a fresh token here and every
    # ownership-sensitive write is conditional on it. NULL = unowned (queued/terminal).
    # Internal to the worker lifecycle: deliberately NOT exposed in ScanRead.
    execution_token: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    # WHEN this scan entered the queue -- what the queued relay ages off. Distinct from
    # created_at on purpose: a scan requeued by the graceful-shutdown hook was CREATED long
    # ago, so ageing off created_at made it relay-eligible the instant it was requeued, i.e.
    # redispatchable while its old worker was still draining. The requeue refreshes this, so
    # the earliest redispatch is requeue + scan_queued_relay_seconds.
    queued_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
