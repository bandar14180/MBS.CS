import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, text
from apps.api.core.db_types import GUID, JSONType, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    # Denormalized on purpose: the Celery worker that executes this scan has
    # no HTTP request/{workspace_id} path param to bootstrap the workspace from,
    # and `projects`/`targets` ARE auto-filtered by tenancy.py -- it can't even read
    # those tables to *discover* the workspace without already knowing it.
    # Scans itself is deliberately NOT auto-filtered (tenancy.EXEMPT_TABLES; see blueprint "Step 4"
    # notes): the worker is handed a trusted, internally-generated scan_id,
    # never a client-supplied workspace_id, so reading this one row by id is
    # exactly the bootstrap it needs -- then it can BIND the workspace context
    # itself before touching anything else.
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    initiated_by: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    # NOTE: no ai_plan_id yet -- the ai_plans table doesn't exist until Phase 3
    # (AI Layer v1). requested_modules lives in `config` in the meantime.
    config: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    celery_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # EXECUTION OWNERSHIP FENCE (P1-1 P3). `status='running'` alone cannot say WHICH
    # execution owns the scan, so an executor whose row was requeued by the graceful-
    # shutdown hook could not tell it had been revoked -- it kept running and its terminal
    # write silently matched 0 rows. `_claim_scan` stamps a fresh token here and every
    # ownership-sensitive write is conditional on it. NULL = unowned (queued/terminal).
    # Internal to the worker lifecycle: deliberately NOT exposed in ScanRead.
    execution_token: Mapped[uuid.UUID | None] = mapped_column(GUID(), nullable=True)
    # WHEN this scan entered the queue -- what the queued relay ages off. Distinct from
    # created_at on purpose: a scan requeued by the graceful-shutdown hook was CREATED long
    # ago, so ageing off created_at made it relay-eligible the instant it was requeued, i.e.
    # redispatchable while its old worker was still draining. The requeue refreshes this, so
    # the earliest redispatch is requeue + scan_queued_relay_seconds.
    queued_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    # LIVENESS, not progress-reporting. Refreshed by the executor roughly every
    # TOOL_PROGRESS_INTERVAL_SECONDS while a tool is running (see orchestrator's
    # `_run_with_progress`), so the orphan reaper can distinguish a scan that is genuinely
    # ALIVE from one whose worker died -- WITHOUT capping how long a scan may legitimately
    # run. That distinction is the whole point: a healthy 5-hour nuclei/ffuf run keeps
    # stamping this and is never reaped, while a scan whose worker was SIGKILLed stops
    # stamping it and is recovered within scan_stale_heartbeat_seconds instead of having to
    # wait out a fixed wall-clock timeout.
    #
    # NULL is expected and meaningful: a freshly claimed scan has not ticked yet, and a
    # scan running an older build never stamps it at all. Both are handled by the reaper
    # falling back to `started_at` (COALESCE), so a NULL here can never make a scan
    # immortal.
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
