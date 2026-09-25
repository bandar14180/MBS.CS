"""Scanner worker identity and revocation state -- MBS.SC Phase 3 / Property F.

Before this table, an "execution worker" was not an entity at all: it was any process
holding the shared broker credentials. That has three consequences worth stating plainly,
because they are what this model exists to end:

  * NO IDENTITY. Any process with the Redis URL could pop a task off the `scans` queue.
    There was nothing to authenticate, so there was nothing to authorize.
  * NO REVOCATION. Cutting off a suspected-compromised worker meant rotating the broker
    password for EVERY worker, i.e. an outage, so in practice it would not be done
    promptly.
  * NO BINDING. Nothing tied a worker to a customer's private network, so any worker
    could in principle be handed any site's job.

A row here is a named, individually revocable principal. The manager resolves the
presented credential to exactly one of these rows and authorizes every request against
it -- pool, site and workspace all come from the SERVER's row, never from the request.
"""
import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base

# MBS.SC: `scanner_workers` has FKs to `private_sites` and `workspaces`, and SQLAlchemy resolves an FK's target table lazily out of the
# shared MetaData. A module that imports this model WITHOUT also importing those
# tables raises NoReferencedTableError the moment the mapper is configured -- which
# is what an operator script or a focused test does. Importing them here makes the
# dependency structural rather than a rule people have to remember.
from apps.api.modules.private_sites import models as _private_sites_models  # noqa: F401
from apps.api.modules.workspaces import models as _workspaces_models  # noqa: F401
from apps.api.core.db_types import GUID, UTCDateTime

#   pending    registered, not yet approved for work.
#   active     may lease jobs (subject to every other check).
#   draining   finish in-flight work, lease nothing new (graceful decommission).
#   suspended  temporarily blocked; reversible.
#   revoked    terminal. Credential is dead; never leases again.
WORKER_STATUSES = ("pending", "active", "draining", "suspended", "revoked")

# The ONLY health states a worker may self-report (F-9-01). Declared here, next to the
# column that stores them, so the API validation boundary and the persisted column cannot
# drift apart -- the values were previously documented only in the comment on
# `health_state` below, and the heartbeat endpoint accepted any string up to 32 chars.
#
# WHY THIS EXISTS. The Phase 9 adversarial audit confirmed an authenticated worker could
# POST `health_state="super-healthy"` and have it persisted verbatim. That is telemetry
# corruption, not an authorization bypass -- no gate reads this column -- but a metric an
# operator cannot trust is worse than no metric, and `mbs_tunnel_up` is projected from it.
#
# ADVISORY, AND STILL ADVISORY. Constraining the vocabulary does NOT make this field an
# authorization input: nothing here gates leasing, and private scanning is still decided by
# the live per-job tunnel probe (`preflight_private_job`). This narrows what a worker may
# SAY about itself; it changes nothing about what it may DO.
WORKER_HEALTH_STATES: tuple[str, ...] = ("healthy", "degraded", "unhealthy", "unknown")
# May this worker be handed NEW work? Enforced at the lease boundary only.
LEASE_ELIGIBLE_STATUSES = frozenset({"active"})
# May this worker ACT as an authenticated worker at all -- submit the results of a scan it
# already holds, post evidence, heartbeat, complete its lease? Enforced at authentication,
# so every status missing here is refused on every endpoint at once.
#
# `draining` is in this set but NOT in the one above, and that difference IS the state's
# meaning: "finish in-flight work, take nothing new". A decommissioning worker that could
# not report would lose the results of the scan it was explicitly allowed to finish.
WORKING_STATUSES = frozenset({"active", "draining"})


class ScannerWorker(Base):
    __tablename__ = "scanner_workers"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)

    # The stable name the worker presents (also its container identity / cert CN).
    worker_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)

    # Which pool this worker belongs to. A worker may only take work routed to its own
    # pool -- checked server-side against THIS column, never against a request field.
    pool_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # PRIVATE workers only: the single site this worker may serve. NULL for a public
    # worker. service.assert_worker_may_serve_site() enforces the binding in both
    # directions -- a public worker gets no private job, and a private worker gets no
    # job for a different site.
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("private_sites.id", ondelete="CASCADE"), nullable=True, index=True
    )

    # Tenant binding. NULL for a shared public worker (it scans public targets for many
    # tenants, which is safe because a public target is not tenant-private infrastructure).
    # NON-NULL for a private worker, where it must match the site's workspace.
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=True, index=True
    )

    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)

    # --- Credential / certificate metadata (NEVER the secret itself) -----------------
    # Only a HASH of the bootstrap token is stored, so a database read cannot recover a
    # usable worker credential (same reasoning as password storage).
    token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    # mTLS identity, when deployed with certificates: the manager pins the presented
    # client cert to the worker row by fingerprint, so a valid cert issued to worker A
    # cannot be replayed as worker B.
    cert_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    cert_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cert_not_after: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    # --- Health ----------------------------------------------------------------------
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True, index=True)
    # healthy | degraded | unhealthy | unknown -- self-reported, advisory only.
    health_state: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    last_health_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Last observed WireGuard handshake age in seconds (private workers).
    last_handshake_age_s: Mapped[int | None] = mapped_column(nullable=True)

    # --- Revocation ------------------------------------------------------------------
    # Enforced by the MANAGER, so revocation takes effect without needing to reach the
    # (possibly compromised, possibly offline) scanner host at all.
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)")
    )
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    __table_args__ = (
        Index("ix_scanner_workers_pool_status", "pool_id", "status"),
    )

    @property
    def is_private(self) -> bool:
        return self.site_id is not None
