"""Remediation workflow entities.

WHAT THIS IS AND IS NOT
-----------------------
This module models the HUMAN REMEDIATION WORK for an issue -- who owns it, when it is due,
what state the work is in, what proof exists that it was done. It is deliberately SEPARATE
from, and never conflated with, two things that already exist:

  * `vulnerabilities.status` -- the SCANNER/analyst view of whether the finding is currently
    live (open/confirmed/fixed/reopened/...). A remediation item reaching `verified` does NOT
    set a vulnerability to `fixed`; that lifecycle stays scanner/human owned exactly as it is
    (see vulnerabilities/service.py's ingest_finding and set_status).
  * `remediations` (vulnerabilities/remediation_models.py) -- AI/human GUIDANCE text for one
    vulnerability ("here is how to fix it"). That is advice; this is workflow. The guidance
    row is referenced from a RemediationItem, never duplicated into it.

ISSUE-LEVEL, NOT LOCATION-LEVEL
-------------------------------
The unit of remediation work is the ISSUE, not the vulnerability ROW. A vulnerability row is
one (template_id|matcher|matched_at) fingerprint -- one LOCATION -- so one command-injection
template hitting 22 URLs is 22 rows but ONE thing to fix. Identity here is therefore
`reports/scoring.issue_key` (the same canonical key the Security Score, Executive Top Risks
and the ATT&CK tally already use), enforced structurally by the (project_id, issue_key)
unique constraint. There is no second grouping key in this codebase.

TENANCY
-------
Every table here carries its own `workspace_id` and is registered as a DIRECT tenant-scoped
table in apps/api/core/tenancy.py. `remediation_items` alone could have been a 2-hop VIA
table (project -> workspace), but `remediation_events` / `verification_requests` /
`remediation_evidence` hang off `remediation_items`, which would put them at THREE hops --
more than tenancy._VIA_TABLES supports (that module asserts a 1- or 2-hop limit). One
consistent rule for the whole subsystem is also simpler to audit than a mix.
"""

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, Integer, String, Text, text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base
from apps.api.core.db_types import GUID, JSONType, UTCDateTime

# --- Lifecycle ------------------------------------------------------------------------------
# The approved remediation lifecycle. `proposed` is where an item is born (the system, or a
# human, has identified work to do); everything after it is a deliberate human decision.
STATUS_PROPOSED = "proposed"
STATUS_ACCEPTED = "accepted"
STATUS_IN_PROGRESS = "in_progress"
STATUS_AWAITING_VERIFICATION = "awaiting_verification"
STATUS_VERIFIED = "verified"
STATUS_CLOSED = "closed"
STATUS_RISK_ACCEPTED = "risk_accepted"
STATUS_REJECTED = "rejected"
STATUS_REOPENED = "reopened"

REMEDIATION_STATUSES = frozenset({
    STATUS_PROPOSED, STATUS_ACCEPTED, STATUS_IN_PROGRESS, STATUS_AWAITING_VERIFICATION,
    STATUS_VERIFIED, STATUS_CLOSED, STATUS_RISK_ACCEPTED, STATUS_REJECTED, STATUS_REOPENED,
})

# States that still represent OUTSTANDING work. Used by the progress rollup; not a second
# status taxonomy -- purely a partition of the one above.
OPEN_STATUSES = frozenset({
    STATUS_PROPOSED, STATUS_ACCEPTED, STATUS_IN_PROGRESS, STATUS_AWAITING_VERIFICATION,
    STATUS_REOPENED,
})

# --- Priority -------------------------------------------------------------------------------
# DELIBERATELY INDEPENDENT of vulnerability severity. Severity is what the scanner/CVSS says
# about the weakness; priority is what the ORGANISATION decides to work on first, which can
# legitimately differ (a medium on the payment path can outrank a high on a staging box).
# Severity is never written to represent priority, and priority never feeds the risk score.
PRIORITY_CRITICAL = "critical"
PRIORITY_HIGH = "high"
PRIORITY_MEDIUM = "medium"
PRIORITY_LOW = "low"
REMEDIATION_PRIORITIES = frozenset({PRIORITY_CRITICAL, PRIORITY_HIGH, PRIORITY_MEDIUM, PRIORITY_LOW})

# Provenance of the item / of its notes. AI-authored content is NEVER labelled human.
SOURCE_AI = "ai"
SOURCE_HUMAN = "human"
SOURCE_SYSTEM = "system"
REMEDIATION_SOURCES = frozenset({SOURCE_AI, SOURCE_HUMAN, SOURCE_SYSTEM})


class RemediationItem(Base):
    """One unit of remediation WORK, identified at the issue level."""

    __tablename__ = "remediation_items"
    __table_args__ = (
        # THE issue-level invariant. One issue in one project == exactly one remediation item,
        # enforced by the database rather than by service-layer convention, so no code path
        # (concurrent ingest included) can create a second item for the same issue.
        UniqueConstraint("project_id", "issue_key", name="uq_remediation_items_project_issue"),
        Index("ix_remediation_items_ws_status", "workspace_id", "status"),
        Index("ix_remediation_items_due", "workspace_id", "due_date"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # scoring.issue_key -- e.g. "template:unix-command-injection" or "title:<...>". A MySQL
    # utf8mb4 index key is capped at 3072 bytes (768 chars), so the 512 chars that match
    # vulnerabilities.title fit the composite unique index with room to spare.
    issue_key: Mapped[str] = mapped_column(String(512), nullable=False)

    # REPRESENTATIVE vulnerability for the issue (highest severity/CVSS member at creation
    # time). Nullable + ON DELETE SET NULL: the item survives its representative row being
    # retention-swept, and the issue_key remains the identity either way. This is a convenience
    # link for the UI/report, NEVER the item's identity.
    vulnerability_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # The AI/human GUIDANCE row this work is based on, when one exists. Reuses the existing
    # `remediations` table -- guidance text is not copied here.
    remediation_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("remediations.id", ondelete="SET NULL"), nullable=True
    )

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=STATUS_PROPOSED)
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default=PRIORITY_MEDIUM)

    # Assignee MUST be a workspace member -- validated in the service layer against
    # workspace_members, never trusted from the request body (an arbitrary user id would
    # otherwise leak the existence of users outside the workspace and mis-route work).
    assignee_user_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # UTC, stored via UTCDateTime like every other timestamp here. NULL = no due date, which is
    # distinct from "overdue" and from "due today".
    due_date: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    # HUMAN notes. AI guidance lives in `remediations` (remediation_id above) and is never
    # written here, so `notes` + `notes_source` cannot misrepresent AI text as human-authored.
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes_source: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # How the ITEM came to exist: system (derived from a scan's findings), human, or ai
    # (proposed by the agent). Provenance is immutable after creation.
    source: Mapped[str] = mapped_column(String(16), nullable=False, default=SOURCE_SYSTEM)

    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    # OPTIMISTIC LOCK. Every mutating service call requires the caller's `version` to match and
    # increments it in the same conditional UPDATE; a stale writer gets 409. An integer (not a
    # timestamp) so the comparison is exact and clock-independent.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default=text("1"))

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"), onupdate=text("CURRENT_TIMESTAMP(6)")
    )


class RemediationEvent(Base):
    """APPEND-ONLY workflow history for one remediation item.

    COMPLEMENTS `audit_events`, never replaces it: the audit log is the workspace-wide
    security record (who did what, across every resource type), while this is the item's own
    timeline, rendered directly in the UI. Every transition writes BOTH.

    There is no update or delete endpoint for this table anywhere in the API surface, and
    nothing in the service layer mutates a row after insert -- that is what makes it immutable
    in practice, and it is asserted directly by the immutability tests.
    """

    __tablename__ = "remediation_events"
    __table_args__ = (Index("ix_remediation_events_item_created", "remediation_item_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    remediation_item_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("remediation_items.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # created | assigned | due_date_changed | priority_changed | notes_changed | transition |
    # verification_requested | verification_completed | evidence_added | risk_accepted |
    # risk_acceptance_revoked | risk_acceptance_expired
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Nullable: the actor may be deleted later (SET NULL keeps the event), and system/expiry
    # events genuinely have no human actor.
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"), index=True
    )


class RemediationEvidence(Base):
    """Links an existing `evidence` row to a remediation item.

    A JOIN TABLE, not a second evidence store: the artifact itself (storage_uri, checksum,
    evidence_type) lives in the ONE `evidence` table the scanner already uses. This mirrors
    `vulnerability_evidence`, which does exactly the same job on the finding side.
    """

    __tablename__ = "remediation_evidence"

    remediation_item_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("remediation_items.id", ondelete="CASCADE"), primary_key=True
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))


class VerificationRequest(Base):
    """A request to RETEST an issue, and the outcome of that retest.

    Verification is backed by an ACTUAL scan through the existing Pentest Engine: `scan_id` is
    the scan whose result decides the outcome. No AI claim, boolean, or uploaded file can set
    `result` -- only `complete_verification`, driven by what the re-scan actually found for
    this issue_key (see remediation/verification.py).

    ATOMIC CLAIM: `claimed_at`/`claimed_by_token` follow the same conditional-UPDATE fencing
    pattern the scan executor uses (`scanner_engine/orchestrator._claim_scan`) -- a single
    `UPDATE ... WHERE status='pending'` whose rowcount decides the winner -- so exactly one
    worker can ever act on a request.
    """

    __tablename__ = "verification_requests"
    __table_args__ = (Index("ix_verification_requests_ws_status", "workspace_id", "status"),)

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    remediation_item_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("remediation_items.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # pending | claimed | completed | failed
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    # passed | failed | incomplete_coverage -- set ONLY by complete_verification from real
    # retest data. NULL until then. Width 24 (not 16): "incomplete_coverage" (Prompt 13,
    # Finding #3) is 19 characters.
    result: Mapped[str | None] = mapped_column(String(24), nullable=True)
    # The retest scan. Nullable until one is dispatched/linked. SET NULL on scan retention
    # sweep so the verification record survives its scan being aged off.
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Fencing token of the worker that won the claim (mirrors scans.execution_token).
    claimed_by_token: Mapped[uuid.UUID | None] = mapped_column(GUID(), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    # What the retest actually observed, as structured facts (live location count, the scan
    # that produced them) -- the reproducible basis for `result`, not a prose claim.
    detail: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    # Prompt 13, Finding #3: the issue's distinct scorable locations AS OF request_verification()
    # time -- the reference set complete_verification() checks the retest actually covered
    # before it is allowed to report `passed`. A JSON list of `matched_at` strings (or empty
    # for legacy rows created before this column existed / issues with no locatable findings).
    # Captured once, at request time, and never mutated afterward -- this is evidence input to
    # the verdict, not a live-updated field.
    baseline_locations: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
