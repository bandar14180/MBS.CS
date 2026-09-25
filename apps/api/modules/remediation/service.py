"""Remediation workflow service.

EVERY mutating function in this module follows the same six-step discipline, in this order,
because reordering any of them opens a real hole:

  1. resolve the item through a WORKSPACE-SCOPED query (never trust a body-supplied
     workspace/project/owner id -- that is the IDOR guard);
  2. validate the transition against the state machine BEFORE writing anything;
  3. apply the change under an OPTIMISTIC-LOCK compare-and-set on `version`;
  4. append an immutable RemediationEvent;
  5. append an audit_events row through the EXISTING audit service;
  6. commit -- so an illegal or stale request leaves no event, no audit row, and no version bump.

WHAT THIS SERVICE MAY NEVER DO, and structurally cannot:
  * write `vulnerabilities.severity`, `.cvss_score`, `.cvss_vector`, or
    `risk_scores.final_risk_score` -- none of those models is even imported for writing here;
  * set `remediation_item.status` to `verified` outside complete_verification();
  * set it to `risk_accepted` outside accept_risk();
  * change a vulnerability's own status as a side effect of remediation progress.
"""

import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status as http_status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.pagination import MAX_LIMIT, Pagination, paginate
from apps.api.modules.audit import service as audit
from apps.api.modules.projects.service import get_project
from apps.api.modules.remediation import state_machine
from apps.api.modules.remediation.models import (
    OPEN_STATUSES,
    REMEDIATION_PRIORITIES,
    RemediationEvent,
    RemediationItem,
    SOURCE_HUMAN,
    SOURCE_SYSTEM,
    STATUS_AWAITING_VERIFICATION,
    STATUS_CLOSED,
    STATUS_PROPOSED,
    STATUS_REOPENED,
    STATUS_RISK_ACCEPTED,
    STATUS_VERIFIED,
)
from apps.api.modules.users.models import WorkspaceMember

# Statuses whose entry means the remediation WORK is done (used to stamp resolved_at). This is
# about the work item only -- it says nothing about whether the vulnerability is live, which
# stays scanner/analyst-owned (see the module docstring in models.py).
_RESOLVED_STATUSES = frozenset({STATUS_VERIFIED, STATUS_CLOSED, STATUS_RISK_ACCEPTED})


class StaleVersionError(HTTPException):
    """409 for a lost-update race. Its own class so the concurrency tests can assert on the
    exact failure mode rather than on any 409 that happens to be raised."""

    def __init__(self, expected: int, actual: int | None = None) -> None:
        super().__init__(
            http_status.HTTP_409_CONFLICT,
            f"Remediation item was modified by someone else (expected version {expected}"
            + (f", current is {actual}" if actual is not None else "")
            + "). Re-read the item and retry.",
        )


# --- helpers ---------------------------------------------------------------------------------

async def _record_event(
    db: AsyncSession,
    item: RemediationItem,
    event_type: str,
    actor_user_id: uuid.UUID | None,
    *,
    from_status: str | None = None,
    to_status: str | None = None,
    detail: str | None = None,
) -> None:
    """Append to the item's immutable timeline. Never updates an existing row."""
    db.add(
        RemediationEvent(
            workspace_id=item.workspace_id,
            remediation_item_id=item.id,
            event_type=event_type,
            from_status=from_status,
            to_status=to_status,
            actor_user_id=actor_user_id,
            detail=detail,
        )
    )


async def _bump_version(db: AsyncSession, item: RemediationItem, expected_version: int) -> None:
    """OPTIMISTIC LOCK, as a single conditional UPDATE.

    Deliberately NOT `if item.version != expected: raise` in Python: that check and the
    subsequent write are two statements with a window between them, so two concurrent
    requests can both read version 1, both pass the check, and both write -- the exact lost
    update this exists to prevent. `UPDATE ... WHERE id = :id AND version = :expected` makes
    the check and the write ONE atomic statement, and rowcount tells the caller whether they
    won. Same discipline as the scan executor's `_claim_scan` fence.

    The ORM object's own `version` is advanced to match so the response body returned to the
    winner reflects what is actually in the database."""
    result = await db.execute(
        update(RemediationItem)
        .where(RemediationItem.id == item.id, RemediationItem.version == expected_version)
        .values(version=expected_version + 1, updated_at=datetime.now(timezone.utc))
    )
    if result.rowcount != 1:
        # Read back the real version for a diagnosable message. Still workspace-filtered by
        # the tenancy layer, so this cannot disclose another tenant's row.
        actual = await db.scalar(select(RemediationItem.version).where(RemediationItem.id == item.id))
        await db.rollback()
        raise StaleVersionError(expected_version, actual)
    item.version = expected_version + 1


async def _require_workspace_member(
    db: AsyncSession, workspace_id: uuid.UUID, user_id: uuid.UUID
) -> None:
    """An assignee MUST be a member of THIS workspace.

    Without this, a caller could assign work to any user id they can guess -- which both
    mis-routes the work and turns the endpoint into an oracle for whether an arbitrary user id
    exists on the platform. 400 (not 404) because the failure is in the submitted payload."""
    member = await db.scalar(
        select(WorkspaceMember.id).where(
            WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.user_id == user_id
        )
    )
    if member is None:
        raise HTTPException(
            http_status.HTTP_400_BAD_REQUEST, "Assignee must be a member of this workspace"
        )


async def get_item(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, item_id: uuid.UUID
) -> RemediationItem:
    """THE resolution path. Filters on workspace_id AND project_id explicitly (belt and
    braces alongside the tenancy auto-filter), so a cross-workspace or cross-project id is a
    404 -- indistinguishable from a non-existent id, which is what prevents the endpoint from
    confirming that another tenant's item exists."""
    item = await db.scalar(
        select(RemediationItem).where(
            RemediationItem.id == item_id,
            RemediationItem.project_id == project_id,
            RemediationItem.workspace_id == workspace_id,
        )
    )
    if item is None:
        raise HTTPException(http_status.HTTP_404_NOT_FOUND, "Remediation item not found")
    return item


# --- creation / sync -------------------------------------------------------------------------

async def sync_items_for_project(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    actor_user_id: uuid.UUID | None,
) -> list[RemediationItem]:
    """Create a remediation item for every SCORABLE issue in the project that lacks one.

    ISSUE-LEVEL BY CONSTRUCTION: findings are grouped with reports.scoring.group_issues -- the
    same canonical grouping the Security Score and the report's Top Risks use -- so N
    vulnerability rows sharing one issue_key produce exactly ONE item. The
    (project_id, issue_key) unique constraint is the structural backstop.

    IDEMPOTENT: an existing item for an issue is left completely alone (its status, owner, due
    date and notes are human state that a re-scan must never overwrite). Re-running this after
    a new scan therefore only ADDS items for newly-discovered issues.

    Scope is scoring.is_scorable, so informational findings, detections, and already
    fixed/false-positive/accepted rows do not manufacture work items. That also means the item
    set and the security score always describe the same population."""
    from apps.api.modules.reports.data import gather_report_data
    from apps.api.modules.reports.scoring import group_issues

    await get_project(db, workspace_id, project_id)
    data = await gather_report_data(db, project_id)
    issues = group_issues(data.vulns)
    if not issues:
        return []

    existing_keys = set(
        await db.scalars(
            select(RemediationItem.issue_key).where(RemediationItem.project_id == project_id)
        )
    )

    # Representative vulnerability per issue: the highest-severity/CVSS member, matching how
    # group_issues picks its representative title. Used only as a convenience link.
    rep_vuln_by_key: dict[str, uuid.UUID] = {}
    from apps.api.modules.reports.scoring import issue_key as _issue_key, is_scorable

    for row in data.vulns:
        if not is_scorable(row):
            continue
        rep_vuln_by_key.setdefault(_issue_key(row), row.id)

    created: list[RemediationItem] = []
    for issue in issues:
        if issue.key in existing_keys:
            continue
        item = RemediationItem(
            workspace_id=workspace_id,
            project_id=project_id,
            issue_key=issue.key,
            vulnerability_id=rep_vuln_by_key.get(issue.key),
            title=issue.title,
            status=STATUS_PROPOSED,
            # Priority is SEEDED from severity as a starting point and is thereafter fully
            # independent -- a human may re-prioritise without touching severity, and a later
            # re-scan never re-derives it. Severity itself is never written here.
            priority=_seed_priority(issue.severity),
            source=SOURCE_SYSTEM,
            created_by=actor_user_id,
        )
        db.add(item)
        await db.flush()
        await _record_event(
            db, item, "created", actor_user_id,
            to_status=STATUS_PROPOSED,
            detail=f"issue_key={issue.key} locations={issue.location_count}",
        )
        created.append(item)

    if created:
        await audit.record(
            db, workspace_id, actor_user_id, "remediation.items_synced", "remediation_item",
            detail=f"project={project_id} created={len(created)}",
        )
    await db.commit()
    for item in created:
        await db.refresh(item)
    return created


def _seed_priority(severity: str | None) -> str:
    """Initial priority suggestion from severity. A ONE-TIME seed at creation, never a
    synchronization: `priority` and `severity` are independent fields thereafter (requirement
    7), and nothing re-derives one from the other."""
    sev = (severity or "").lower()
    return sev if sev in REMEDIATION_PRIORITIES else "medium"


# --- reads -----------------------------------------------------------------------------------

async def list_items(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    *,
    status_filter: str | None = None,
    priority: str | None = None,
    assignee_user_id: uuid.UUID | None = None,
    overdue: bool | None = None,
    page: Pagination | None = None,
) -> tuple[list[RemediationItem], int]:
    await get_project(db, workspace_id, project_id)
    query = select(RemediationItem).where(
        RemediationItem.project_id == project_id, RemediationItem.workspace_id == workspace_id
    )
    if status_filter:
        query = query.where(RemediationItem.status == status_filter)
    if priority:
        query = query.where(RemediationItem.priority == priority)
    if assignee_user_id:
        query = query.where(RemediationItem.assignee_user_id == assignee_user_id)
    if overdue:
        # OVERDUE means: a due date in the past AND work still outstanding. A verified/closed/
        # risk-accepted item past its due date is finished, not overdue -- reporting it as
        # overdue would inflate the metric with work that is actually done.
        query = query.where(
            RemediationItem.due_date.is_not(None),
            RemediationItem.due_date < datetime.now(timezone.utc),
            RemediationItem.status.in_(OPEN_STATUSES),
        )
    query = query.order_by(RemediationItem.created_at, RemediationItem.id)
    return await paginate(db, query, page or Pagination(limit=MAX_LIMIT, offset=0))


async def list_events(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, item_id: uuid.UUID
) -> list[RemediationEvent]:
    await get_item(db, workspace_id, project_id, item_id)
    return list(
        await db.scalars(
            select(RemediationEvent)
            .where(RemediationEvent.remediation_item_id == item_id)
            .order_by(RemediationEvent.created_at, RemediationEvent.id)
        )
    )


def is_overdue(item: RemediationItem, now: datetime | None = None) -> bool:
    """Pure, so the same rule is testable without a database and cannot drift from the SQL
    predicate in list_items above."""
    if item.due_date is None or item.status not in OPEN_STATUSES:
        return False
    return item.due_date < (now or datetime.now(timezone.utc))


async def progress_for_project(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID
) -> dict:
    """Remediation progress, COMPUTED from remediation items -- never stored, never a second
    risk calculation. Returns per-status counts plus the two derived numbers the UI and the
    assessment both need."""
    rows = (
        await db.execute(
            select(RemediationItem.status, func.count())
            .where(
                RemediationItem.project_id == project_id,
                RemediationItem.workspace_id == workspace_id,
            )
            .group_by(RemediationItem.status)
        )
    ).all()
    by_status = {st: int(n) for st, n in rows}

    overdue = int(
        await db.scalar(
            select(func.count())
            .select_from(RemediationItem)
            .where(
                RemediationItem.project_id == project_id,
                RemediationItem.workspace_id == workspace_id,
                RemediationItem.due_date.is_not(None),
                RemediationItem.due_date < datetime.now(timezone.utc),
                RemediationItem.status.in_(OPEN_STATUSES),
            )
        )
        or 0
    )
    total = sum(by_status.values())
    # "Resolved" counts work that is FINISHED by any legitimate route -- verified, closed, or
    # formally risk-accepted. A risk-accepted item is a completed decision, not outstanding
    # work, which is why it belongs here and not in `open`.
    resolved = sum(by_status.get(s, 0) for s in _RESOLVED_STATUSES)
    return {
        "total": total,
        "proposed": by_status.get("proposed", 0),
        "accepted": by_status.get("accepted", 0),
        "in_progress": by_status.get("in_progress", 0),
        "awaiting_verification": by_status.get("awaiting_verification", 0),
        "verified": by_status.get("verified", 0),
        "closed": by_status.get("closed", 0),
        "risk_accepted": by_status.get("risk_accepted", 0),
        "rejected": by_status.get("rejected", 0),
        "reopened": by_status.get("reopened", 0),
        "open": sum(by_status.get(s, 0) for s in OPEN_STATUSES),
        "resolved": resolved,
        "overdue": overdue,
        # Integer percent so the client never has to decide how to round; 0 when there is no
        # work at all (rather than 100, which would claim completion of nothing).
        "completion_percent": round(100 * resolved / total) if total else 0,
    }


# --- mutations -------------------------------------------------------------------------------

async def update_item(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    item_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    expected_version: int,
    *,
    assignee_user_id: uuid.UUID | None = None,
    clear_assignee: bool = False,
    due_date: datetime | None = None,
    clear_due_date: bool = False,
    priority: str | None = None,
    notes: str | None = None,
) -> RemediationItem:
    """Update the item's workflow fields. Status is NOT settable here -- see transition().

    `clear_assignee` / `clear_due_date` are explicit flags rather than "pass None to clear",
    because None already means "leave unchanged" for a PATCH; conflating the two would make it
    impossible to update a due date without also being able to accidentally erase an assignee.
    """
    item = await get_item(db, workspace_id, project_id, item_id)

    changes: list[tuple[str, str]] = []  # (event_type, human-readable detail)

    if clear_assignee:
        if item.assignee_user_id is not None:
            changes.append(("assigned", "assignee cleared"))
            item.assignee_user_id = None
    elif assignee_user_id is not None:
        # The membership check is what stops an arbitrary external user id being written.
        await _require_workspace_member(db, workspace_id, assignee_user_id)
        if item.assignee_user_id != assignee_user_id:
            changes.append(("assigned", f"assignee -> {assignee_user_id}"))
            item.assignee_user_id = assignee_user_id

    if clear_due_date:
        if item.due_date is not None:
            changes.append(("due_date_changed", "due date cleared"))
            item.due_date = None
    elif due_date is not None:
        # Normalize to UTC. A naive datetime is assumed UTC, matching the storage convention
        # UTCDateTime documents, so a client that omits an offset is not silently shifted.
        due = due_date if due_date.tzinfo else due_date.replace(tzinfo=timezone.utc)
        due = due.astimezone(timezone.utc)
        if item.due_date != due:
            changes.append(("due_date_changed", f"due date -> {due.isoformat()}"))
            item.due_date = due

    if priority is not None:
        if priority not in REMEDIATION_PRIORITIES:
            raise HTTPException(
                http_status.HTTP_400_BAD_REQUEST,
                f"priority must be one of: {', '.join(sorted(REMEDIATION_PRIORITIES))}",
            )
        if item.priority != priority:
            changes.append(("priority_changed", f"{item.priority} -> {priority}"))
            item.priority = priority

    if notes is not None and notes != (item.notes or ""):
        changes.append(("notes_changed", "notes updated"))
        item.notes = notes
        # PROVENANCE: notes written through this endpoint are authored by an authenticated
        # HUMAN, full stop. AI guidance lives in the separate `remediations` row and is never
        # copied here, so this label cannot become a lie.
        item.notes_source = SOURCE_HUMAN

    if not changes:
        # Nothing actually changed -- do not bump the version or append events for a no-op.
        return item

    await _bump_version(db, item, expected_version)
    for event_type, detail in changes:
        await _record_event(db, item, event_type, actor_user_id, detail=detail)
    await audit.record(
        db, workspace_id, actor_user_id, "remediation.updated", "remediation_item",
        resource_id=item.id, detail="; ".join(d for _, d in changes),
    )
    await db.commit()
    await db.refresh(item)
    return item


async def transition(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    item_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    expected_version: int,
    to_status: str,
    detail: str | None = None,
) -> RemediationItem:
    """Move an item along the lifecycle. The ONLY human entry point for a status change.

    Refuses the two GUARDED targets (`verified`, `risk_accepted`) even when the graph would
    otherwise allow them: reaching those requires evidence this endpoint does not have (a real
    retest result / an approved, justified, expiring acceptance), so they have their own
    authorized entry points. Without this guard a user with plain `remediation:manage` could
    declare work verified by typing the word."""
    item = await get_item(db, workspace_id, project_id, item_id)

    if to_status in state_machine.GUARDED_TARGETS:
        raise HTTPException(
            http_status.HTTP_400_BAD_REQUEST,
            f"'{to_status}' cannot be set directly. Use the verification workflow for "
            "'verified', or the risk-acceptance endpoint for 'risk_accepted'.",
        )
    if not state_machine.is_legal(item.status, to_status):
        allowed = sorted(state_machine.allowed_targets(item.status) - state_machine.GUARDED_TARGETS)
        raise HTTPException(
            http_status.HTTP_409_CONFLICT,
            f"Illegal transition '{item.status}' -> '{to_status}'. "
            f"Allowed from '{item.status}': {', '.join(allowed) or 'none'}.",
        )

    return await _apply_transition(
        db, item, actor_user_id, expected_version, to_status, detail=detail,
        audit_action="remediation.transitioned",
    )


async def _apply_transition(
    db: AsyncSession,
    item: RemediationItem,
    actor_user_id: uuid.UUID | None,
    expected_version: int,
    to_status: str,
    *,
    detail: str | None = None,
    audit_action: str = "remediation.transitioned",
    event_type: str = "transition",
) -> RemediationItem:
    """Shared transition body used by transition(), the verification completion path, and the
    risk-acceptance path -- so all three produce identical event/audit/version semantics and
    only differ in who is authorized to reach them. Assumes legality was already checked by
    the caller (each entry point has its own, different, additional preconditions)."""
    from_status = item.status
    await _bump_version(db, item, expected_version)

    item.status = to_status
    now = datetime.now(timezone.utc)
    if to_status == STATUS_VERIFIED:
        item.verified_at = now
    if to_status in _RESOLVED_STATUSES:
        item.resolved_at = now
    elif to_status in OPEN_STATUSES:
        # Re-opened / re-worked: the item is outstanding again, so a stale resolution stamp
        # must not survive to make finished-work metrics over-count.
        item.resolved_at = None
        if to_status != STATUS_AWAITING_VERIFICATION:
            item.verified_at = None

    await _record_event(
        db, item, event_type, actor_user_id,
        from_status=from_status, to_status=to_status, detail=detail,
    )
    await audit.record(
        db, item.workspace_id, actor_user_id, audit_action, "remediation_item",
        resource_id=item.id, detail=f"{from_status} -> {to_status}" + (f": {detail}" if detail else ""),
    )
    await db.commit()
    await db.refresh(item)
    return item


async def reopen_for_regression(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, issue_key: str
) -> RemediationItem | None:
    """Revive the remediation item for an issue the scanner has just RE-DETECTED.

    Called from the ingest path when a `fixed` vulnerability flips back to `reopened`, so the
    work item follows the finding instead of sitting at `verified`/`closed` while the issue is
    demonstrably live again. Returns None when there is no item for the issue, or when the item
    is in a state where `reopened` is not a legal target (e.g. already in progress) -- a
    regression must never force an illegal transition.

    Actor is None: this is the ENGINE acting on evidence, not a person, and recording a human
    actor here would misattribute the decision."""
    item = await db.scalar(
        select(RemediationItem).where(
            RemediationItem.project_id == project_id,
            RemediationItem.workspace_id == workspace_id,
            RemediationItem.issue_key == issue_key,
        )
    )
    if item is None or not state_machine.is_legal(item.status, STATUS_REOPENED):
        return None
    return await _apply_transition(
        db, item, None, item.version, STATUS_REOPENED,
        detail="re-detected by a scan", audit_action="remediation.reopened",
    )
