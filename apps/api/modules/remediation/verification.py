"""Verification: prove an issue is actually gone, by RE-TESTING it.

THE RULE THIS MODULE EXISTS TO ENFORCE
--------------------------------------
A remediation item may become `verified` ONLY on the strength of a real retest through the
existing Pentest Engine. Specifically, `complete_verification` derives the outcome from what
the retest SCAN actually observed for the item's issue_key -- the same canonical issue
identity used everywhere else -- and nothing else. It will not accept:

  * an AI assertion that the finding is fixed;
  * a client-supplied boolean or checkbox;
  * an uploaded screenshot on its own.

Those can all be RECORDED (as remediation evidence, with provenance), and none of them can set
`result`. The signature of `complete_verification` deliberately takes no `passed` parameter:
there is no argument a caller could pass to declare the outcome.

RACE PROTECTION
---------------
Requests are claimed with the SAME conditional-UPDATE fencing pattern the scan executor uses
(`scanner_engine/orchestrator._claim_scan`): one `UPDATE ... WHERE status='pending'` whose
rowcount decides the single winner. Two workers cannot both act on one request, so a retest is
never double-processed and a completion can never be applied twice.
"""

import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status as http_status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.audit import service as audit
from apps.api.modules.remediation import state_machine
from apps.api.modules.remediation.models import (
    RemediationItem,
    STATUS_AWAITING_VERIFICATION,
    STATUS_IN_PROGRESS,
    STATUS_VERIFIED,
    VerificationRequest,
)
from apps.api.modules.remediation.service import _apply_transition, _record_event, get_item

RESULT_PASSED = "passed"
RESULT_FAILED = "failed"
# Prompt 13, Finding #3: the retest scan did not demonstrably cover every location the issue
# had at the moment verification was requested. This is a THIRD outcome, distinct from
# passed/failed -- neither claims the issue is gone (passed) nor that it is still present
# (failed); it says the retest's evidence is insufficient to conclude either. The item is left
# at its current status (never auto-reopened, never auto-verified) so a human/retry can
# dispatch a retest with adequate coverage. See count_live_locations/_scorable_locations and
# complete_verification's coverage check below.
RESULT_INCOMPLETE_COVERAGE = "incomplete_coverage"


async def request_verification(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    item_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    expected_version: int,
    scan_id: uuid.UUID | None = None,
) -> VerificationRequest:
    """Ask for the item's issue to be retested, moving it to `awaiting_verification`.

    An optional `scan_id` links a retest that has ALREADY been run through the normal scan
    endpoint (the usual flow: fix, re-scan the target, then point the verification at that
    scan). It is validated to belong to this workspace and project -- a body-supplied scan id
    from another tenant is refused rather than trusted."""
    item = await get_item(db, workspace_id, project_id, item_id)

    if not state_machine.is_legal(item.status, STATUS_AWAITING_VERIFICATION):
        raise HTTPException(
            http_status.HTTP_409_CONFLICT,
            f"Cannot request verification from status '{item.status}'. "
            f"Move the item to '{STATUS_IN_PROGRESS}' first.",
        )

    if scan_id is not None:
        await _require_project_scan(db, workspace_id, project_id, scan_id)

    # Refuse a second outstanding request: two pending requests for one item would produce two
    # completions racing to transition the same item, and the second would fail the state
    # machine anyway -- better to reject it plainly here.
    outstanding = await db.scalar(
        select(VerificationRequest.id).where(
            VerificationRequest.remediation_item_id == item.id,
            VerificationRequest.status.in_(("pending", "claimed")),
        )
    )
    if outstanding is not None:
        raise HTTPException(
            http_status.HTTP_409_CONFLICT, "A verification request is already outstanding for this item"
        )

    # Prompt 13, Finding #3: snapshot which locations this issue has RIGHT NOW, before any
    # retest runs. This is the reference set complete_verification() later checks the retest
    # actually covered -- captured here (not recomputed at completion time from "whatever the
    # scan touched") specifically so a location that existed at request time but the retest
    # scan simply never re-visited cannot silently vanish from consideration. A location that
    # appears only AFTER this snapshot (a brand-new finding discovered by unrelated means
    # between request and completion) is intentionally not retroactively required -- the
    # retest is answering "is the issue AS KNOWN AT REQUEST TIME gone", not "is every future
    # detection also covered".
    baseline = await _scorable_locations(db, project_id, item.issue_key)

    request = VerificationRequest(
        workspace_id=workspace_id,
        remediation_item_id=item.id,
        status="pending",
        scan_id=scan_id,
        requested_by=actor_user_id,
        detail={},
        baseline_locations=sorted(baseline),
    )
    db.add(request)
    await db.flush()

    await _record_event(
        db, item, "verification_requested", actor_user_id,
        detail=f"request={request.id}" + (f" scan={scan_id}" if scan_id else ""),
    )
    # The transition commits; the request row above is part of the same transaction, so either
    # both land or neither does.
    await _apply_transition(
        db, item, actor_user_id, expected_version, STATUS_AWAITING_VERIFICATION,
        detail="verification requested", audit_action="remediation.verification_requested",
    )
    await db.refresh(request)
    return request


async def _require_project_scan(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, scan_id: uuid.UUID
):
    """`scans` is tenancy-EXEMPT (the worker bootstraps from it before the workspace is
    known), so it is NOT auto-filtered -- the workspace_id/project_id predicates here are the
    actual isolation for this lookup and must not be dropped."""
    from apps.api.modules.scans.models import Scan

    scan = await db.scalar(
        select(Scan).where(
            Scan.id == scan_id, Scan.workspace_id == workspace_id, Scan.project_id == project_id
        )
    )
    if scan is None:
        raise HTTPException(http_status.HTTP_404_NOT_FOUND, "Scan not found in this project")

    # PROMPT 37 (adversarial audit): the retest scan must have FINISHED.
    #
    # Reproduced defect: a scan still in `running` could be linked as the retest. Because the
    # coverage gate only asks whether SOME detection ToolRun reached completed/partial, an
    # in-flight scan whose first nuclei run had finished satisfied it, `_live_locations`
    # counted only what had been ingested SO FAR (zero), and the item was driven to
    # `verified` -- a PASS derived from a retest that had not finished looking. The finding
    # the rest of that scan was about to re-ingest would have contradicted the verdict.
    #
    # "Zero findings so far" is not evidence of absence, which is the same rule the coverage
    # gate already enforces for a failed detection pass. This closes the remaining hole.
    #
    # Terminal statuses are imported from the orchestrator rather than re-listed here, so a
    # future lifecycle state cannot silently become verifiable by being forgotten in a copy.
    # `failed`/`cancelled` are deliberately INCLUDED as linkable: they are genuinely finished,
    # and the existing coverage gate is what decides they produced no usable detection pass
    # (-> INCOMPLETE_COVERAGE). Excluding them here would replace that precise, auditable
    # outcome with a blunt 409.
    from apps.api.scanner_engine.orchestrator import _TERMINAL_STATUSES

    if scan.status not in _TERMINAL_STATUSES:
        raise HTTPException(
            http_status.HTTP_409_CONFLICT,
            f"Retest scan is still in progress (status '{scan.status}'). A verification result "
            "is derived from a COMPLETED retest -- an unfinished scan has not finished looking, "
            "so zero findings so far is not evidence the issue is gone.",
        )
    return scan


async def claim_verification(
    db: AsyncSession, request_id: uuid.UUID, worker_token: uuid.UUID
) -> bool:
    """ATOMIC CLAIM. Returns True iff THIS caller won.

    Raw conditional UPDATE, matching orchestrator._claim_scan: the `status='pending'` predicate
    IS the claim token, so the database -- not application logic -- decides the winner in one
    statement. A read-then-write would leave a window in which two workers both see `pending`.

    Committed immediately so the claim is durable and visible to every other worker before any
    slow retest work begins.

    Raw SQL bypasses the ORM tenancy filter (see tenancy.py's docstring), which is safe and
    intended here: this is an internal worker path keyed by a trusted, internally-generated
    request id, exactly like the scan claim it mirrors. The request's workspace is bound by the
    caller before any subsequent ORM work."""
    result = await db.execute(
        text(
            "UPDATE verification_requests SET status = 'claimed', claimed_at = now(6), "
            "claimed_by_token = :tok WHERE id = :id AND status = 'pending'"
        ),
        {"id": str(request_id), "tok": str(worker_token)},
    )
    claimed = result.rowcount == 1
    await db.commit()
    return claimed


async def complete_verification(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    request_id: uuid.UUID,
    *,
    actor_user_id: uuid.UUID | None = None,
    worker_token: uuid.UUID | None = None,
) -> VerificationRequest:
    """Decide the outcome FROM THE RETEST DATA and apply it.

    NOTE THE SIGNATURE: there is no `passed` argument. The outcome is computed by counting the
    issue's still-live locations in the linked scan -- so no caller, human or AI, can assert a
    result. That is the structural form of "do not mark a vulnerability verified merely because
    an AI response says it is fixed".

    Outcome rules:
      * PASSED -- the retest scan observed ZERO active (scorable) findings for this issue_key;
      * FAILED -- it observed one or more. The item returns to `in_progress`, which is the
        approved awaiting_verification -> in_progress path, so a failed fix reopens the work
        instead of silently stalling.

    A request with no linked scan cannot be completed at all: without a retest there is nothing
    to derive an outcome from, and inventing one is precisely what this module forbids.
    """
    request = await db.scalar(
        select(VerificationRequest).where(
            VerificationRequest.id == request_id, VerificationRequest.workspace_id == workspace_id
        )
    )
    if request is None:
        raise HTTPException(http_status.HTTP_404_NOT_FOUND, "Verification request not found")
    if request.status == "completed":
        # Idempotent: a retried worker converges instead of double-applying a transition.
        return request
    if worker_token is not None and request.claimed_by_token != worker_token:
        raise HTTPException(
            http_status.HTTP_409_CONFLICT, "Verification request is owned by another worker"
        )
    if request.scan_id is None:
        raise HTTPException(
            http_status.HTTP_409_CONFLICT,
            "Cannot complete verification without a retest scan. Link a completed scan to the "
            "request first -- a verification result is derived from retest evidence, never asserted.",
        )

    item = await db.scalar(
        select(RemediationItem).where(RemediationItem.id == request.remediation_item_id)
    )
    if item is None:
        raise HTTPException(http_status.HTTP_404_NOT_FOUND, "Remediation item not found")

    live_locations, live_set = await _live_locations(db, item.project_id, item.issue_key, request.scan_id)

    # Prompt 13, Finding #3: COVERAGE CHECK. A PASS must mean "the retest looked and found
    # nothing", never merely "the retest didn't happen to look here". Compare the location set
    # snapshotted at request time (baseline_locations) against what THIS scan actually touched
    # for this issue -- any vulnerabilities table row for this issue_key whose last_seen_scan_id
    # is this scan, whether still live or not (a location the retest re-examined and found
    # CLEAN also updates last_seen_scan_id on the still-open... no: a fixed/no-longer-detected
    # row is simply never re-touched by ingest_finding, so "touched" is necessarily the same
    # signal as "still live" for individual vulnerability rows). Since a genuinely-fixed
    # location produces NO row with this scan's id at all, location-level "the retest looked
    # here and it's clean" cannot be distinguished from "the retest never looked here" purely
    # from the vulnerabilities table. The only real, already-recorded signal for "did the
    # retest scan actually execute its finding-producing tools to a usable completion" is
    # ToolRun -- so coverage is gated on that: the linked scan must have at least one
    # non-failed ToolRun for a vulnerability-detection tool. This does not claim
    # location-by-location proof of re-examination (the underlying tools do not report negative
    # results per URL) -- it draws the line at "a real, completed detection pass happened",
    # which is the concrete gap the audit identified (a failed/timed-out/partial retest must
    # never silently produce PASSED).
    coverage_ok = await _retest_had_usable_detection_coverage(db, request.scan_id)
    baseline = set(request.baseline_locations or [])
    # Locations from the baseline that are neither still live NOR demonstrably covered by a
    # usable retest -- present only to make the outcome auditable; the actual gate is
    # `coverage_ok` (see comment above for why per-location proof of a NEGATIVE isn't available).
    uncovered = sorted(baseline - live_set) if not coverage_ok else []

    if not coverage_ok:
        outcome = RESULT_INCOMPLETE_COVERAGE
    elif live_locations == 0:
        outcome = RESULT_PASSED
    else:
        outcome = RESULT_FAILED

    request.status = "completed"
    request.result = outcome
    request.completed_at = datetime.now(timezone.utc)
    # The REPRODUCIBLE basis for the verdict, stored as structured facts rather than prose, so
    # an auditor can re-derive it from the same scan.
    request.detail = {
        "scan_id": str(request.scan_id),
        "issue_key": item.issue_key,
        "live_locations": live_locations,
        "baseline_locations": sorted(baseline),
        "coverage_ok": coverage_ok,
        "uncovered_locations": uncovered,
        "evaluated_at": request.completed_at.isoformat(),
    }

    await _record_event(
        db, item, "verification_completed", actor_user_id,
        detail=f"result={request.result} live_locations={live_locations} scan={request.scan_id}",
    )

    # INCOMPLETE_COVERAGE leaves the item exactly where it is -- neither verified nor bounced
    # back to in_progress, since we have not established the fix failed, only that we cannot
    # yet say it succeeded. Per Prompt 13 scope: no new RemediationItem status is introduced for
    # this; `awaiting_verification` already describes "retest outcome not yet established".
    if outcome == RESULT_INCOMPLETE_COVERAGE:
        await audit.record(
            db, workspace_id, actor_user_id, "remediation.verification_completed", "remediation_item",
            resource_id=item.id,
            detail=(
                f"result={request.result}; item left at '{item.status}' -- retest scan "
                f"{request.scan_id} did not demonstrate usable detection coverage"
            ),
            # Prompt 34: the verification ran but established nothing, so recording this as
            # a success would overstate it. `failure` here means "did not conclude", which
            # is what the detail says in prose.
            outcome=audit.OUTCOME_FAILURE,
        )
        await db.commit()
        await db.refresh(request)
        return request

    passed = outcome == RESULT_PASSED
    target = STATUS_VERIFIED if passed else STATUS_IN_PROGRESS
    # `verified` is a GUARDED target reachable only from here -- that guard lives in
    # service.transition(), which this path deliberately does not go through.
    if state_machine.is_legal(item.status, target):
        await _apply_transition(
            db, item, actor_user_id, item.version, target,
            detail=f"verification {request.result} ({live_locations} live location(s))",
            audit_action="remediation.verification_completed",
            event_type="transition",
        )
    else:
        # The item moved on since the request (e.g. a human reopened it). Record the outcome
        # faithfully and leave the item where it is rather than forcing an illegal transition.
        await audit.record(
            db, workspace_id, actor_user_id, "remediation.verification_completed", "remediation_item",
            resource_id=item.id,
            detail=f"result={request.result}; item left at '{item.status}' (transition not legal)",
            # Prompt 34: the requested state change was refused by the state machine.
            outcome=audit.OUTCOME_DENIED,
        )
        await db.commit()
    await db.refresh(request)
    return request


async def _retest_had_usable_detection_coverage(db: AsyncSession, scan_id: uuid.UUID) -> bool:
    """Did the linked retest scan actually run a vulnerability-detection tool to a usable
    (non-failed) completion? `failed` means the orchestrator explicitly discarded that tool's
    output as untrustworthy (see orchestrator._run_single_tool's reset-to-empty-on-failure
    guard) -- so a scan whose only detection tool run FAILED produced no usable evidence about
    ANY location, and a `completed`/`partial` run did. This deliberately checks tool EXECUTION,
    not per-location results: the underlying tools (nuclei/nuclei-dast) do not emit a positive
    "checked and clean" record per URL, only positive findings -- so tool-level completion is
    the strongest real signal available that a detection pass actually happened."""
    from apps.api.scanner_engine.models import ToolRun
    from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY

    # Tools whose `capability` marks them as producers of VulnerabilityFinding objects (see
    # each runner's `capability` class attribute in tool_runners/*.py) -- today nuclei
    # ("vulnerability_detection") and nuclei-dast ("dast_fuzzing"). Derived from the live
    # registry rather than a hardcoded name list so a future third detection tool is picked up
    # automatically as long as it declares one of these capabilities; a tool that declares
    # neither (every current recon-only runner) is correctly excluded.
    detection_tools = {
        name for name, runner_cls in TOOL_REGISTRY.items()
        if getattr(runner_cls, "capability", "") in ("vulnerability_detection", "dast_fuzzing")
    }

    runs = list(
        await db.scalars(
            select(ToolRun).where(ToolRun.scan_id == scan_id, ToolRun.tool_name.in_(detection_tools))
        )
    )
    if not runs:
        return False
    return any(r.status in ("completed", "partial") for r in runs)


async def _scorable_locations(db: AsyncSession, project_id: uuid.UUID, issue_key: str) -> set[str]:
    """Every DISTINCT, currently-scorable location this issue has RIGHT NOW (no scan filter) --
    the reference set request_verification() snapshots as `baseline_locations`. Shares the
    identity/liveness adapter with `_live_locations` below (see its docstring)."""
    from apps.api.modules.vulnerabilities.models import Vulnerability

    rows = list(
        await db.scalars(select(Vulnerability).where(Vulnerability.project_id == project_id))
    )
    locations, _unlocated = _partition_by_issue(rows, issue_key)
    return locations


async def _live_locations(
    db: AsyncSession, project_id: uuid.UUID, issue_key: str, scan_id: uuid.UUID
) -> tuple[int, set[str]]:
    """How many DISTINCT locations of this issue the given scan still sees as live, and the
    location set itself.

    Identity and liveness both come from the canonical shared definitions -- scoring.issue_key
    and scoring.is_scorable -- so "is this issue still there?" means the same thing here as it
    does to the security score and the report. A finding whose status the scan has moved to
    `fixed` is not live; a re-detected one (`reopened`) is.

    Scoped to findings the scan actually touched (`last_seen_scan_id`), so an old finding the
    retest never revisited does not count as LIVE here -- whether that absence is legitimate
    (the issue is fixed) or a coverage gap (the retest never looked) is decided separately by
    `_retest_had_usable_detection_coverage` in complete_verification, not by this function."""
    from apps.api.modules.vulnerabilities.models import Vulnerability

    rows = list(
        await db.scalars(
            select(Vulnerability).where(
                Vulnerability.project_id == project_id,
                Vulnerability.last_seen_scan_id == scan_id,
            )
        )
    )
    locations, unlocated = _partition_by_issue(rows, issue_key)
    return len(locations) + unlocated, locations


def _partition_by_issue(rows: list, issue_key: str) -> tuple[set[str], int]:
    """Shared adapter: filter `rows` (Vulnerability ORM objects) to the ones belonging to
    `issue_key` and scorable, then split into (named locations, count of unlocated rows).
    scoring.issue_key / is_scorable read attribute names the ORM row does not carry
    (template_id, matched_at, final_risk_score), so this builds the small adapter object once
    per row rather than reimplementing either canonical function."""
    from apps.api.modules.reports.data import _parse_fingerprint
    from apps.api.modules.reports.scoring import is_scorable, issue_key as compute_issue_key

    locations: set[str] = set()
    unlocated = 0
    for v in rows:
        template_id, _matcher, matched_at = _parse_fingerprint(v.fingerprint)

        class _Row:
            pass

        row = _Row()
        row.template_id = template_id
        row.matched_at = matched_at
        row.title = v.title
        row.severity = v.severity
        row.status = v.status
        row.cvss_score = v.cvss_score
        row.category = v.category
        row.final_risk_score = None

        if compute_issue_key(row) != issue_key or not is_scorable(row):
            continue
        if matched_at:
            locations.add(matched_at)
        else:
            unlocated += 1
    return locations, unlocated


async def count_live_locations(
    db: AsyncSession, project_id: uuid.UUID, issue_key: str, scan_id: uuid.UUID
) -> int:
    """Back-compat wrapper preserving the pre-Finding-#3 public signature/behavior (tests and
    any external caller expecting an int). Prefer `_live_locations` internally, which also
    returns the location set the coverage check needs."""
    count, _locations = await _live_locations(db, project_id, issue_key, scan_id)
    return count


async def list_verification_requests(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, item_id: uuid.UUID
) -> list[VerificationRequest]:
    await get_item(db, workspace_id, project_id, item_id)
    return list(
        await db.scalars(
            select(VerificationRequest)
            .where(
                VerificationRequest.remediation_item_id == item_id,
                VerificationRequest.workspace_id == workspace_id,
            )
            .order_by(VerificationRequest.created_at)
        )
    )
