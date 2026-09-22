import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.projects.service import get_project
from apps.api.core.pagination import MAX_LIMIT, Pagination, paginate
from apps.api.modules.vulnerabilities.lineage import (
    MATCH_RULE_TEMPLATE_AND_LOCATION,
    find_ancestor,
    record_lineage,
    sticky_status_to_inherit,
)
from apps.api.modules.vulnerabilities.models import Vulnerability, VulnerabilityEvidence, VulnerabilityHistory
from apps.api.modules.vulnerabilities.taxonomy import (
    canonical_cwe,
    cwe_is_canonical,
    normalize_severity,
    severity_is_canonical,
)
from apps.api.scanner_engine.tool_runners.base import VulnerabilityFinding

# Nominal CVSS base scores by severity, used only when the tool doesn't report a
# score (so ranking still works). Not an AI estimate -- just a severity floor.
_SEVERITY_SCORE = {"info": 0.0, "low": 3.1, "medium": 5.5, "high": 7.5, "critical": 9.5}

# Statuses an analyst may set via the API. "reopened"/"open" are also reachable
# automatically by the engine on re-detection.
SETTABLE_STATUSES = {"open", "confirmed", "false_positive", "fixed", "accepted_risk"}
# Analyst decisions the engine must not silently override when a finding recurs.
_STICKY_STATUSES = {"false_positive", "accepted_risk"}

# --- Vulnerability status state machine ---------------------------------------------------
# Previously `set_status` accepted ANY value in SETTABLE_STATUSES from ANY current state, so a
# finding could jump `fixed -> fixed`, `false_positive -> fixed`, or `accepted_risk -> open`
# with no rule at all -- the status column was effectively free-form once the caller had
# `vulnerability:manage`. This encodes the legal transitions explicitly and rejects the rest.
#
# WHAT IS DELIBERATELY PRESERVED: the ENGINE path in ingest_finding is NOT routed through this
# table. `fixed -> reopened` on re-detection, and the sticky `false_positive`/`accepted_risk`
# behaviour, are scanner-owned lifecycle rules that must keep working exactly as before (see
# ingest_finding); this machine governs the HUMAN/API path only. That split is why `reopened`
# is a legal *source* state here but never a settable *target*.
#
# The rules, each of which is a real domain statement rather than a graph shape chosen for
# symmetry:
#   * open        -- the engine's initial state. An analyst may triage it anywhere.
#   * confirmed   -- triaged as real. May still be dismissed (false_positive), fixed, or
#                    accepted as risk; may fall back to `open` if triage is withdrawn.
#   * reopened    -- a regression the engine re-detected. Behaves exactly like `open`.
#   * fixed       -- remediated. May be re-opened by a human (`open`) when the fix is found
#                    wanting, or re-confirmed; may NOT jump straight to false_positive or
#                    accepted_risk, which would rewrite history about a finding already
#                    declared resolved.
#   * false_positive / accepted_risk -- sticky ANALYST decisions. Reversible only back to
#                    `open`/`confirmed` (i.e. "I was wrong, it is live again"); never
#                    directly to `fixed`, since something never present cannot be fixed and
#                    an accepted risk must be re-triaged before it can be called fixed.
# A no-op self-transition (X -> X) is rejected: it would append a misleading audit event and
# a status-change timestamp for a change that did not happen.
_LEGAL_STATUS_TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"confirmed", "false_positive", "fixed", "accepted_risk"}),
    "confirmed": frozenset({"open", "false_positive", "fixed", "accepted_risk"}),
    "reopened": frozenset({"open", "confirmed", "false_positive", "fixed", "accepted_risk"}),
    "fixed": frozenset({"open", "confirmed"}),
    "false_positive": frozenset({"open", "confirmed"}),
    "accepted_risk": frozenset({"open", "confirmed"}),
}


def legal_status_targets(current_status: str) -> frozenset[str]:
    """Which statuses may be set from `current_status` via the API. An UNKNOWN current status
    (legacy/hand-edited row) falls back to the full settable set rather than trapping the row
    in an unreachable state -- fail OPEN here is correct because the alternative is a finding
    no analyst can ever triage again, and the transition is still audited either way."""
    return _LEGAL_STATUS_TRANSITIONS.get(current_status, frozenset(SETTABLE_STATUSES))


async def _workspace_for_project(db: AsyncSession, project_id: uuid.UUID) -> uuid.UUID | None:
    """The project's owning workspace. Needed because remediation items are DIRECT
    workspace-scoped while the ingest path only carries a project_id. Returns None rather than
    raising if the project is unreachable -- the caller treats that as "no remediation
    bookkeeping to do", never as a reason to fail an ingest."""
    from apps.api.modules.projects.models import Project

    return await db.scalar(select(Project.workspace_id).where(Project.id == project_id))


def _issue_key_for(vuln) -> str:
    """The vulnerability's canonical issue identity.

    Delegates to reports.scoring.issue_key -- the ONE definition shared by the security score,
    the report groupings and the remediation items -- via a small adapter, because that
    function reads `template_id` while the ORM row stores the composite `fingerprint`. Parsing
    it here with the canonical `_parse_fingerprint` is exactly what schemas.py already does for
    the same reason."""
    from apps.api.modules.reports.data import _parse_fingerprint
    from apps.api.modules.reports.scoring import issue_key

    template_id, _matcher, _matched_at = _parse_fingerprint(vuln.fingerprint)

    class _Row:
        pass

    row = _Row()
    row.template_id = template_id
    row.title = vuln.title
    return issue_key(row)


def _parse_fingerprint_for_lineage(fingerprint: str) -> tuple[str | None, str | None, str | None]:
    """Deferred-import wrapper around reports.data._parse_fingerprint, matching the same
    cycle-avoidance pattern _issue_key_for already uses in this module (scanner ingest imports
    this module; reports imports remediation which imports this module -- a module-level import
    of reports.data here would create a cycle at scanner import time)."""
    from apps.api.modules.reports.data import _parse_fingerprint

    return _parse_fingerprint(fingerprint)


def _score_for(finding: VulnerabilityFinding) -> float | None:
    if finding.cvss_score is not None:
        return finding.cvss_score
    # DELIBERATELY NOT NORMALISED (Prompt A). The severity COLUMN is normalised at the ingest
    # boundary, but the CVSS floor is not: a severity the tool never actually stated must not
    # be turned into a numeric score. Feeding `normalize_severity` here would give an
    # unrecognised severity the `medium` floor of 5.5 -- a fabricated score attached to a
    # finding whose severity the tool did not express, which is exactly the "no invented
    # score" rule test_cvss_score_falls_back_to_severity_floor exists to enforce.
    # `None` is the honest answer and the report layer already renders it as "no score".
    return _SEVERITY_SCORE.get(finding.severity)


# The fields Prompt 13, Finding #4's history table tracks -- exactly the set ingest_finding's
# existing-row branch overwrites in place. Kept as one tuple so the "did content change"
# comparison and the snapshot construction below can never drift apart from each other.
_HISTORY_TRACKED_FIELDS = ("title", "description", "severity", "cvss_vector", "cvss_score")


def _content_changed(vuln: Vulnerability, finding: VulnerabilityFinding, new_score: float | None) -> bool:
    """Would applying `finding`'s values to `vuln` actually change any tracked field?
    Compared BEFORE the assignment happens, so a re-detection reporting byte-identical content
    (the common case: a scan re-confirms the same finding unchanged) appends no history row.

    Severity is compared in its NORMALISED form (Prompt A) because that is what the refresh
    branch actually assigns. Comparing the raw `finding.severity` against the already-normalised
    stored value would make any non-canonical severity look permanently changed, appending one
    spurious history row on EVERY rescan of that finding forever."""
    return (
        vuln.title != finding.title
        or vuln.description != finding.description
        or vuln.severity != normalize_severity(finding.severity)
        or vuln.cvss_vector != finding.cvss_vector
        or vuln.cvss_score != new_score
    )


async def _record_history(
    db: AsyncSession,
    vuln: Vulnerability,
    project_id: uuid.UUID,
    scan_id: uuid.UUID,
    tool_run_id: uuid.UUID,
    change_reason: str,
) -> None:
    """Append one immutable snapshot of `vuln`'s CURRENT field values. Called AFTER the fields
    are assigned onto `vuln` (both branches of ingest_finding), so this always records the
    state as of the scan that just produced it -- never the pre-update state, which the
    previous history row (if any) already captured."""
    db.add(
        VulnerabilityHistory(
            project_id=project_id,
            vulnerability_id=vuln.id,
            scan_id=scan_id,
            tool_run_id=tool_run_id,
            fingerprint=vuln.fingerprint,
            title=vuln.title,
            category=vuln.category,
            description=vuln.description,
            severity=vuln.severity,
            cvss_vector=vuln.cvss_vector,
            cvss_score=vuln.cvss_score,
            change_reason=change_reason,
        )
    )


async def ingest_finding(
    db: AsyncSession,
    project_id: uuid.UUID,
    scan_id: uuid.UUID,
    finding: VulnerabilityFinding,
    tool_run_id: uuid.UUID,
    evidence_id: uuid.UUID,
    asset_id: uuid.UUID | None = None,
) -> Vulnerability:
    """Dedupe a finding into the vulnerabilities table and link its evidence.

    New fingerprint -> create as `open`. Recurring fingerprint -> refresh
    metadata + last_seen, and if it had been marked `fixed`, flip to `reopened`
    (it came back). Analyst decisions (`false_positive`/`accepted_risk`) stick.
    Every ingest appends a vulnerability_evidence row (blueprint §1)."""
    # TAXONOMY BOUNDARY (Prompt A). Every write of `severity` below -- both the create branch
    # and the existing-row refresh -- uses this ONE normalised value, so the persisted column is
    # guaranteed to hold a member of `taxonomy.SEVERITIES`. Downstream consumers
    # (reports/data.py, dashboard/service.py, render.py, scoring) each had their own fallback
    # for an unrecognised severity and those fallbacks DISAGREED: the report relabelled it
    # `info` while the dashboard dropped it from the breakdown but still counted it in the
    # total. Normalising here makes those branches unreachable instead of inconsistently
    # reached. A tool reporting a clean severity is unaffected -- the value round-trips
    # unchanged.
    canonical_severity = normalize_severity(finding.severity)
    # Prompt 23: the CWE in `category` gets the same treatment as the severity above, at the
    # same boundary and for the same reason. `.strip().lower()` in the ATT&CK and compliance
    # catalogues fixes case but not the SEPARATOR, so `cwe_89` / `CWE 89` / `89` silently
    # returned no techniques and no controls while reports/narrative still resolved them --
    # consumers disagreeing invisibly about one finding. Canonicalising here makes those
    # lookups agree. A malformed or absent CWE becomes None: never guessed, never invented.
    canonical_category = canonical_cwe(finding.category)
    if finding.category and canonical_category is None:
        # The tool supplied something in the CWE slot that is not a CWE id. It is NOT written
        # to the taxonomy column (an unparseable id is not a weakness class), but it is also
        # not lost: the raw value stays in the finding metadata stored with its evidence, and
        # is logged verbatim here so an operator can see what the tool actually said.
        import logging

        logging.getLogger("mbs.scanner").warning(
            "vulnerability.cwe_unrecognized project=%s fingerprint=%s reported=%r",
            project_id, finding.fingerprint, finding.category,
        )
    elif not cwe_is_canonical(finding.category) and canonical_category is not None:
        import logging

        logging.getLogger("mbs.scanner").info(
            "vulnerability.cwe_normalized project=%s fingerprint=%s reported=%r stored=%r",
            project_id, finding.fingerprint, finding.category, canonical_category,
        )
    if not severity_is_canonical(finding.severity):
        # Never silent: the tool said something outside the vocabulary and an operator needs to
        # be able to find out. The ORIGINAL string is logged verbatim (and preserved in the
        # finding's own metadata, which is stored with its evidence), so normalising loses
        # nothing -- it only stops the unrecognised value from reaching the taxonomy column.
        import logging

        logging.getLogger("mbs.scanner").warning(
            "vulnerability.severity_normalized project=%s fingerprint=%s reported=%r stored=%r",
            project_id, finding.fingerprint, finding.severity, canonical_severity,
        )

    existing = await db.scalar(
        select(Vulnerability).where(
            Vulnerability.project_id == project_id, Vulnerability.fingerprint == finding.fingerprint
        )
    )

    if existing is None:
        vuln = Vulnerability(
            project_id=project_id,
            asset_id=asset_id,
            first_detected_scan_id=scan_id,
            last_seen_scan_id=scan_id,
            fingerprint=finding.fingerprint,
            title=finding.title,
            category=canonical_category,
            description=finding.description,
            severity=canonical_severity,
            cvss_vector=finding.cvss_vector,
            cvss_score=_score_for(finding),
            status="open",
        )
        db.add(vuln)
        await db.flush()

        # Content history (Prompt 13, Finding #4): the first snapshot for a brand-new
        # Vulnerability row is always written -- there is no "unchanged" case for a row that
        # didn't exist a moment ago.
        await _record_history(db, vuln, project_id, scan_id, tool_run_id, change_reason="created")

        # Fingerprint-drift lineage (Prompt 13, Finding #2). This fingerprint has never been
        # seen in this project before -- but it may still be the SAME logical issue as an
        # older, already-dismissed row if a deterministic ancestor can be found (same project,
        # same template_id, same normalized location). Best-effort: a lineage lookup/write
        # failure must never abort ingesting a real finding, mirroring the existing
        # reopen_for_regression best-effort guard immediately below.
        try:
            template_id, _matcher, matched_at = _parse_fingerprint_for_lineage(finding.fingerprint)
            ancestor = await find_ancestor(
                db, project_id, template_id, matched_at, exclude_fingerprint=finding.fingerprint
            )
            if ancestor is not None:
                inherited = sticky_status_to_inherit(ancestor.vulnerability.status)
                if inherited is not None:
                    # Copy ONLY the sticky decision -- title/description/severity/cvss on the
                    # new row stay the CURRENT detection's own data, exactly as a fresh `open`
                    # row would (mirrors the existing-row branch's "sticky stays, everything
                    # else refreshes" rule, applied here across a fingerprint change instead of
                    # within one).
                    vuln.status = inherited
                    vuln.status_justification = (
                        f"Inherited from a prior finding with a different fingerprint "
                        f"(vulnerability {ancestor.vulnerability.id}), deterministically "
                        f"matched by template + normalized location. Original justification: "
                        f"{ancestor.vulnerability.status_justification or '(none recorded)'}"
                    )
                    vuln.status_changed_by = ancestor.vulnerability.status_changed_by
                    vuln.status_changed_at = ancestor.vulnerability.status_changed_at
                await record_lineage(
                    db,
                    project_id=project_id,
                    old_vulnerability_id=ancestor.vulnerability.id,
                    new_vulnerability_id=vuln.id,
                    match_rule=MATCH_RULE_TEMPLATE_AND_LOCATION,
                    matched_location=ancestor.matched_location,
                    inherited_status=inherited,
                )
                await db.flush()
        except Exception:  # noqa: BLE001 -- lineage bookkeeping must never abort a real finding
            import logging

            logging.getLogger("mbs.remediation").warning(
                "vulnerability.lineage_lookup_failed vuln=%s", vuln.id, exc_info=True
            )
    else:
        vuln = existing
        new_score = _score_for(finding)
        # Compared BEFORE assignment (Prompt 13, Finding #4) -- see _content_changed's
        # docstring for why order matters here.
        content_changed = _content_changed(vuln, finding, new_score)
        vuln.last_seen_scan_id = scan_id
        vuln.title = finding.title
        vuln.description = finding.description
        vuln.severity = canonical_severity
        vuln.cvss_vector = finding.cvss_vector
        vuln.cvss_score = new_score
        if content_changed:
            # A re-detection that actually changed something the operator can see (severity
            # drift, a rewritten description, ...) gets its own history row so that change is
            # reconstructable later. A re-detection reporting byte-identical content -- the
            # common case: a scan re-confirms an already-known finding unchanged -- appends
            # nothing, so this table doesn't grow one row per scan for every stable finding.
            await _record_history(db, vuln, project_id, scan_id, tool_run_id, change_reason="observed")
        if asset_id is not None:
            vuln.asset_id = asset_id
        if vuln.status == "fixed":
            vuln.status = "reopened"  # regression: it's back
            # KEEP THE REMEDIATION WORK ITEM IN STEP with the finding. Without this the item
            # would sit at `verified`/`closed` while the issue is demonstrably live again, and
            # the (project_id, issue_key) unique constraint forbids creating a second item for
            # it -- so the regression would have no workflow representation at all.
            #
            # Deferred import: vulnerabilities.service is imported by the scanner ingest path,
            # and remediation.service imports the reporting layer, so a module-level import
            # here would create a cycle at scanner import time.
            #
            # Best-effort by design: this is the SCANNER's ingest path, and a remediation
            # bookkeeping failure must never abort ingesting a real finding. The vulnerability
            # lifecycle itself (the `reopened` flip above) is unconditional and already
            # applied, which is the part that must not be lost.
            try:
                from apps.api.modules.remediation.service import reopen_for_regression

                workspace_id = await _workspace_for_project(db, project_id)
                if workspace_id is not None:
                    await reopen_for_regression(
                        db, workspace_id, project_id, _issue_key_for(vuln)
                    )
            except Exception:  # noqa: BLE001 -- see above
                import logging

                logging.getLogger("mbs.remediation").warning(
                    "remediation.regression_link_failed vuln=%s", vuln.id, exc_info=True
                )
        # open/confirmed/reopened stay; sticky analyst decisions stay untouched.

    # IDEMPOTENT link. The PK is (vulnerability_id, evidence_id), and a single tool_run
    # produces ONE evidence row shared by every finding it yields -- so two findings in the
    # same run that dedupe to the SAME vulnerability (same fingerprint) both try to link
    # (this vuln, this evidence). A plain INSERT raised a 1062 duplicate-key IntegrityError,
    # which poisoned the whole scan's Session and crashed finalization (observed against
    # nuclei-dast, which re-hits one template on one URL while fuzzing params). Insert-or-
    # ignore instead: the pair is already linked, which is exactly the desired end state.
    #
    # ON DUPLICATE KEY (not SELECT-then-INSERT) so it is atomic and race-free -- the database
    # enforces uniqueness in one statement. `tool_run_id` is preserved: a duplicate keeps the
    # FIRST run that cited this evidence (the update is a no-op on the PK columns), which is
    # correct since the shared evidence row belongs to this one tool_run anyway. Mirrors the
    # do-nothing-on-conflict idiom in attack/service.py + compliance/service.py.
    stmt = mysql_insert(VulnerabilityEvidence.__table__).values(
        vulnerability_id=vuln.id, evidence_id=evidence_id, tool_run_id=tool_run_id
    )
    stmt = stmt.on_duplicate_key_update(tool_run_id=VulnerabilityEvidence.tool_run_id)
    await db.execute(stmt)
    await db.flush()
    return vuln


async def list_vulnerabilities(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    severity: str | None = None,
    status_filter: str | None = None,
    page: Pagination | None = None,
) -> tuple[list[Vulnerability], int]:
    # AUDIT-010: verify the project EXISTS IN THIS WORKSPACE before listing.
    #
    # The query below is correctly scoped, so a cross-tenant project id never leaked data --
    # it returned `200 []`. But `200 []` and `404` are different answers to the same
    # question, and this API already answers it with 404 everywhere else (the single-resource
    # getters, and the reports/targets list endpoints, which call get_project for exactly
    # this reason). An empty 200 says "this project is yours and has nothing"; the truth is
    # "this project is not yours". Beyond the inconsistency, it is a weak existence oracle:
    # a caller could tell a real foreign project id from a random UUID if the two ever
    # diverged, and it hides genuine client bugs behind a success response.
    await get_project(db, workspace_id, project_id)
    query = select(Vulnerability).where(Vulnerability.project_id == project_id)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if status_filter:
        query = query.where(Vulnerability.status == status_filter)
    # Phase 0 MySQL cutover: was `.desc().nullslast()`. Postgres's DESC default is NULLS
    # FIRST, so nullslast() was needed there to push NULLs to the end. MySQL/MariaDB treat
    # NULL as the lowest possible value for ordering, so a plain DESC already puts NULLs
    # last -- verified directly against MariaDB. `NULLS LAST` syntax itself isn't supported
    # by MariaDB at all (MySQL 8.0.13+ added it, but this codebase targets both), so this
    # isn't just simplification, it's required for portability.
    query = query.order_by(Vulnerability.cvss_score.desc(), Vulnerability.created_at, Vulnerability.id)
    return await paginate(db, query, page or Pagination(limit=MAX_LIMIT, offset=0))


async def get_vulnerability(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, vuln_id: uuid.UUID
) -> Vulnerability:
    vuln = await db.scalar(
        select(Vulnerability).where(Vulnerability.id == vuln_id, Vulnerability.project_id == project_id)
    )
    if vuln is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Vulnerability not found")
    return vuln


async def set_status(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    vuln_id: uuid.UUID,
    new_status: str,
    justification: str,
    changed_by: uuid.UUID,
) -> Vulnerability:
    if new_status not in SETTABLE_STATUSES:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Status must be one of: {', '.join(sorted(SETTABLE_STATUSES))}",
        )
    vuln = await get_vulnerability(db, workspace_id, project_id, vuln_id)

    # State-machine gate. Checked AFTER the vulnerability is resolved (so a caller cannot
    # probe the existence of another workspace's finding through the error shape) and BEFORE
    # anything is written, so an illegal transition leaves no audit event and no timestamp.
    allowed = legal_status_targets(vuln.status)
    if new_status not in allowed:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Illegal status transition '{vuln.status}' -> '{new_status}'. "
            f"Allowed from '{vuln.status}': {', '.join(sorted(allowed)) or 'none'}.",
        )

    previous_status = vuln.status
    vuln.status = new_status
    vuln.status_justification = justification
    vuln.status_changed_by = changed_by
    vuln.status_changed_at = datetime.now(timezone.utc)

    from apps.api.modules.audit import service as audit

    await audit.record(
        db, workspace_id, changed_by, "vulnerability.status_changed", "vulnerability",
        resource_id=vuln_id, detail=f"{previous_status} -> {new_status}: {justification}",
    )
    await db.commit()
    await db.refresh(vuln)
    return vuln
