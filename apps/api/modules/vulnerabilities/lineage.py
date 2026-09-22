"""Deterministic fingerprint-drift lineage (Prompt 13, Finding #2).

PROBLEM. `Vulnerability` identity is `(project_id, fingerprint)`. `ingest_finding`'s only
sticky-status preservation path is its existing-row branch, reached ONLY when the incoming
finding's fingerprint is byte-identical to an already-persisted row's. If the fingerprint
changes for what is really the same logical issue -- Finding #1's normalization landing,
a nuclei template rename, a matcher-name change between tool releases -- `ingest_finding`
takes the new-row branch and creates a fresh `status="open"` Vulnerability with no relationship
to the old, possibly-dismissed row. An analyst's `false_positive`/`accepted_risk` verdict is
then silently bypassed.

WHAT THIS MODULE DOES. `find_ancestor` is called ONLY on the new-row path (an existing exact
fingerprint match never reaches here) and looks for AT MOST ONE prior vulnerability in the
SAME project that is deterministically the same real-world issue:

    same project_id
        AND
    same parsed template_id (the tool's own identity for "this is the same check")
        AND
    normalize_location(candidate.matched_at) == normalize_location(new.matched_at)

Every one of those three conditions must hold exactly; there is no scoring, no threshold, no
"close enough" comparator. If more than one distinct prior fingerprint satisfies all three
(genuinely ambiguous -- e.g. the location normalizes the same but two different historical
fingerprints exist for it, such as a matcher rename AND a location rewrite both having
happened), NO ancestor is returned: an ambiguous candidate must never inherit a decision (see
test_vulnerability_lineage.py's ambiguous-candidate tests). Matching is intentionally narrow:
different templates, different projects, or locations that remain distinct after normalization
are never candidates at all, by construction of the query itself (§ below).

WHAT GETS INHERITED. Only a STICKY status (`false_positive`/`accepted_risk`) is copied onto the
new row, and only that: title/description/severity/cvss on the new row keep coming from the
CURRENT finding (the new detection's own data), exactly as a fresh `open` row would. This
mirrors the existing-row branch's own rule (`vulnerabilities/service.py`: "open/confirmed/
reopened stay; sticky analyst decisions stay untouched") -- here applied across a fingerprint
change instead of within one. An ancestor whose status is `open`/`confirmed`/`fixed`/`reopened`
is still recorded as a `VulnerabilityLineage` row (the relationship itself is real and worth
keeping auditable), but `inherited_status` on that row is NULL and nothing is copied onto the
new Vulnerability.

IDEMPOTENCY. `find_ancestor` is only ever invoked from the create branch of `ingest_finding`,
which by construction runs once per (project_id, fingerprint) -- a second ingest of the same
finding hits the existing-row branch instead and never calls this module again. Once a lineage
row exists for a `new_vulnerability_id` the unique constraint on that column makes a second
insert for the same new row impossible even under concurrent ingestion (the second writer's
INSERT would violate the UNIQUE constraint; see `record_lineage`, which uses INSERT IGNORE
semantics for exactly this race)."""
from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.vulnerabilities.models import Vulnerability, VulnerabilityLineage
from apps.api.scanner_engine.location_normalize import normalize_location

MATCH_RULE_TEMPLATE_AND_LOCATION = "template_id+normalized_location"

# Statuses eligible for inheritance across a fingerprint change. Mirrors
# vulnerabilities.service._STICKY_STATUSES exactly -- imported lazily inside the function
# below to avoid a circular import (service.py will import this module).
_STICKY_STATUSES = frozenset({"false_positive", "accepted_risk"})


@dataclass(frozen=True)
class Ancestor:
    """A single, deterministic prior Vulnerability this new finding is linked to."""

    vulnerability: Vulnerability
    matched_location: str | None


async def find_ancestor(
    db: AsyncSession,
    project_id: uuid.UUID,
    template_id: str | None,
    matched_at: str | None,
    exclude_fingerprint: str,
) -> Ancestor | None:
    """Find the one prior Vulnerability in `project_id` that is deterministically the same
    logical issue as a NEW finding whose fingerprint does not exactly match anything on file.

    Returns None (no link) whenever the match is anything less than certain -- including the
    "more than one distinct candidate" case, which means the correlation is ambiguous and must
    not silently pick a winner. `exclude_fingerprint` is the new finding's OWN fingerprint,
    excluded so this can never "find" a row that is actually the exact match (that path is
    handled entirely by ingest_finding's existing-row branch and never reaches this function)."""
    if not template_id or not matched_at:
        return None

    normalized_new = normalize_location(matched_at)
    if not normalized_new:
        return None

    # Every OTHER vulnerability in this same project. Deliberately not filtered by template_id
    # in SQL (fingerprint's structure -- `template_id|matcher|matched_at` -- is an ingestion
    # convention, not a queryable column), so template_id/matched_at are parsed in Python from
    # each candidate's stored fingerprint. Project size here is bounded by one project's
    # vulnerability count, not the whole table.
    from apps.api.modules.reports.data import _parse_fingerprint  # local import: avoid cycle

    candidates = (
        await db.scalars(
            select(Vulnerability).where(
                Vulnerability.project_id == project_id,
                Vulnerability.fingerprint != exclude_fingerprint,
            )
        )
    ).all()

    matches: list[Vulnerability] = []
    matched_location: str | None = None
    for candidate in candidates:
        cand_template, _cand_matcher, cand_matched_at = _parse_fingerprint(candidate.fingerprint)
        if cand_template != template_id:
            continue
        cand_normalized = normalize_location(cand_matched_at)
        if not cand_normalized or cand_normalized != normalized_new:
            continue
        matches.append(candidate)
        matched_location = cand_normalized

    if len(matches) != 1:
        # Zero candidates: nothing to link. More than one: ambiguous -- refuse to guess which
        # one is the "real" ancestor rather than silently picking the first/newest/etc.
        return None

    return Ancestor(vulnerability=matches[0], matched_location=matched_location)


async def record_lineage(
    db: AsyncSession,
    project_id: uuid.UUID,
    old_vulnerability_id: uuid.UUID,
    new_vulnerability_id: uuid.UUID,
    match_rule: str,
    matched_location: str | None,
    inherited_status: str | None,
) -> None:
    """Persist the lineage link. INSERT-IGNORE on the (new_vulnerability_id) unique key: a
    concurrent duplicate ingest racing to create the same new row would, if both tried to link
    lineage, simply keep the first writer -- never raise, never double-link, matching the same
    idempotency idiom already used by the (vulnerability_id, evidence_id) link in
    ingest_finding."""
    stmt = mysql_insert(VulnerabilityLineage.__table__).values(
        id=uuid.uuid4(),
        project_id=project_id,
        old_vulnerability_id=old_vulnerability_id,
        new_vulnerability_id=new_vulnerability_id,
        match_rule=match_rule,
        matched_location=matched_location,
        inherited_status=inherited_status,
    )
    stmt = stmt.on_duplicate_key_update(new_vulnerability_id=VulnerabilityLineage.new_vulnerability_id)
    await db.execute(stmt)


def sticky_status_to_inherit(ancestor_status: str) -> str | None:
    """The status to copy onto a new row, or None if the ancestor's status is not sticky."""
    return ancestor_status if ancestor_status in _STICKY_STATUSES else None
