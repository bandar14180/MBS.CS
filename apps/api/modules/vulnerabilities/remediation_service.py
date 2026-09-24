"""The remediation PRODUCER: deterministic guidance written during ingestion.

THE GAP THIS CLOSES
-------------------
`remediations` held zero rows after a 698-finding scan. Everything around the table existed
-- the model, the migration, and the report's read-side join in `reports/data.py`, which
silently degrades to "no remediation available" for every finding. What did not exist was
anything that WROTE a row during a scan. The only writer, `ai_service.generate_remediation`,
is an on-demand HTTP endpoint: one call per vulnerability, requiring a configured AI
provider. A scan therefore always completed with no guidance at all.

WHERE THIS SITS, AND WHY
------------------------
In the domain/pipeline layer, called from `ingest_vulnerability_findings` alongside
`upsert_risk_score`, `sync_mappings` and `sync_attack_mappings` -- the same boundary the
other per-finding enrichments already use. Deliberately NOT in the renderer: guidance
generated at render time would exist only inside a PDF, could not be queried, reviewed,
tracked or exported, and would be recomputed differently by each consumer. Persisting it at
ingest makes the report a reader of stored data rather than a producer of it.

PROPERTIES
----------
Deterministic  -- a pure catalogue lookup keyed on the finding's canonical identity. No model,
                  no network, no clock, no randomness: the same finding always yields the same
                  guidance, so two runs cannot disagree.
Idempotent     -- ON DUPLICATE KEY UPDATE against `uq_remediations_vulnerability`. Re-running
                  a scan rewrites the row in place; it never duplicates and never raises.
Finding-aware  -- resolved from the template id first, then the canonical CWE (see
                  remediation_catalog for why CWE alone is insufficient here).
Duplicate-safe -- one row per vulnerability, enforced by the unique constraint rather than by
                  a read-then-write race.

WHAT IT WILL NOT DO
-------------------
It writes NOTHING for a finding type with no reviewed entry. An unsupported type getting no
row is a truthful "we have not written guidance for this", and it stays distinguishable from
a supported type. Emitting filler ("Fix the vulnerability.") would make the two
indistinguishable and put MBS's name on advice nobody reviewed.

It also never overwrites HUMAN-authored or AI-authored guidance. `generated_by` records the
provenance, and this producer only writes rows it owns (`generated_by='catalog'`), so an
analyst's edit or an AI generation made through the existing endpoint survives a re-scan.
"""

from __future__ import annotations

import logging
import uuid
from typing import cast

from sqlalchemy import Table, select
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.vulnerabilities.remediation_catalog import guidance_for
from apps.api.modules.vulnerabilities.remediation_models import Remediation

logger = logging.getLogger("mbs.remediation")

# Provenance marker for rows THIS producer owns. The column already carried "ai" | "human";
# a third value distinguishes deterministic catalogue output from both, which is what lets the
# producer refresh its own rows on a re-scan without ever clobbering an analyst's edit.
GENERATED_BY_CATALOG = "catalog"

# Bumped when the catalogue's wording or structure changes materially, so a stored row can be
# traced to the revision that produced it -- the same role `prompt_version` plays for AI rows.
CATALOG_VERSION = "catalog-v1"


def _template_id(fingerprint: str | None) -> str | None:
    """Nuclei fingerprints are `template-id|matcher|matched-at`; the first segment is the
    template. Returns None when the fingerprint carries no delimiter (a non-nuclei finding),
    in which case resolution falls through to the CWE."""
    if not fingerprint or "|" not in fingerprint:
        return None
    head = fingerprint.split("|", 1)[0].strip()
    return head or None


async def sync_remediation(
    db: AsyncSession,
    vulnerability_id: uuid.UUID,
    fingerprint: str | None,
    category: str | None,
) -> bool:
    """Write deterministic remediation guidance for one finding. Returns True if a row was
    written or refreshed, False if the finding's type has no reviewed guidance.

    Safe to call on every ingest: the write is an upsert keyed on the vulnerability, so a
    recurring finding refreshes its guidance rather than accumulating rows.
    """
    guidance = guidance_for(_template_id(fingerprint), category)
    if guidance is None:
        # Unsupported type: no row, by policy. Logged at debug so the catalogue's coverage can
        # be measured from a real run without making an ordinary scan noisy.
        logger.debug(
            "remediation.no_guidance vuln=%s template=%s category=%s",
            vulnerability_id, _template_id(fingerprint), category,
        )
        return False

    # Never overwrite guidance this producer does not own. A human edit or an AI generation
    # made through the existing endpoint is authoritative over the catalogue, so a re-scan
    # must leave it alone. Checked explicitly rather than folded into the upsert because
    # ON DUPLICATE KEY UPDATE cannot express "only if the existing row is mine".
    existing = await db.scalar(
        select(Remediation.generated_by).where(Remediation.vulnerability_id == vulnerability_id)
    )
    if existing is not None and existing != GENERATED_BY_CATALOG:
        logger.debug(
            "remediation.preserved vuln=%s generated_by=%s", vulnerability_id, existing
        )
        return False

    steps = list(guidance.steps)
    references = guidance.reference_dicts()
    # `__table__` is typed as the broad `FromClause` on the declarative base, while
    # `mysql_insert` wants a `TableClause`. The runtime object IS a Table; the cast narrows it
    # for the type checker rather than suppressing the whole module, which is how the other
    # upsert call sites avoid this (they are on the per-module override list in pyproject).
    table = cast(Table, Remediation.__table__)
    stmt = mysql_insert(table).values(
        vulnerability_id=vulnerability_id,
        summary=guidance.summary,
        steps=steps,
        reference_links=references,
        generated_by=GENERATED_BY_CATALOG,
        model_version=None,
        prompt_version=CATALOG_VERSION,
    )
    # Refresh in place so a catalogue revision reaches findings that already have a row.
    stmt = stmt.on_duplicate_key_update(
        summary=guidance.summary,
        steps=steps,
        reference_links=references,
        generated_by=GENERATED_BY_CATALOG,
        prompt_version=CATALOG_VERSION,
    )
    await db.execute(stmt)
    return True


async def get_remediation_row(
    db: AsyncSession, vulnerability_id: uuid.UUID
) -> Remediation | None:
    """The stored remediation for a vulnerability, or None. Read-only helper for callers that
    want the row without the API layer's tenancy/404 behaviour."""
    return await db.scalar(
        select(Remediation).where(Remediation.vulnerability_id == vulnerability_id)
    )
