"""Surfaces the report layer's evidence-confidence classification alongside a RemediationItem's
workflow status (Prompt 13, Finding #6).

THE PROBLEM THIS CLOSES
------------------------
Two independent systems both use language like "verified", answering two DIFFERENT questions:

  * `RemediationItem.status == "verified"` / `VerificationRequest.result == "passed"`
    (remediation/verification.py) -- "a REAL RETEST scan did not re-detect this issue at any
    of its known locations". This is a statement about ABSENCE of re-detection.

  * `reports.verification.classify_verification_row(...)` -- "does the evidence captured for
    the ORIGINAL detection (screenshots, response excerpts) corroborate that it was a genuine,
    specific, exploitable condition, as opposed to a generic/inferred pattern match". This is a
    statement about the QUALITY of the original detection's evidence.

Before this module, a client reading `GET .../remediation/{id}` saw ONLY the workflow status --
`"verified"` -- with no way to know whether the underlying finding's evidence-confidence
classification was VERIFIED, PARTIALLY_VERIFIED, or UNVERIFIED. This is the concrete surface
where the two meanings of "verified" could be conflated: a workflow-verified item whose
original detection evidence is weak/generic renders identically to one whose evidence is
strong, unless something makes the distinction visible.

THE FIX (kept deliberately conservative, per design decision -- no hard gate)
-------------------------------------------------------------------------------
This does NOT change what `RemediationItem.status` means, does not gate the transition to
`verified`, and does not alter `reports.verification`'s classifier. It ADDS a read-only,
best-effort `evidence_confidence` block to the item's API representation, computed from the
item's REPRESENTATIVE vulnerability's OWN evidence (the same artifacts `reports.verification`
already classifies for the Technical Report) -- so a client can see BOTH facts side by side and
is never left inferring evidence strength from workflow status alone.

WHY NOT A HARD GATE. Blocking `complete_verification` on evidence-confidence would conflate two
independently-legitimate signals: a retest-based PASS is real proof the issue is gone RIGHT
NOW, regardless of how strong the ORIGINAL detection's evidence was. Requiring strong original
evidence before allowing a retest-verified PASS would make cleanly-fixed issues un-verifiable
whenever the original detection happened to be a generic template match -- punishing exactly
the cases where verification-by-retest is most valuable. Exposing both signals, explicitly and
un-conflated, is the "safest design" this Prompt's own instructions call out as acceptable.

WHY THIS IS BEST-EFFORT. An item's `vulnerability_id` is nullable (the representative
vulnerability can be retention-swept out from under it; see RemediationItem's own docstring) --
absent representative or absent evidence renders as `None`, never fabricated."""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.remediation.models import RemediationItem


async def evidence_confidence_for_item(db: AsyncSession, item: RemediationItem) -> dict | None:
    """The report layer's (verification_state, confidence) classification for `item`'s
    representative vulnerability, or None if there is no representative or no evidence to
    classify from. Returns a plain dict (not a Pydantic model) so the router can splat it
    directly into the response payload alongside the item's own fields."""
    if item.vulnerability_id is None:
        return None

    from apps.api.modules.reports.data import _parse_fingerprint
    from apps.api.modules.reports.verification import classify_verification_row
    from apps.api.modules.vulnerabilities.models import Vulnerability, VulnerabilityEvidence
    from apps.api.scanner_engine.models import Evidence

    vuln = await db.scalar(select(Vulnerability).where(Vulnerability.id == item.vulnerability_id))
    if vuln is None:
        return None

    evidence_rows = (
        await db.execute(
            select(Evidence.evidence_type, Evidence.storage_uri, Evidence.checksum)
            .join(VulnerabilityEvidence, VulnerabilityEvidence.evidence_id == Evidence.id)
            .where(VulnerabilityEvidence.vulnerability_id == vuln.id)
        )
    ).all()

    screenshots: list[tuple[str, str]] = []
    evidence_uris: list[str] = []
    for etype, uri, checksum in evidence_rows:
        if etype == "screenshot":
            screenshots.append((uri, checksum))
        else:
            evidence_uris.append(uri)

    template_id, matcher_name, _matched_at = _parse_fingerprint(vuln.fingerprint)

    class _Row:
        pass

    row = _Row()
    row.template_id = template_id
    row.matcher_name = matcher_name
    row.evidence_uris = evidence_uris
    row.screenshots = screenshots
    row.classification = None  # classification.py's derived label; not needed for this call
    row.cve = None

    verification, confidence = classify_verification_row(row)
    return {
        "vulnerability_id": vuln.id,
        "verification": verification,
        "confidence": confidence,
    }
