"""Explicit, on-demand re-verification of stored Evidence against its recorded checksum
(Prompt 13, Finding #9).

WHY THIS EXISTS. `Evidence.checksum` is a genuine SHA-256 of the actual bytes, computed once at
write time (evidence_store.store_raw_output/store_screenshot). It was never re-verified against
the stored object afterward -- a checksum that is only ever WRITTEN, never READ BACK AND
COMPARED, cannot detect storage-layer corruption, an accidental overwrite, or tampering between
write and read time. This module closes that gap with an explicit, auditable check.

WHY NOT ON EVERY READ / EVERY SCAN. Re-hashing an artifact means downloading and hashing its
full bytes -- for raw tool output that can be substantial, and doing it on the hot path of
ordinary scan execution or evidence display would make routine operations pay a real I/O and
CPU cost for a check that is not needed on every access. This is therefore a SEPARATE, callable
operation -- `verify_evidence`/`verify_evidence_batch` -- meant to be invoked from an explicit
integrity audit (a CLI command, an on-demand API call, or a periodic job the operator chooses
to schedule), never automatically inline with scan/report generation.

RESULT SEMANTICS. Four distinct outcomes, never collapsed into a bare pass/fail boolean and
NEVER silently treated as success on ambiguity:
  * PASS              -- the object was fetched and its SHA-256 matches the recorded checksum.
  * INTEGRITY_FAILURE -- the object was fetched but its SHA-256 does NOT match. This is the
                         one outcome that means "the stored bytes are not what was recorded."
  * MISSING_OBJECT     -- the storage backend could not produce the object at all (deleted,
                         moved, or a transient backend failure indistinguishable from either
                         without more context). Reported distinctly from INTEGRITY_FAILURE:
                         "cannot find it" and "found it corrupted" are different facts that
                         call for different operator responses.
  * NO_CHECKSUM        -- a legacy row with no checksum recorded (Evidence.checksum is NOT
                         NULL in the schema, but a placeholder/empty value from a very old
                         migration path is handled defensively rather than crashing).

Every result is recorded via the existing audit trail (apps.api.modules.audit.service.record)
so a check's outcome is itself durable and auditable, not merely a transient return value the
caller might discard."""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from enum import Enum

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.scanner_engine.models import Evidence


class IntegrityResult(str, Enum):
    PASS = "pass"
    INTEGRITY_FAILURE = "integrity_failure"
    MISSING_OBJECT = "missing_object"
    NO_CHECKSUM = "no_checksum"


@dataclass(frozen=True)
class EvidenceIntegrityCheck:
    evidence_id: uuid.UUID
    result: IntegrityResult
    recorded_checksum: str | None
    actual_checksum: str | None  # None when the object could not be fetched at all


def _parse_storage_uri(storage_uri: str) -> tuple[str, str] | None:
    """`s3://bucket/key` -> (bucket, key). None for a non-s3 URI (e.g. the
    `unavailable://...` sentinel written when evidence storage itself failed at ingest time --
    there is no real object to check, so this is reported as MISSING_OBJECT by the caller, not
    a parse error)."""
    if not storage_uri or not storage_uri.startswith("s3://"):
        return None
    rest = storage_uri[len("s3://") :]
    if "/" not in rest:
        return None
    bucket, key = rest.split("/", 1)
    if not bucket or not key:
        return None
    return bucket, key


async def verify_evidence(db: AsyncSession, evidence_id: uuid.UUID) -> EvidenceIntegrityCheck:
    """Fetch one Evidence row's stored object, re-hash it, and compare against the recorded
    checksum. Never raises for an ordinary integrity problem (a mismatch or a missing object is
    a RESULT, not an exception) -- only a genuinely unexpected condition (e.g. the evidence row
    itself does not exist) raises, since that is a caller error, not an integrity finding."""
    evidence = await db.scalar(select(Evidence).where(Evidence.id == evidence_id))
    if evidence is None:
        raise ValueError(f"no such Evidence row: {evidence_id}")

    if not evidence.checksum:
        return EvidenceIntegrityCheck(
            evidence_id=evidence_id, result=IntegrityResult.NO_CHECKSUM,
            recorded_checksum=None, actual_checksum=None,
        )

    parsed = _parse_storage_uri(evidence.storage_uri)
    if parsed is None:
        # Not a real, fetchable object (e.g. the `unavailable://...` sentinel written when
        # evidence storage itself failed at ingest time) -- there is nothing to re-hash.
        return EvidenceIntegrityCheck(
            evidence_id=evidence_id, result=IntegrityResult.MISSING_OBJECT,
            recorded_checksum=evidence.checksum, actual_checksum=None,
        )
    bucket, key = parsed

    from apps.api.scanner_engine.storage_provider import get_storage_provider

    try:
        content = get_storage_provider(bucket).get(key)
    except Exception:  # noqa: BLE001 -- ANY fetch failure (missing key, backend error,
        # network) is reported as MISSING_OBJECT, never silently treated as success and never
        # allowed to propagate as an unhandled exception out of an integrity CHECK.
        return EvidenceIntegrityCheck(
            evidence_id=evidence_id, result=IntegrityResult.MISSING_OBJECT,
            recorded_checksum=evidence.checksum, actual_checksum=None,
        )

    actual = hashlib.sha256(content).hexdigest()
    result = IntegrityResult.PASS if actual == evidence.checksum else IntegrityResult.INTEGRITY_FAILURE
    return EvidenceIntegrityCheck(
        evidence_id=evidence_id, result=result,
        recorded_checksum=evidence.checksum, actual_checksum=actual,
    )


async def verify_evidence_and_record(
    db: AsyncSession, workspace_id: uuid.UUID, evidence_id: uuid.UUID, actor_user_id: uuid.UUID | None
) -> EvidenceIntegrityCheck:
    """verify_evidence, plus a durable audit trail entry for the outcome. Does not raise on an
    audit-write failure -- the CHECK result is the primary deliverable; if the audit write
    itself fails, the caller still gets a correct, honest EvidenceIntegrityCheck back (no
    mismatch is ever swallowed by a logging problem)."""
    check = await verify_evidence(db, evidence_id)

    # Prompt 33: emit the outcome BEFORE the audit write, and outside its try/except. The audit
    # row is the durable record and the metric is the operational signal; an audit-write
    # failure must not also lose the signal that an INTEGRITY_FAILURE was observed. The label
    # is the enum's own value -- a closed set, carrying no evidence id, tenant or URI.
    from apps.api.core.observability import record_evidence_integrity

    record_evidence_integrity(check.result.value)

    try:
        from apps.api.modules.audit import service as audit

        await audit.record(
            db, workspace_id, actor_user_id, "evidence.integrity_checked", "evidence",
            resource_id=evidence_id,
            detail=(
                f"result={check.result.value} "
                f"recorded={check.recorded_checksum or 'none'} "
                f"actual={check.actual_checksum or 'unavailable'}"
            ),
            # Prompt 34: an integrity check that did not PASS is an audit FAILURE outcome --
            # both INTEGRITY_FAILURE (checksum mismatch) and MISSING_OBJECT (evidence gone)
            # mean the evidence could not be affirmed, and neither may read as success.
            outcome=(
                audit.OUTCOME_SUCCESS
                if check.result is IntegrityResult.PASS
                else audit.OUTCOME_FAILURE
            ),
        )
        await db.commit()
    except Exception:  # noqa: BLE001 -- the check result must survive an audit-write failure
        import logging

        logging.getLogger("mbs.evidence").warning(
            "evidence.integrity_audit_write_failed evidence=%s", evidence_id, exc_info=True
        )

    return check


async def verify_evidence_batch(
    db: AsyncSession, workspace_id: uuid.UUID, evidence_ids: list[uuid.UUID],
    actor_user_id: uuid.UUID | None,
) -> list[EvidenceIntegrityCheck]:
    """Check several Evidence rows in one call (e.g. every artifact for one vulnerability, or
    a scheduled sweep's batch). Each row is checked and recorded independently -- one failure
    (a genuinely corrupt object, or a fetch error) never stops the remaining checks in the
    batch from running, so a batch always returns a result for every id given."""
    results: list[EvidenceIntegrityCheck] = []
    for evidence_id in evidence_ids:
        try:
            results.append(await verify_evidence_and_record(db, workspace_id, evidence_id, actor_user_id))
        except ValueError:
            # A caller-supplied id that does not correspond to a real Evidence row -- surfaced
            # as an explicit, non-PASS result rather than silently dropped from the batch.
            results.append(EvidenceIntegrityCheck(
                evidence_id=evidence_id, result=IntegrityResult.MISSING_OBJECT,
                recorded_checksum=None, actual_checksum=None,
            ))
    return results
