"""Remediation proof: upload, storage, and immutable linkage.

REUSES the ONE evidence store (scanner_engine.models.Evidence + the S3 evidence bucket). The
only new pieces are a workspace-scoped object key and a join row -- there is no second
artifact table, no second checksum scheme, and no second bucket.

WHAT AN UPLOADED ARTIFACT IS AND IS NOT
---------------------------------------
An uploaded file is PROOF OF WORK ("here is the patch, the config diff, the change ticket"),
recorded with an uploader and a timestamp so a human decision is attributable. It is NOT, and
is never treated as, technical proof that the vulnerability is gone -- only a real retest
through the Pentest Engine establishes that (see verification.py). Uploading evidence
therefore does not, and cannot, transition an item to `verified`.
"""

import hashlib
import uuid

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError
from fastapi import HTTPException, status as http_status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.config import get_settings
from apps.api.modules.audit import service as audit
from apps.api.modules.remediation.models import RemediationEvidence
from apps.api.modules.remediation.service import _record_event, get_item
from apps.api.scanner_engine.models import Evidence

EVIDENCE_TYPE_REMEDIATION_PROOF = "remediation_proof"

# Cap on a single uploaded artifact. Remediation proof is a patch/diff/screenshot/ticket
# export, not a disk image; an unbounded upload is a cheap way to fill the evidence bucket.
MAX_UPLOAD_BYTES = 25 * 1024 * 1024


def _client():
    settings = get_settings()
    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint_url,
        aws_access_key_id=settings.s3_access_key,
        aws_secret_access_key=settings.s3_secret_key,
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )


def store_remediation_proof(
    workspace_id: uuid.UUID, remediation_item_id: uuid.UUID, filename: str, content: bytes,
    content_type: str = "application/octet-stream",
) -> tuple[str, str]:
    """Upload one artifact. Returns (storage_uri, sha256_checksum).

    WORKSPACE-PREFIXED KEY: `workspaces/{workspace_id}/remediation/{item_id}/...`. Existing
    scanner keys (`tool-runs/{id}/...`, `vulnerabilities/{id}/...`) are deliberately NOT
    rewritten -- a mass re-key would invalidate every stored storage_uri and the retention
    sweep's prefix deletion for no security gain, since those objects are already reachable
    only through workspace-scoped rows. NEW client-facing evidence gets the tenant prefix so
    a bucket-level policy or a per-tenant export can operate on one prefix.

    The checksum in the key makes the write idempotent (re-uploading identical bytes
    overwrites the same object rather than accumulating near-duplicates) and matches the value
    stored on the Evidence row, exactly as store_screenshot already does.

    The filename is NOT used to build the key. A client-supplied name can contain `../`, an
    absolute path, or unicode that changes meaning after normalization; using it verbatim
    would be a path-traversal primitive against the object store. It is preserved as metadata
    for display only."""
    settings = get_settings()
    client = _client()
    bucket = settings.s3_bucket_evidence
    try:
        client.head_bucket(Bucket=bucket)
    except ClientError:
        client.create_bucket(Bucket=bucket)

    checksum = hashlib.sha256(content).hexdigest()
    # Extension only, from a strict allowlist -- never the caller's full filename.
    ext = ""
    if "." in filename:
        candidate = filename.rsplit(".", 1)[-1].lower()
        if candidate.isalnum() and len(candidate) <= 8:
            ext = f".{candidate}"
    key = f"workspaces/{workspace_id}/remediation/{remediation_item_id}/proof-{checksum[:16]}{ext}"
    client.put_object(
        Bucket=bucket, Key=key, Body=content, ContentType=content_type,
        Metadata={"original-filename": filename[:255]},
    )
    return f"s3://{bucket}/{key}", checksum


async def add_remediation_evidence(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    item_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    filename: str,
    content: bytes,
    content_type: str,
) -> Evidence:
    """Store an artifact and link it to the remediation item. IMMUTABLE once written: there is
    no endpoint that edits an Evidence row's bytes, uri or checksum."""
    item = await get_item(db, workspace_id, project_id, item_id)
    if not content:
        raise HTTPException(http_status.HTTP_400_BAD_REQUEST, "Uploaded file is empty")
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            http_status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Evidence must be at most {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB",
        )

    storage_uri, checksum = store_remediation_proof(
        workspace_id, item.id, filename, content, content_type
    )
    evidence = Evidence(
        # NULL, honestly: no tool run produced this. Fabricating one would put a false claim
        # into the evidence chain (requirement 9: do not fabricate tool_run IDs).
        tool_run_id=None,
        evidence_type=EVIDENCE_TYPE_REMEDIATION_PROOF,
        storage_uri=storage_uri,
        checksum=checksum,
        uploaded_by=actor_user_id,
    )
    db.add(evidence)
    await db.flush()

    db.add(
        RemediationEvidence(
            remediation_item_id=item.id,
            evidence_id=evidence.id,
            workspace_id=workspace_id,
            uploaded_by=actor_user_id,
        )
    )
    await _record_event(
        db, item, "evidence_added", actor_user_id,
        detail=f"{filename[:120]} sha256={checksum[:16]}",
    )
    await audit.record(
        db, workspace_id, actor_user_id, "remediation.evidence_added", "remediation_item",
        resource_id=item.id, detail=f"evidence={evidence.id} sha256={checksum}",
    )
    await db.commit()
    await db.refresh(evidence)
    return evidence


async def list_remediation_evidence(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, item_id: uuid.UUID
) -> list[Evidence]:
    """Evidence for one item. Resolved through get_item first, so evidence is unreachable
    outside the authorized workspace/project boundary even with a guessed evidence id."""
    await get_item(db, workspace_id, project_id, item_id)
    return list(
        await db.scalars(
            select(Evidence)
            .join(RemediationEvidence, RemediationEvidence.evidence_id == Evidence.id)
            .where(
                RemediationEvidence.remediation_item_id == item_id,
                RemediationEvidence.workspace_id == workspace_id,
            )
            .order_by(Evidence.created_at)
        )
    )
