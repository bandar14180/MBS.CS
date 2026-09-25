"""Request/response models for the remediation workflow.

SECURITY NOTE ON WHAT IS ABSENT: no request model here accepts `workspace_id`, `project_id`,
`severity`, `cvss_score`, `cvss_vector`, `final_risk_score`, `status` (outside the dedicated
transition body), or `version` as a writable value. Scope comes from the URL path and the
authenticated context; severity/CVSS/risk are scanner- and risk-engine-owned. Pydantic models
here are strict about extra keys, so a client sending `{"severity": "low"}` to a remediation
endpoint is REJECTED rather than silently ignored -- a silent ignore looks like success and
would leave a caller believing they had changed a protected field.
"""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from apps.api.modules.remediation.models import REMEDIATION_PRIORITIES

Priority = Literal["critical", "high", "medium", "low"]
# The statuses a HUMAN may target through the transition endpoint. `verified` and
# `risk_accepted` are absent BY DESIGN -- they have their own authorized entry points (a real
# retest / an approved, justified, expiring acceptance), so they are rejected at the schema
# boundary before the service is even reached.
TransitionTarget = Literal[
    "accepted", "in_progress", "awaiting_verification", "closed", "reopened", "rejected", "proposed"
]

# Every request model forbids unknown fields, so an attempt to smuggle a protected field
# (severity/cvss/risk/workspace_id) is a 422, not a silent no-op.
_STRICT = ConfigDict(extra="forbid")


class EvidenceConfidence(BaseModel):
    """Prompt 13, Finding #6: the report layer's evidence-based classification of the item's
    representative vulnerability, surfaced alongside (never merged into) the item's workflow
    `status`. See remediation/evidence_confidence.py for why these are deliberately kept
    distinct: `status == "verified"` means a real retest found the issue gone; `verification`
    here means the ORIGINAL detection's captured evidence corroborates a specific, exploitable
    condition rather than a generic/inferred pattern match. A workflow-verified item can
    legitimately show `verification: "unverified"` here -- that is not a contradiction, it is
    two different questions answered honestly."""

    vulnerability_id: uuid.UUID
    verification: str
    confidence: str


class RemediationItemRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    workspace_id: uuid.UUID
    project_id: uuid.UUID
    issue_key: str
    vulnerability_id: uuid.UUID | None
    remediation_id: uuid.UUID | None
    title: str
    status: str
    priority: str
    assignee_user_id: uuid.UUID | None
    due_date: datetime | None
    notes: str | None
    # Provenance, exposed so a client can SEE whether notes were written by a person or
    # produced by the AI guidance path. Never inferred client-side.
    notes_source: str | None
    source: str
    resolved_at: datetime | None
    verified_at: datetime | None
    version: int
    created_at: datetime
    updated_at: datetime
    # None when there is no representative vulnerability or no evidence to classify from --
    # never fabricated. Populated by the router via evidence_confidence_for_item(), not by ORM
    # attribute access (from_attributes alone cannot compute this).
    evidence_confidence: EvidenceConfidence | None = None


class RemediationItemUpdate(BaseModel):
    model_config = _STRICT

    # REQUIRED. The optimistic-lock token: a client must state which version it is editing, so
    # a concurrent writer gets a deterministic 409 instead of silently clobbering.
    version: int = Field(ge=1)
    assignee_user_id: uuid.UUID | None = None
    # Explicit clear flags -- None already means "leave unchanged" in a PATCH, so clearing
    # needs its own signal rather than overloading None.
    clear_assignee: bool = False
    due_date: datetime | None = None
    clear_due_date: bool = False
    priority: Priority | None = None
    notes: str | None = Field(default=None, max_length=8192)


class RemediationTransition(BaseModel):
    model_config = _STRICT

    version: int = Field(ge=1)
    to_status: TransitionTarget
    detail: str | None = Field(default=None, max_length=2048)


class RemediationEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    remediation_item_id: uuid.UUID
    event_type: str
    from_status: str | None
    to_status: str | None
    actor_user_id: uuid.UUID | None
    detail: str | None
    created_at: datetime


class RemediationEvidenceRead(BaseModel):
    """Evidence metadata. `storage_uri` is a REFERENCE; `checksum` is an integrity digest."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tool_run_id: uuid.UUID | None
    evidence_type: str
    storage_uri: str
    checksum: str
    uploaded_by: uuid.UUID | None
    created_at: datetime


class RemediationEvidenceCreate(BaseModel):
    """An uploaded artifact, as JSON with base64 content.

    JSON rather than multipart because every other endpoint in this API is JSON and multipart
    would mean adding `python-multipart` as a runtime dependency for one route. The base64
    ceiling below is on the ENCODED string; base64 inflates by 4/3, so it corresponds to the
    evidence_service byte cap and stops an oversized body being decoded before it is rejected.
    """

    model_config = _STRICT

    # Display metadata only. The object key is built from the item id and the content hash --
    # this value never reaches the storage path, since a client-supplied name can carry `../`.
    filename: str = Field(min_length=1, max_length=255)
    content_type: str = Field(default="application/octet-stream", max_length=128)
    content_base64: str = Field(min_length=1, max_length=34_000_000)

    def content_bytes(self) -> bytes:
        """Decode, STRICTLY. `validate=True` rejects non-alphabet characters rather than
        silently discarding them, so a malformed body is a clear 400 instead of a truncated
        artifact whose checksum would then certify the wrong bytes."""
        import base64
        import binascii

        from fastapi import HTTPException, status as http_status

        try:
            return base64.b64decode(self.content_base64, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(
                http_status.HTTP_400_BAD_REQUEST, "content_base64 is not valid base64"
            ) from None


class VerificationRequestCreate(BaseModel):
    model_config = _STRICT

    version: int = Field(ge=1)
    # OPTIONAL link to a retest scan that has already run. Validated server-side against this
    # workspace and project -- a scan id from another tenant is refused, never trusted.
    scan_id: uuid.UUID | None = None


class VerificationRequestRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    remediation_item_id: uuid.UUID
    status: str
    result: str | None
    scan_id: uuid.UUID | None
    requested_by: uuid.UUID | None
    claimed_at: datetime | None
    completed_at: datetime | None
    detail: dict
    # Prompt 13, Finding #3: the issue's distinct scorable locations snapshotted at the moment
    # this request was created -- the reference set complete_verification checks retest
    # coverage against. Exposed read-only; nothing ever accepts this from a caller.
    baseline_locations: list[str]
    created_at: datetime


class RiskAcceptanceCreate(BaseModel):
    model_config = _STRICT

    vulnerability_id: uuid.UUID
    # NON-EMPTY by schema. An acceptance with no stated reason is not an accepted risk.
    justification: str = Field(min_length=1, max_length=4096)
    # REQUIRED, and validated server-side to be in the future. An acceptance that cannot lapse
    # is indistinguishable from ignoring the finding.
    expires_at: datetime
    review_due_at: datetime | None = None
    approved_by: uuid.UUID | None = None
    remediation_item_id: uuid.UUID | None = None
    version: int | None = Field(default=None, ge=1)


class RiskAcceptanceRevoke(BaseModel):
    model_config = _STRICT

    reason: str = Field(min_length=1, max_length=4096)


class RiskAcceptanceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    vulnerability_id: uuid.UUID
    remediation_item_id: uuid.UUID | None
    justification: str
    accepted_by: uuid.UUID | None
    approved_by: uuid.UUID | None
    expires_at: datetime
    review_due_at: datetime | None
    status: str
    revoked_by: uuid.UUID | None
    revoked_at: datetime | None
    revoke_reason: str | None
    created_at: datetime


class RemediationProgressRead(BaseModel):
    total: int
    proposed: int
    accepted: int
    in_progress: int
    awaiting_verification: int
    verified: int
    closed: int
    risk_accepted: int
    rejected: int
    reopened: int
    open: int
    resolved: int
    overdue: int
    completion_percent: int


__all__ = [
    "REMEDIATION_PRIORITIES",
    "RemediationEventRead",
    "RemediationEvidenceCreate",
    "RemediationEvidenceRead",
    "RemediationItemRead",
    "RemediationItemUpdate",
    "RemediationProgressRead",
    "RemediationTransition",
    "RiskAcceptanceCreate",
    "RiskAcceptanceRead",
    "RiskAcceptanceRevoke",
    "VerificationRequestCreate",
    "VerificationRequestRead",
]
