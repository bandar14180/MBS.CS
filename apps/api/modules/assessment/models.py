"""Client Risk Assessment: an immutable, client-facing snapshot of security posture.

A SNAPSHOT, NOT A CALCULATOR
----------------------------
This module stores NUMBERS THAT WERE ALREADY COMPUTED ELSEWHERE. Every value frozen onto an
assessment comes from the existing pipeline:

  * `security_score`      <- reports.scoring.compute_security_score (the ONE scoring model);
  * `score_band`          <- reports.render._score_band (the ONE banding function);
  * severity counts       <- reports.data.gather_report_data's active_severity_counts;
  * top risks             <- reports.render._top_risk_groups;
  * unresolved/scorable   <- reports.scoring.is_scorable;
  * affected assets/endpoints <- ReportData.affected_assets / affected_endpoint_count;
  * per-finding severity/CVSS/final_risk <- the vulnerability and risk_scores rows as they
    stood at issue time.

There is no second formula anywhere in this package. The parity test asserts an issued
assessment's numbers equal the Executive Report's for identical data.

IMMUTABILITY
------------
A `draft` assessment is a working document. `issue()` freezes it: the summary JSON and every
`risk_assessment_findings` row are written once, `status` becomes `issued`, and from then on
every mutating service function refuses to touch it (409). That is what makes a client-facing
deliverable trustworthy -- the PDF a client received in March must still say in June what it
said in March, even though the live vulnerabilities have since changed.

HISTORICAL COMPARISON
---------------------
`previous_assessment_id` points at the prior ISSUED assessment for the same scope. Trends are
computed snapshot-to-snapshot, never against mutable live state, so a comparison cannot drift
after the fact.
"""

import uuid
from datetime import datetime

from sqlalchemy import Float, ForeignKey, Index, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base
from apps.api.core.db_types import GUID, JSONType, UTCDateTime

STATUS_DRAFT = "draft"
STATUS_ISSUED = "issued"
ASSESSMENT_STATUSES = frozenset({STATUS_DRAFT, STATUS_ISSUED})


class RiskAssessment(Base):
    """One periodic assessment of a project's (or workspace's) security posture."""

    __tablename__ = "risk_assessments"
    __table_args__ = (
        Index("ix_risk_assessments_ws_project_status", "workspace_id", "project_id", "status"),
        Index("ix_risk_assessments_issued", "workspace_id", "issued_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # NULLABLE by design: a workspace-wide assessment (no single project) is a legitimate
    # scope. The scoping helper treats NULL as "whole workspace" rather than as missing data.
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    period_start: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    period_end: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=STATUS_DRAFT)

    # --- FROZEN posture (written at issue time; NULL while draft) --------------------------
    # Copied verbatim from compute_security_score / _score_band. Nullable so a draft exists
    # before its numbers are taken, and so a NULL is never confused with a score of 0.
    security_score: Mapped[int | None] = mapped_column(nullable=True)
    score_band: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # The rest of the snapshot as structured JSON: severity_counts, active_severity_counts,
    # totals, affected assets/endpoints, top_risks, remediation_progress. One JSON column
    # rather than 20 scalar columns because the shape is a REPORT PAYLOAD read as a whole,
    # never queried field-by-field, and adding a metric later must not require a migration
    # that would leave older issued assessments with NULLs they can never have.
    summary: Mapped[dict] = mapped_column(JSONType, nullable=False, default=dict)
    # Management recommendations + executive narrative, derived from the project's actual
    # risk/remediation data (see assessment/narrative.py). Provenance is recorded in
    # `narrative_source`, so AI-assisted prose is never presented as human-authored.
    narrative: Mapped[str | None] = mapped_column(Text, nullable=True)
    narrative_source: Mapped[str | None] = mapped_column(String(16), nullable=True)  # system | ai | human

    # Prior ISSUED assessment for the same scope, resolved at issue time. SET NULL so deleting
    # an old assessment cannot orphan the chain.
    previous_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("risk_assessments.id", ondelete="SET NULL"), nullable=True
    )
    # The PDF produced through the EXISTING reports pipeline (reports.type == 'risk_assessment').
    # Nullable: an assessment can be issued without rendering a PDF, and the report row may be
    # retention-swept later while the assessment itself is retained longer.
    report_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("reports.id", ondelete="SET NULL"), nullable=True
    )

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    issued_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    issued_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"), onupdate=text("CURRENT_TIMESTAMP(6)")
    )


class RiskAssessmentFinding(Base):
    """One finding as it stood AT ISSUE TIME. Frozen, never updated.

    The values here are COPIES, deliberately denormalized: the whole point is that a later
    re-scan changing `vulnerabilities.severity`, a re-computed `final_risk_score`, or a
    remediation item moving to `closed` must NOT retroactively alter what an already-issued
    client assessment says. `vulnerability_id` is kept as a nullable back-reference for
    navigation only -- reading through it would defeat the freeze, so the read paths use the
    frozen columns and the report renderer never dereferences it.
    """

    __tablename__ = "risk_assessment_findings"
    __table_args__ = (Index("ix_raf_assessment_severity", "assessment_id", "frozen_severity"),)

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("risk_assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # scoring.issue_key -- the SAME identity the score, the report groupings and the
    # remediation items use, so a finding can be traced across all four surfaces.
    issue_key: Mapped[str] = mapped_column(String(512), nullable=False)
    vulnerability_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True
    )

    frozen_title: Mapped[str] = mapped_column(String(512), nullable=False)
    frozen_severity: Mapped[str] = mapped_column(String(16), nullable=False)
    # NULL stays distinct from 0.0 here exactly as it does in scoring.py: None means "not
    # scored", 0.0 means "scored, and it is zero".
    frozen_cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    frozen_final_risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    frozen_vulnerability_status: Mapped[str] = mapped_column(String(24), nullable=False)
    # NULL when the issue had no remediation item at issue time -- distinct from `proposed`.
    frozen_remediation_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Whether an ACTIVE risk acceptance covered this finding at issue time.
    risk_accepted: Mapped[bool] = mapped_column(nullable=False, default=False)
    # How many distinct locations the issue affected -- the breadth the score already accounts
    # for (scoring._location_factor), frozen so the client view matches the score.
    location_count: Mapped[int] = mapped_column(nullable=False, default=1)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
