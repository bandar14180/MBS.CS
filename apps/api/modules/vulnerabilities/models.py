import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        # Dedup identity: one row per (project, fingerprint) -- a re-scan that
        # re-detects the same issue updates this row rather than duplicating.
        UniqueConstraint("project_id", "fingerprint", name="uq_vulnerabilities_project_fingerprint"),
    )

    id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Nullable (deviation from §5's implied NOT NULL): best-effort link to the
    # asset a finding was observed at; some findings can't be tied to a single
    # inventoried asset. The scan/target chain still anchors it via first_detected_scan_id.
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    first_detected_scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    last_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )

    fingerprint: Mapped[str] = mapped_column(String(512), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Lifecycle: open | confirmed | false_positive | fixed | accepted_risk | reopened
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="open")
    status_justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_changed_by: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    status_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    ai_validated: Mapped[bool] = mapped_column(nullable=False, default=False)
    ai_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class VulnerabilityEvidence(Base):
    """Many-to-many: a finding can cite multiple evidence artifacts, and re-scans
    append new evidence to an existing vulnerability."""

    __tablename__ = "vulnerability_evidence"

    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), primary_key=True
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True
    )
    tool_run_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("tool_runs.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
