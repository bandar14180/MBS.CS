import uuid
from datetime import datetime

from sqlalchemy import Float, ForeignKey, func, Index, String, Text, text, UniqueConstraint
from apps.api.core.db_types import GUID, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        # Dedup identity: one row per (project, fingerprint) -- a re-scan that
        # re-detects the same issue updates this row rather than duplicating.
        UniqueConstraint("project_id", "fingerprint", name="uq_vulnerabilities_project_fingerprint"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Nullable (deviation from §5's implied NOT NULL): best-effort link to the
    # asset a finding was observed at; some findings can't be tied to a single
    # inventoried asset. The scan/target chain still anchors it via first_detected_scan_id.
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    first_detected_scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    last_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
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
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    status_changed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    ai_validated: Mapped[bool] = mapped_column(nullable=False, default=False)
    ai_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"), onupdate=func.now()
    )


class VulnerabilityEvidence(Base):
    """Many-to-many: a finding can cite multiple evidence artifacts, and re-scans
    append new evidence to an existing vulnerability."""

    __tablename__ = "vulnerability_evidence"

    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), primary_key=True
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("evidence.id", ondelete="CASCADE"), primary_key=True
    )
    tool_run_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("tool_runs.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))


class VulnerabilityHistory(Base):
    """APPEND-ONLY snapshot of a Vulnerability's content at one point in time (Prompt 13,
    Finding #4).

    WHY THIS EXISTS. `ingest_finding`'s existing-row branch overwrites `title`/`description`/
    `severity`/`cvss_vector`/`cvss_score` in place on every re-detection, with no prior value
    kept anywhere -- a rescan that changes a finding's reported severity silently destroys the
    old value. This table is the missing historical layer: one row is appended every time
    `ingest_finding` actually creates a Vulnerability OR changes one of those fields on an
    existing row (a re-detection reporting byte-identical content appends nothing -- see
    `_content_changed` in vulnerabilities/service.py), so the full chronology across Scan 1,
    Scan 2, Scan 3, ... is reconstructable by ordering these rows by `created_at`.

    WHAT THIS IS NOT. Not a second source of truth: `vulnerabilities` remains the single live
    row every other subsystem (remediation, reports, verification) reads; this table is
    read-only, append-only, and consulted only when an operator or auditor asks "what did this
    finding look like earlier". Not a workflow/status history either -- RemediationEvent
    already owns human workflow transitions (proposed/accepted/verified/...); this owns the
    SCANNER-observed CONTENT of the finding at each scan that touched it.

    IDENTITY / DEDUP. No unique constraint: multiple rows per vulnerability_id are the whole
    point (one per distinct observed state). Writing is idempotent at the CALL-SITE level, not
    the schema level -- `_content_changed` decides whether a re-detection actually produced a
    new state before this row is ever constructed, so repeated identical ingestion appends
    nothing (see test_vulnerability_history.py).

    TENANCY. VIA-scoped exactly like `vulnerability_evidence`/`vulnerability_lineage`: 2-hop
    through `vulnerability_id -> vulnerabilities -> project_id -> projects`. `project_id` is
    carried directly (same redundant-with-the-FK-chain shape as its two siblings above) so no
    cross-project row can ever be constructed.

    IMMUTABILITY. Like RemediationEvent, there is no update/delete endpoint anywhere in the API
    surface and nothing in the service layer mutates a row after insert -- immutability is a
    code convention here, not a DB constraint, matching every other append-only table in this
    codebase (RemediationEvent, AuditEvent)."""

    __tablename__ = "vulnerability_history"
    __table_args__ = (
        Index("ix_vulnerability_history_vuln_created", "vulnerability_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # The scan that PRODUCED this snapshot -- SET NULL on scan retention sweep so the history
    # row (and the content it recorded) survives its originating scan being aged off, exactly
    # like Vulnerability.first_detected_scan_id/last_seen_scan_id already do.
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    # The tool run that produced THIS specific observation, when known -- provenance for the
    # snapshot itself, distinct from vulnerability_evidence's finding<->evidence link (this
    # answers "which run reported these exact field values", not "what evidence backs this
    # finding"). Nullable: a snapshot written for reasons other than a live tool run (none
    # exist yet, but the column does not assume there never will be one) still fits.
    tool_run_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("tool_runs.id", ondelete="SET NULL"), nullable=True
    )
    fingerprint: Mapped[str] = mapped_column(String(512), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    # observed | created -- "created" marks the row written for a brand-new Vulnerability
    # (Scan 1's first detection); "observed" marks every subsequent content-changing
    # re-detection. Purely descriptive (both are equally valid history entries); lets a caller
    # distinguish "this is where the issue started" without inferring it from row order.
    change_reason: Mapped[str] = mapped_column(String(16), nullable=False, default="observed")
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"), index=True
    )


class VulnerabilityLineage(Base):
    """Explicit, auditable link between two Vulnerability ROWS in the SAME project that the
    ingest engine has deterministically established are the same logical, real-world issue
    despite carrying different `fingerprint` values (Prompt 13, Finding #2).

    WHY THIS EXISTS. `Vulnerability` identity is `(project_id, fingerprint)`
    (uq_vulnerabilities_project_fingerprint above) -- correct for exact-match dedup, but a
    fingerprint changes (e.g. Finding #1's normalization landing, a nuclei template rename, a
    matcher-name change between nuclei releases) with no warning. Before this table existed,
    that produced a brand-new `status="open"` row with no relationship to an older row that an
    analyst had already dismissed as `false_positive` or accepted as `accepted_risk` -- the
    dismissal was silently bypassed (see vulnerabilities/service.py `ingest_finding`'s
    existing-row branch, which is the ONLY place sticky-status preservation happens, and only
    when the fingerprint is byte-identical).

    WHAT THIS IS NOT. This is not fuzzy matching and it is not a general "these look similar"
    correlation. `_lineage.find_ancestor` (the only writer of this table) requires the two
    rows to share `project_id` AND the SAME parsed `template_id` (the tool's own identity for
    "this is the same check") AND a location that is identical ONLY after
    `location_normalize.normalize_location` -- i.e. the two matched_at values were already
    the same real-world location under Finding #1's own normalization rules, just spelled
    differently before/after whatever changed the raw fingerprint string. Two candidates from
    different templates, different projects, or locations that remain distinct even after
    normalization are NEVER linked -- see the false-merge tests in test_vulnerability_lineage.py.

    WHAT INHERITING MEANS. When a lineage row is created, the caller-supplied `inherited_status`
    is what `ingest_finding` copied from the ancestor onto the new row's `status`/
    `status_justification`/`status_changed_by`/`status_changed_at` at CREATE time -- but only
    for a STICKY status (false_positive/accepted_risk). This table is written unconditionally
    whenever a deterministic ancestor is found (even if inheritance did not apply, e.g. the
    ancestor was merely `open`), so "why does this new row exist, and is it related to an
    older one" is always answerable, while "was a decision inherited" is answerable from
    `inherited_status` specifically without recomputing anything.

    TENANCY. VIA-scoped exactly like `vulnerability_evidence`: 2-hop through
    `new_vulnerability_id -> vulnerabilities -> project_id -> projects`, with `project_id`
    also carried directly (redundant with the FK chain, matching vulnerability_evidence's own
    shape) so a cross-project link can never be constructed even in principle -- see
    `_lineage.find_ancestor`, which filters its candidate query by `project_id` before any
    other comparison. `old_vulnerability_id` is a normal FK with no ondelete action beyond
    CASCADE, so a lineage row cannot outlive either vulnerability it connects.

    IDEMPOTENCY. `UniqueConstraint(new_vulnerability_id)` -- a given new row has AT MOST one
    ancestor. Re-ingesting the identical finding twice hits `ingest_finding`'s existing-row
    branch (same fingerprint => same vulnerability row, no new lineage lookup at all), so this
    table is never touched by repeated ingestion of the same result; it is written exactly
    once, at the moment a genuinely new fingerprint is first created for a project."""

    __tablename__ = "vulnerability_lineage"
    __table_args__ = (
        UniqueConstraint("new_vulnerability_id", name="uq_vulnerability_lineage_new_vuln"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    old_vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    new_vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    # The deterministic rule that matched (e.g. "template_id+normalized_location") -- not a
    # confidence SCORE (this mechanism is binary: deterministic match or no link at all), but
    # naming the rule keeps a future second rule (if one is ever added) distinguishable in an
    # audit trail from this one.
    match_rule: Mapped[str] = mapped_column(String(64), nullable=False)
    # The normalized location both fingerprints resolved to -- the actual evidence the link
    # relies on, kept verbatim so the inheritance can be audited without recomputing
    # normalization against whatever the current code does at read time.
    matched_location: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    # NULL when the ancestor's status was not sticky (e.g. it was merely `open`) -- a lineage
    # row is still recorded in that case so the relationship itself stays auditable, but
    # nothing was inherited.
    inherited_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
