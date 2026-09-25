import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, text
from apps.api.core.db_types import GUID, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class ToolRun(Base):
    __tablename__ = "tool_runs"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running")
    command_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # PROMPT 10 (execution determinism & reproducible trace). The exact, reconstructible
    # command line the tool was invoked with -- target values, resolved hosts, ports,
    # tool flags and the effective timeout/rate/wordlist knobs baked in by the runner, all
    # non-secret (scan.config carries only tuning numbers; the tool runners never receive
    # credentials as CLI arguments -- see tool_runners/*.py: config.get("timeout_seconds"/
    # "top_ports"/"rate"/"nuclei_tags"/...), never an API key or token). `command_hash`
    # above already existed as a tamper-evident DIGEST of this same string, but a hash
    # cannot answer "what arguments actually ran" -- only "did this match a value I
    # already have to compare against". Before this field the only place the actual text
    # existed was the free-text evidence blob on the in-process path
    # (orchestrator._run_single_tool's `f"$ {raw.command}\n\n=== STDOUT ==="`), which the
    # remote/lease execution plane never wrote at all (command_hash stayed "" there --
    # see scanner_manager/app.py). Nullable: existing rows predate this column and a
    # backfill would have nothing truthful to put here.
    effective_command: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Was this run's own wall-clock budget exceeded? Every tool runner already computes
    # this (base.run_with_timeout returns TimedRun.timed_out) but previously discarded it
    # the moment it was folded into a free-text "timed out" suffix on stderr and a bare
    # exit_code=-1 -- indistinguishable, without string-matching stderr, from a genuine
    # tool crash that also happened to exit -1. Defaults False so every historical and
    # not-yet-timed-out row reads as the true, non-timed-out state.
    timed_out: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("0"))
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw_output_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Exact failure text (exception message, or a tail of the tool's stderr on a
    # non-zero exit) so a failure is visible and debuggable, not just a status.
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class Evidence(Base):
    """One stored artifact: scanner output, a screenshot, or human-uploaded remediation proof.

    ONE evidence store for the whole platform -- a second table for remediation proof would
    have duplicated the checksum/storage_uri/immutability semantics and split the audit
    surface in two. The two kinds of row are told apart by `tool_run_id`, and each is scoped
    to its workspace by its own path (see tenancy._evidence_criterion).
    """

    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    # NULLABLE as of the remediation workflow. Scanner evidence always has a tool run; HUMAN
    # remediation proof genuinely does not, and fabricating a tool_run id for it would put a
    # lie into the evidence chain (an artifact would claim to have been produced by a tool
    # execution that never happened). NULL is therefore the honest representation, and
    # `remediation_evidence` carries the ownership link for those rows instead.
    tool_run_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("tool_runs.id", ondelete="CASCADE"), nullable=True, index=True
    )
    # raw_output | screenshot | remediation_proof
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False)
    storage_uri: Mapped[str] = mapped_column(Text, nullable=False)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    # Who uploaded it, for human-supplied artifacts. NULL for machine-produced scanner
    # evidence, where the tool run IS the provenance.
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
