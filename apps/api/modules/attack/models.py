import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Text, text, UniqueConstraint
from apps.api.core.db_types import GUID, JSONType, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class AttackMapping(Base):
    """Maps one vulnerability to a MITRE ATT&CK technique + Cyber Kill Chain phase
    (the deterministic base produced by attack/catalog.py). A finding maps to
    zero-or-more techniques. Scoped, like compliance_mappings, through
    vulnerabilities -> projects.workspace_id as a VIA table in apps/api/core/tenancy.py
    (no own workspace column; the FK chain is what scopes it)."""

    __tablename__ = "attack_mappings"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "technique_id", name="uq_attack_vuln_technique"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tactic_id: Mapped[str] = mapped_column(String(16), nullable=False)      # e.g. TA0001
    tactic_name: Mapped[str] = mapped_column(String(64), nullable=False)    # e.g. Initial Access
    technique_id: Mapped[str] = mapped_column(String(16), nullable=False)   # e.g. T1190
    technique_name: Mapped[str] = mapped_column(String(128), nullable=False)
    kill_chain_phase: Mapped[str] = mapped_column(String(32), nullable=False)  # catalog.KillChainPhase.*
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))


class AttackNarrative(Base):
    """One AI-generated attack-path narrative per scan: the ordered kill-chain
    "story" the Correlator synthesizes from all of a scan's findings. Best-effort
    (the scan completes even if this is never written). Tenant-scoped by its own
    workspace_id as a DIRECT table in tenancy.py, like ai_usage (scans is EXEMPT, so
    we can't scope through them)."""

    __tablename__ = "attack_narratives"
    __table_args__ = (
        UniqueConstraint("scan_id", name="uq_attack_narrative_scan"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Ordered kill-chain steps: [{phase, technique_id, technique_name, detail}, ...]
    steps: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    model_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prompt_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
