import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, String, text, Text
from apps.api.core.db_types import GUID, JSONType, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base


class Report(Base):
    """A generated report over a project's findings (blueprint §5). The PDF bytes
    live in object storage; this row is the record + pointer."""

    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # executive | technical | risk_assessment (15 chars -- fits String(16); no migration
    # needed for the new value, which is why the type stays a plain string column rather
    # than a DB enum).
    type: Mapped[str] = mapped_column(String(16), nullable=False)
    format: Mapped[str] = mapped_column(String(8), nullable=False, default="pdf")
    storage_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    # scans included in the report; empty/absent = the whole project. Validated to belong to
    # this workspace+project at CREATE time (reports/service.py create_report), but this is a
    # JSON list, not a relational FK -- a cited scan can later be retention-purged out from
    # under an already-issued report. See `scans_purged` below for how that is made explicit
    # rather than silently dangling (Prompt 13, Finding #8).
    scan_ids: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    # True once the retention sweep has deleted at least one scan named in `scan_ids` after
    # this report was generated. `scan_ids` itself is NEVER rewritten (it is the historically
    # accurate record of what was included at generation time); this flag is the explicit,
    # queryable signal that the report's cited scope may now include scans that no longer
    # exist. Defaulted False so every pre-existing row (and every report whose scans have not
    # been purged) reads as exactly what it always meant. Set by
    # apps.api.retention.repo.mark_reports_with_purged_scans, called from the scan-purge step
    # in retention/service.py -- BEFORE the scans are actually deleted, so the flag and the
    # deletion land in the same transaction.
    scans_purged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    generated_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    generated_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
