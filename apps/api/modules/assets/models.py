import uuid
from datetime import datetime

from sqlalchemy import Computed, ForeignKey, String, text, UniqueConstraint
from sqlalchemy.dialects.mysql import BINARY
from apps.api.core.db_types import GUID, JSONType, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base

# Longest asset value the column accepts. Enforced at the application boundary too
# (modules/assets/service.py) so an over-long value is skipped with a logged reason rather
# than raising DataError mid-transaction -- which is what took scan 615d0e0b down.
MAX_ASSET_VALUE_LENGTH = 2048


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        # Keyed on the DIGEST of `value`, not `value` itself. InnoDB caps an index key at
        # 3072 bytes and this table is utf8mb4, so a 2048-character `value` (8192 bytes)
        # cannot be indexed directly -- see migration f7a8b9c0d1e2 for the full derivation.
        # The grain enforced is unchanged: one row per (target_id, asset_type, value).
        UniqueConstraint(
            "target_id", "asset_type", "value_hash", name="uq_assets_target_type_value"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_type: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(MAX_ASSET_VALUE_LENGTH), nullable=False)
    # MySQL derives this from `value`; nothing in Python ever writes it, which is why it
    # cannot drift from the data it keys. BINARY(32) rather than CHAR(64) so comparison is
    # byte-exact and unaffected by this table's case-insensitive utf8mb4_unicode_ci
    # collation, which would otherwise treat two hex digests differing in case as equal.
    # mysql.BINARY, not the generic LargeBinary: the latter renders as a BLOB-family type,
    # which is a different column than the fixed-width BINARY(32) the migration creates --
    # `alembic check` flags the mismatch as drift.
    value_hash: Mapped[bytes] = mapped_column(
        BINARY(32),
        Computed("UNHEX(SHA2(`value`, 256))", persisted=True),
        nullable=False,
    )
    metadata_: Mapped[dict] = mapped_column("metadata", JSONType, nullable=False, default=dict)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
