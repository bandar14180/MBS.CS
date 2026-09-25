import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, text, Text
from apps.api.core.db_types import GUID, UTCDateTime
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base

# MBS.SC: `targets.site_id` carries a ForeignKey to `private_sites.id`, and SQLAlchemy
# resolves an FK's target table lazily out of the shared MetaData. Any module that imports
# Target WITHOUT also importing PrivateSite therefore raises NoReferencedTableError the
# moment the mapper is configured -- which is exactly what several existing test modules do
# (they import Project/Target/Scan directly, not core.models_all). Importing it here makes
# the dependency structural: you cannot get Target without the table its FK points at.
from apps.api.modules.private_sites import models as _private_sites_models  # noqa: F401


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    created_by: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    # Business context the customer sets (blueprint §7 step 7 / Risk Engine):
    # how important this asset is, which weights technical CVSS into a business
    # risk score. low | medium | high | critical.
    criticality: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    # MBS.SC Phase 3 -- which NETWORK ZONE this target lives in: "public" | "private".
    #
    # Defaults to "public", so every pre-existing target keeps exactly its current
    # behaviour (public scanning path, no private authorization). A target only becomes
    # private by an explicit decision that also names the site it belongs to.
    network_zone: Mapped[str] = mapped_column(String(16), nullable=False, default="public")
    # The private site whose tunnel and authorized CIDRs govern this target. REQUIRED
    # when network_zone == "private" and REJECTED when it is "public"; the invariant is
    # enforced in modules/projects/service.py::validate_target_network_zone(), which also
    # proves the site belongs to the SAME workspace as the target's project. Nullable in
    # the schema because public targets (the overwhelming majority) have no site.
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("private_sites.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    added_by: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)"))
