"""Private site: a customer's internal network, reachable only through its own tunnel.

MBS.SC Phase 3. A "private site" is the unit that makes private scanning AUTHORIZABLE
rather than merely ENABLED. Before this table existed, the only expression of "we may
scan internal addresses" was two process-wide settings, which could not name a tenant --
so any tenant's private scan authorized every tenant's private scan.

A site binds, in one row that the manager can check on every request:

    workspace  ->  authorized CIDRs  ->  scanner pool  ->  tunnel endpoint

Every private scan is validated against exactly one of these rows.

WHAT IS DELIBERATELY NOT HERE: the WireGuard PRIVATE KEY.
--------------------------------------------------------
`peer_public_key` is the CUSTOMER's public key, and `worker_public_key` is the public
half of the key the private worker generates. The worker's PRIVATE key is generated
inside the private worker namespace and never leaves it -- it is not a column here, not
in any migration, and not accepted by any manager endpoint. Persisting it centrally
would mean one control-plane database compromise yields the ability to impersonate the
scanner INSIDE every customer's internal network simultaneously, which is a far worse
outcome than the compromise itself. Public key material is all the control plane needs
to distribute configuration, so it is all the control plane holds.
"""
import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.core.db import Base

# MBS.SC: `private_sites` has an FK to `workspaces`, and SQLAlchemy resolves an FK's target table lazily out of the
# shared MetaData. A module that imports this model WITHOUT also importing those
# tables raises NoReferencedTableError the moment the mapper is configured -- which
# is what an operator script or a focused test does. Importing them here makes the
# dependency structural rather than a rule people have to remember.
from apps.api.modules.workspaces import models as _workspaces_models  # noqa: F401
from apps.api.core.db_types import GUID, JSONType, UTCDateTime

# Lifecycle. Scanning is permitted from ACTIVE only -- see service.assert_site_scannable.
#
#   pending        row created; no key exchange yet.
#   key_exchanged  both public keys known; tunnel not yet proven.
#   verified       tunnel came up and a handshake was observed at least once.
#   active         verified AND released for scanning. The ONLY scannable state.
#   suspended      temporarily blocked (incident, billing, customer request). Reversible.
#   revoked        terminal. Never scannable again; a new site row is required.
SITE_STATUSES = ("pending", "key_exchanged", "verified", "active", "suspended", "revoked")
SCANNABLE_SITE_STATUSES = frozenset({"active"})


class PrivateSite(Base):
    __tablename__ = "private_sites"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    # EXACTLY ONE workspace owns a site. Not nullable, no "shared site" concept: a
    # nullable owner is how cross-tenant access gets reintroduced by accident.
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # The authoritative answer to "which internal addresses may this tenant scan".
    # A JSON list of CIDR strings; net_policy parses and validates them (malformed
    # entries are dropped, never widened). This is the ONLY source of private
    # authorization -- global settings can bound it but never extend it.
    authorized_cidrs: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)

    # Site-local resolvers, reached THROUGH the tunnel (Phase 9). Empty list means the
    # site has no private DNS and hostname targets cannot be resolved for it -- which
    # fails closed rather than leaking the query to a public resolver.
    dns_servers: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)
    dns_search_domains: Mapped[list] = mapped_column(JSONType, nullable=False, default=list)

    # --- WireGuard metadata (PUBLIC key material only -- see the module docstring) ---
    wg_endpoint_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    wg_endpoint_port: Mapped[int | None] = mapped_column(nullable=True)
    # The CUSTOMER's public key (their WireGuard server / peer).
    peer_public_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # The public half of the keypair the PRIVATE WORKER generated locally. Uploaded by
    # the worker; the matching private key stays in the worker namespace forever.
    worker_public_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Keepalive for NAT traversal; None -> omit from the generated config.
    wg_persistent_keepalive: Mapped[int | None] = mapped_column(nullable=True)

    # Which isolated pool serves this site. Phase 10: a private site gets its OWN pool
    # so two customers' overlapping 10.0.0.0/8 ranges never share a routing namespace.
    scanner_pool_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    # Why a site was suspended/revoked -- shown to operators, never to another tenant.
    status_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Tunnel health, reported by the private worker via the manager. Advisory for
    # display; the authoritative pre-scan check is a LIVE probe (Phase 12), because a
    # stored timestamp cannot prove the tunnel is up right now.
    last_handshake_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), server_default=text("CURRENT_TIMESTAMP(6)")
    )
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    __table_args__ = (
        # Site names are meaningful to operators ("acme-dc1"); keep them unique per
        # workspace so a runbook reference is unambiguous, while letting two different
        # customers each have a site called "hq".
        Index("ix_private_sites_workspace_name", "workspace_id", "name", unique=True),
    )
