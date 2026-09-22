"""Private-site authorization -- the single place private network access is decided.

MBS.SC Phases 3/4/12. Every private scan must pass through `build_scan_network_policy`,
which walks the authorization chain and refuses at the first broken link:

    workspace  ->  site (owned by THAT workspace, and ACTIVE)
               ->  authorized CIDRs (non-empty, parseable)
               ->  target address inside those CIDRs
               ->  worker bound to THAT site
               ->  tunnel healthy

Two rules govern everything here:

1. AUTHORIZATION IS DERIVED, NEVER ASSERTED. No caller passes in "the workspace this is
   allowed for". The workspace comes from the SCAN row; the CIDRs come from the SITE row;
   the site must independently prove it belongs to that workspace. A caller can therefore
   ask for a policy but cannot influence what the policy grants.

2. EVERY FAILURE IS A REFUSAL. There is no partial success and no fallback to global
   configuration. A missing site, a suspended site, an empty CIDR list, a
   workspace mismatch -- each raises PrivateSiteNotAuthorized, so a bug in a caller
   loses private access rather than silently widening it.
"""
from __future__ import annotations

import ipaddress
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.private_sites.models import (
    SCANNABLE_SITE_STATUSES,
    PrivateSite,
)
from apps.api.scanner_engine import net_policy

logger = logging.getLogger(__name__)


class PrivateSiteNotAuthorized(PermissionError):
    """Private access refused. Carries a stable machine-readable `reason` so the API,
    the scan record and the metrics all name the SAME failure without re-deriving it."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        # Counted HERE, at construction, so every refusal is observable no matter which
        # call site raised it -- a new check cannot forget to record its own denial.
        # Only the bounded `reason` code is exported; no tenant identifier.
        try:
            from apps.api.core.observability import record_private_scan_blocked

            record_private_scan_blocked(reason)
        except Exception:  # noqa: BLE001 -- metrics must never break an authz decision
            pass


# Stable refusal reasons (Phase 12 vocabulary). Kept as constants so a log line, a metric
# label and a scan's failure reason cannot drift apart.
REASON_SITE_NOT_FOUND = "SITE_NOT_FOUND"
REASON_SITE_WRONG_WORKSPACE = "SITE_WRONG_WORKSPACE"
REASON_SITE_SUSPENDED = "SITE_SUSPENDED"
REASON_SITE_REVOKED = "SITE_REVOKED"
REASON_SITE_NOT_ACTIVE = "SITE_NOT_ACTIVE"
REASON_NO_AUTHORIZED_CIDRS = "NO_AUTHORIZED_CIDRS"
REASON_TARGET_OUTSIDE_CIDRS = "TARGET_OUTSIDE_AUTHORIZED_CIDRS"
REASON_PRIVATE_SCANNING_DISABLED = "PRIVATE_SCANNING_DISABLED"
REASON_TARGET_MISSING_SITE = "TARGET_MISSING_SITE"


async def get_site_for_workspace(
    db: AsyncSession, site_id: uuid.UUID, workspace_id: uuid.UUID
) -> PrivateSite:
    """Load a site and PROVE it belongs to `workspace_id`.

    The workspace comparison is explicit here even though `private_sites` is also
    auto-filtered by tenancy.py. That redundancy is deliberate: this function is called
    from the scan executor and the manager, where the ambient tenancy context is bound
    from the scan row rather than from an HTTP request, and a boundary this sensitive
    should not depend on a single mechanism being correctly installed. If the ORM filter
    is ever bypassed (raw SQL, admin_bypass, a future refactor), this check still holds.
    """
    site = await db.get(PrivateSite, site_id)
    if site is None:
        raise PrivateSiteNotAuthorized(
            REASON_SITE_NOT_FOUND, f"Private site {site_id} does not exist."
        )
    if site.workspace_id != workspace_id:
        # Do NOT reveal which workspace owns it -- that would leak cross-tenant
        # information through an error message. Log the detail server-side instead.
        logger.warning(
            "private_site.cross_tenant_access_denied site=%s owner_ws=%s requesting_ws=%s",
            site_id, site.workspace_id, workspace_id,
            extra={"event": "private_site.cross_tenant_denied", "site_id": str(site_id)},
        )
        raise PrivateSiteNotAuthorized(
            REASON_SITE_WRONG_WORKSPACE,
            f"Private site {site_id} is not available to this workspace.",
        )
    return site


def assert_site_scannable(site: PrivateSite) -> None:
    """Refuse unless the site's lifecycle state permits scanning (ACTIVE only)."""
    if site.status in SCANNABLE_SITE_STATUSES:
        return
    reason = {
        "suspended": REASON_SITE_SUSPENDED,
        "revoked": REASON_SITE_REVOKED,
    }.get(site.status, REASON_SITE_NOT_ACTIVE)
    raise PrivateSiteNotAuthorized(
        reason,
        f"Private site '{site.name}' is '{site.status}', not 'active'; scanning is refused.",
    )


def authorized_networks(site: PrivateSite) -> tuple:
    """The site's authorized CIDRs, parsed. Raises if it authorizes nothing.

    An empty/entirely-malformed list is a REFUSAL, not an empty allowance that some later
    check might treat as "unrestricted" -- the most dangerous way to misread emptiness.
    """
    nets = net_policy._parse_cidrs(site.authorized_cidrs)
    if not nets:
        raise PrivateSiteNotAuthorized(
            REASON_NO_AUTHORIZED_CIDRS,
            f"Private site '{site.name}' has no valid authorized CIDRs; scanning is refused.",
        )
    return nets


def assert_address_within_site(site: PrivateSite, address: str) -> None:
    """Refuse unless `address` falls inside one of the site's authorized CIDRs.

    This is the check that stops tenant A reaching tenant B's 10.0.0.0/8 even when both
    tenants legitimately use overlapping RFC1918 space: the comparison is against THIS
    site's list, and a site belongs to exactly one workspace.
    """
    nets = authorized_networks(site)
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        raise PrivateSiteNotAuthorized(
            REASON_TARGET_OUTSIDE_CIDRS,
            f"Address {address!r} is not a valid IP address.",
        )
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if not any(ip.version == n.version and ip in n for n in nets):
        raise PrivateSiteNotAuthorized(
            REASON_TARGET_OUTSIDE_CIDRS,
            f"Address {address} is outside the authorized CIDRs of site '{site.name}'.",
        )


async def build_scan_network_policy(
    db: AsyncSession,
    *,
    workspace_id: uuid.UUID,
    scan_id: uuid.UUID | None,
    network_zone: str,
    site_id: uuid.UUID | None,
    worker_id: str | None = None,
    pool_id: str | None = None,
) -> net_policy.ScanNetworkPolicy:
    """Derive the immutable per-scan network policy from PERSISTED authorization.

    This is the ONLY supported way to obtain a private policy. A public target yields a
    public-only policy that authorizes no private range at all -- so an ordinary scan is
    unaffected by whatever private sites the workspace happens to own, and by whatever
    the global on-prem settings say.
    """
    if network_zone != "private":
        return net_policy.build_public_policy(workspace_id=workspace_id, scan_id=scan_id)

    if site_id is None:
        # A private target with no site cannot be authorized against anything.
        raise PrivateSiteNotAuthorized(
            REASON_TARGET_MISSING_SITE,
            "Target is marked private but names no private site; scanning is refused.",
        )

    site = await get_site_for_workspace(db, site_id, workspace_id)
    assert_site_scannable(site)
    nets = authorized_networks(site)

    policy = net_policy.build_private_policy(
        workspace_id=workspace_id,
        scan_id=scan_id,
        site_id=site.id,
        authorized_cidrs=[str(n) for n in nets],
        dns_servers=site.dns_servers or (),
        worker_id=worker_id,
        pool_id=pool_id or site.scanner_pool_id,
    )
    logger.info(
        "private_site.policy_built site=%s workspace=%s scan=%s cidrs=%d resolvers=%d",
        site.id, workspace_id, scan_id, len(policy.authorized_cidrs), len(policy.dns_servers),
        extra={
            "event": "private_site.policy_built",
            "site_id": str(site.id),
            "workspace_id": str(workspace_id),
            "scan_id": str(scan_id) if scan_id else None,
        },
    )
    return policy


async def list_sites(db: AsyncSession, workspace_id: uuid.UUID) -> list[PrivateSite]:
    """Sites owned by `workspace_id`. Explicitly filtered as well as ORM-filtered."""
    rows = await db.execute(
        select(PrivateSite).where(PrivateSite.workspace_id == workspace_id)
        .order_by(PrivateSite.created_at)
    )
    return list(rows.scalars().all())
