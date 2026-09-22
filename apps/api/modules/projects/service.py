import ipaddress
import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.pagination import MAX_LIMIT, Pagination, paginate
from apps.api.modules.projects.models import Project, Target


async def create_project(
    db: AsyncSession, workspace_id: uuid.UUID, creator_id: uuid.UUID, name: str, description: str | None
) -> Project:
    from apps.api.modules.billing import service as billing

    await billing.enforce_project_quota(db, workspace_id)
    project = Project(workspace_id=workspace_id, name=name, description=description, created_by=creator_id)
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return project


async def list_projects(
    db: AsyncSession, workspace_id: uuid.UUID, page: Pagination | None = None
) -> tuple[list[Project], int]:
    query = select(Project).where(Project.workspace_id == workspace_id).order_by(Project.created_at, Project.id)
    return await paginate(db, query, page or Pagination(limit=MAX_LIMIT, offset=0))


async def get_project(db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID) -> Project:
    project = await db.scalar(
        select(Project).where(Project.id == project_id, Project.workspace_id == workspace_id)
    )
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    return project


async def update_project(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    name: str | None,
    description: str | None,
    project_status: str | None,
) -> Project:
    project = await get_project(db, workspace_id, project_id)
    if name is not None:
        project.name = name
    if description is not None:
        project.description = description
    if project_status is not None:
        project.status = project_status
    await db.commit()
    await db.refresh(project)
    return project


async def delete_project(db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID) -> None:
    project = await get_project(db, workspace_id, project_id)
    await db.delete(project)
    await db.commit()


async def create_target(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    project_id: uuid.UUID,
    added_by: uuid.UUID,
    target_type: str,
    value: str,
    criticality: str = "medium",
    site_id: uuid.UUID | None = None,
) -> Target:
    """Create a target, deriving its execution context SERVER-SIDE (MBS.SC P7-2).

    `site_id` is an IDENTIFIER REQUIRING AUTHORIZATION, not a grant. The chain below runs
    in a deliberate order -- authenticate (already done by the router's
    `require_permission`), resolve the workspace, prove the PROJECT is in it, prove the
    SITE is in it, and only then let the site influence anything:

        workspace -> project ownership -> site ownership -> zone -> CIDRs -> target

    `network_zone` is NEVER accepted from the caller; it is derived here (site => private,
    no site => public). That is what stops a client declaring its own execution context.
    """
    await get_project(db, workspace_id, project_id)  # 404s if project isn't in this workspace

    # P7-2 -- SITE AUTHORIZATION, BEFORE the site may influence anything at all.
    #
    # `get_site_for_workspace` proves the site EXISTS and belongs to THIS workspace, and
    # raises without disclosing the owning workspace on a cross-tenant attempt. Reusing it
    # (rather than a second lookup here) keeps one authority for site ownership, shared
    # with the scan path and the manager.
    site = None
    network_zone = "public"
    scan_policy = None
    if site_id is not None:
        from apps.api.modules.private_sites import service as private_sites_service

        try:
            site = await private_sites_service.get_site_for_workspace(db, site_id, workspace_id)
            # A target may only be attached to a site that is actually scannable and that
            # authorizes at least one CIDR -- the same conditions the scan path enforces, so
            # a target cannot be created now and fail authorization later.
            private_sites_service.assert_site_scannable(site)
            # Derived, never supplied: the policy comes from the PERSISTED site row.
            scan_policy = await private_sites_service.build_scan_network_policy(
                db, workspace_id=workspace_id, scan_id=None,
                network_zone="private", site_id=site.id,
            )
        except private_sites_service.PrivateSiteNotAuthorized as exc:
            # 403 with the stable reason only. `exc.message` never names the owning
            # workspace (see get_site_for_workspace), so this cannot leak cross-tenant
            # metadata.
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, f"{exc.reason}: {exc.message}"
            ) from exc
        network_zone = "private"

    # SSRF guard: refuse a target that is (or resolves to) a private/reserved/
    # metadata address unless the on-prem allowlist explicitly permits it. The
    # authoritative re-check happens again at scan time (DNS-rebinding defense).
    #
    # P7-2: a PRIVATE target is validated against its own site's policy, so an address
    # inside the site's authorized CIDRs is accepted while everything else still is not.
    # The policy was derived from persisted state above -- passing it here widens nothing
    # the site had not already been granted.
    from apps.api.scanner_engine.net_guard import TargetNotAllowed, validate_target_value

    try:
        validate_target_value(target_type, value, policy=scan_policy)
    except TargetNotAllowed as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    # A private target must additionally fall INSIDE its site's authorized CIDRs. This is
    # the check that stops tenant A attaching tenant B's address to its own site: the
    # comparison is against THIS site's list, and a site belongs to exactly one workspace.
    if site is not None and target_type in ("domain", "ip_range"):
        from apps.api.modules.private_sites import service as private_sites_service

        # Parsed from the RAW value, deliberately NOT through `_host_from_value`: that
        # helper treats "/" as a URL path separator, so it rewrites "10.0.0.0/8" to
        # "10.0.0.0" and the range's BREADTH becomes invisible. A straddling range is
        # exactly what this check exists to catch, so the prefix length must survive.
        try:
            net = ipaddress.ip_network(value.strip(), strict=False)
        except ValueError:
            net = None
        if net is not None:
            # Both edges, so a range that merely straddles an authorized CIDR is refused.
            try:
                for edge in (net.network_address, net.broadcast_address):
                    private_sites_service.assert_address_within_site(site, str(edge))
            except private_sites_service.PrivateSiteNotAuthorized as exc:
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN, f"{exc.reason}: {exc.message}"
                ) from exc
        # A hostname is deliberately NOT resolved here: private-name resolution is the
        # worker's job through the site's own resolver, and the scan-time check
        # (resolve_and_validate) is authoritative. Observed, not fixed -- see P7-3.

    from apps.api.modules.billing import service as billing

    await billing.enforce_target_quota(db, workspace_id)
    target = Target(
        project_id=project_id, type=target_type, value=value, added_by=added_by,
        criticality=criticality,
        # Both derived above; neither was taken from the request body.
        network_zone=network_zone,
        site_id=site.id if site is not None else None,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return target


async def update_target_criticality(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, target_id: uuid.UUID, criticality: str
) -> Target:
    target = await get_target(db, workspace_id, project_id, target_id)
    target.criticality = criticality
    await db.commit()
    await db.refresh(target)
    return target


async def list_targets(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, page: Pagination | None = None
) -> tuple[list[Target], int]:
    await get_project(db, workspace_id, project_id)
    query = select(Target).where(Target.project_id == project_id).order_by(Target.created_at, Target.id)
    return await paginate(db, query, page or Pagination(limit=MAX_LIMIT, offset=0))


async def get_target(
    db: AsyncSession, workspace_id: uuid.UUID, project_id: uuid.UUID, target_id: uuid.UUID
) -> Target:
    await get_project(db, workspace_id, project_id)  # 404s if project isn't in this workspace
    target = await db.scalar(select(Target).where(Target.id == target_id, Target.project_id == project_id))
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")
    return target
