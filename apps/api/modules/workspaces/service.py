import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core import tenancy

from apps.api.modules.users.models import Role, User, WorkspaceMember
from apps.api.modules.workspaces.models import Workspace


async def _get_system_role_by_name(db: AsyncSession, role_name: str) -> Role:
    role = await db.scalar(select(Role).where(Role.workspace_id.is_(None), Role.name == role_name))
    if role is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown role: {role_name}")
    return role


async def create_workspace(db: AsyncSession, owner: User, name: str) -> Workspace:
    owner_role = await _get_system_role_by_name(db, "owner")

    workspace = Workspace(name=name, owner_user_id=owner.id)
    db.add(workspace)
    await db.flush()

    # No {workspace_id} path param exists yet at this point (the workspace was
    # just created), so get_workspace_context never ran to bind this. Phase 0 MySQL
    # cutover: bind it manually (tenancy.py) so the membership insert below is scoped.
    # AUDIT-004 classification: INTENTIONALLY PERSISTENT. create_workspace() runs inside a
    # request whose {workspace_id} path param does not exist yet, so nothing bound this
    # Task. The binding must persist for the rest of the request handler (the membership
    # INSERT below and anything the caller does afterwards with the new workspace), and it
    # is confined to the request's own Task/Context exactly as in core/deps.py.
    tenancy.bind_workspace(workspace.id)

    db.add(
        WorkspaceMember(
            workspace_id=workspace.id,
            user_id=owner.id,
            role_id=owner_role.id,
            joined_at=datetime.now(timezone.utc),
        )
    )
    await db.commit()
    await db.refresh(workspace)
    return workspace


async def list_workspaces_for_user(db: AsyncSession, user_id: uuid.UUID) -> list[Workspace]:
    result = await db.scalars(
        select(Workspace)
        .join(WorkspaceMember, WorkspaceMember.workspace_id == Workspace.id)
        .where(WorkspaceMember.user_id == user_id)
        .order_by(Workspace.created_at)
    )
    return list(result)


async def list_members(db: AsyncSession, workspace_id: uuid.UUID) -> list[dict]:
    rows = await db.execute(
        select(WorkspaceMember, User, Role)
        .join(User, User.id == WorkspaceMember.user_id)
        .join(Role, Role.id == WorkspaceMember.role_id)
        .where(WorkspaceMember.workspace_id == workspace_id)
        .order_by(WorkspaceMember.invited_at)
    )
    return [
        {
            "id": member.id,
            "user_id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role_name": role.name,
            "invited_at": member.invited_at,
            "joined_at": member.joined_at,
        }
        for member, user, role in rows.all()
    ]


async def invite_member(db: AsyncSession, workspace_id: uuid.UUID, email: str, role_name: str) -> dict:
    user = await db.scalar(select(User).where(User.email == email))
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No registered user with that email")

    existing = await db.scalar(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.user_id == user.id
        )
    )
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "User is already a member of this workspace")

    role = await _get_system_role_by_name(db, role_name)

    # NOTE: no pending-invite/email-token flow yet (that belongs to the
    # Notification Service, built in a later phase) -- this adds the user
    # to the workspace immediately.
    member = WorkspaceMember(
        workspace_id=workspace_id,
        user_id=user.id,
        role_id=role.id,
        joined_at=datetime.now(timezone.utc),
    )
    db.add(member)
    await db.commit()
    # `invited_at` is server-defaulted only (no client-side `default=` -- see
    # WorkspaceMember in apps/api/modules/users/models.py) and `member` was just
    # constructed in Python, so it never had a value for that column to begin with.
    # Postgres/asyncpg populated it for free via an implicit INSERT ... RETURNING, which is
    # why this worked silently pre-cutover; MySQL has no RETURNING, so without this refresh
    # the attribute is unloaded and reading it below triggers an implicit lazy SELECT that
    # async SQLAlchemy can't run outside an explicit await -- MissingGreenlet, a 500 on
    # every invite. Found by running this endpoint against real MySQL (not MariaDB, which
    # does support RETURNING and never exposed the gap).
    await db.refresh(member)

    return {
        "id": member.id,
        "user_id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role_name": role.name,
        "invited_at": member.invited_at,
        "joined_at": member.joined_at,
    }


async def _count_owners(db: AsyncSession, workspace_id: uuid.UUID) -> int:
    owner_role = await _get_system_role_by_name(db, "owner")
    count = await db.scalar(
        select(func.count())
        .select_from(WorkspaceMember)
        .where(WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.role_id == owner_role.id)
    )
    return count or 0


async def update_member_role(
    db: AsyncSession, workspace_id: uuid.UUID, target_user_id: uuid.UUID, role_name: str
) -> dict:
    member = await db.scalar(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.user_id == target_user_id
        )
    )
    if member is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Member not found")

    new_role = await _get_system_role_by_name(db, role_name)
    current_role = await db.get(Role, member.role_id)

    if current_role is not None and current_role.name == "owner" and new_role.name != "owner":
        if await _count_owners(db, workspace_id) <= 1:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Workspace must have at least one owner")

    member.role_id = new_role.id
    await db.commit()

    user = await db.get(User, target_user_id)
    if user is None:  # membership row whose user no longer exists -> 404, not a 500
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Member not found")
    return {
        "id": member.id,
        "user_id": target_user_id,
        "email": user.email,
        "full_name": user.full_name,
        "role_name": new_role.name,
        "invited_at": member.invited_at,
        "joined_at": member.joined_at,
    }


async def remove_member(db: AsyncSession, workspace_id: uuid.UUID, target_user_id: uuid.UUID) -> None:
    member = await db.scalar(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.user_id == target_user_id
        )
    )
    if member is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Member not found")

    role = await db.get(Role, member.role_id)
    if role is not None and role.name == "owner" and await _count_owners(db, workspace_id) <= 1:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Workspace must have at least one owner")

    await db.delete(member)
    await db.commit()


async def list_system_roles(db: AsyncSession) -> list[Role]:
    result = await db.scalars(select(Role).where(Role.workspace_id.is_(None)).order_by(Role.name))
    return list(result)
