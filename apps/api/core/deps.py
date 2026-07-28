import uuid
from dataclasses import dataclass
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core.config import Settings, get_settings
from apps.api.core.db import get_db
from apps.api.core.security import decode_access_token
from apps.api.modules.users.models import Permission, Role, RolePermission, User, WorkspaceMember

SettingsDep = Annotated[Settings, Depends(get_settings)]
DbDep = Annotated[AsyncSession, Depends(get_db)]

_bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    db: DbDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
) -> User:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    token = credentials.credentials

    # API-key path: keys carry a distinct prefix so they never collide with a JWT.
    # A key authenticates AS its creator, bound to its workspace (enforced in
    # get_workspace_context via request.state).
    if token.startswith("mbsk_"):
        from apps.api.modules.api_keys.service import authenticate_key

        key = await authenticate_key(db, token)
        if key is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or revoked API key")
        user = await db.get(User, key.created_by)
        if user is None or user.status != "active":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API key owner not found or inactive")
        request.state.api_key_workspace_id = key.workspace_id
        return user

    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")

    user_id = uuid.UUID(payload["sub"])
    user = await db.get(User, user_id)
    if user is None or user.status != "active":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")
    return user


CurrentUserDep = Annotated[User, Depends(get_current_user)]


@dataclass
class WorkspaceContext:
    workspace_id: uuid.UUID
    member: WorkspaceMember
    permissions: frozenset[str]


async def get_workspace_context(
    request: Request,
    workspace_id: uuid.UUID,
    db: DbDep,
    current_user: CurrentUserDep,
) -> WorkspaceContext:
    """Resolves the workspace from the `{workspace_id}` path segment. Every
    workspace-scoped router is mounted under `/workspaces/{workspace_id}/...`
    so this binds automatically as a sub-dependency."""
    # An API key may only be used for the workspace it was issued for.
    key_ws = getattr(request.state, "api_key_workspace_id", None)
    if key_ws is not None and key_ws != workspace_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "API key is not valid for this workspace")

    member = await db.scalar(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == current_user.id,
        )
    )
    if member is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not a member of this workspace")

    # Defense-in-depth: scope the DB session to this workspace for any Postgres
    # row-level security policies, in addition to the app-layer check above.
    await db.execute(
        text("SELECT set_config('app.current_workspace_id', :wid, true)"), {"wid": str(workspace_id)}
    )

    perm_keys = await db.scalars(
        select(Permission.key)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(Role, Role.id == RolePermission.role_id)
        .where(Role.id == member.role_id)
    )
    return WorkspaceContext(workspace_id=workspace_id, member=member, permissions=frozenset(perm_keys))


WorkspaceContextDep = Annotated[WorkspaceContext, Depends(get_workspace_context)]


def require_permission(permission_key: str):
    async def _check(ctx: WorkspaceContextDep) -> WorkspaceContext:
        if permission_key not in ctx.permissions:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {permission_key}")
        return ctx

    return _check
