import uuid
from dataclasses import dataclass
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.core import tenancy
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

    # Phase 0 MySQL cutover: bind the workspace-isolation context (apps/api/core/tenancy.py)
    # BEFORE the membership lookup below, not after. Under the old Postgres RLS flow, the
    # equivalent `set_config` call ran AFTER the membership SELECT, which worked there only
    # because the pre-check below re-filters explicitly by workspace_id/user_id regardless.
    # Binding first here is deliberate and safe even though `workspace_id` isn't verified
    # yet: the membership query is still explicitly scoped to it either way, so an
    # unauthorized caller gets exactly the same 403 -- nothing is read or returned before
    # that check. This ordering also means the tenancy filter is provably active (not
    # merely redundant with the app-layer check) for the membership query itself.
    # AUDIT-004 classification: INTENTIONALLY PERSISTENT, and it must stay that way.
    # This is a FastAPI request dependency: the binding has to outlive this function and
    # cover the whole request (router, service, and the response serialisation that may
    # lazy-load). A `with` scope here would unbind before the endpoint body ever runs.
    # Safety comes from the boundary, not the scope: each request is served in its own
    # asyncio Task with its own contextvars Context, so this binding cannot outlive the
    # request or be observed by a concurrent one (see tenancy.py's module docstring).
    tenancy.bind_workspace(workspace_id)

    member = await db.scalar(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id,
            WorkspaceMember.user_id == current_user.id,
        )
    )
    if member is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not a member of this workspace")

    # Deletion gate: once a workspace is `deleting`, block every new MUTATING operation so
    # nothing can be created into (or re-dispatched within) a half-torn-down tenant. Reads
    # (GET/HEAD/OPTIONS) still work so an operator can observe the teardown; the DELETE
    # endpoint itself is idempotent and re-entrant (it short-circuits when already deleting).
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        from apps.api.modules.workspaces.models import Workspace

        ws = await db.get(Workspace, workspace_id)
        if ws is not None and ws.status == "deleting" and request.method != "DELETE":
            raise HTTPException(status.HTTP_409_CONFLICT, "Workspace is being deleted")

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
