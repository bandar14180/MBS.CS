from fastapi import APIRouter, Depends
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from apps.api.core.config import get_settings
from apps.api.core.deps import CurrentUserDep, DbDep, WorkspaceContextDep, require_permission
from apps.api.modules.assistant import service
from apps.api.modules.assistant.schemas import AssistantAnswer, AssistantAsk

router = APIRouter(prefix="/workspaces/{workspace_id}/assistant", tags=["assistant"])

# AI status (whether the live AI layer is configured) — top-level, any signed-in user.
ai_router = APIRouter(prefix="/ai", tags=["ai"])


class AIStatus(BaseModel):
    enabled: bool
    model: str
    provider: str
    # For the local provider: whether the model server is currently reachable.
    # None for hosted providers (a reachability probe would cost a paid call).
    reachable: bool | None = None


@ai_router.get("/status", response_model=AIStatus)
async def ai_status(current_user: CurrentUserDep) -> AIStatus:
    settings = get_settings()
    # Provider-aware: reports whichever provider/model is configured. `enabled`
    # reflects the selected provider having a key (kept backward compatible -- the
    # field name/shape is unchanged; `provider`/`reachable` are additive).
    reachable: bool | None = None
    if settings.ai_provider == "local":
        from apps.api.ai_agent.providers.local import LocalClient

        # Best-effort, off the event loop; never fails the endpoint.
        reachable = await run_in_threadpool(LocalClient().health)
    return AIStatus(
        enabled=settings.ai_enabled,
        model=settings.active_ai_model,
        provider=settings.ai_provider,
        reachable=reachable,
    )


@router.post(
    "/ask",
    response_model=AssistantAnswer,
    dependencies=[Depends(require_permission("project:read"))],
)
async def ask(payload: AssistantAsk, db: DbDep, ctx: WorkspaceContextDep) -> AssistantAnswer:
    return await service.ask(
        db,
        ctx.workspace_id,
        payload.question,
        project_id=payload.project_id,
        vulnerability_id=payload.vulnerability_id,
    )
