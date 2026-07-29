from fastapi import APIRouter, Depends
from pydantic import BaseModel

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


@ai_router.get("/status", response_model=AIStatus)
async def ai_status(current_user: CurrentUserDep) -> AIStatus:
    settings = get_settings()
    return AIStatus(enabled=bool(settings.anthropic_api_key), model=settings.ai_model)


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
