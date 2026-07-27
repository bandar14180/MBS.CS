from fastapi import APIRouter, Depends

from apps.api.core.deps import DbDep, WorkspaceContextDep, require_permission
from apps.api.modules.assistant import service
from apps.api.modules.assistant.schemas import AssistantAnswer, AssistantAsk

router = APIRouter(prefix="/workspaces/{workspace_id}/assistant", tags=["assistant"])


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
