import uuid

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.assistant.schemas import AssistantAnswer
from apps.api.modules.vulnerabilities.service import get_vulnerability


def _vuln_context(vuln) -> str:
    parts = [
        f"Title: {vuln.title}",
        f"Severity: {vuln.severity}",
        f"Category: {vuln.category or '(unknown)'}",
        f"CVSS: {vuln.cvss_score if vuln.cvss_score is not None else '(none)'}",
        f"Status: {vuln.status}",
    ]
    if vuln.description:
        parts.append(f"Description: {vuln.description}")
    return "\n".join(parts)


async def ask(
    db: AsyncSession,
    workspace_id: uuid.UUID,
    question: str,
    project_id: uuid.UUID | None = None,
    vulnerability_id: uuid.UUID | None = None,
) -> AssistantAnswer:
    context: str | None = None
    grounded = False

    if vulnerability_id is not None:
        if project_id is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "project_id is required when vulnerability_id is provided"
            )
        # 404s (via RLS + explicit check) if the finding isn't in this workspace/project.
        vuln = await get_vulnerability(db, workspace_id, project_id, vulnerability_id)
        context = _vuln_context(vuln)
        grounded = True

    from apps.api.ai_agent.assistant import SecurityAssistant
    from apps.api.ai_agent.providers.usage import collect_ai_usage
    from apps.api.ai_agent.usage_repo import persist_ai_usage
    from apps.api.core.observability import get_correlation_id

    try:
        # Capture token/cost usage for this call and persist it (best-effort) after.
        with collect_ai_usage(
            agent_role="assistant",
            workspace_id=workspace_id,
            correlation_id=get_correlation_id(),
        ) as usage_records:
            result = SecurityAssistant().answer(question, context)
    except RuntimeError as exc:  # no provider key configured -> fail soft (503)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))

    await persist_ai_usage(usage_records)

    return AssistantAnswer(
        answer=result.answer,
        model_version=result.model_version,
        prompt_version=result.prompt_version,
        grounded_in_vulnerability=grounded,
    )
