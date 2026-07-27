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

    try:
        result = SecurityAssistant().answer(question, context)
    except RuntimeError as exc:  # ANTHROPIC_API_KEY not set
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))

    return AssistantAnswer(
        answer=result.answer,
        model_version=result.model_version,
        prompt_version=result.prompt_version,
        grounded_in_vulnerability=grounded,
    )
