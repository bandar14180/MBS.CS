from dataclasses import dataclass, field

from apps.api.ai_agent.claude_client import ClaudeClient, SupportsComplete
from apps.api.ai_agent.prompts.remediation import (
    REMEDIATION_PROMPT_VERSION,
    REMEDIATION_SYSTEM,
    REMEDIATION_USER_TEMPLATE,
)


@dataclass
class RemediationResult:
    summary: str
    steps: list[str]
    references: list[dict]  # [{"title", "url"}]
    model_version: str
    prompt_version: str = REMEDIATION_PROMPT_VERSION


class RemediationWriter:
    def __init__(self, client: SupportsComplete | None = None):
        self._client = client or ClaudeClient()

    def write(
        self,
        title: str,
        severity: str,
        category: str | None,
        matched_at: str | None,
        cvss_score: float | None,
        description: str | None,
    ) -> RemediationResult:
        user = REMEDIATION_USER_TEMPLATE.format(
            title=title,
            severity=severity,
            category=category or "(unknown)",
            matched_at=matched_at or "(unknown)",
            cvss=cvss_score if cvss_score is not None else "(none)",
            description=description or "(none)",
        )
        raw = self._client.complete_json(REMEDIATION_SYSTEM, user)

        # Enforce structure in code, don't trust the model's shape blindly.
        steps = [str(s) for s in raw.get("steps", []) if str(s).strip()]
        references = [
            {"title": str(r.get("title", "")), "url": str(r.get("url", ""))}
            for r in raw.get("references", [])
            if isinstance(r, dict) and r.get("url")
        ]
        return RemediationResult(
            summary=str(raw.get("summary", "")).strip(),
            steps=steps,
            references=references,
            model_version=self._client.model_version,
        )
