from dataclasses import dataclass, field

from apps.api.ai_agent.guards import REMEDIATION_FALLBACK_SUMMARY, redact_output, validate_output
from apps.api.ai_agent.providers import SupportsComplete, get_ai_client
from apps.api.ai_agent.prompts.remediation import (
    REMEDIATION_PROMPT_VERSION,
    REMEDIATION_SYSTEM,
    REMEDIATION_USER_TEMPLATE,
)
from apps.api.ai_agent.sanitize import sanitize_untrusted, wrap_untrusted


@dataclass
class RemediationResult:
    summary: str
    steps: list[str]
    references: list[dict]  # [{"title", "url"}]
    model_version: str
    prompt_version: str = REMEDIATION_PROMPT_VERSION


class RemediationWriter:
    def __init__(self, client: SupportsComplete | None = None):
        self._client = client or get_ai_client()

    def write(
        self,
        title: str,
        severity: str,
        category: str | None,
        matched_at: str | None,
        cvss_score: float | None,
        description: str | None,
    ) -> RemediationResult:
        # AI-1 Step 1-2: the finding fields are untrusted target data -> sanitize + delimit.
        finding_block = wrap_untrusted(
            "finding",
            "\n".join(
                [
                    f"- Title: {sanitize_untrusted(title, max_len=300)}",
                    f"- Severity: {sanitize_untrusted(severity, max_len=32)}",
                    f"- Category: {sanitize_untrusted(category, max_len=64) or '(unknown)'}",
                    f"- Observed at: {sanitize_untrusted(matched_at, max_len=300) or '(unknown)'}",
                    f"- CVSS: {cvss_score if cvss_score is not None else '(none)'}",
                    f"- Description: {sanitize_untrusted(description, max_len=1500) or '(none)'}",
                ]
            ),
            sanitize=False,
        )
        user = REMEDIATION_USER_TEMPLATE.format(finding_block=finding_block)
        raw = self._client.complete_json(REMEDIATION_SYSTEM, user)

        # Enforce structure in code, don't trust the model's shape blindly.
        raw_steps = [str(s) for s in raw.get("steps", []) if str(s).strip()]
        references = [
            {"title": redact_output(str(r.get("title", ""))), "url": str(r.get("url", ""))}
            for r in raw.get("references", [])
            if isinstance(r, dict) and r.get("url") and str(r.get("url", "")).lower().startswith("http")
        ]

        # AI-1 Step 3: validate + redact user-facing text. If the summary or ANY step contains an
        # exploit/destructive/"disable a control" pattern (e.g. from a prompt-injected finding),
        # withhold the whole guidance and return a safe fallback rather than deliver it.
        summary, ok, _reason = validate_output(str(raw.get("summary", "")).strip(), fallback=REMEDIATION_FALLBACK_SUMMARY)
        safe_steps: list[str] = []
        for s in raw_steps:
            s_safe, s_ok, _ = validate_output(s, fallback="")
            if not s_ok:
                ok = False
                safe_steps = []
                break
            safe_steps.append(s_safe)
        from apps.api.ai_agent.audit import ai_security_event

        if not ok:
            # AI-1 Step 4: record the block with a CATEGORY reason (never the matched target text).
            ai_security_event(
                "ai.output_blocked", agent="remediation", reason="unsafe_output",
                model_version=self._client.model_version, prompt_version=REMEDIATION_PROMPT_VERSION,
            )
            return RemediationResult(
                summary=REMEDIATION_FALLBACK_SUMMARY, steps=[], references=[],
                model_version=self._client.model_version,
            )
        ai_security_event(
            "ai.decision", agent="remediation", decision="write", blocked=False,
            steps=len(safe_steps), references=len(references),
            model_version=self._client.model_version, prompt_version=REMEDIATION_PROMPT_VERSION,
        )
        return RemediationResult(
            summary=summary,
            steps=safe_steps,
            references=references,
            model_version=self._client.model_version,
        )
