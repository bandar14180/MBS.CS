import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field

ScanType = Literal["web", "api", "network", "cloud"]


class ScanCreate(BaseModel):
    target_id: uuid.UUID
    scan_type: ScanType
    requested_modules: list[str] = Field(
        min_length=1, description="Tool keys from the scanner_engine tool registry, e.g. ['naabu']"
    )
    use_ai_planner: bool = Field(
        default=False,
        description="Let the AI Planner order/prune the requested tools (needs ANTHROPIC_API_KEY; "
        "falls back to deterministic order if it fails).",
    )
    use_agent: bool = Field(
        default=False,
        description="Run the autonomous RedTeamAgent: it drives tool selection dynamically by "
        "kill-chain phase within the engagement's Rules of Engagement (supersedes use_ai_planner; "
        "fail-soft).",
    )
    exploitation_enabled: bool = Field(
        default=False,
        description="Rules of Engagement: allow SAFE, non-destructive exploitation confirmation "
        "(needs the deployment to also enable it). Off by default.",
    )
    approved_hosts: list[str] = Field(
        default_factory=list,
        description="Human pre-approval: hosts the agent may attempt exploitation on ('*' = all in "
        "scope). Unapproved hosts are modeled only, never exploited.",
    )


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    workspace_id: uuid.UUID
    project_id: uuid.UUID
    target_id: uuid.UUID
    initiated_by: uuid.UUID
    scan_type: str
    status: str
    config: dict
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class ToolRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    tool_name: str
    tool_version: str
    status: str
    command_hash: str
    started_at: datetime
    completed_at: datetime | None
    exit_code: int | None
    raw_output_ref: str | None
    error_message: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at is None:
            return None
        return round((self.completed_at - self.started_at).total_seconds(), 1)


class EvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tool_run_id: uuid.UUID
    evidence_type: str
    storage_uri: str
    checksum: str
    created_at: datetime


class AIPlanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    tool_sequence: list
    reasoning_summary: str | None
    model_version: str
    prompt_version: str
    created_at: datetime


class ScanTimelineEvent(BaseModel):
    """One chronological scan event (Phase 1.3): scan started, tool executed, finding
    generated, agent decision, scan completed. No secrets -- statuses/tool names/titles
    only (the operator's own data)."""

    ts: datetime | None
    event: str
    tool: str | None = None
    status: str | None = None
    detail: str | None = None


class AgentDecisionTraceRead(BaseModel):
    """Read-only agent-decision trace (Phase 1.3). Exposes only curated, non-sensitive
    fields -- prompts are NEVER stored in agent_decisions, and raw evidence/candidate
    blobs are intentionally not surfaced here (reasoning summary only)."""

    model_config = ConfigDict(from_attributes=True)

    step_no: int
    phase: str
    action: str                       # decision type: run_tool | finish
    selected_tool: str | None = None
    selected_confidence: float | None = None
    rationale: str | None = None      # short reasoning summary (model output, bounded)
    stop_reason: str | None = None
    created_at: datetime
