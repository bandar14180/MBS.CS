import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AttackMappingRead(BaseModel):
    """One vulnerability -> MITRE ATT&CK technique + Cyber Kill Chain phase."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    vulnerability_id: uuid.UUID
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    kill_chain_phase: str
    created_at: datetime


class TechniqueHit(BaseModel):
    technique_id: str
    technique_name: str
    kill_chain_phase: str
    count: int


class TacticMatrixRead(BaseModel):
    """One column of the ATT&CK matrix: a tactic and the techniques hit under it."""

    tactic_id: str
    tactic_name: str
    techniques: list[TechniqueHit]


class KillChainTechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    findings: list[str]


class KillChainStep(BaseModel):
    phase: str
    phase_name: str
    techniques: list[KillChainTechnique]


class KillChainRead(BaseModel):
    """A scan's Cyber Kill Chain view. `ai_generated` distinguishes the AI
    Correlator narrative from the deterministic fallback."""

    ai_generated: bool
    summary: str | None = None
    model_version: str | None = None
    steps: list[KillChainStep]


class AttackGraphRead(BaseModel):
    """Read-only view of a scan's evidence-driven attack graph (M4.4.5), sourced from
    the persisted EngagementState.attack_graph -- never recomputed and never writable
    via the API. `has_engagement` is False for a non-agent scan (empty graph, not a
    404). The graph dict is the actual persisted nodes/edges/counts/confirmed_access."""

    has_engagement: bool
    status: str | None = None
    current_phase: str | None = None
    objective: str | None = None
    graph: dict = {}
