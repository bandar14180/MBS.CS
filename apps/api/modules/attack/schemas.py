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
