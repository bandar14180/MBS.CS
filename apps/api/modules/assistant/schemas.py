import uuid

from pydantic import BaseModel, Field


class AssistantAsk(BaseModel):
    question: str = Field(min_length=3, max_length=2000, description="The user's security question.")
    # Optional grounding: when a vulnerability is referenced, project_id is required
    # too so the finding can be loaded and verified within this workspace.
    project_id: uuid.UUID | None = None
    vulnerability_id: uuid.UUID | None = None


class AssistantAnswer(BaseModel):
    answer: str
    model_version: str
    prompt_version: str
    grounded_in_vulnerability: bool = False
