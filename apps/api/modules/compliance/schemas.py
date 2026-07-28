import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, computed_field

from apps.api.modules.compliance.catalog import framework_name


class ComplianceMappingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    vulnerability_id: uuid.UUID
    framework: str
    control_id: str
    control_description: str | None
    created_at: datetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def framework_label(self) -> str:
        """Human-readable framework name, e.g. 'iso27001' -> 'ISO/IEC 27001'."""
        return framework_name(self.framework)
