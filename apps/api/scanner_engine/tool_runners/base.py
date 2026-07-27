from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class RawToolOutput:
    command: str
    stdout: str
    stderr: str
    exit_code: int


@dataclass
class CommonFinding:
    """The one shape the orchestrator and (later) the AI planner ever see --
    adding a new tool means writing an adapter that produces this, nothing
    upstream needs to change (blueprint §4/§8)."""

    asset_type: str
    value: str
    metadata: dict = field(default_factory=dict)


class BaseToolRunner(ABC):
    name: str
    version: str
    requires_active_testing: bool = False

    @abstractmethod
    async def run(self, target_value: str, config: dict) -> RawToolOutput: ...

    @abstractmethod
    def parse(self, raw: RawToolOutput) -> list[CommonFinding]: ...
