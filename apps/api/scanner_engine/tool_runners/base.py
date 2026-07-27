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

    # Position in the deterministic recon pipeline; the orchestrator runs
    # requested tools in ascending phase order regardless of request order.
    phase: int = 100

    # Target `type` values this tool applies to (None = all). The orchestrator
    # skips a requested runner when the target type doesn't match, instead of
    # running it and recording a failure (e.g. subfinder only makes sense on a
    # domain, not an ip_range).
    applicable_target_types: set[str] | None = None

    @abstractmethod
    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        """Execute the tool. `prior_findings` are the CommonFindings accumulated
        by earlier-phase tools in the same scan, so a runner can build on them
        (e.g. httpx probes subfinder's subdomains, nmap deep-scans naabu's
        ports). An empty list means run against `target_value` alone."""

    @abstractmethod
    def parse(self, raw: RawToolOutput) -> list[CommonFinding]: ...
