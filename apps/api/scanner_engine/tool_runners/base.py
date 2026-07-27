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
    """An inventory finding (a discovered asset). The orchestrator upserts these
    into the assets table. Adding a new tool means writing an adapter that
    produces these, nothing upstream needs to change (blueprint §4/§8)."""

    asset_type: str
    value: str
    metadata: dict = field(default_factory=dict)


@dataclass
class VulnerabilityFinding:
    """A vulnerability finding (something wrong, not just something present).
    The orchestrator feeds these to the Vulnerability Engine, which dedupes them
    across scans and links each to the tool-run evidence that produced it
    (blueprint §1: no evidence => not a finding)."""

    fingerprint: str  # stable identity for dedup across re-scans (e.g. template-id@matched-at)
    title: str
    severity: str  # info | low | medium | high | critical
    category: str | None = None  # CWE id / OWASP category / template tag
    description: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None
    matched_at: str | None = None  # URL/host:port the finding was observed at
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
    def parse(self, raw: RawToolOutput) -> list[CommonFinding]:
        """Assets discovered by this tool. Recon tools implement this."""

    def parse_vulnerabilities(self, raw: RawToolOutput) -> list["VulnerabilityFinding"]:
        """Vulnerabilities found by this tool. Defaults to none so recon tools
        (which only inventory assets) don't need to implement it; vuln scanners
        like Nuclei override it."""
        return []
