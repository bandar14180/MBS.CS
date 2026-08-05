from apps.api.scanner_engine.tool_runners.base import BaseToolRunner
from apps.api.scanner_engine.tool_runners.httpx_runner import HttpxRunner
from apps.api.scanner_engine.tool_runners.katana_runner import KatanaRunner
from apps.api.scanner_engine.tool_runners.naabu_runner import NaabuRunner
from apps.api.scanner_engine.tool_runners.nmap_runner import NmapRunner
from apps.api.scanner_engine.tool_runners.nuclei_dast_runner import NucleiDastRunner
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner
from apps.api.scanner_engine.tool_runners.subfinder_runner import SubfinderRunner

# Extensibility point (blueprint §4/§8): a new tool means a new
# tool_runners/{name}_runner.py implementing BaseToolRunner, plus one entry
# here. Nothing else -- not the orchestrator, not the API layer, not any AI
# prompt -- needs to change. The orchestrator runs requested tools in ascending
# `phase` order, forming the deterministic recon pipeline.
TOOL_REGISTRY: dict[str, type[BaseToolRunner]] = {
    "subfinder": SubfinderRunner,
    "httpx": HttpxRunner,
    "naabu": NaabuRunner,
    "nmap": NmapRunner,
    "katana": KatanaRunner,
    "nuclei": NucleiRunner,
    "nuclei-dast": NucleiDastRunner,
}
