from apps.api.scanner_engine.tool_runners.base import BaseToolRunner
from apps.api.scanner_engine.tool_runners.naabu_runner import NaabuRunner

# Extensibility point (blueprint §4/§8): a new tool means a new
# tool_runners/{name}_runner.py implementing BaseToolRunner, plus one entry
# here. Nothing else -- not the orchestrator, not the API layer, not any AI
# prompt -- needs to change.
TOOL_REGISTRY: dict[str, type[BaseToolRunner]] = {
    "naabu": NaabuRunner,
}
