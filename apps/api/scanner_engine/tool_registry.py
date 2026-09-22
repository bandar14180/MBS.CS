from apps.api.scanner_engine.tool_runners.amass_runner import AmassRunner
from apps.api.scanner_engine.tool_runners.arjun_runner import ArjunRunner
from apps.api.scanner_engine.tool_runners.base import BaseToolRunner
from apps.api.scanner_engine.tool_runners.dnsx_runner import DnsxRunner
from apps.api.scanner_engine.tool_runners.ffuf_runner import FfufRunner
from apps.api.scanner_engine.tool_runners.httpx_runner import HttpxRunner
from apps.api.scanner_engine.tool_runners.katana_runner import KatanaRunner
from apps.api.scanner_engine.tool_runners.naabu_runner import NaabuRunner
from apps.api.scanner_engine.tool_runners.nmap_runner import NmapRunner
from apps.api.scanner_engine.tool_runners.nuclei_dast_runner import NucleiDastRunner
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner
from apps.api.scanner_engine.tool_runners.subfinder_runner import SubfinderRunner
from apps.api.scanner_engine.tool_runners.whatweb_runner import WhatwebRunner

# Extensibility point (blueprint §4/§8): a new tool means a new
# tool_runners/{name}_runner.py implementing BaseToolRunner, plus one entry
# here. Nothing else -- not the orchestrator, not the API layer, not any AI
# prompt -- needs to change. The orchestrator runs requested tools in ascending
# `phase` order, forming the deterministic recon pipeline.
#
# Several entries below intentionally share a `capability` with another entry
# (subfinder/amass/dnsx all serve `subdomain_discovery`; httpx/whatweb both
# serve `web_service_discovery`) -- see scanner_engine.capability_registry.
# Registering a redundant/alternate implementation of an existing capability is
# ONLY ever this: a new runner file + one line here with the same `capability`
# string. Nothing about the AI prompts, the planner, or the agent changes.
TOOL_REGISTRY: dict[str, type[BaseToolRunner]] = {
    "subfinder": SubfinderRunner,
    "amass": AmassRunner,
    "dnsx": DnsxRunner,
    "httpx": HttpxRunner,
    "whatweb": WhatwebRunner,
    "naabu": NaabuRunner,
    "nmap": NmapRunner,
    "katana": KatanaRunner,
    "ffuf": FfufRunner,
    "arjun": ArjunRunner,
    "nuclei": NucleiRunner,
    "nuclei-dast": NucleiDastRunner,
}
