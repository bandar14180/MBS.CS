"""Capability Registry -- the indirection layer between WHAT the AI decision
layers (AIPlanner, RedTeamAgent) reason about and WHICH concrete tool actually
runs.

Every BaseToolRunner declares a `capability` (e.g. "subdomain_discovery",
"vulnerability_detection"): the assessment capability it provides, independent
of the binary's name. The AI never needs to know a specific tool exists -- it
reasons in terms of capabilities, and this registry (combined with the
runner's own policy attributes: safety_tier, applicable_target_types,
requires_active_testing) resolves a capability to the best available
implementation, the way `TOOL_REGISTRY` resolves a tool name to a runner
class.

Today every capability has exactly one implementation, so `resolve_capability`
behaves identically to picking that one tool. The point is what happens
tomorrow: registering a second implementation of an existing capability (e.g.
a `massdns` runner alongside `subfinder` for `subdomain_discovery`) is then
just one new TOOL_REGISTRY entry sharing the same `capability` string --
nothing in the AI prompts, the planner, the agent, or the orchestrator needs
to change.
"""
from apps.api.scanner_engine.safety import tier_at_most
from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY


def capability_registry() -> dict[str, list[str]]:
    """capability -> tool names implementing it, ordered by pipeline phase (the
    preferred/first implementation of a capability sorts first)."""
    out: dict[str, list[str]] = {}
    for name, cls in sorted(TOOL_REGISTRY.items(), key=lambda kv: kv[1].phase):
        out.setdefault(cls.capability, []).append(name)
    return out


def capabilities() -> list[str]:
    """Every distinct capability the platform currently has at least one tool for."""
    return sorted(capability_registry())


def tools_for_capability(capability: str) -> list[str]:
    return capability_registry().get(capability, [])


def capability_for_tool(name: str) -> str | None:
    cls = TOOL_REGISTRY.get(name)
    return cls.capability if cls else None


class Category:
    """The three assessment-surface categories the Capability Registry groups
    capabilities into -- the layer between the registry and its capabilities
    (Registry -> Category -> Capability -> Tool)."""

    DISCOVERY = "discovery"  # finding assets that exist (hosts, subdomains)
    WEB = "web"               # everything that speaks HTTP: probing, crawling, fuzzing, vuln detection
    NETWORK = "network"       # raw TCP/service-layer recon


# capability -> category. Every capability the platform has a tool for must be
# listed here (enforced by tests/test_capability_registry.py) -- an
# uncategorized capability would silently vanish from the CAPABILITY REGISTRY
# tree that category_tree() builds for the AI/API.
CAPABILITY_CATEGORY: dict[str, str] = {
    "subdomain_discovery": Category.DISCOVERY,
    "web_service_discovery": Category.WEB,
    "web_crawling": Category.WEB,
    "content_discovery": Category.WEB,
    "parameter_discovery": Category.WEB,
    "vulnerability_detection": Category.WEB,
    "dast_fuzzing": Category.WEB,
    "port_discovery": Category.NETWORK,
    "service_fingerprinting": Category.NETWORK,
}


def category_for_capability(capability: str) -> str:
    return CAPABILITY_CATEGORY.get(capability, "uncategorized")


def categories() -> dict[str, list[str]]:
    """category -> capabilities in it (only capabilities with a registered tool)."""
    out: dict[str, list[str]] = {}
    for capability in capabilities():
        out.setdefault(category_for_capability(capability), []).append(capability)
    return out


def category_tree() -> dict[str, dict[str, list[str]]]:
    """category -> {capability -> [tool names]} -- the full CAPABILITY REGISTRY
    tree from the architecture diagram (Registry -> DISCOVERY/WEB/NETWORK ->
    capability -> tool). Pure presentation/reasoning structure: resolution still
    goes through `resolve_capability`, this is just the tree shape."""
    tree: dict[str, dict[str, list[str]]] = {}
    for capability, tools in capability_registry().items():
        tree.setdefault(category_for_capability(capability), {})[capability] = tools
    return tree


def resolve_capability(
    capability: str,
    *,
    target_type: str,
    active_testing_allowed: bool,
    max_tier: str,
    already_run: frozenset[str] = frozenset(),
) -> str | None:
    """Pick the tool that should serve `capability` right now -- the
    REGISTRY's decision, never the AI's. Returns the first (highest-priority)
    implementation that applies to the target type, is within the safety
    ceiling, is active-testing-gated correctly, and hasn't already run in this
    engagement. None if no implementation currently qualifies."""
    for name in tools_for_capability(capability):
        if name in already_run:
            continue
        cls = TOOL_REGISTRY[name]
        if cls.applicable_target_types is not None and target_type not in cls.applicable_target_types:
            continue
        if not tier_at_most(cls.safety_tier, max_tier):
            continue
        if cls.requires_active_testing and not active_testing_allowed:
            continue
        return name
    return None
