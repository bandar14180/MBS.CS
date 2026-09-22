"""Capability Registry (scanner_engine.capability_registry) -- the indirection
layer between the AI decision layers and TOOL_REGISTRY, plus the DISCOVERY/
WEB/NETWORK category grouping on top of it. Pure -- no DB."""
from apps.api.scanner_engine.capability_registry import (
    CAPABILITY_CATEGORY,
    capabilities,
    capability_for_tool,
    capability_registry,
    category_for_capability,
    category_tree,
    resolve_capability,
)
from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY


def test_every_capability_is_categorized():
    # An uncategorized capability would silently vanish from category_tree()'s
    # AI/API-facing tree -- catch that here, not in production.
    for capability in capabilities():
        assert capability in CAPABILITY_CATEGORY, f"{capability!r} has no entry in CAPABILITY_CATEGORY"


def test_every_registered_tool_has_a_capability():
    for name, cls in TOOL_REGISTRY.items():
        assert cls.capability, f"{name!r} runner has no `capability` set"


def test_capability_registry_groups_by_phase_order():
    reg = capability_registry()
    assert reg["subdomain_discovery"] == ["subfinder", "amass", "dnsx"]
    assert reg["web_service_discovery"] == ["httpx", "whatweb"]
    assert reg["port_discovery"] == ["naabu"]


def test_capability_for_tool_roundtrip():
    assert capability_for_tool("subfinder") == "subdomain_discovery"
    assert capability_for_tool("nonexistent-tool") is None


def test_category_for_capability():
    assert category_for_capability("subdomain_discovery") == "discovery"
    assert category_for_capability("vulnerability_detection") == "web"
    assert category_for_capability("port_discovery") == "network"
    assert category_for_capability("made_up_capability") == "uncategorized"


def test_category_tree_shape():
    tree = category_tree()
    assert set(tree) == {"discovery", "web", "network"}
    assert tree["discovery"]["subdomain_discovery"] == ["subfinder", "amass", "dnsx"]
    assert tree["network"]["port_discovery"] == ["naabu"]
    assert tree["web"]["web_service_discovery"] == ["httpx", "whatweb"]


def test_resolve_capability_picks_first_qualifying_implementation():
    # subfinder(phase 10) qualifies before amass(11)/dnsx(15) on a plain domain target.
    assert resolve_capability(
        "subdomain_discovery", target_type="domain", active_testing_allowed=False, max_tier="passive",
    ) == "subfinder"


def test_resolve_capability_skips_already_run():
    assert resolve_capability(
        "subdomain_discovery", target_type="domain", active_testing_allowed=False, max_tier="passive",
        already_run=frozenset({"subfinder"}),
    ) == "amass"


def test_resolve_capability_respects_safety_ceiling():
    # nuclei is active_safe; a passive ceiling excludes it -> no implementation qualifies.
    assert resolve_capability(
        "vulnerability_detection", target_type="domain", active_testing_allowed=True, max_tier="passive",
    ) is None


def test_resolve_capability_gates_active_testing():
    assert resolve_capability(
        "vulnerability_detection", target_type="domain", active_testing_allowed=False, max_tier="active_safe",
    ) is None
    assert resolve_capability(
        "vulnerability_detection", target_type="domain", active_testing_allowed=True, max_tier="active_safe",
    ) == "nuclei"
