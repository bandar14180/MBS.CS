"""Scanner capability registry — the single source of truth for which target
types the platform can actually assess.

Today only network hosts (domain / ip_range) have a working engine. `api`,
`cloud_account`, and `repo` are accepted as target *types* (for inventory) but have
no scanner, so a scan on them is refused at creation rather than "completing"
having assessed nothing (no hollow success). Adding a future engine is a matter of
listing its target type here and registering its runners — the API and the
create-scan guard derive everything from this registry.

Config (`supported_target_types`) may only NARROW the code-known scannable set; it
can never enable a type that has no engine.
"""
from apps.api.core.config import get_settings
from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY

# Target types that a real scanner engine exists for, in code. This is the ceiling.
_ENGINE_TARGET_TYPES: frozenset[str] = frozenset({"domain", "ip_range"})


def supported_target_types() -> set[str]:
    """Target types that both have an engine AND are enabled by config. The
    intersection means SUPPORTED_TARGET_TYPES can restrict but never widen beyond
    what is actually implemented."""
    configured = set(get_settings().supported_target_types)
    return set(_ENGINE_TARGET_TYPES) & configured


def is_supported(target_type: str) -> bool:
    return target_type in supported_target_types()


def scanners_for(target_type: str) -> list[str]:
    """The tool modules that apply to a target type (a runner applies when its
    `applicable_target_types` is None or includes the type). Empty for unsupported
    types."""
    if not is_supported(target_type):
        return []
    names: list[str] = []
    for name, runner_cls in TOOL_REGISTRY.items():
        applies = runner_cls.applicable_target_types
        if applies is None or target_type in applies:
            names.append(name)
    return sorted(names)


def capability_map() -> dict[str, dict]:
    """Full capability view for the API: every known target type with whether it is
    supported and, if so, which scanners run for it."""
    from apps.api.modules.projects.schemas import TargetType  # Literal of all types

    all_types = list(getattr(TargetType, "__args__", ("domain", "ip_range")))
    return {
        t: {"supported": is_supported(t), "scanners": scanners_for(t)}
        for t in all_types
    }
