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


def tool_pipeline() -> list[dict]:
    """The FULL registered tool pipeline, in execution (phase) order, with the
    metadata a client needs to render it.

    This exists because the frontend used to carry its own hardcoded copy of the
    pipeline (a `MODULES` list in the scan form, a `PHASE_ORDER` list in the
    progress widget). Both had drifted: `amass`, `dnsx`, `whatweb` and `ffuf`
    were registered and runnable on the backend but absent from BOTH lists, so
    they could never be selected for a scan and -- even when a scan requested
    them another way (API, schedule, AI planner) -- their ToolRun rows were
    filtered out of the progress widget entirely, hiding successes AND failures.
    Serving the list from the registry makes that drift impossible: a new runner
    in TOOL_REGISTRY appears in the UI with no frontend change.

    `produces_vulnerabilities` is derived, not declared: a runner that does not
    override `parse_vulnerabilities` can only ever write `assets`, never a
    `Vulnerability` row -- which is why a recon tool can run perfectly and still
    contribute nothing to the executive report. Clients surface that difference
    so "no vulnerabilities" is never mistaken for "nothing ran".
    """
    from apps.api.scanner_engine.capability_registry import category_for_capability
    from apps.api.scanner_engine.tool_preflight import effective_preflight
    from apps.api.scanner_engine.tool_runners.base import BaseToolRunner

    # The scanner binaries live only in the WORKER image, so this must not be resolved
    # against the calling process's own PATH -- served from the API container that would
    # mark every tool unavailable. effective_preflight() returns the worker's published
    # view, or None for "unknown", which clients render as neither available nor missing.
    status_by_tool = effective_preflight()
    out: list[dict] = []
    for name, cls in sorted(TOOL_REGISTRY.items(), key=lambda kv: (kv[1].phase, kv[0])):
        status = (status_by_tool or {}).get(name)
        out.append(
            {
                "name": name,
                "phase": cls.phase,
                "capability": cls.capability,
                "category": category_for_capability(cls.capability),
                "kill_chain_phase": cls.kill_chain_phase,
                "safety_tier": cls.safety_tier,
                "requires_active_testing": cls.requires_active_testing,
                "applicable_target_types": (
                    sorted(cls.applicable_target_types) if cls.applicable_target_types else None
                ),
                "produces_vulnerabilities": (
                    cls.parse_vulnerabilities is not BaseToolRunner.parse_vulnerabilities
                ),
                "binary": cls.binary or name,
                # True/False from the worker; None = no worker has reported yet.
                "binary_available": (None if status_by_tool is None else bool(status and status["available"])),
                "missing_requirements": list(status["missing_requirements"]) if status else [],
            }
        )
    return out
