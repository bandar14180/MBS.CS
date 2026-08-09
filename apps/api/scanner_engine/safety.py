"""Safety enforcement for the autonomous red-team agent.

A HARD, code-enforced boundary (never prompt-based): every action the agent takes
must pass `assert_action_allowed()` before execution. Non-destructive by
construction -- any operation that could modify / delete / persist / exfiltrate is
denied, and real exploitation is gated behind explicit Rules of Engagement.

Philosophy: **prove access, never cause damage.** Even if the model misbehaves, it
cannot reach a destructive action because the execution layer refuses it.
"""
from dataclasses import dataclass, field


class SafetyTier:
    PASSIVE = "passive"          # public / passive recon; no state-changing traffic to the target
    ACTIVE_SAFE = "active_safe"  # active but non-intrusive (port scan, version detect, vuln DETECTION)
    INTRUSIVE = "intrusive"      # real exploitation / foothold -- gated (exploitation_enabled + approval)
    SIMULATED = "simulated"      # modeled only; never executed against the target


# Ordered severity for the ceiling check (SIMULATED is not an execution tier).
_TIER_ORDER = {SafetyTier.PASSIVE: 0, SafetyTier.ACTIVE_SAFE: 1, SafetyTier.INTRUSIVE: 2}

# Read-only "proof of access" post-exploitation primitives. Anything NOT here is denied.
DEFAULT_POST_EXPLOIT_ALLOWLIST = frozenset(
    {"whoami", "id", "hostname", "uname", "pwd", "list_dir", "count_rows", "read_canary"}
)

# Backstop deny-list (defense in depth; the post-exploit allowlist is the primary
# control). Command-like words are matched at WORD boundaries so a benign token like
# "confirm" or "perform" is never mistaken for the "rm" command; a few
# unambiguous phrases/redirects are matched as substrings.
_DESTRUCTIVE_WORDS = frozenset(
    {
        "delete", "drop", "truncate", "insert", "update", "write", "rm", "unlink",
        "chmod", "chown", "mkfs", "format", "shutdown", "reboot", "kill", "persist",
        "backdoor", "implant", "exfil", "exfiltrate", "encrypt", "ransom",
    }
)
_DESTRUCTIVE_SUBSTRINGS = (">>", " > ")


class SafetyViolation(RuntimeError):
    """Raised when an action is denied by the safety policy (agent must stop/abort)."""


@dataclass(frozen=True)
class RulesOfEngagement:
    """Per-engagement safety envelope. Built from the scan config, but never more
    permissive than the deployment-wide settings ceiling."""

    max_tier: str = SafetyTier.ACTIVE_SAFE       # ceiling; INTRUSIVE also needs exploitation_enabled
    exploitation_enabled: bool = False           # gate for INTRUSIVE actions
    require_approval: bool = True                # human-in-the-loop before first foothold per host
    allowed_post_exploit: frozenset = field(default_factory=lambda: DEFAULT_POST_EXPLOIT_ALLOWLIST)

    @classmethod
    def from_config(cls, scan_config: dict | None = None) -> "RulesOfEngagement":
        from apps.api.core.config import get_settings

        s = get_settings()
        cfg = scan_config or {}
        ceiling = s.agent_safety_ceiling
        requested = cfg.get("safety_tier", ceiling)
        # config can restrict but never exceed the settings ceiling.
        max_tier = requested if tier_at_most(requested, ceiling) else ceiling
        return cls(
            max_tier=max_tier,
            # exploitation needs BOTH the engagement flag AND the deployment to allow it.
            exploitation_enabled=bool(cfg.get("exploitation_enabled", False)) and s.agent_exploitation_enabled,
            require_approval=bool(cfg.get("require_approval", True)),
        )


def tier_at_most(tier: str, ceiling: str) -> bool:
    return _TIER_ORDER.get(tier, 99) <= _TIER_ORDER.get(ceiling, -1)


def is_destructive(operation: str) -> bool:
    import re

    op = (operation or "").lower()
    if any(sub in op for sub in _DESTRUCTIVE_SUBSTRINGS):
        return True
    words = set(re.findall(r"[a-z]+", op))
    return bool(words & _DESTRUCTIVE_WORDS)


def assert_action_allowed(
    *,
    safety_tier: str,
    roe: RulesOfEngagement,
    operation: str = "",
    post_exploit_primitive: str | None = None,
) -> None:
    """The non-bypassable gate. Raises SafetyViolation if the action is not permitted.

    - A `simulated` action never touches the target -> always allowed (it's analysis).
    - Any destructive `operation` is denied outright (backstop).
    - `safety_tier` must be within the RoE ceiling; INTRUSIVE additionally requires
      exploitation_enabled.
    - Post-exploitation must name a primitive on the read-only allowlist.
    """
    if safety_tier == SafetyTier.SIMULATED:
        return
    if is_destructive(operation):
        raise SafetyViolation(f"destructive operation denied: {operation[:80]!r}")
    if not tier_at_most(safety_tier, roe.max_tier):
        raise SafetyViolation(f"safety_tier '{safety_tier}' exceeds engagement ceiling '{roe.max_tier}'")
    if safety_tier == SafetyTier.INTRUSIVE and not roe.exploitation_enabled:
        raise SafetyViolation("active exploitation is not enabled for this engagement")
    if post_exploit_primitive is not None and post_exploit_primitive not in roe.allowed_post_exploit:
        raise SafetyViolation(
            f"post-exploit primitive '{post_exploit_primitive}' is not on the read-only allowlist"
        )
