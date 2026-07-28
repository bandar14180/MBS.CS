"""Subscription plan catalog. Static for now (no payment processor yet) -- the
enforcement architecture is what matters: every quota check reads a workspace's
`plan_tier` and looks the limits up here.

`None` means unlimited. `pilot` is the default tier for new/existing workspaces
(the current beta) and is intentionally unlimited so nothing is retroactively
capped; paid tiers (free/pro/enterprise) opt into real limits.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Plan:
    tier: str
    name: str
    max_projects: int | None
    max_targets: int | None
    max_scans_per_month: int | None
    price_usd_month: int  # informational; billing integration is future work


PLANS: dict[str, Plan] = {
    "free": Plan("free", "Free", max_projects=2, max_targets=5, max_scans_per_month=10, price_usd_month=0),
    "pro": Plan("pro", "Professional", max_projects=25, max_targets=200, max_scans_per_month=500, price_usd_month=99),
    "enterprise": Plan(
        "enterprise", "Enterprise", max_projects=None, max_targets=None, max_scans_per_month=None, price_usd_month=0
    ),
    # Default/beta tier -- unlimited so existing workspaces are never capped.
    "pilot": Plan("pilot", "Pilot", max_projects=None, max_targets=None, max_scans_per_month=None, price_usd_month=0),
}

# Tiers a customer may self-select via the API (pilot is internal/default only).
SELECTABLE_TIERS = ("free", "pro", "enterprise")

DEFAULT_TIER = "pilot"


def get_plan(tier: str | None) -> Plan:
    """Resolve a workspace's plan; unknown tiers fall back to the default (unlimited)
    so a bad/legacy value never accidentally blocks a workspace."""
    return PLANS.get(tier or DEFAULT_TIER, PLANS[DEFAULT_TIER])
