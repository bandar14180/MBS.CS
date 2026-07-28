from pydantic import BaseModel


class UsageCounts(BaseModel):
    projects: int
    targets: int
    scans_this_month: int


class PlanLimits(BaseModel):
    projects: int | None
    targets: int | None
    scans_per_month: int | None


class UsageRead(BaseModel):
    plan_tier: str
    plan_name: str
    price_usd_month: int
    usage: UsageCounts
    limits: PlanLimits


class PlanUpdate(BaseModel):
    tier: str


class PlanCatalogItem(BaseModel):
    tier: str
    name: str
    price_usd_month: int
    max_projects: int | None
    max_targets: int | None
    max_scans_per_month: int | None
