import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.risk.models import RiskScore

# How much each business-criticality tier amplifies (or dampens) technical
# severity. A critical asset doubles the effective risk of the same CVSS; a low
# asset halves it. Blueprint §7 step 7: combine CVSS with asset criticality.
CRITICALITY_WEIGHT = {"low": 0.5, "medium": 1.0, "high": 1.5, "critical": 2.0}
_MAX_RISK = 10.0


@dataclass
class ComputedRisk:
    business_impact_score: float | None
    asset_criticality_weight: float
    final_risk_score: float | None
    rationale: str


def compute_risk(cvss_score: float | None, criticality: str) -> ComputedRisk:
    weight = CRITICALITY_WEIGHT.get(criticality, 1.0)
    if cvss_score is None:
        return ComputedRisk(
            business_impact_score=None,
            asset_criticality_weight=weight,
            final_risk_score=None,
            rationale=f"No CVSS score available; asset criticality '{criticality}' (weight {weight}).",
        )
    final = round(min(_MAX_RISK, cvss_score * weight), 1)
    return ComputedRisk(
        business_impact_score=cvss_score,
        asset_criticality_weight=weight,
        final_risk_score=final,
        rationale=(
            f"CVSS {cvss_score} x asset criticality '{criticality}' (weight {weight}) "
            f"= {final} (capped at {_MAX_RISK})."
        ),
    )


async def upsert_risk_score(
    db: AsyncSession, vulnerability_id: uuid.UUID, cvss_score: float | None, criticality: str
) -> None:
    """Compute and store the business risk for a vulnerability. One row per vuln;
    recomputed (updated) on re-detection so risk tracks the latest CVSS/context."""
    r = compute_risk(cvss_score, criticality)
    stmt = pg_insert(RiskScore.__table__).values(
        vulnerability_id=vulnerability_id,
        business_impact_score=r.business_impact_score,
        asset_criticality_weight=r.asset_criticality_weight,
        final_risk_score=r.final_risk_score,
        rationale=r.rationale,
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_risk_scores_vulnerability",
        set_={
            "business_impact_score": r.business_impact_score,
            "asset_criticality_weight": r.asset_criticality_weight,
            "final_risk_score": r.final_risk_score,
            "rationale": r.rationale,
            "computed_at": func.now(),
        },
    )
    await db.execute(stmt)


async def get_risk_score(db: AsyncSession, vulnerability_id: uuid.UUID) -> RiskScore | None:
    return await db.scalar(select(RiskScore).where(RiskScore.vulnerability_id == vulnerability_id))
