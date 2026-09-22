import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.modules.risk.models import RiskScore

# How much each business-criticality tier amplifies (or dampens) technical
# severity. A critical asset doubles the effective risk of the same CVSS; a low
# asset halves it. Blueprint §7 step 7: combine CVSS with asset criticality.
CRITICALITY_WEIGHT = {"low": 0.5, "medium": 1.0, "high": 1.5, "critical": 2.0}
_MAX_RISK = 10.0

# CVSS v3.1 qualitative severity bands (NVD). Lower bound inclusive, upper inclusive.
# DELIBERATELY a function of the CVSS BASE SCORE ALONE: a 5.5 is "Medium" whether it sits on a
# throwaway host or the crown jewels. Asset criticality changes BUSINESS risk
# (final_risk_score), never the TECHNICAL severity of the flaw -- conflating the two is exactly
# the defect this exists to stop, where a Medium CVSS 5.5 on a critical asset reached
# final_risk_score 10.0 and was then read as a "Critical vulnerability".
_CVSS_BANDS = ((9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"))
_CVSS_NONE_BAND = "Medium"  # unreachable; see cvss_severity_band


def cvss_severity_band(cvss_score: float | None) -> str | None:
    """CVSS v3.1 qualitative band for a base score, or None when there is no score.

    None (not scored) stays distinct from 0.0 (scored, and it is zero -> "None" band), the same
    distinction scoring.py and the renderer already keep. Never consults asset criticality."""
    if cvss_score is None:
        return None
    if cvss_score <= 0.0:
        return "None"
    for lower, label in _CVSS_BANDS:
        if cvss_score >= lower:
            return label
    return "None"


@dataclass
class ComputedRisk:
    business_impact_score: float | None
    asset_criticality_weight: float
    final_risk_score: float | None
    rationale: str
    # --- Presentation-only additions. NEITHER is persisted (risk_scores has no column for
    # them and upsert_risk_score does not write them), so no migration and no change to any
    # stored value, frozen assessment snapshot, or security score. They exist so the report can
    # show WHY a number is what it is, instead of a bare capped 10.0.
    #
    # The technical severity band of the CVSS base score alone -- see cvss_severity_band.
    cvss_severity: str | None = None
    # What CVSS x weight came to BEFORE the _MAX_RISK cap. Without it a capped 10.0 is
    # indistinguishable from a genuine 10.0: CVSS 5.5 x 2.0 = 11.0 -> 10.0 and CVSS 9.8 x 2.0
    # = 19.6 -> 10.0 both render as "10.0", which is what made a Medium finding read as
    # Critical. None when there is no CVSS to multiply.
    uncapped_risk_score: float | None = None

    @property
    def is_capped(self) -> bool:
        """True when the cap actually bit -- i.e. final_risk_score understates the raw product."""
        return (
            self.uncapped_risk_score is not None
            and self.final_risk_score is not None
            and self.uncapped_risk_score > self.final_risk_score
        )


def compute_risk(cvss_score: float | None, criticality: str) -> ComputedRisk:
    weight = CRITICALITY_WEIGHT.get(criticality, 1.0)
    if cvss_score is None:
        return ComputedRisk(
            business_impact_score=None,
            asset_criticality_weight=weight,
            final_risk_score=None,
            rationale=f"No CVSS score available; asset criticality '{criticality}' (weight {weight}).",
            cvss_severity=None,
            uncapped_risk_score=None,
        )
    # UNCHANGED arithmetic -- this is the persisted value and every consumer (scoring
    # ._risk_factor, frozen assessment snapshots, the remediation read paths) depends on it
    # continuing to mean exactly what it meant before.
    uncapped = round(cvss_score * weight, 1)
    final = round(min(_MAX_RISK, cvss_score * weight), 1)
    band = cvss_severity_band(cvss_score)
    # Only claim "capped" when the cap ACTUALLY bit. The previous text appended
    # "(capped at 10.0)" to every rationale, so a risk of 1.5 also read as capped.
    cap_note = f" (capped at {_MAX_RISK} from {uncapped})" if uncapped > final else ""
    return ComputedRisk(
        business_impact_score=cvss_score,
        asset_criticality_weight=weight,
        final_risk_score=final,
        rationale=(
            f"CVSS {cvss_score} ({band}) x asset criticality '{criticality}' (weight {weight}) "
            f"= {final}{cap_note}. Asset criticality adjusts BUSINESS risk only; the CVSS "
            f"severity remains {band}."
        ),
        cvss_severity=band,
        uncapped_risk_score=uncapped,
    )


async def upsert_risk_score(
    db: AsyncSession, vulnerability_id: uuid.UUID, cvss_score: float | None, criticality: str
) -> None:
    """Compute and store the business risk for a vulnerability. One row per vuln;
    recomputed (updated) on re-detection so risk tracks the latest CVSS/context."""
    r = compute_risk(cvss_score, criticality)
    # Phase 0 MySQL cutover: Postgres's pg_insert(...).on_conflict_do_update(constraint=...)
    # -> mysql_insert(...).on_duplicate_key_update(...). MySQL has no `constraint=` concept
    # here -- ON DUPLICATE KEY UPDATE matches whichever unique index/PK the row violates,
    # automatically, so the uq_risk_scores_vulnerability unique constraint (unchanged,
    # still created by the table DDL) is all that's needed for this to target the right row.
    stmt = mysql_insert(RiskScore.__table__).values(
        vulnerability_id=vulnerability_id,
        business_impact_score=r.business_impact_score,
        asset_criticality_weight=r.asset_criticality_weight,
        final_risk_score=r.final_risk_score,
        rationale=r.rationale,
    )
    stmt = stmt.on_duplicate_key_update(
        business_impact_score=r.business_impact_score,
        asset_criticality_weight=r.asset_criticality_weight,
        final_risk_score=r.final_risk_score,
        rationale=r.rationale,
        computed_at=func.now(),
    )
    await db.execute(stmt)


async def get_risk_score(db: AsyncSession, vulnerability_id: uuid.UUID) -> RiskScore | None:
    return await db.scalar(select(RiskScore).where(RiskScore.vulnerability_id == vulnerability_id))
