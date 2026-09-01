"""Security posture scoring (0-100).

Separate module from `data.py` because the scoring semantics are a domain model in their
own right -- pure, deterministic, and testable without a database or a report.

WHY THIS REPLACED THE OLD MODEL
-------------------------------
The previous score was `100 - sum(per_row_penalty[severity])` with
critical=25/high=15/medium=7/low=3/info=0. Three defects made it unusable in practice:

  1. It counted VULNERABILITY ROWS, and a row is one (template, matcher, matched_at)
     fingerprint -- i.e. one LOCATION, not one issue. One command-injection template
     hitting 22 URLs scored as 22 independent high findings (22 x 15 = 330 penalty).
  2. Being linear and unbounded-before-clamping, it saturated at 0 after ~4 criticals or
     ~7 highs. Every materially-insecure project collapsed to the same 0/100, so the score
     carried no information exactly where it mattered most.
  3. `cvss_score` and `final_risk_score` were both ignored, so a CVSS 9.8 high and a
     CVSS 5.1 high were indistinguishable.

Observed on the real dataset: a project with 62 active non-info findings scored 0/100,
but those 62 rows were only 5 distinct issue types.

THE MODEL
---------
    active findings
      -> drop non-active statuses (fixed / false_positive / accepted_risk)
      -> drop info-severity findings AND detections (classification.py) -- see is_scorable
      -> group occurrences by underlying issue identity
      -> per-issue penalty = base(severity) x cvss_factor x risk_factor x location_factor
      -> combine issues with diminishing returns
      -> score = round(100 x PRODUCT(1 - penalty_i/100))

Each step is documented at its constant/function below.
"""

import math
from dataclasses import dataclass

# --- Status semantics -------------------------------------------------------------------
# Statuses that still count against posture. Mirrors the lifecycle in
# vulnerabilities/service.py: `fixed` (remediated), `false_positive` and `accepted_risk`
# (sticky analyst decisions the engine will not override) are all NON-active and must not
# reduce the score. `reopened` IS active -- a regression is a live problem again.
ACTIVE_STATUSES = frozenset({"open", "confirmed", "reopened"})

# --- Severity semantics -----------------------------------------------------------------
# `info` is detection-only (technology fingerprints, banner grabs, exposed-but-harmless
# metadata). It is reported for visibility and must never reduce the score, so it is
# absent from this table and filtered out before scoring.
#
# Base penalty is the score cost of ONE distinct issue of that severity at ONE location
# with neutral CVSS/risk. Chosen so a single critical is immediately visible (100 -> ~60,
# "Weak") while a single low is a nudge (100 -> ~96, still "Strong"). The gaps are wide
# enough that severity ordering survives the multiplicative factors below.
_BASE_PENALTY = {"critical": 40.0, "high": 25.0, "medium": 10.0, "low": 4.0}

# An unrecognised severity string is treated as `low` rather than dropped: an unknown
# severity is an unknown risk, and silently ignoring it would understate posture.
_UNKNOWN_SEVERITY_PENALTY = _BASE_PENALTY["low"]

# --- CVSS semantics ---------------------------------------------------------------------
# CVSS is TECHNICAL severity, 0.0-10.0. It refines the severity band rather than replacing
# it, so it is applied as a bounded multiplier around 1.0:
#     factor = _CVSS_NEUTRAL + _CVSS_SLOPE * cvss   -> 0.75 at 0.0, 1.25 at 10.0
# A missing CVSS (None) is NOT 0.0. None means "not scored" and yields a neutral 1.0
# factor; 0.0 means "scored, and it is zero" and yields the genuine 0.75 floor. That
# distinction is required by the domain (the report renders missing CVSS as N/A) and is
# the reason this is a multiplier and not an additive term.
_CVSS_NEUTRAL = 0.75
_CVSS_SLOPE = 0.05

# --- Business-risk semantics ------------------------------------------------------------
# `final_risk_score` (risk_scores.final_risk_score) is NOT another CVSS. Per risk/service.py
# it is `min(10, cvss * asset_criticality_weight)` where the weight is
# low=0.5 / medium=1.0 / high=1.5 / critical=2.0. So it is BUSINESS risk: technical severity
# re-weighted by how much the affected asset matters. Same direction as CVSS -- HIGHER means
# WORSE -- which is why it lowers the security score rather than raising it.
#
# It is deliberately given a SMALLER span than CVSS (0.85..1.15 vs 0.75..1.25) for two
# reasons: it is derived from CVSS, so a large span would double-count the same signal; and
# it saturates at the 10.0 cap for any CVSS >= 5.0 on a critical asset, which is the norm in
# practice (the entire real dataset sits at weight 2.0). Treating it as a secondary modifier
# preserves the CVSS-vs-business-risk distinction without letting a saturated field dominate.
#
# Missing risk (None -- no risk row, or a row whose CVSS was unknown) is neutral 1.0, the
# same deterministic no-opinion treatment as a missing CVSS.
_RISK_NEUTRAL = 0.85
_RISK_SLOPE = 0.03

# --- Location semantics -----------------------------------------------------------------
# The same underlying issue at N locations is worse than at one, but NOT N times worse:
# it is usually one root cause (one unpatched component, one missing header, one vulnerable
# handler) and typically one fix. Logarithmic growth encodes that:
#     factor = 1 + _LOCATION_SLOPE * ln(N)
# 1 location -> 1.00x, 4 -> 1.49x, 20 -> 2.05x, 100 -> 2.61x. Breadth registers, but 20
# locations of one issue can never cost what 20 distinct issues cost.
_LOCATION_SLOPE = 0.35

# Hard ceiling on any SINGLE issue's penalty. Guarantees no lone issue -- however severe,
# however widespread -- can drive the score to 0 on its own; reaching a very low score
# requires genuinely many distinct problems. This is what makes requirement "score must not
# reach 0 merely because the same issue affects many endpoints" structurally true rather
# than incidentally true.
_MAX_ISSUE_PENALTY = 65.0


@dataclass(frozen=True)
class ScoredIssue:
    """One underlying issue after grouping -- the unit the score is actually computed over.

    Exposed (not private) so reports, tests, and manual verification can show exactly which
    issues produced a score and what each one cost."""

    key: str  # grouping identity, e.g. "template:unix-command-injection"
    title: str  # representative (highest-severity, then longest-titled) member
    severity: str  # highest severity among the grouped occurrences
    location_count: int  # DISTINCT locations, not raw row count
    occurrence_count: int  # raw rows grouped, incl. rows sharing a location
    max_cvss: float | None  # None only when every member's CVSS is None
    max_risk: float | None  # None only when every member's final_risk_score is None
    penalty: float  # this issue's score cost, after the per-issue ceiling


def issue_key(finding) -> str:
    """Identity of the UNDERLYING issue a finding is an occurrence of.

    Deliberately NOT `fingerprint` and NOT `matched_at`. Per vulnerabilities/models.py the
    dedup identity is (project_id, fingerprint), and per nuclei_runner.py a fingerprint is
    `template_id|matcher|matched_at` -- so a fingerprint identifies one OCCURRENCE AT ONE
    LOCATION. Grouping by it would reproduce the per-row bug this module exists to fix.

    `template_id` is the correct identity: it names the vulnerability class the detection
    engine matched (`unix-command-injection`, `CVE-2022-0591`), independent of where it was
    observed. Findings with no template_id (legacy or non-nuclei rows, where
    _parse_fingerprint yields None) fall back to their own title, so each stays a distinct
    issue instead of collapsing into one shared bucket. The `template:`/`title:` prefixes
    keep a template_id from ever colliding with an identical-looking title.

    This is the same key discipline render._top_risk_groups already uses for Executive Top
    Risks, so the score and that table agree on what "one issue" means."""
    template_id = getattr(finding, "template_id", None)
    if template_id:
        return f"template:{template_id}"
    return f"title:{getattr(finding, 'title', None) or ''}"


def is_active(finding) -> bool:
    """Does this finding count against posture? See ACTIVE_STATUSES."""
    return getattr(finding, "status", None) in ACTIVE_STATUSES


def is_scorable(finding) -> bool:
    """Active AND an actual vulnerability rather than a detection-only observation.

    THREE independent exclusions, all applied here (not as a zero weight) so an excluded
    finding cannot affect grouping, counts, or the diminishing-returns product in any way:

      1. non-active status  -- fixed / false_positive / accepted_risk (see ACTIVE_STATUSES);
      2. `info` severity    -- reported for visibility, never a posture cost;
      3. a DETECTION        -- a technology/WAF/version observation is not a weakness.

    (2) and (3) are DISTINCT concepts and neither implies the other. `info` is a SEVERITY;
    a detection is a CLASSIFICATION, and nuclei emits detections at low/medium severity too
    (e.g. a `tech-detect` template rated low). Filtering on severity alone therefore let a
    pure detection reduce the score, which is exactly what classification.py exists to
    prevent -- so this defers to that SINGLE classifier rather than re-deriving a second,
    divergent detection heuristic here.

    The classifier fails toward VULNERABILITY (a positive CVSS/CVE/exploit-tag outranks every
    detection marker), so this can only ever exclude a finding that carries no vulnerability
    evidence at all -- it can never hide a real weakness from the score.

    Note this reads CLASSIFICATION, not CVSS: a finding with cvss_score=None is still fully
    scorable, and None stays distinct from 0.0 throughout (see _cvss_factor)."""
    severity = (getattr(finding, "severity", None) or "").lower()
    if not is_active(finding) or severity == "info":
        return False
    # Imported here rather than at module import: classification.py is a leaf module, but a
    # top-level import would make this pure scoring module depend on the reporting package at
    # import time. Keeping it local also keeps `scoring` importable in isolation.
    from apps.api.modules.reports.classification import DETECTION, classify_row

    return classify_row(finding) != DETECTION


def _cvss_factor(max_cvss: float | None) -> float:
    """None -> neutral 1.0 (not scored). 0.0 -> 0.75 (scored, genuinely zero)."""
    if max_cvss is None:
        return 1.0
    return _CVSS_NEUTRAL + _CVSS_SLOPE * max(0.0, min(10.0, max_cvss))


def _risk_factor(max_risk: float | None) -> float:
    """None -> neutral 1.0. Higher business risk -> higher factor -> LOWER security score."""
    if max_risk is None:
        return 1.0
    return _RISK_NEUTRAL + _RISK_SLOPE * max(0.0, min(10.0, max_risk))


def _location_factor(location_count: int) -> float:
    """Sub-linear breadth. See _LOCATION_SLOPE."""
    return 1.0 + _LOCATION_SLOPE * math.log(max(1, location_count))


def _severity_rank(severity: str | None) -> int:
    """critical=4 .. low=1, unknown=0. Used to pick a group's representative severity."""
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return order.get((severity or "").lower(), 0)


def group_issues(findings) -> list[ScoredIssue]:
    """Collapse scorable findings into distinct underlying issues, each with its penalty.

    Returned highest-penalty first, then by key, so the ordering is deterministic and the
    list can be shown verbatim as the score's explanation."""
    buckets: dict[str, list] = {}
    for f in findings:
        if not is_scorable(f):
            continue
        buckets.setdefault(issue_key(f), []).append(f)

    issues: list[ScoredIssue] = []
    for key, members in buckets.items():
        severity = max((m.severity for m in members), key=_severity_rank)

        # DISTINCT locations. Two rows at the same matched_at (e.g. different matchers of
        # one template) are one affected location, so breadth is not inflated by matcher
        # granularity. A member with no matched_at still counts as one location -- an
        # unlocated occurrence is real, it is just not attributable to a URL.
        located = {m.matched_at for m in members if getattr(m, "matched_at", None)}
        unlocated = sum(1 for m in members if not getattr(m, "matched_at", None))
        location_count = max(1, len(located) + unlocated)

        cvss_values = [m.cvss_score for m in members if getattr(m, "cvss_score", None) is not None]
        risk_values = [
            m.final_risk_score for m in members if getattr(m, "final_risk_score", None) is not None
        ]
        max_cvss = max(cvss_values) if cvss_values else None
        max_risk = max(risk_values) if risk_values else None

        base = _BASE_PENALTY.get((severity or "").lower(), _UNKNOWN_SEVERITY_PENALTY)
        penalty = (
            base
            * _cvss_factor(max_cvss)
            * _risk_factor(max_risk)
            * _location_factor(location_count)
        )
        penalty = min(_MAX_ISSUE_PENALTY, penalty)

        # Representative title: highest severity first, then the longest title as a stable,
        # content-free tiebreak (longer titles are typically the more specific ones).
        rep = max(members, key=lambda m: (_severity_rank(m.severity), len(m.title or ""), m.title or ""))

        issues.append(
            ScoredIssue(
                key=key,
                title=rep.title,
                severity=severity,
                location_count=location_count,
                occurrence_count=len(members),
                max_cvss=max_cvss,
                max_risk=max_risk,
                penalty=penalty,
            )
        )

    issues.sort(key=lambda i: (-i.penalty, i.key))
    return issues


def score_from_issues(issues) -> int:
    """Combine per-issue penalties with diminishing returns.

        score = 100 * PRODUCT over issues of (1 - penalty_i / 100)

    Each issue removes a FRACTION of the posture that remains, rather than a fixed number
    of points. Three consequences, all of them required behaviour:

      * Bounded by construction. Every factor is in [0.35, 1.0], so the product stays in
        (0, 1] and the score in [0, 100] without needing a clamp to rescue it.
      * Strictly monotone. Adding any issue with a positive penalty strictly lowers the
        score, so N distinct vulnerabilities always score below N-1 -- the linear model
        went flat at 0 and lost that ordering entirely.
      * Never spuriously 0. A score of 0 would require an infinite number of distinct
        issues; with the per-issue ceiling at 65, one issue at any breadth bottoms out at
        35. A project only approaches 0 by genuinely having many distinct serious problems.

    Rounding is applied once, at the end, so the arithmetic is exact until presentation."""
    remaining = 1.0
    for issue in issues:
        remaining *= 1.0 - min(_MAX_ISSUE_PENALTY, max(0.0, issue.penalty)) / 100.0
    return max(0, min(100, round(100 * remaining)))


def compute_security_score(findings) -> int:
    """Security posture, 0-100. Higher is better (100 = no active vulnerabilities).

    `findings` is any iterable of objects exposing `severity`, `status`, `template_id`,
    `title`, `matched_at`, `cvss_score`, `final_risk_score` -- i.e. report VulnRow, an ORM
    Vulnerability joined to its risk row, or a test stub. Pure and deterministic: the same
    findings always produce the same score, with no database, clock, or ordering dependence.
    """
    return score_from_issues(group_issues(findings))
