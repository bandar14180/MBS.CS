"""Management recommendations, derived from the project's ACTUAL risk and remediation data.

DETERMINISTIC, NOT GENERATED. Every sentence below is a function of numbers already computed
by the reporting pipeline and the remediation workflow -- the security score and its band, the
active severity counts, the remediation progress rollup, the overdue count, the trend against
the previous issued snapshot. Nothing is invented, and running this twice on the same snapshot
produces byte-identical text.

WHY NOT AI HERE
---------------
An AI provider IS available in this codebase, and using it for prose would be defensible -- but
the output would then have to be labelled `ai` and could not be relied upon by the parity test,
which requires the assessment's stated numbers to match the report's exactly. Recommendations
that a client acts on should be traceable to a rule, so this stays deterministic and is
labelled `system`. If AI prose is ever added, it must be ADVISORY, carry `narrative_source =
"ai"`, and must not change any status, score, or approval -- AI proposes, humans dispose.
"""


def _plural(n: int, singular: str, plural: str | None = None) -> str:
    return singular if n == 1 else (plural or singular + "s")


def build_narrative(summary: dict, previous_summary: dict | None = None) -> str:
    """One paragraph of posture, then concrete, ranked recommendations.

    Each recommendation is emitted ONLY when the data actually supports it, so an assessment
    never advises action on something the project does not have. A project in genuinely good
    shape gets a short narrative rather than padded filler."""
    score = summary.get("security_score")
    band = summary.get("score_band") or "Unknown"
    active_by_sev = summary.get("active_severity_counts") or {}
    critical = int(active_by_sev.get("critical", 0))
    high = int(active_by_sev.get("high", 0))
    medium = int(active_by_sev.get("medium", 0))
    issues = int(summary.get("unresolved_issue_count", 0))
    progress = summary.get("remediation_progress") or {}
    overdue = int(progress.get("overdue", 0))
    open_items = int(progress.get("open", 0))
    completion = int(progress.get("completion_percent", 0))
    accepted = int(summary.get("risk_accepted_count", 0))
    assets = summary.get("affected_assets") or []
    endpoints = int(summary.get("affected_endpoint_count", 0))

    parts: list[str] = []

    # --- posture ---------------------------------------------------------------------------
    if score is None:
        parts.append("Security posture has not yet been scored for this period.")
    else:
        parts.append(
            f"The project's security score is {score}/100 ({band}), derived from "
            f"{issues} distinct unresolved {_plural(issues, 'issue')} across "
            f"{len(assets)} affected {_plural(len(assets), 'asset')} and {endpoints} "
            f"affected {_plural(endpoints, 'endpoint')}."
        )

    # --- trend, only when there is a real predecessor to compare against --------------------
    if previous_summary:
        prev_score = previous_summary.get("security_score")
        if prev_score is not None and score is not None:
            delta = score - prev_score
            if delta > 0:
                parts.append(
                    f"This is an improvement of {delta} {_plural(delta, 'point')} since the "
                    f"previous assessment ({prev_score}/100)."
                )
            elif delta < 0:
                parts.append(
                    f"This is a decline of {abs(delta)} {_plural(abs(delta), 'point')} since "
                    f"the previous assessment ({prev_score}/100), which warrants attention "
                    "before the next reporting period."
                )
            else:
                parts.append(
                    f"The score is unchanged from the previous assessment ({prev_score}/100)."
                )

    # --- recommendations, ordered by what actually matters most ----------------------------
    recs: list[str] = []
    if critical:
        recs.append(
            f"Remediate the {critical} active critical-severity {_plural(critical, 'finding')} "
            "first; these carry the largest single contribution to the score and should be "
            "scheduled immediately."
        )
    if high:
        recs.append(
            f"Address the {high} active high-severity {_plural(high, 'finding')} in the current "
            "remediation cycle."
        )
    if overdue:
        recs.append(
            f"{overdue} remediation {_plural(overdue, 'item is', 'items are')} past the agreed "
            "due date. Re-baseline the dates or escalate ownership -- an overdue item is an "
            "unmanaged risk, not a scheduled one."
        )
    if open_items and completion < 50:
        recs.append(
            f"Remediation completion stands at {completion}%, with {open_items} "
            f"{_plural(open_items, 'item')} still outstanding. Assign owners and due dates to "
            "any unassigned items so progress becomes measurable."
        )
    if accepted:
        recs.append(
            f"{accepted} {_plural(accepted, 'finding has', 'findings have')} a formal risk "
            "acceptance in force. Confirm each acceptance is still justified before its expiry "
            "date, since an accepted risk remains a live technical exposure."
        )
    if medium and not (critical or high):
        recs.append(
            f"With no critical or high-severity findings outstanding, the {medium} active "
            f"medium-severity {_plural(medium, 'finding')} represent the next meaningful "
            "improvement to the score."
        )
    if not recs:
        recs.append(
            "No outstanding critical or high-severity findings and no overdue remediation work. "
            "Maintain the current scanning cadence and re-assess next period."
        )

    parts.append("Recommended management actions:")
    parts.extend(f"{i}. {rec}" for i, rec in enumerate(recs, start=1))
    return "\n".join(parts)
