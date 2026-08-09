"""Compact, normalized engagement-state projection for the autonomous agent.

The RedTeamAgent must reason over the *security state*, not raw tool output. These
pure builders turn accumulated evidence into the small, bounded context the model
sees each decision cycle (blueprint §13/§26):

  * what assets/services have been discovered,
  * which MITRE ATT&CK techniques + Cyber Kill Chain phases the findings already
    evidence -- so ATT&CK/kill-chain are a *reasoning input*, not a report section
    (blueprint §16/§17), and
  * how prior actions turned out, including *why* they failed -- a failed action is
    itself evidence the model should reason around (blueprint §14).

Kept DB-free and pure so it is unit-testable and cheap; the orchestrator gathers the
raw rows (findings, kill-chain steps, outcomes) and calls these.
"""
from collections import Counter
from dataclasses import dataclass


@dataclass
class ActionOutcome:
    """One completed agent action and how it ended -- the memory of what has been
    tried, so the model doesn't blindly repeat a dead path."""

    tool: str
    status: str          # completed | partial | failed | blocked | skipped
    detail: str = ""     # short reason/result (finding count, failure/block cause)


def summarize_findings(discovered, *, max_examples: int = 8) -> str:
    """Bounded summary of discovered assets (never raw tool output). Keeps the
    model's context small as an engagement grows."""
    if not discovered:
        return "(none yet)"
    counts = Counter(f.asset_type for f in discovered)
    totals = "; ".join(f"{n} {t}(s)" for t, n in counts.items())
    examples = ", ".join(f"{f.asset_type}:{f.value}" for f in discovered[:max_examples])
    return f"{totals}. Examples: {examples}"


def summarize_attack_context(steps: list[dict]) -> str:
    """Compact MITRE ATT&CK / Cyber Kill Chain view from a scan's deterministic
    kill_chain_steps: which phases are evidenced and by which techniques. This is
    what lets the agent choose actions that ADVANCE kill-chain coverage rather than
    repeat a covered phase (blueprint §16/§17)."""
    if not steps:
        return "(no techniques mapped yet)"
    parts: list[str] = []
    for step in steps:
        techniques = step.get("techniques", [])
        techs = ", ".join(f"{t['technique_id']} {t['technique_name']}" for t in techniques)
        parts.append(f"{step['phase_name']}: {techs}" if techs else step["phase_name"])
    return " | ".join(parts)


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def summarize_attack_graph(graph: dict | None, *, max_paths: int = 3) -> str:
    """Compact, bounded view of the evidence-driven attack graph for the agent's
    reasoning context (blueprint §7): node counts plus a few highest-severity
    asset/service -> finding -> technique paths and any confirmed access. This is
    what makes the attack graph a reasoning input, not just a report artifact."""
    if not graph or not graph.get("nodes"):
        return "(empty)"
    nodes = {n["id"]: n for n in graph["nodes"]}
    counts = graph.get("counts")
    if not counts:  # build_graph output has no precomputed counts; derive them
        counts = {}
        for n in graph["nodes"]:
            counts[n["type"]] = counts.get(n["type"], 0) + 1
    header = ", ".join(f"{counts[t]} {t}" for t in sorted(counts)) or "no nodes"

    # Fold edges into: what a finding hangs off, and which techniques it maps to.
    location_of: dict[str, str] = {}
    techniques_of: dict[str, list[str]] = {}
    for e in graph.get("edges", []):
        if e["rel"] == "has_finding":
            location_of[e["target"]] = nodes.get(e["source"], {}).get("label", "?")
        elif e["rel"] == "maps_to":
            tid = (nodes.get(e["target"], {}).get("attributes") or {}).get("technique_id")
            if tid:
                techniques_of.setdefault(e["source"], []).append(tid)

    findings = [n for n in graph["nodes"] if n["type"] == "finding"]
    findings.sort(key=lambda n: _SEVERITY_RANK.get((n.get("attributes") or {}).get("severity", "info"), 0), reverse=True)
    paths: list[str] = []
    for f in findings[:max_paths]:
        loc = location_of.get(f["id"], "?")
        techs = ", ".join(dict.fromkeys(techniques_of.get(f["id"], []))) or "no technique"
        paths.append(f"{loc} -> {f['label'][:40]} -> {techs}")

    access = [n["label"] for n in graph["nodes"] if n["type"] == "access"]
    out = f"Graph: {header}."
    if paths:
        out += " Paths: " + " | ".join(paths) + "."
    if access:
        out += " Confirmed access: " + ", ".join(access[:3]) + "."
    return out[:800]


def summarize_prior_beliefs(observations, inferences, hypotheses, *, max_each: int = 4) -> str:
    """Compact carry-forward of the PREVIOUS cycle's reasoning (from the persisted
    agent_decisions row), keeping the three evidence tiers DISTINCT and explicitly
    marking hypotheses UNVERIFIED so a prior guess is never re-consumed as a fact
    (blueprint §8). Bounded (max_each per tier) to keep the prompt small (§26)."""
    observations = list(observations or [])
    inferences = list(inferences or [])
    hypotheses = list(hypotheses or [])
    if not (observations or inferences or hypotheses):
        return "(none yet)"
    parts: list[str] = []
    if observations:
        parts.append("observed: " + "; ".join(str(o) for o in observations[:max_each]))
    if inferences:
        parts.append("inferred: " + "; ".join(str(i) for i in inferences[:max_each]))
    if hypotheses:
        parts.append("hypotheses (UNVERIFIED): " + "; ".join(str(h) for h in hypotheses[:max_each]))
    return " | ".join(parts)


def summarize_actions(outcomes: list[ActionOutcome], *, max_items: int = 12) -> str:
    """Prior action outcomes (most-recent last), surfacing failures/blocks with
    their reason so the model can reason around them instead of retrying a dead
    path (blueprint §14)."""
    if not outcomes:
        return "(none yet)"
    lines: list[str] = []
    for outcome in outcomes[-max_items:]:
        line = f"{outcome.tool} -> {outcome.status}"
        if outcome.detail:
            line += f" ({outcome.detail})"
        lines.append(line)
    return "; ".join(lines)
