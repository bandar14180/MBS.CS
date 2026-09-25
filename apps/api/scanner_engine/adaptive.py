"""Adaptive Detection Engine -- deterministic, evidence-driven next-step selection (Prompt 21).

WHAT THIS IS, and the two things it is emphatically NOT.

The platform already has two ways to decide what runs: the DETERMINISTIC fixed-phase pipeline
(run_scan's non-agent path), which is not adaptive, and the LLM-driven RedTeamAgent
(_run_agent_driven), which is adaptive but its candidate PROPOSAL is a model call and is
therefore not deterministic. Prompt 21 asks for adaptive selection that is BOTH -- adaptive
AND deterministic, bounded, scope/tenant-safe, evidence-driven and reproducible.

This module is that: a PURE function that reads the intelligence Prompts 14-20 already
produced (coverage/debt state, canonical endpoint identity, evidence-backed parameters, API
classification, authentication state) and emits an ordered set of ELIGIBLE next detection
steps -- CANDIDATES, never findings. It:

  * invents nothing -- every candidate is derived from an existing CommonFinding/asset and
    carries its provenance;
  * decides eligibility deterministically from evidence + coverage state;
  * defers ALL authority to the existing guards -- capability_registry.resolve_capability for
    tool selection (safety tier / active-testing / already-run), scope_guard for scope, safety
    for the RoE ceiling. It re-applies them, it never replaces or relaxes them;
  * is bounded -- it dedups by canonical identity and drops anything whose capability already
    ran, so it cannot generate the same work twice or recurse without progress;
  * is fail-soft and pure -- no DB, no network, no randomness, no LLM.

THE HARD INVARIANT (Prompt 21 §6): a candidate is a SIGNAL, not a finding. This module ends
at "this capability is eligible for this target, and here is why". Executing it, capturing
evidence and verifying a vulnerability remain the existing pipeline's job, unchanged.

    signal -> candidate (HERE) -> test -> observation -> evidence -> verification -> finding

DETERMINISM: candidates are produced by iterating findings in input order, and the final list
is sorted by a stable total key (capability phase, then reason strength, then canonical
target, then capability name). Identical state in -> identical ordered candidates out.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from apps.api.scanner_engine import scope_guard
from apps.api.scanner_engine.capability_registry import resolve_capability
from apps.api.scanner_engine.coverage import (
    STATE_ATTEMPTED_FAILED,
    STATE_DISCOVERED,
    STATE_PARTIAL,
    ToolRunOutcome,
    build_coverage,
)
from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY

# Coverage states that mean "this surface still has an unfulfilled, in-scope testing
# opportunity" -- i.e. a candidate here is justified. A `covered`/`verified` surface is done;
# `requires_auth`/`out_of_scope`/`unsupported` are deliberately NOT adaptive work (we do not
# invent credentials, cross scope, or run a tool that does not exist).
_ACTIONABLE_COVERAGE = frozenset({STATE_DISCOVERED, STATE_ATTEMPTED_FAILED, STATE_PARTIAL})

# Reason codes are STABLE, machine-checkable strings (not free text) so a decision trace is
# reproducible and testable. Order in this tuple is the strength ranking used for tie-breaking
# (earlier = stronger signal), so ordering never depends on set iteration.
_REASON_STRENGTH = (
    "discovered_parameter",       # an evidence-backed param exists -> the strongest DAST signal
    "api_surface",                # the endpoint is classified as an API
    "live_web_service",           # httpx confirmed a live HTTP service
    "incomplete_coverage",        # the expected capability has not adequately run
    "attempted_failed_upstream",  # the expected capability ran but failed -> retry is justified
    "partial_upstream",           # the expected capability only partially ran
)
_REASON_RANK = {code: i for i, code in enumerate(_REASON_STRENGTH)}


@dataclass(frozen=True)
class AdaptiveCandidate:
    """One eligible next detection step. A CANDIDATE, never a finding.

    `capability` is the assessment capability to run (registry indirection), `tool` is the
    concrete implementation the registry resolved for it right now. `target` is the canonical
    surface to point it at. `reasons` is the machine-checkable decision trace. `provenance`
    records where the evidence came from (source tool + the raw value if canonicalization
    changed it), so the candidate never detaches from what was actually observed."""

    capability: str
    tool: str
    target: str
    reasons: tuple[str, ...]
    provenance: dict = field(default_factory=dict)

    @property
    def phase(self) -> int:
        return TOOL_REGISTRY[self.tool].phase

    def reason_trace(self) -> str:
        """Human-readable, deterministic reason string for the audit log."""
        return f"{self.capability} eligible for {self.target}: {'+'.join(self.reasons)}"

    def _sort_key(self) -> tuple:
        # Stable total order: pipeline phase, then strongest reason, then canonical target,
        # then capability name. No randomness, no set iteration in the key.
        strongest = min((_REASON_RANK.get(r, len(_REASON_STRENGTH)) for r in self.reasons), default=len(_REASON_STRENGTH))
        return (self.phase, strongest, self.target, self.capability)


# The evidence-driven rules: (asset_type predicate, expected capability, reason derivation).
# Each rule reads ONLY existing finding metadata (P16 canonical value, P17 params, P18
# is_api/api_kind, P20 auth_state) plus the coverage state -- never a network probe.


def _url_reasons(finding, coverage_state: str) -> tuple[str, list[str]] | None:
    """For a discovered `url` endpoint, decide which capability (if any) is the justified next
    step and why. Returns (capability, reason_codes) or None.

    A url with an evidence-backed parameter (P17: metadata.params / a `?` query) is ready for
    parameter-aware DAST fuzzing. A paramless url is a parameter-discovery candidate. API
    classification (P18) is a PRIORITISING signal, never a reachability claim."""
    md = finding.metadata or {}
    value = finding.value or ""
    reasons: list[str] = []
    if md.get("is_api"):
        reasons.append("api_surface")

    has_param = bool(md.get("params")) or ("?" in value)
    if has_param:
        # Evidence-backed parameter -> DAST fuzzing candidate.
        reasons.insert(0, "discovered_parameter")
        capability = "dast_fuzzing"
    else:
        # No param yet -> parameter discovery is the justified next step.
        capability = "parameter_discovery"
        reasons.append("incomplete_coverage")

    reasons.append(_coverage_reason(coverage_state))
    # De-dup reason codes while preserving order, dropping falsy placeholders.
    seen: set[str] = set()
    ordered: list[str] = []
    for r in reasons:
        if r and r not in seen:
            seen.add(r)
            ordered.append(r)
    return capability, ordered


def _http_service_reasons(coverage_state: str) -> tuple[str, list[str]]:
    """A confirmed live web service that has not been adequately crawled is a web_crawling
    candidate -- the endpoint-discovery step that feeds everything downstream."""
    return "web_crawling", ["live_web_service", _coverage_reason(coverage_state)]


def _coverage_reason(coverage_state: str) -> str:
    return {
        STATE_ATTEMPTED_FAILED: "attempted_failed_upstream",
        STATE_PARTIAL: "partial_upstream",
    }.get(coverage_state, "incomplete_coverage")


def select_adaptive_candidates(
    findings,
    outcomes: list[ToolRunOutcome],
    *,
    target_type: str,
    target_value: str,
    active_testing_allowed: bool,
    max_tier: str,
    already_run: frozenset[str] = frozenset(),
    enforce_scope: bool = True,
) -> list[AdaptiveCandidate]:
    """Deterministically select the eligible next detection steps from accumulated evidence.

    Pure. Reuses the authoritative guards rather than reimplementing them:
      * coverage.build_coverage -> the per-surface coverage/auth/scope state (P14/P20);
      * scope_guard.finding_in_scope -> the SAME scope check the orchestrator uses (P16 scope);
      * capability_registry.resolve_capability -> tool selection under safety tier /
        active-testing gate / already-run (so a candidate can never name a tool the RoE forbids
        or that already ran).

    A candidate is emitted ONLY when ALL hold: the surface is in scope, its coverage state is
    actionable (discovered / attempted_failed / partial -- never covered/verified/requires_auth/
    out_of_scope/unsupported), and the registry resolves a concrete tool for the justified
    capability. Everything else yields no candidate -- fail-closed, never a fabricated target."""
    # Coverage projection carries the authoritative per-surface state (incl. auth_state ->
    # requires_auth and in_scope -> out_of_scope). Keyed by canonical value.
    projection = build_coverage(findings, outcomes, target_type=target_type)
    state_by_value: dict[str, str] = {s.value: s.state for s in projection.surfaces}

    # Extra authorized roots, computed ONCE, exactly as the orchestrator does, so the scope
    # decision here is identical to the one at execution time.
    extra_hosts = scope_guard.derived_scope_roots(target_type, target_value, findings)

    candidates: list[AdaptiveCandidate] = []
    seen_keys: set[tuple[str, str]] = set()  # (capability, canonical target) -> dedup

    for f in findings:
        asset_type = getattr(f, "asset_type", None)
        value = getattr(f, "value", "") or ""
        if not asset_type or not value:
            continue

        coverage_state = state_by_value.get(value, STATE_DISCOVERED)
        # Only actionable coverage states yield work. requires_auth / out_of_scope / unsupported
        # / covered / verified are all correctly excluded here (Prompt 21 §7 cases A-G).
        if coverage_state not in _ACTIONABLE_COVERAGE:
            continue

        # Authoritative scope re-check (Invariant 1). Fail closed: an indeterminable host is
        # out of scope. Skipped only when the caller explicitly disables enforcement (parity
        # with scan_enforce_derived_scope), and even then the coverage state already excluded
        # out_of_scope surfaces above.
        if enforce_scope and not scope_guard.finding_in_scope(
            target_type, target_value, f, extra_authorized_hosts=extra_hosts
        ):
            continue

        if asset_type == "url":
            derived = _url_reasons(f, coverage_state)
            if derived is None:
                continue
            capability, reasons = derived
        elif asset_type == "http_service":
            capability, reasons = _http_service_reasons(coverage_state)
        else:
            # subdomain/service/port already drive the fixed early pipeline; the adaptive layer
            # focuses on the app-layer surfaces (endpoints/params/APIs) where evidence-driven
            # branching adds value. Not a fabricated target -> no candidate.
            continue

        # Tool selection is the REGISTRY's decision, under the same safety/active-testing/
        # already-run rules used everywhere else. None => not eligible right now (e.g. DAST
        # needs active testing the scope did not grant, or the capability already ran).
        tool = resolve_capability(
            capability,
            target_type=target_type,
            active_testing_allowed=active_testing_allowed,
            max_tier=max_tier,
            already_run=already_run,
        )
        if tool is None:
            continue

        dedup_key = (capability, value)
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        provenance = {"source": (f.metadata or {}).get("source"), "asset_type": asset_type}
        raw_url = (f.metadata or {}).get("raw_url")
        if raw_url:
            provenance["raw_url"] = raw_url  # P16 provenance preserved
        params = (f.metadata or {}).get("params")
        if params:
            provenance["params"] = params    # P17 evidence-backed param provenance

        candidates.append(
            AdaptiveCandidate(
                capability=capability,
                tool=tool,
                target=value,
                reasons=tuple(reasons),
                provenance=provenance,
            )
        )

    # Deterministic total ordering (Prompt 21 §4). Stable sort over a total key.
    candidates.sort(key=lambda c: c._sort_key())
    return candidates


# --- DB adapter (the one place that touches the ORM) --------------------------------------
# Kept separate from the pure core so the selector stays unit-testable without a DB. It only
# READS already-persisted, tenancy-scoped rows (assets + tool_runs) and derives the RoE from
# the same verified authorization the orchestrator uses -- it never runs a tool, writes a row,
# or schedules work. It is an OBSERVABILITY surface over adaptive intelligence, not an executor.

async def build_scan_next_steps(db, scan) -> list[AdaptiveCandidate]:
    """The adaptive next-step candidates for ONE scan, derived from its persisted assets +
    tool_runs. DETERMINISTIC and READ-ONLY. Both source tables are tenancy VIA-tables (scoped
    by the bound workspace), so this cannot read across tenants. Active-testing eligibility and
    the safety ceiling come from the SAME verified authorization scope + RoE the orchestrator
    enforced -- so a candidate is never presented that the engagement itself could not run.

    `scan` is the ORM Scan row (already loaded + ownership-checked by the caller)."""
    from sqlalchemy import select

    from apps.api.modules.assets.models import Asset
    from apps.api.modules.authorization_scope.service import require_verified_target
    from apps.api.modules.projects.models import Target
    from apps.api.scanner_engine.models import ToolRun
    from apps.api.scanner_engine.safety import RulesOfEngagement

    target = await db.get(Target, scan.target_id)
    if target is None:
        return []
    target_type = getattr(target, "type", "domain")
    target_value = getattr(target, "value", "")

    class _AssetFinding:
        __slots__ = ("asset_type", "value", "metadata")

        def __init__(self, a):
            self.asset_type = a.asset_type
            self.value = a.value
            self.metadata = a.metadata_ or {}

    findings = [
        _AssetFinding(a)
        for a in await db.scalars(select(Asset).where(Asset.target_id == scan.target_id))
    ]
    outcomes = [
        ToolRunOutcome(tool=tr.tool_name, status=tr.status)
        for tr in await db.scalars(select(ToolRun).where(ToolRun.scan_id == scan.id))
    ]
    already_run = frozenset(
        tr.tool_name
        for tr in await db.scalars(select(ToolRun).where(ToolRun.scan_id == scan.id))
        if tr.status in ("completed", "completed_with_errors", "partial")
    )

    # Re-derive active-testing + safety ceiling from the SAME authoritative sources the
    # orchestrator used, so the observability surface can never suggest work the engagement's
    # own authorization forbids. A revoked/expired scope raises -> no candidates (fail-closed).
    try:
        vscope = await require_verified_target(db, scan.workspace_id, scan.project_id, scan.target_id)
        active_testing_allowed = bool(vscope.active_testing_allowed)
    except Exception:  # noqa: BLE001 -- no valid scope now => present nothing (fail-closed)
        return []
    roe = RulesOfEngagement.from_config(scan.config or {})

    return select_adaptive_candidates(
        findings,
        outcomes,
        target_type=target_type,
        target_value=target_value,
        active_testing_allowed=active_testing_allowed,
        max_tier=roe.max_tier,
        already_run=already_run,
    )
