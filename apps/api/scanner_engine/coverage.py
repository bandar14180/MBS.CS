"""Engagement-wide coverage projection + coverage-debt detection (Prompt 14).

WHAT THIS ADDS, and what it deliberately does NOT. The platform already tracks coverage
in two narrow places: `nuclei_dast.coverage_state` labels ONE tool's reach (crawled |
fallback_root_only | none), and `capabilities.py`/`capability_registry.py` describe what
the platform COULD run. Neither answers the engagement-level question Prompt 14 is about:

    "Of the surface we actually DISCOVERED, what still has an unfulfilled testing
     opportunity -- and is that because it is out of scope, failed, or simply never
     reached the tool that should have tested it?"

This module answers that DETERMINISTICALLY and PURELY (DB-free, like state_projection.py
and attack_graph.py), from evidence the orchestrator already has: the accumulated
CommonFindings (`prior_findings`) and the per-tool run outcomes. It invents nothing, runs
no tool, and changes NO vulnerability semantics -- it is a read-model over existing state.

WHY IT MATTERS (the false-confidence rule). A scan that runs to `completed` while a
discovered `/api/` endpoint never reached parameter discovery, or a live http_service was
never crawled, has UNTESTED surface. Without this projection, "no finding" on that surface
is silently indistinguishable from "no vulnerability there". This module makes the two
distinguishable by name:

    NO finding  !=  NO vulnerability          (when the surface was never adequately tested)

THE CHAIN MODEL is not invented here -- it mirrors the REAL deterministic pipeline
(tool_runners/_web.py + the runner phases). Each discovered artifact type has an
"expected next capability" that the pipeline would point at it:

    subdomain     -> web_service_discovery   (httpx probes it)
    http_service  -> web_crawling            (katana crawls it) -> vulnerability_detection
    service/port  -> service_fingerprinting  (nmap) and web_service_discovery (if it speaks HTTP)
    url (no ?)    -> parameter_discovery      (arjun) then dast_fuzzing
    url (with ?)  -> dast_fuzzing             (nuclei-dast injects the param)

An artifact is COVERED for a capability iff a tool implementing that capability actually
RAN to a usable state (completed / partial) in this engagement AND that capability was in
scope. It is DEBT iff the capability applies, is in scope, and no such tool reached it.

STATES (Prompt 14 enumerates these; every discovered surface maps to exactly one):

    discovered          -- seen, but its expected test capability has no run at all
    out_of_scope        -- the artifact is outside authorized scope (never a debt)
    unsupported         -- no tool implements the expected capability / target type (not debt)
    attempted_failed    -- the expected capability ran but every run failed
    partial             -- the expected capability ran but only partially (timeout/OOM/etc.)
    covered             -- the expected capability ran to completion
    verified            -- a finding on this surface reached VERIFIED (strongest)

COVERAGE DEBT = the set of (artifact, expected_capability) pairs in state `discovered`
or `attempted_failed` that are in scope and supported. That set is what "no finding does
not mean no vulnerability" is measured against.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from apps.api.scanner_engine.auth_state import UNCROSSED_AUTH_STATES as _UNCROSSED_AUTH_STATES
from apps.api.scanner_engine.capability_registry import (
    capability_for_tool,
    tools_for_capability,
)

# --- Artifact-type -> the capability the pipeline would point at it next -------------------
# DERIVED from the real chain (tool_runners/_web.py + runner phases), never invented. The
# value is the CAPABILITY (registry indirection), not a tool name, so a future second
# implementation of a capability satisfies the same debt with no change here.
#
# A url is split by whether it already carries a query string: a parameterised url is ready
# for dast_fuzzing directly (nuclei-dast injects the param), while a paramless url first
# needs parameter_discovery (arjun) to find injectable params -- exactly the _web.py logic.
_EXPECTED_CAPABILITY: dict[str, str] = {
    "subdomain": "web_service_discovery",   # httpx probes discovered subdomains
    "http_service": "web_crawling",         # katana crawls a confirmed live web service
    "service": "service_fingerprinting",    # nmap deep-scans a discovered port/service
    "port": "service_fingerprinting",
    "url": "parameter_discovery",           # default for a url; overridden below for `?` urls
}

# The states a discovered surface can be in for its expected capability. Ordered weakest
# (most debt) to strongest so a projection can sort/aggregate deterministically.
STATE_DISCOVERED = "discovered"
STATE_OUT_OF_SCOPE = "out_of_scope"
STATE_UNSUPPORTED = "unsupported"
STATE_ATTEMPTED_FAILED = "attempted_failed"
STATE_PARTIAL = "partial"
STATE_COVERED = "covered"
STATE_VERIFIED = "verified"
# Prompt 20: surface observed to sit behind an auth boundary the unauthenticated scan did
# not cross (401/403 or a login redirect). It is in-scope and supported but genuinely
# UNREACHABLE without credentials the platform (correctly) never invents, so it is NOT debt
# the recon pipeline could pay down -- yet it must be NAMED, never silently "covered". This
# is the "no finding on a protected endpoint != no vulnerability" distinction made explicit.
STATE_REQUIRES_AUTH = "requires_auth"

# States that constitute genuine coverage DEBT: in-scope, supported surface whose expected
# test never reached a usable outcome. out_of_scope/unsupported are explicitly NOT debt
# (Prompt 14: debt must be distinguishable from intentionally-out-of-scope and unsupported).
_DEBT_STATES = frozenset({STATE_DISCOVERED, STATE_ATTEMPTED_FAILED})


@dataclass
class ToolRunOutcome:
    """One tool run and how it ended -- the memory of what actually executed. `status` uses
    the orchestrator's own vocabulary: completed | partial | failed | skipped_unauthorized |
    abandoned_revoked | running. Only completed/partial count as "reached a usable state"."""

    tool: str
    status: str


@dataclass
class SurfaceCoverage:
    """One discovered surface's coverage for its expected next capability."""

    asset_type: str
    value: str
    expected_capability: str | None
    state: str
    in_scope: bool
    reason: str = ""


@dataclass
class CoverageProjection:
    """The engagement-wide coverage read-model. `debt` is the actionable subset."""

    surfaces: list[SurfaceCoverage] = field(default_factory=list)
    debt: list[SurfaceCoverage] = field(default_factory=list)
    # capability -> aggregate run state actually observed this engagement.
    capability_states: dict[str, str] = field(default_factory=dict)

    @property
    def has_debt(self) -> bool:
        return bool(self.debt)

    def debt_summary(self) -> str:
        """Bounded, human-readable summary of the coverage debt -- the "what should we test
        next" answer. `(no coverage debt)` when every in-scope supported surface was reached."""
        if not self.debt:
            return "(no coverage debt)"
        by_cap: dict[str, int] = {}
        for s in self.debt:
            by_cap[s.expected_capability or "?"] = by_cap.get(s.expected_capability or "?", 0) + 1
        parts = "; ".join(f"{n} surface(s) awaiting {cap}" for cap, n in sorted(by_cap.items()))
        return f"Coverage debt: {parts}."


def _expected_capability(asset_type: str, value: str) -> str | None:
    """The capability the pipeline would point at this artifact next. A url that already
    carries a query string is ready to fuzz directly; a paramless url needs param discovery
    first. Unknown asset types have no expected next capability (None)."""
    if asset_type == "url" and value and "?" in value:
        return "dast_fuzzing"
    return _EXPECTED_CAPABILITY.get(asset_type)


def _capability_run_state(
    capability: str,
    outcomes: list[ToolRunOutcome],
    *,
    target_type: str,
) -> str:
    """Aggregate run state for a capability across the engagement, from the tools that
    actually ran. Precedence (strongest wins): covered > partial > attempted_failed >
    unsupported > discovered.

    UNSUPPORTED is decided by the registry, not by the run log: a capability with no tool
    applicable to this target type can never be debt (there is nothing that COULD run)."""
    impls = tools_for_capability(capability)
    if not impls:
        return STATE_UNSUPPORTED
    # Did ANY tool implementing this capability run, and how did it end?
    states = [o.status for o in outcomes if capability_for_tool(o.tool) == capability]
    if not states:
        # No implementation of this capability ran at all in this engagement.
        return STATE_DISCOVERED
    if any(s in ("completed", "completed_with_errors") for s in states):
        return STATE_COVERED
    if any(s == "partial" for s in states):
        return STATE_PARTIAL
    if all(s in ("failed", "abandoned_revoked") for s in states):
        return STATE_ATTEMPTED_FAILED
    # skipped_unauthorized / running only: the capability was never actually exercised.
    return STATE_DISCOVERED


def build_coverage(
    findings,
    outcomes: list[ToolRunOutcome],
    *,
    target_type: str,
    verified_locations: frozenset[str] = frozenset(),
) -> CoverageProjection:
    """Deterministically project engagement coverage from accumulated findings + tool-run
    outcomes. Pure; no DB, no I/O; safe to call at any point in a scan.

    `findings` are CommonFinding-like objects (asset_type, value, metadata). The metadata's
    `in_scope` flag (set by the orchestrator's scope_guard) decides out_of_scope -- an
    out-of-scope surface is NEVER counted as debt (it was intentionally not probed).

    `verified_locations` are the matched_at/value strings of findings that carry the
    strongest evidence (a CONFIRMED vulnerability at that surface -- see build_scan_coverage),
    so such a surface is marked `verified` (the coverage state) rather than merely `covered`
    -- the strongest state, and never debt. The parameter is kept location-agnostic so the
    pure core stays independent of the Vulnerability lifecycle vocabulary."""
    surfaces: list[SurfaceCoverage] = []
    # Cache per-capability run state (independent of the specific artifact).
    cap_state_cache: dict[str, str] = {}

    def _cap_state(cap: str) -> str:
        if cap not in cap_state_cache:
            cap_state_cache[cap] = _capability_run_state(cap, outcomes, target_type=target_type)
        return cap_state_cache[cap]

    for f in findings:
        asset_type = getattr(f, "asset_type", None)
        value = getattr(f, "value", "") or ""
        if not asset_type or not value:
            continue
        metadata = getattr(f, "metadata", None) or {}
        # in_scope defaults to True only when the orchestrator never tagged it (older assets);
        # a tagged False is authoritative and fails closed to out_of_scope.
        in_scope = metadata.get("in_scope", True)
        expected = _expected_capability(asset_type, value)

        # Prompt 20: an observed auth boundary this unauthenticated scan did not cross.
        auth_state = metadata.get("auth_state")
        behind_auth = auth_state in _UNCROSSED_AUTH_STATES

        if not in_scope:
            state, reason = STATE_OUT_OF_SCOPE, "outside authorized scope; not probed"
        elif value in verified_locations:
            state, reason = STATE_VERIFIED, "a finding here reached VERIFIED"
        elif behind_auth:
            # Named, not silently covered: a protected/login-redirect surface is genuinely
            # unreachable without credentials the platform never invents.
            state, reason = (
                STATE_REQUIRES_AUTH,
                f"behind an auth boundary ({auth_state}); not reachable by the unauthenticated scan",
            )
        elif expected is None:
            state, reason = STATE_UNSUPPORTED, f"no expected next capability for asset_type={asset_type}"
        else:
            state = _cap_state(expected)
            reason = {
                STATE_COVERED: f"{expected} ran to completion",
                STATE_PARTIAL: f"{expected} ran only partially (timeout/kill/partial output)",
                STATE_ATTEMPTED_FAILED: f"{expected} ran but every run failed",
                STATE_UNSUPPORTED: f"no tool implements {expected} for target_type={target_type}",
                STATE_DISCOVERED: f"{expected} never ran against this surface",
            }[state]

        surfaces.append(
            SurfaceCoverage(
                asset_type=asset_type,
                value=value,
                expected_capability=expected,
                state=state,
                in_scope=bool(in_scope),
                reason=reason,
            )
        )

    debt = [s for s in surfaces if s.state in _DEBT_STATES and s.in_scope and s.expected_capability]
    return CoverageProjection(
        surfaces=surfaces,
        debt=debt,
        capability_states=dict(cap_state_cache),
    )


# --- DB adapter (the one place that touches the ORM) --------------------------------------
# Kept separate from the pure core above so the projection stays unit-testable without a DB.
# This adapter only READS already-persisted, tenancy-scoped rows -- it never runs a tool and
# never writes -- so it cannot bypass tenant isolation or change any scan/vuln state.

async def build_scan_coverage(db, scan) -> CoverageProjection:
    """Coverage projection for ONE scan, derived from its persisted assets + tool_runs.

    DETERMINISTIC and READ-ONLY. Both `assets` and `tool_runs` are tenancy VIA-tables
    (scoped by the bound workspace, exactly like get_scan_timeline), so this cannot read
    across tenants. A VERIFIED finding's matched_at marks its surface `verified`.

    `scan` is the ORM Scan row (already loaded + ownership-checked by the caller)."""
    from sqlalchemy import select

    from apps.api.modules.assets.models import Asset
    from apps.api.modules.projects.models import Target
    from apps.api.modules.scans.models import Scan  # noqa: F401 (type clarity)
    from apps.api.modules.vulnerabilities.models import Vulnerability
    from apps.api.scanner_engine.models import ToolRun

    target = await db.get(Target, scan.target_id)
    target_type = getattr(target, "type", "domain") if target else "domain"

    # Assets are per-TARGET (the grain of the assets table), which is the surface this
    # target's scans discovered. CommonFinding-shaped view: (asset_type, value, metadata).
    assets = list(
        await db.scalars(select(Asset).where(Asset.target_id == scan.target_id))
    )

    class _AssetFinding:
        __slots__ = ("asset_type", "value", "metadata")

        def __init__(self, a):
            self.asset_type = a.asset_type
            self.value = a.value
            self.metadata = a.metadata_ or {}

    findings = [_AssetFinding(a) for a in assets]

    outcomes = [
        ToolRunOutcome(tool=tr.tool_name, status=tr.status)
        for tr in await db.scalars(select(ToolRun).where(ToolRun.scan_id == scan.id))
    ]

    # STRONGEST-EVIDENCE surfaces: a finding triaged to `confirmed` (real, not a false
    # positive) is the strongest coverage a surface can have -- an analyst verified there IS
    # a vulnerability there. That is the Vulnerability lifecycle's confirmation state
    # (SETTABLE_STATUSES in vulnerabilities/service.py); "verified" is a REMEDIATION status
    # meaning fixed, which is the opposite of what strong coverage means, so it is NOT used
    # here. A vulnerability's surface is the Asset it was observed at (asset_id -> value);
    # findings not tied to a single asset simply contribute no `verified` mark (never a false
    # upgrade).
    verified = frozenset(
        val
        for val in await db.scalars(
            select(Asset.value)
            .select_from(Vulnerability)
            .join(Asset, Vulnerability.asset_id == Asset.id)
            .where(
                Vulnerability.last_seen_scan_id == scan.id,
                Vulnerability.status == "confirmed",
            )
        )
        if val
    )

    return build_coverage(
        findings, outcomes, target_type=target_type, verified_locations=verified
    )
