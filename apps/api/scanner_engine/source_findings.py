"""Prompt 35 -- readiness boundary for FUTURE source-code (SAST/Semgrep-style) findings.

WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT
=============================================
This module is a NORMALIZATION + PROVENANCE CONTRACT, nothing more. It exists so that a
future source-code scanner can be added without touching the canonical finding, evidence,
taxonomy or correlation models, and without a second parallel findings pipeline.

It is NOT, and must not grow into:
  * a Semgrep runner, engine, rule store or rule loader;
  * a customer-facing scanner (no BaseToolRunner subclass, no capability registration, no
    entry in the tool registry, so the orchestrator cannot schedule it);
  * a new database table.

Nothing here executes Semgrep or any other process. The module is pure and synchronous, has
no DB, network or filesystem access, and importing it has no side effects. The platform is
fully functional with Semgrep absent -- which is the only state that exists today.

WHY THE EXISTING MODELS ARE ENOUGH (audited, Prompt 35)
=======================================================
The readiness fields map onto what the canonical pipeline already stores:

  repository / source id   -> SourceRef.repository, carried in VulnerabilityFinding.metadata.
                              A repo is an ASSET-like identifier, but no asset_type for it is
                              invented here: that belongs to whichever ingest path first
                              genuinely creates one.
  commit / version         -> SourceRef.commit (+ ref). This is the reproducibility anchor:
                              a source finding without a commit cannot be re-derived, so
                              `SourceRef` requires one rather than defaulting it.
  file path                -> SourceRef.path, normalized by location_normalize (separators
                              only, CASE PRESERVED -- see that module's Prompt 35 block).
  line / column            -> SourceRef.line / SourceRef.column, both optional because not
                              every rule reports a column and fabricating 0 would assert a
                              position the tool never gave.
  rule id                  -> SourceRef-independent: `rule_id`, kept VERBATIM in metadata.
                              It is the tool's own identifier and is never mapped onto a CWE.
  CWE                      -> vulnerabilities.category, via taxonomy.canonical_cwe, which
                              returns None for anything unrecognised. A rule with no
                              legitimate CWE mapping therefore carries NO CWE. Never guessed.
  severity                 -> taxonomy.normalize_severity, the same closed vocabulary every
                              other finding uses, so reports/dashboards need no new branch.
  code evidence            -> the existing `evidence` table + evidence_store: a code snippet
                              is an artifact with a storage_uri and a sha256, exactly like
                              raw tool output. No new evidence kind is required.
  scanner provenance       -> the existing `tool_runs` row (tool_name, tool_version,
                              effective_command, command_hash).
  verification / evidence  -> unchanged. See PROVENANCE below -- this is the important part.
  tenant isolation         -> unchanged: a source finding is a Vulnerability under a
                              project, scoped by the existing workspace filter. No new
                              tenancy path, and therefore no new way to get it wrong.
  correlation with runtime -> `correlation_hints()` below emits candidate keys only.

PROVENANCE -- THE LOAD-BEARING RULE
===================================
A static-analysis match is OBSERVED IN SOURCE. It is NOT a verified runtime vulnerability.
Semgrep finding "this sink is reachable from this source" is a statement about code text; it
says nothing about whether the deployed application actually exposes it.

So `source_provenance()` stamps every such finding OBSERVED-in-source and marks the runtime
exploitability INFERRED. Nothing in this module can produce a VERIFIED state, and nothing
here may be consumed as evidence that a runtime issue exists. Correlating a SAST match with
a runtime finding raises CONFIDENCE for triage; it is not proof, and it never promotes a
finding to VERIFIED. That promotion stays where it already lives -- in the verification
subsystem, on observed runtime behaviour.

MISSING BOUNDARY, STATED RATHER THAN IMPLEMENTED
================================================
There is no repository/commit ASSET in the data model today, so `repository` and `commit`
live in the finding's metadata dict (which is persisted with the finding's evidence) rather
than in typed columns. That is sufficient for identity, fingerprinting and reporting, but it
means a source finding cannot yet be queried BY repository in SQL. Adding that column set is
a deliberate, separate decision with a migration; it is not invented here on speculation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from apps.api.scanner_engine.location_normalize import normalize_source_location

# Provenance tiers, spelled exactly as the rest of the engine spells them (see
# scanner_engine/auth_state.py and api_intel.py, which use this same flat metadata namespace).
PROVENANCE_OBSERVED = "OBSERVED"
PROVENANCE_INFERRED = "INFERRED"

# The metadata key under which a source finding declares what produced it. Readers that do
# not know about source findings ignore it, which is why this is additive and safe.
SOURCE_KIND = "source_code"


class SourceRefError(ValueError):
    """Raised when a source reference is not reproducible enough to be a finding."""


@dataclass(frozen=True)
class SourceRef:
    """An immutable, reproducible pointer to a location in source code.

    `repository` and `commit` are REQUIRED: a source finding that cannot name the exact
    revision it was found in is not reproducible, and an irreproducible location must not
    enter the finding pipeline at all. `line`/`column` are optional because a rule may
    legitimately report file-level scope only."""

    repository: str
    commit: str
    path: str
    line: int | None = None
    column: int | None = None
    ref: str | None = None  # branch/tag NAME, if known. Never a substitute for `commit`.

    def __post_init__(self) -> None:
        for name in ("repository", "commit", "path"):
            if not str(getattr(self, name) or "").strip():
                raise SourceRefError(
                    f"source finding requires a non-empty {name}: a location that cannot be "
                    "reproduced is not a finding"
                )
        for name in ("line", "column"):
            value = getattr(self, name)
            if value is not None and value < 1:
                raise SourceRefError(f"{name} must be 1-based and positive, got {value!r}")

    @property
    def location(self) -> str:
        """The canonical "path:line[:col]" location string, normalized case-preservingly.

        This is what belongs in `VulnerabilityFinding.matched_at`, so a source finding uses
        the SAME identity slot as every other finding instead of a parallel one."""
        raw = self.path
        if self.line is not None:
            raw = f"{raw}:{self.line}"
            if self.column is not None:
                raw = f"{raw}:{self.column}"
        # No line number -> there is nothing for the "path:line" normalizer to match, so
        # normalize the separators directly rather than passing it through unchanged.
        return normalize_source_location(raw) if self.line is not None else raw.replace("\\", "/")


def source_provenance(ref: SourceRef, *, rule_id: str, tool: str) -> dict:
    """The provenance block a future source finding must carry.

    Asserts the honest epistemic state and nothing stronger: the code location was OBSERVED
    in the named revision; any runtime consequence is INFERRED. See this module's PROVENANCE
    section -- a value here can never be read as verification."""
    if not str(rule_id or "").strip():
        raise SourceRefError("rule_id is required: a source finding must name the rule that produced it")
    return {
        "source": SOURCE_KIND,
        "tool": tool,
        # The tool's own rule identifier, verbatim. Not translated into a CWE.
        "rule_id": rule_id,
        "repository": ref.repository,
        "commit": ref.commit,
        "ref": ref.ref,
        "file_path": ref.path,
        "line": ref.line,
        "column": ref.column,
        # The code location itself is directly observed in the checked-out revision.
        "code_location_provenance": PROVENANCE_OBSERVED,
        # Whether the deployed app actually reaches this code is NOT established by
        # reading source. This key is what stops a SAST hit being read as exploitability.
        "runtime_exploitability_provenance": PROVENANCE_INFERRED,
        "inferred_keys": ["runtime_exploitability_provenance"],
    }


def correlation_hints(ref: SourceRef, *, runtime_paths: tuple[str, ...] = ()) -> dict:
    """CANDIDATE keys for correlating a source finding with runtime findings.

    Returns hints, not conclusions. Correlation on these keys may raise triage confidence;
    per this module's PROVENANCE rule it must never promote either finding to VERIFIED, and
    a match here is not evidence that the runtime path is exploitable.

    `runtime_paths` are URL paths a caller already OBSERVED at runtime; they are echoed back
    as candidates only, and no match is asserted -- deciding a match is the correlation
    subsystem's job, not this module's."""
    return {
        "source_file": ref.path,
        "source_commit": ref.commit,
        "repository": ref.repository,
        "candidate_runtime_paths": tuple(runtime_paths),
        # Explicit so a consumer cannot mistake a hint for a decided correlation.
        "correlation_decided": False,
    }


@dataclass
class SourceFindingDraft:
    """The minimum shape a future source scanner would hand to the EXISTING ingest path.

    Deliberately NOT a new persisted model: `to_finding_kwargs()` produces keyword arguments
    for the canonical `VulnerabilityFinding` dataclass, so such a finding is deduped,
    taxonomy-normalized, evidence-linked and tenant-scoped by exactly the code that already
    handles every other finding."""

    ref: SourceRef
    rule_id: str
    title: str
    severity: str
    tool: str
    cwe: str | None = None
    description: str | None = None
    extra_metadata: dict = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable identity across re-scans: rule + normalized location.

        The COMMIT is deliberately excluded. Including it would mint a brand-new
        fingerprint on every commit, so the same unfixed weakness would be reported as a new
        finding forever and `reopened`/`fixed` lifecycle tracking would never work. The
        commit is still recorded in provenance, where it answers "which revision did we see
        this in" without fracturing identity."""
        return f"{self.rule_id}|{self.ref.location}"

    def to_finding_kwargs(self) -> dict:
        """Keyword arguments for the canonical `VulnerabilityFinding`.

        `category` carries the CWE and is passed through unchanged for the ingest boundary's
        `canonical_cwe()` to validate -- an unmappable value becomes None there rather than
        being guessed at here. Severity is likewise left for `normalize_severity()` at the
        same boundary, so there is exactly one taxonomy gate, not two."""
        metadata = {
            **source_provenance(self.ref, rule_id=self.rule_id, tool=self.tool),
            **correlation_hints(self.ref),
            **self.extra_metadata,
        }
        return {
            "fingerprint": self.fingerprint(),
            "title": self.title,
            "severity": self.severity,
            "category": self.cwe,
            "description": self.description,
            "matched_at": self.ref.location,
            "metadata": metadata,
        }
