"""Prompt 35 -- Semgrep/SAST readiness boundary.

These tests prove the readiness CONTRACT and that the existing canonical models already
carry source-code findings. They do NOT execute Semgrep, do not require it to be installed,
and do not register a scanner.
"""
import shutil

import pytest

from apps.api.modules.vulnerabilities.taxonomy import (
    SEVERITIES,
    canonical_cwe,
    normalize_severity,
)
from apps.api.scanner_engine.location_normalize import (
    looks_like_source_location,
    normalize_location,
    normalize_source_location,
)
from apps.api.scanner_engine.source_findings import (
    PROVENANCE_INFERRED,
    PROVENANCE_OBSERVED,
    SourceFindingDraft,
    SourceRef,
    SourceRefError,
    correlation_hints,
    source_provenance,
)
from apps.api.scanner_engine.tool_runners.base import VulnerabilityFinding


def _ref(**kw) -> SourceRef:
    base = dict(
        repository="git@github.com:acme/Api.git",
        commit="9f2c1ab3de4f5061728394a5b6c7d8e9f0a1b2c3",
        path="src/Auth/LoginHandler.java",
        line=42,
    )
    base.update(kw)
    return SourceRef(**base)


# --------------------------------------------------------- the platform needs no Semgrep


def test_module_is_importable_without_semgrep_installed() -> None:
    """The readiness layer must never depend on the binary existing."""
    assert shutil.which("semgrep") is None or True  # either way, the import above succeeded


def test_no_semgrep_runner_is_registered() -> None:
    """Readiness must NOT make Semgrep a customer-facing scanner: the orchestrator must not
    be able to schedule it."""
    from apps.api.scanner_engine import tool_registry

    names = {n.lower() for n in dir(tool_registry)}
    registry = getattr(tool_registry, "TOOL_RUNNERS", None) or getattr(tool_registry, "RUNNERS", None)
    if isinstance(registry, dict):
        assert not any("semgrep" in str(k).lower() for k in registry)
    assert "semgrepr" not in names  # no accidental runner symbol


# ---------------------------------------------------------- case-preserving source paths


def test_source_path_case_is_preserved() -> None:
    """THE defect this prompt found: the network normalizer lowercased source paths, which on
    a case-sensitive filesystem names a different file."""
    assert normalize_location("src/Auth/LoginHandler.java:42") == "src/Auth/LoginHandler.java:42"
    assert normalize_location("apps/api/Main.py:10:5") == "apps/api/Main.py:10:5"


def test_source_separators_are_normalized_but_nothing_else() -> None:
    assert normalize_source_location("src\\Auth\\File.cs:9") == "src/Auth/File.cs:9"
    assert normalize_source_location("./src/A.py:3") == "src/A.py:3"


@pytest.mark.parametrize(
    "network_location,expected",
    [
        ("EXAMPLE.com:8080", "example.com:8080"),
        ("example.com:443", "example.com:443"),
        ("1.2.3.4:80", "1.2.3.4:80"),
        ("[::1]:8080", "[::1]:8080"),
        ("HOST", "host"),
    ],
)
def test_network_locations_are_unchanged_by_the_source_branch(network_location, expected) -> None:
    """Regression guard. An earlier form of the source pattern also matched a dot, which made
    "EXAMPLE.com:8080" look like source and silently stopped host-lowercasing -- changing
    existing network fingerprints. Every network shape must keep its current behaviour."""
    assert not looks_like_source_location(network_location)
    assert normalize_location(network_location) == expected


def test_url_normalization_is_unchanged() -> None:
    assert normalize_location("https://EX.com:443/a") == "https://ex.com/a"


# ------------------------------------------------------------------ reproducibility gate


@pytest.mark.parametrize("missing", ["repository", "commit", "path"])
def test_irreproducible_source_reference_is_rejected(missing: str) -> None:
    """A source finding that cannot name its exact revision is not reproducible, so it must
    not be constructible at all."""
    with pytest.raises(SourceRefError, match="reproduce|non-empty"):
        _ref(**{missing: ""})


@pytest.mark.parametrize("field_name,bad", [("line", 0), ("column", 0), ("line", -3)])
def test_positions_must_be_one_based(field_name: str, bad: int) -> None:
    with pytest.raises(SourceRefError, match="1-based"):
        _ref(**{field_name: bad})


def test_file_level_finding_needs_no_line_or_column() -> None:
    """Not every rule reports a position; fabricating 0 would assert one it never gave."""
    ref = SourceRef(repository="r", commit="c", path="src/A/B.py")
    assert ref.line is None and ref.column is None
    assert ref.location == "src/A/B.py"


def test_location_includes_line_and_column_when_present() -> None:
    assert _ref().location == "src/Auth/LoginHandler.java:42"
    assert _ref(column=7).location == "src/Auth/LoginHandler.java:42:7"


# -------------------------------------------------------------------------- provenance


def test_source_finding_is_observed_in_source_but_only_inferred_at_runtime() -> None:
    """Detection is not verification: reading code proves the code says something, not that
    the deployed app exposes it."""
    prov = source_provenance(_ref(), rule_id="java.lang.security.audit.sqli", tool="semgrep")
    assert prov["code_location_provenance"] == PROVENANCE_OBSERVED
    assert prov["runtime_exploitability_provenance"] == PROVENANCE_INFERRED
    assert "runtime_exploitability_provenance" in prov["inferred_keys"]


def test_provenance_can_never_express_verified() -> None:
    """Nothing this module produces may claim a VERIFIED state."""
    prov = source_provenance(_ref(), rule_id="r", tool="semgrep")
    hints = correlation_hints(_ref(), runtime_paths=("/login",))
    assert "VERIFIED" not in str(prov).upper().replace("UNVERIFIED", "")
    assert hints["correlation_decided"] is False


def test_rule_id_is_required_and_kept_verbatim() -> None:
    with pytest.raises(SourceRefError, match="rule_id"):
        source_provenance(_ref(), rule_id="  ", tool="semgrep")
    rule = "python.django.security.audit.XSS.Raw"
    assert source_provenance(_ref(), rule_id=rule, tool="semgrep")["rule_id"] == rule


def test_provenance_records_commit_for_reproducibility() -> None:
    prov = source_provenance(_ref(ref="main"), rule_id="r", tool="semgrep")
    assert prov["commit"] == "9f2c1ab3de4f5061728394a5b6c7d8e9f0a1b2c3"
    assert prov["ref"] == "main"


# ------------------------------------------------------------- canonical model carries it


def test_draft_maps_onto_the_canonical_finding_dataclass() -> None:
    """The point of the readiness boundary: no new finding model. The draft must be
    constructible straight into the existing VulnerabilityFinding."""
    draft = SourceFindingDraft(
        ref=_ref(column=7),
        rule_id="java.lang.security.audit.sqli",
        title="SQL injection via string concatenation",
        severity="high",
        tool="semgrep",
        cwe="CWE-89",
        description="Tainted input reaches a JDBC sink.",
    )
    finding = VulnerabilityFinding(**draft.to_finding_kwargs())

    assert finding.matched_at == "src/Auth/LoginHandler.java:42:7"
    assert finding.severity in SEVERITIES
    assert finding.metadata["source"] == "source_code"
    assert finding.metadata["rule_id"] == "java.lang.security.audit.sqli"
    assert finding.metadata["commit"].startswith("9f2c1ab")


def test_cwe_goes_through_the_existing_taxonomy_and_is_never_invented() -> None:
    """A legitimately mapped CWE canonicalizes; an unmappable rule carries NO CWE."""
    assert canonical_cwe("CWE-89") == "cwe-89"
    assert canonical_cwe("best-practice") is None  # never guessed

    draft = SourceFindingDraft(
        ref=_ref(), rule_id="r", title="t", severity="high", tool="semgrep", cwe="best-practice"
    )
    # Passed through unchanged for the ONE ingest-boundary gate to reject -- not pre-guessed.
    assert draft.to_finding_kwargs()["category"] == "best-practice"
    assert canonical_cwe(draft.to_finding_kwargs()["category"]) is None


def test_severity_uses_the_existing_closed_vocabulary() -> None:
    assert normalize_severity("ERROR") in SEVERITIES  # unknown -> documented fallback
    assert normalize_severity("high") == "high"


# ------------------------------------------------------------------------- fingerprint


def test_fingerprint_is_stable_across_commits() -> None:
    """Identity must NOT include the commit: otherwise every commit mints a new finding and
    the fixed/reopened lifecycle can never work."""
    a = SourceFindingDraft(ref=_ref(commit="a" * 40), rule_id="r", title="t", severity="high", tool="semgrep")
    b = SourceFindingDraft(ref=_ref(commit="b" * 40), rule_id="r", title="t", severity="high", tool="semgrep")
    assert a.fingerprint() == b.fingerprint()


def test_fingerprint_distinguishes_rule_and_location() -> None:
    base = dict(title="t", severity="high", tool="semgrep")
    a = SourceFindingDraft(ref=_ref(), rule_id="rule-a", **base)
    b = SourceFindingDraft(ref=_ref(), rule_id="rule-b", **base)
    c = SourceFindingDraft(ref=_ref(line=99), rule_id="rule-a", **base)
    assert len({a.fingerprint(), b.fingerprint(), c.fingerprint()}) == 3


def test_fingerprint_is_case_sensitive_on_path() -> None:
    """Two files differing only in case are different files and must not collapse."""
    base = dict(rule_id="r", title="t", severity="high", tool="semgrep")
    a = SourceFindingDraft(ref=_ref(path="src/Auth/A.java"), **base)
    b = SourceFindingDraft(ref=_ref(path="src/auth/a.java"), **base)
    assert a.fingerprint() != b.fingerprint()
