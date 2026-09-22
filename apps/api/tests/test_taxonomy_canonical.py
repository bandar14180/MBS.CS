"""Prompt 23 -- canonical CWE/CVE taxonomy, and the seam between producers and consumers.

WHY THIS FILE EXISTS ALONGSIDE test_vulnerability_taxonomy.py. That file covers the SEVERITY
vocabulary (Prompt A) exhaustively and is untouched. This file covers the identifiers that
module explicitly declined to handle -- CWE and CVE -- and the specific defect the Prompt 23
audit found: `.strip().lower()` in the ATT&CK and compliance catalogues normalises case but not
the SEPARATOR, so `cwe_89`, `CWE 89` and a bare `89` silently returned no techniques and no
controls while reports/narrative still resolved them to "sqli".

The governing rule throughout: a CWE or CVE is either recovered from what the tool actually
said, or it is absent. It is never guessed, never derived from severity or title, and never
repaired into a plausible-looking id.
"""

import json

import pytest

from apps.api.modules.attack.catalog import techniques_for
from apps.api.modules.compliance.catalog import controls_for_category
from apps.api.modules.reports.narrative import _class_from_cwe
from apps.api.modules.vulnerabilities.taxonomy import (
    canonical_cve,
    canonical_cwe,
    cve_is_canonical,
    cwe_is_canonical,
    normalize_severity,
)
from apps.api.scanner_engine.tool_runners.base import RawToolOutput
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner


def _nuclei_line(**classification):
    """One nuclei JSONL record carrying the given classification block."""
    return json.dumps({
        "template-id": "sqli-test",
        "matched-at": "https://e.com/a",
        "matcher-name": "status",
        "info": {"name": "SQLi", "severity": "high", "classification": classification},
    })


def _parse_one(line):
    return NucleiRunner().parse_vulnerabilities(RawToolOutput(
        command="nuclei", stdout=line, stderr="", exit_code=0
    ))[0]


# ===================== canonical taxonomy normalization ===================================

@pytest.mark.parametrize("spelling", ["cwe-89", "CWE-89", "cwe_89", "CWE 89", "89", "cwe-089",
                                      "  cwe-89  ", "Cwe-89"])
def test_inconsistent_scanner_labels_converge_on_one_canonical_cwe(spelling) -> None:
    """THE CORE DEFECT. Every spelling a tool may emit for CWE-89 must become one key."""
    assert canonical_cwe(spelling) == "cwe-89"


def test_canonical_cwe_is_idempotent_and_deterministic() -> None:
    once = canonical_cwe("CWE_89")
    assert canonical_cwe(once) == once == "cwe-89"
    assert len({canonical_cwe("CWE 89") for _ in range(20)}) == 1


def test_cwe_is_canonical_distinguishes_already_clean_from_corrected() -> None:
    assert cwe_is_canonical("cwe-89")
    for corrected in ("CWE-89", "cwe_89", "89", "cwe-089"):
        assert not cwe_is_canonical(corrected), corrected


# ===================== the consumer disagreement this closes ==============================

@pytest.mark.parametrize("spelling", ["cwe-89", "CWE-89", "cwe_89", "CWE 89", "89"])
def test_all_three_consumers_agree_once_canonicalised(spelling) -> None:
    """Before canonicalisation `cwe_89`/`CWE 89`/`89` gave attack=0 and compliance=0 while
    narrative gave "sqli" -- one finding, three subsystems, two silently wrong. After, all
    three resolve identically."""
    key = canonical_cwe(spelling)
    assert len(techniques_for(key)) == len(techniques_for("cwe-89")) > 0
    assert len(controls_for_category(key)) == len(controls_for_category("cwe-89")) > 0
    assert _class_from_cwe(key) == "sqli"


def test_duplicate_semantic_categories_collapse_to_one_key() -> None:
    """`cwe-89`, `CWE_89` and `89` are the SAME weakness class under different names. A
    canonical form exists, so they must not persist as distinct categories."""
    assert len({canonical_cwe(s) for s in ("cwe-89", "CWE_89", "89", "cwe-089", "CWE 89")}) == 1


def test_distinct_weaknesses_do_not_collapse() -> None:
    """Canonicalisation must not over-merge: different CWEs stay different."""
    assert len({canonical_cwe(s) for s in ("cwe-89", "cwe-79", "cwe-78", "cwe-22")}) == 4


# ===================== valid / missing / invalid CWE ======================================

def test_valid_cwe_mapping_is_preserved() -> None:
    assert canonical_cwe("CWE-79") == "cwe-79"
    assert techniques_for(canonical_cwe("CWE-79"))


def test_missing_cwe_stays_missing_and_is_never_invented() -> None:
    for absent in (None, "", "   "):
        assert canonical_cwe(absent) is None


@pytest.mark.parametrize("bogus", ["cwe-abc", "cwe-", "cwe", "garbage", "cwe-89-extra",
                                   "x89", "cwe--89", "cwe-0", "0"])
def test_invalid_or_unjustified_cwe_is_rejected_not_repaired(bogus) -> None:
    """An unparseable id is ABSENCE of information. Manufacturing a plausible CWE from it is
    exactly the fabrication Prompt 23 forbids."""
    assert canonical_cwe(bogus) is None


def test_a_cve_is_not_accepted_as_a_cwe() -> None:
    """The two identifiers answer different questions and must never be interchanged."""
    assert canonical_cwe("CVE-2021-41773") is None


# ===================== valid / missing / invalid CVE ======================================

@pytest.mark.parametrize("spelling", ["CVE-2021-41773", "cve-2021-41773", "cve_2021_41773",
                                      " CVE-2021-41773 "])
def test_valid_cve_mapping_normalises_to_the_published_form(spelling) -> None:
    assert canonical_cve(spelling) == "CVE-2021-41773"


def test_missing_cve_stays_missing() -> None:
    for absent in (None, "", "  "):
        assert canonical_cve(absent) is None


@pytest.mark.parametrize("bogus", ["cve-99-1", "cve-2021", "cve-20211-41773", "CVE-abcd-1234",
                                   "cwe-89", "41773", "garbage", "cve-2021-1"])
def test_invalid_or_unjustified_cve_is_rejected_not_repaired(bogus) -> None:
    assert canonical_cve(bogus) is None


def test_cve_is_canonical_flags_corrected_spellings() -> None:
    assert cve_is_canonical("CVE-2021-41773")
    assert not cve_is_canonical("cve_2021_41773")


def test_cve_and_cwe_are_never_derived_from_each_other() -> None:
    assert canonical_cve(canonical_cwe("cwe-89")) is None
    assert canonical_cwe(canonical_cve("CVE-2021-41773")) is None


# ===================== producer: nuclei, incl. provenance =================================

def test_nuclei_cwe_list_form_is_canonicalised() -> None:
    f = _parse_one(_nuclei_line(**{"cwe-id": ["CWE_89", "cwe-20"]}))
    assert f.category == "cwe-89"


def test_nuclei_scalar_cwe_is_canonicalised() -> None:
    assert _parse_one(_nuclei_line(**{"cwe-id": "CWE-79"})).category == "cwe-79"


def test_nuclei_absent_classification_yields_no_cwe_or_cve() -> None:
    """No classification block means no identifiers -- not invented ones."""
    f = _parse_one(_nuclei_line())
    assert f.category is None
    assert f.metadata["cve"] is None


def test_nuclei_malformed_cwe_is_dropped_not_guessed() -> None:
    f = _parse_one(_nuclei_line(**{"cwe-id": "not-a-cwe"}))
    assert f.category is None


def test_scanner_native_identifier_is_preserved_for_provenance() -> None:
    """Normalising must not be lossy: what the tool actually said stays recoverable."""
    f = _parse_one(_nuclei_line(**{"cwe-id": "CWE_89", "cve-id": "cve_2021_41773"}))
    assert f.category == "cwe-89"
    assert f.metadata["cwe_reported"] == "CWE_89"
    assert f.metadata["cve"] == "CVE-2021-41773"
    assert f.metadata["cve_reported"] == "cve_2021_41773"


def test_already_canonical_identifiers_add_no_provenance_noise() -> None:
    f = _parse_one(_nuclei_line(**{"cwe-id": "cwe-89", "cve-id": "CVE-2021-41773"}))
    assert "cwe_reported" not in f.metadata
    assert "cve_reported" not in f.metadata


def test_malformed_cve_is_dropped_but_still_traceable() -> None:
    f = _parse_one(_nuclei_line(**{"cve-id": "cve-99-1"}))
    assert f.metadata["cve"] is None, "a malformed CVE must never reach the taxonomy"
    assert f.metadata["cve_reported"] == "cve-99-1", "but what the tool said is preserved"


# ===================== separation of axes =================================================

def test_severity_does_not_influence_the_cwe() -> None:
    """Taxonomy axes stay independent: no severity->CWE inference in either direction."""
    cats = {_parse_one(json.dumps({
        "template-id": "t", "matched-at": "https://e.com/a",
        "info": {"name": "n", "severity": sev, "classification": {}},
    })).category for sev in ("critical", "high", "info", "low")}
    assert cats == {None}


def test_cwe_does_not_influence_severity_normalisation() -> None:
    assert normalize_severity("high") == "high"
    assert canonical_cwe("cwe-89") == "cwe-89"


def test_detection_remains_separate_from_verification() -> None:
    """Canonicalising identifiers must not move the detection/verification boundary: a CWE is
    a weakness CLASS, never evidence that anything was demonstrated."""
    from apps.api.modules.reports.verification import UNVERIFIED, classify_verification

    state, _ = classify_verification(template_id="sqli-test", matcher_name="status")
    assert state == UNVERIFIED
    # A canonical CWE/CVE present on the finding still proves nothing on its own.
    state2, _ = classify_verification(template_id="sqli-test", cve=canonical_cve("CVE-2021-41773"))
    assert state2 == UNVERIFIED


def test_remediation_guidance_corresponds_to_the_actual_finding_type() -> None:
    """The narrative layer keys guidance off the CWE; a canonical CWE must select the class
    that matches the weakness, and a finding without a CWE must not borrow another's."""
    assert _class_from_cwe(canonical_cwe("cwe-89")) == "sqli"
    assert _class_from_cwe(canonical_cwe("cwe-79")) == "xss"
    assert _class_from_cwe(canonical_cwe("cwe-22")) == "path_traversal"
    assert _class_from_cwe(None) is None
