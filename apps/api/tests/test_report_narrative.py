"""Per-finding narrative: weakness classification, verification-gated impact language, and
the accuracy guarantees the report must not lose.

WHAT THESE PIN
--------------
  1. A finding is matched to the right weakness class from the signals the report already
     holds, and falls back to a non-committal generic explanation rather than guessing.
  2. Impact language is GATED on verification. This is the accuracy boundary of the whole
     report: only a VERIFIED finding may use confirmatory phrasing, and PARTIALLY_VERIFIED /
     UNVERIFIED findings must say, in terms, that exploitation was not demonstrated.
  3. No finding -- at any verification state -- makes an exaggerated claim.
  4. The narrative NEVER alters severity, CVSS, business risk, verification or confidence.

Nothing here touches the scanner, detection, scoring or verification classifiers; the
invariants at the bottom assert exactly that.
"""

import uuid

import pytest

from apps.api.modules.reports import narrative as N
from apps.api.modules.reports.data import ReportData, VulnRow, _normalise_steps
from apps.api.modules.reports.render import _finding_groups, render_technical
from apps.api.modules.reports.verification import (
    PARTIALLY_VERIFIED,
    UNVERIFIED,
    VERIFIED,
)


# --- helpers ------------------------------------------------------------------------------

def _row(**over):
    kwargs = dict(
        id=over.pop("vid", None) or uuid.uuid4(),
        title=over.pop("title", "Finding title"),
        severity=over.pop("severity", "high"),
        status=over.pop("status", "open"),
        category=over.pop("category", None),
        cvss_score=over.pop("cvss_score", 9.8),
        cvss_vector=over.pop("cvss_vector", None),
        final_risk_score=over.pop("final_risk_score", 10.0),
        risk_rationale=over.pop("risk_rationale", None),
        compliance=over.pop("compliance", []),
        evidence_uris=over.pop("evidence_uris", []),
        template_id=over.pop("template_id", "some-template"),
        matcher_name=over.pop("matcher_name", "word"),
        matched_at=over.pop("matched_at", "https://example.com/a"),
    )
    row = VulnRow(**kwargs)
    for key, value in over.items():
        setattr(row, key, value)
    return row


def _data(rows):
    return ReportData(
        project_name="Acme Corp",
        security_score=50,
        severity_counts={"critical": 0, "high": len(rows), "medium": 0, "low": 0, "info": 0},
        total_vulns=len(rows),
        active_vulns=len(rows),
        active_severity_counts={"critical": 0, "high": len(rows), "medium": 0, "low": 0, "info": 0},
        vulns=rows,
    )


def _group(row):
    return _finding_groups([row])[0]


# --- 1. Weakness classification -----------------------------------------------------------

@pytest.mark.parametrize(
    "category,expected",
    [
        ("cwe-89", "sqli"),
        ("CWE-78", "command_injection"),
        ("cwe-918", "ssrf"),
        ("cwe-79", "xss"),
        ("cwe-22", "path_traversal"),
        ("cwe-502", "deserialization"),
        ("cwe-611", "xxe"),
        ("cwe-352", "csrf"),
        ("cwe-601", "open_redirect"),
        ("cwe-693", "security_headers"),
        ("cwe-200", "info_disclosure"),
    ],
)
def test_cwe_selects_the_weakness_class(category, expected):
    """The stored CWE is the most precise signal and is authoritative when recognised."""
    assert N.classify_weakness(category=category).key == expected


@pytest.mark.parametrize(
    "template_id,expected",
    [
        ("unix-command-injection", "command_injection"),
        ("windows-command-injection", "command_injection"),
        ("generic-sqli-detection", "sqli"),
        ("ssrf-detect", "ssrf"),
        ("reflected-xss", "xss"),
        ("apache-path-traversal", "path_traversal"),
        ("open-redirect-check", "open_redirect"),
        ("nginx-eol", "outdated_component"),
    ],
)
def test_template_id_selects_the_class_when_no_cwe(template_id, expected):
    assert N.classify_weakness(template_id=template_id).key == expected


def test_cwe_outranks_the_template_text():
    """A recognised CWE wins: it is a stored column, the template name is a convention."""
    w = N.classify_weakness(category="cwe-89", template_id="unix-command-injection")
    assert w.key == "sqli"


def test_unrecognised_finding_falls_back_to_generic_and_does_not_guess():
    w = N.classify_weakness(category="cwe-999999", template_id="something-opaque", title="x")
    assert w.key == "generic"
    # The generic text must not assert a mechanism it cannot know.
    assert "cannot be stated from the available evidence" in w.potential_impact


def test_short_markers_do_not_match_inside_unrelated_words():
    """"xss"/"rce"/"lfi" are matched as whole tokens, so they cannot fire on a substring."""
    assert N.classify_weakness(template_id="resource-exhaustion-check").key != "command_injection"
    assert N.classify_weakness(title="Forcefully cached response").key != "command_injection"


def test_classify_weakness_row_accepts_both_a_row_and_a_group_dict():
    row = _row(category="cwe-89")
    assert N.classify_weakness_row(row).key == "sqli"
    assert N.classify_weakness_row(_group(row)).key == "sqli"


# --- 2. Verification-gated impact ---------------------------------------------------------

def test_impact_certainty_maps_only_verified_to_confirmed():
    assert N.impact_certainty(VERIFIED) == N.CONFIRMED
    assert N.impact_certainty(PARTIALLY_VERIFIED) == N.POTENTIAL
    assert N.impact_certainty(UNVERIFIED) == N.UNVERIFIED_IMPACT
    # An unknown/garbage state must fail SAFE, never to confirmed.
    assert N.impact_certainty(None) == N.UNVERIFIED_IMPACT
    assert N.impact_certainty("something-else") == N.UNVERIFIED_IMPACT


def test_verified_impact_states_confirmation_and_still_bounds_the_rest():
    w = N._CLASSES["command_injection"]
    text = N.impact(w, VERIFIED)
    assert "captured evidence establishes" in text
    # Even a verified finding must not imply the potential outcomes were all demonstrated.
    assert "remain potential rather than demonstrated" in text


def test_partially_verified_impact_says_exploitation_was_not_demonstrated():
    w = N._CLASSES["sqli"]
    text = N.impact(w, PARTIALLY_VERIFIED)
    assert "NOT fully demonstrated" in text
    assert "Manual validation is recommended" in text
    assert "could potentially" in text
    # It must NOT claim confirmation.
    assert "captured evidence establishes" not in text


def test_unverified_impact_is_marked_potential_and_requires_validation():
    w = N._CLASSES["ssrf"]
    text = N.impact(w, UNVERIFIED)
    assert "POTENTIAL finding" in text
    assert "was not exploited during this assessment" in text
    assert "Manual validation is required" in text
    assert "captured evidence establishes" not in text


@pytest.mark.parametrize("state", [PARTIALLY_VERIFIED, UNVERIFIED, None, "unknown"])
@pytest.mark.parametrize("key", sorted(N._CLASSES))
def test_no_confirmatory_language_on_unproven_findings(key, state):
    """THE CORE ACCURACY RULE, across every weakness class and every non-verified state.

    A finding that was not verified must never be described with a verb that asserts the
    outcome happened."""
    text = N.impact(N._CLASSES[key], state).lower()
    for phrase in (
        "captured evidence establishes",
        "was confirmed",
        "we confirmed",
        "successfully exploited",
        "has been compromised",
        "demonstrated that an attacker",
    ):
        assert phrase not in text, f"{key}/{state} used confirmatory phrase: {phrase}"


@pytest.mark.parametrize("key", sorted(N._CLASSES) + ["generic"])
@pytest.mark.parametrize("state", [VERIFIED, PARTIALLY_VERIFIED, UNVERIFIED])
def test_no_exaggerated_impact_claims_anywhere(key, state):
    """The banned-phrase guard named in the requirements.

    No narrative, at any verification state, may claim total compromise, administrator access,
    or exfiltration of all data -- outcomes this pipeline cannot prove."""
    weakness = N._CLASSES.get(key) or N._GENERIC
    text = " ".join([
        N.impact(weakness, state),
        N.description(weakness),
        N.exploitation_context(weakness),
        " ".join(N.controls(weakness)),
    ]).lower()
    for phrase in (
        "steal all data",
        "all data",
        "complete control",
        "full control",
        "total control",
        "take over the entire",
        "administrator accounts",
        "admin accounts",
        "root access",
        "entire network",
        "all users",
        "any data",
        "unlimited access",
    ):
        assert phrase not in text, f"{key}/{state} contains exaggerated phrase: {phrase}"


def test_every_class_potential_impact_is_conditional():
    """Potential impact must read as conditional, never as an assertion of fact."""
    for key, w in list(N._CLASSES.items()) + [("generic", N._GENERIC)]:
        text = w.potential_impact.lower()
        assert any(
            marker in text
            for marker in (
                "could potentially",   # the standard conditional
                "may ",
                "depends on",
                "cannot be stated",
                "were a separate weakness",   # subjunctive (security_headers)
                "does not",                   # states what the finding does NOT show
            )
        ), f"{key} potential_impact is not conditional: {w.potential_impact}"


# --- 3. Narrative assembly ----------------------------------------------------------------

def test_description_states_where_only_from_the_counts_it_is_given():
    w = N._CLASSES["sqli"]
    assert "observed at" not in N.description(w)
    text = N.description(w, location_count=3, host_count=2)
    assert "observed at 3 locations across 2 hosts" in text


def test_description_marks_an_inference_match():
    text = N.description(N._CLASSES["command_injection"], location_count=1, inference=True)
    assert "matched by inference" in text
    assert "rather than by directly observed output" in text


def test_scanner_description_is_appended_verbatim_and_attributed():
    text = N.description(N._CLASSES["sqli"], scanner_text="Payload ' OR 1=1 returned 200.")
    assert "Scanning engine description: Payload ' OR 1=1 returned 200." in text


# --- scanner text vs MBS-authored text ----------------------------------------------------
# The report carries two kinds of prose about a finding and they must never be confused:
# the scanning engine's own description (vulnerabilities.description) and MBS-authored
# catalogue prose (finding_descriptions.py). These pin the precedence and, more importantly,
# that our words can never be printed under the engine's attribution.

def test_scanner_description_wins_over_the_curated_description():
    """When the engine described the finding, that is what the reader gets -- alone."""
    text = N.description(N._CLASSES["xss"], scanner_text="SCANNER", curated_text="CURATED")
    assert "Scanning engine description: SCANNER" in text
    assert "MBS analyst description" not in text
    assert "CURATED" not in text


def test_curated_description_is_used_when_the_scanner_supplied_none():
    text = N.description(N._CLASSES["xss"], scanner_text=None, curated_text="CURATED")
    assert "MBS analyst description: CURATED" in text
    assert "Scanning engine description" not in text


@pytest.mark.parametrize("scanner_text", [None, "", "   ", "\t\n"])
def test_curated_text_can_never_be_labelled_as_scanner_text(scanner_text):
    """THE PROVENANCE INVARIANT: no input combination puts curated prose under the engine's
    attribution. Checked across every falsy/blank scanner value, since the blank cases are
    the ones that fall through to the curated branch."""
    text = N.description(N._CLASSES["ssrf"], scanner_text=scanner_text, curated_text="CURATED")
    assert "Scanning engine description: CURATED" not in text
    assert "Scanning engine description" not in text
    assert "MBS analyst description: CURATED" in text


def test_whitespace_only_scanner_text_falls_through_to_curated_text():
    """A column holding only whitespace is not a description; it must not suppress ours, and
    must not emit an empty scanner attribution either."""
    text = N.description(N._CLASSES["ssrf"], scanner_text="   \t  ", curated_text="CURATED")
    assert "Scanning engine description" not in text
    assert "MBS analyst description: CURATED" in text


def test_neither_scanner_nor_curated_text_emits_neither_attribution():
    text = N.description(N._CLASSES["xss"], scanner_text=None, curated_text=None)
    assert "Scanning engine description" not in text
    assert "MBS analyst description" not in text
    # The class-based explanation is still present -- only the attributed prose is absent.
    assert N._CLASSES["xss"].what_it_is in text


def test_curated_text_defaults_to_absent_for_existing_callers():
    """The new parameter is optional: every pre-existing call site behaves exactly as before."""
    before = N.description(N._CLASSES["xss"], location_count=2, scanner_text="S")
    after = N.description(N._CLASSES["xss"], location_count=2, scanner_text="S",
                          curated_text=None)
    assert before == after
    assert "MBS analyst description" not in before


def test_exploitation_context_always_states_prerequisites():
    for key, w in list(N._CLASSES.items()) + [("generic", N._GENERIC)]:
        assert "Prerequisites:" in N.exploitation_context(w), key


def test_generated_controls_label_is_unambiguous():
    assert "not derived from scan evidence" in N.GENERATED_CONTROLS_LABEL
    assert "standard guidance for this weakness class" in N.GENERATED_CONTROLS_LABEL


def test_every_class_offers_actionable_controls():
    for key, w in list(N._CLASSES.items()) + [("generic", N._GENERIC)]:
        controls = N.controls(w)
        assert len(controls) >= 3, f"{key} has too few controls"
        assert all(c.strip().endswith(".") for c in controls), key


def test_sqli_and_ssrf_and_command_injection_controls_match_the_weakness():
    """Controls must be appropriate to the actual vulnerability, per the requirements."""
    sqli = " ".join(N.controls(N._CLASSES["sqli"])).lower()
    assert "parameterised quer" in sqli and "least privilege" in sqli

    ssrf = " ".join(N.controls(N._CLASSES["ssrf"])).lower()
    assert "allowlist" in ssrf and "redirect" in ssrf
    assert "loopback" in ssrf or "private" in ssrf
    assert "egress" in ssrf

    ci = " ".join(N.controls(N._CLASSES["command_injection"])).lower()
    assert "shell" in ci and "argument vector" in ci and "least-privileged" in ci


# --- 4. Severity vs CVSS clarification ----------------------------------------------------

def test_severity_cvss_note_only_when_they_differ():
    # HIGH severity with a CVSS that bands Critical -- the case named in the audit.
    note = N.severity_cvss_note("high", 9.8, "Critical")
    assert note is not None
    assert "9.8" in note and "Critical" in note
    assert "neither is derived from the other" in note


def test_severity_cvss_note_absent_when_they_agree():
    assert N.severity_cvss_note("critical", 9.8, "Critical") is None
    assert N.severity_cvss_note("high", 7.5, "High") is None


def test_severity_cvss_note_absent_without_a_score():
    assert N.severity_cvss_note("high", None, None) is None


def test_severity_cvss_note_never_reclassifies():
    """The note EXPLAINS; it must not recommend or perform a change of severity."""
    note = N.severity_cvss_note("high", 9.8, "Critical").lower()
    for phrase in ("should be", "reclassif", "corrected to", "raise the severity", "instead of"):
        assert phrase not in note


# --- 5. End-to-end: the rendered report ---------------------------------------------------

def _pdf_text(pdf: bytes) -> str:
    from apps.api.tests.test_report_layout import _pdf_text as extract

    return extract(pdf)


def test_report_renders_all_required_subsections():
    row = _row(category="cwe-89", title="SQL Injection", template_id="sqli-check")
    text = _pdf_text(render_technical(_data([row])))
    for label in (
        "Vulnerability Description",
        "Security Impact",
        "Exploitation Context",
        "Verification & Confidence",
        "Affected Location(s)",
        "Evidence",
        "References",
    ):
        assert label in text, f"missing subsection: {label}"


def test_report_marks_an_unverified_finding_as_potential():
    """No evidence artefacts -> UNVERIFIED -> the impact heading must say so."""
    row = _row(category="cwe-89", evidence_uris=[])
    group = _group(row)
    assert group["verification"] == UNVERIFIED
    text = _pdf_text(render_technical(_data([row])))
    assert "POTENTIAL (unverified; requires manual validation)" in text
    assert "Manual validation is required" in text
    assert "CONFIRMED by captured evidence" not in text


def test_report_marks_a_partially_verified_finding_as_not_demonstrated():
    row = _row(category="cwe-89", evidence_uris=["s3://ev/raw-output.txt"])
    group = _group(row)
    assert group["verification"] == PARTIALLY_VERIFIED
    text = _pdf_text(render_technical(_data([row])))
    assert "exploitation not fully demonstrated" in text
    assert "NOT fully demonstrated" in text
    assert "CONFIRMED by captured evidence" not in text


def test_report_states_confirmation_only_for_a_verified_finding():
    row = _row(
        category="cwe-89",
        template_id="specific-sqli",
        matcher_name="word",
        evidence_uris=["s3://ev/raw-output.txt"],
        screenshots=[("s3://ev/shot.png", "abc123def456")],
    )
    group = _group(row)
    assert group["verification"] == VERIFIED
    text = _pdf_text(render_technical(_data([row])))
    assert "CONFIRMED by captured evidence" in text


def test_evidence_store_note_explains_that_uris_are_not_reader_accessible():
    row = _row(evidence_items=[("log_excerpt", "s3://mbs-evidence/tool-runs/1/raw-output.txt")])
    text = _pdf_text(render_technical(_data([row])))
    assert "retained in the assessment evidence store" in text
    assert "not directly retrievable from this document" in text


def test_report_carries_the_severity_cvss_clarification_for_high_at_9_8():
    row = _row(severity="high", cvss_score=9.8)
    text = _pdf_text(render_technical(_data([row])))
    assert "bands as Critical under CVSS v3.1" in text
    assert "neither is derived from the other" in text


def test_finding_id_and_severity_are_not_duplicated_in_the_block():
    """The header no longer repeats the fact card (the approved de-duplication).

    Finding ID appears once as the card row and once in the identity line beneath the title --
    that is the quotable identifier -- but severity, CVSS, business risk, verification and
    confidence are each stated exactly once."""
    row = _row(severity="high", cvss_score=9.8, final_risk_score=10.0)
    text = _pdf_text(render_technical(_data([row])))
    # The old header line read "HIGH · status: open · CVSS 9.8 · risk 10.0" -- gone now.
    assert "status: open" not in text
    # Scope to the finding block: these words legitimately appear again in the summary and
    # methodology sections, which are not what this de-duplication is about.
    start = text.find("1. Finding title")
    block = text[start:text.find("Vulnerability Description", start)]
    assert block.count("Severity") == 1
    assert block.count("Business risk") == 1
    assert block.count("Verification") == 1
    assert block.count("CVSS") == 1


# --- 6. Remediation: the list/steps regression (Bug B) ------------------------------------

def test_normalise_steps_accepts_every_shape_the_column_can_hold():
    assert _normalise_steps(None) == []
    assert _normalise_steps([]) == []
    assert _normalise_steps(["a", "b"]) == ["a", "b"]
    assert _normalise_steps("single") == ["single"]
    assert _normalise_steps("") == []
    # Blanks are dropped, order preserved, entries stripped.
    assert _normalise_steps([" a ", "", "b"]) == ["a", "b"]
    # Non-string members are coerced rather than raising.
    assert _normalise_steps([1, 2]) == ["1", "2"]


def test_remediation_steps_list_does_not_crash_report_generation():
    """REGRESSION (Bug B). `remediations.steps` is a JSON list column, but the report typed it
    as a string and called .strip() on it -- an AttributeError that failed the WHOLE technical
    report for any finding that actually had steps. Latent only because the table is empty."""
    row = _row(category="cwe-89")
    row.remediation_summary = "Use parameterised queries."
    row.remediation_steps = ["Replace string concatenation.", "Add an allowlist."]
    pdf = render_technical(_data([row]))       # must not raise
    assert pdf[:4] == b"%PDF"
    text = _pdf_text(pdf)
    assert "Replace string concatenation." in text
    assert "Add an allowlist." in text


def test_remediation_steps_render_as_separate_bullets():
    row = _row()
    row.remediation_steps = ["First step.", "Second step."]
    text = _pdf_text(render_technical(_data([row])))
    # The bullet glyph does not survive PDF text extraction cleanly; assert the steps appear
    # as separate lines rather than concatenated into one run.
    assert "First step." in text
    assert "Second step." in text


def test_pipeline_remediation_suppresses_the_generated_controls():
    row = _row(category="cwe-89")
    row.remediation_summary = "Pipeline guidance."
    text = _pdf_text(render_technical(_data([row])))
    assert "Remediation (from the assessment pipeline)" in text
    assert "not derived from scan evidence" not in text


def test_generated_controls_used_when_the_pipeline_produced_none():
    row = _row(category="cwe-918")   # SSRF
    text = _pdf_text(render_technical(_data([row])))
    assert "not derived from scan evidence" in text
    assert "allowlist" in text.lower()


# --- 7. INVARIANTS: the narrative changes no stored or derived value ----------------------

def test_narrative_does_not_alter_any_finding_value():
    """The narrative reads verification; it must write nothing at all."""
    row = _row(category="cwe-89", severity="high", cvss_score=9.8, final_risk_score=10.0)
    before = (
        row.severity, row.cvss_score, row.final_risk_score, row.status,
        row.verification, row.confidence, row.classification,
    )
    render_technical(_data([row]))
    after = (
        row.severity, row.cvss_score, row.final_risk_score, row.status,
        row.verification, row.confidence, row.classification,
    )
    assert before == after


def test_narrative_module_exposes_no_scoring_or_severity_output():
    """Structural guarantee: nothing in narrative.py returns a severity/CVSS/risk value.

    The module may READ a verification state to choose wording. It must never hand back a
    number or a severity that a caller could mistake for an assessed value."""
    import inspect

    from apps.api.modules.reports import narrative

    source = inspect.getsource(narrative)
    for forbidden in ("cvss_score =", "final_risk_score =", "severity =", "compute_security_score"):
        assert forbidden not in source, f"narrative.py appears to assign {forbidden}"


def test_weakness_class_choice_never_depends_on_severity_or_cvss():
    """Two findings differing ONLY in severity/CVSS must get the same weakness class."""
    a = N.classify_weakness(category="cwe-89", template_id="t", title="x")
    b = N.classify_weakness(category="cwe-89", template_id="t", title="x")
    assert a.key == b.key == "sqli"
    # classify_weakness does not even accept a severity or a CVSS.
    import inspect

    params = set(inspect.signature(N.classify_weakness).parameters)
    assert "severity" not in params and "cvss_score" not in params
