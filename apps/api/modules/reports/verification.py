"""Verification state and confidence for a reported finding (reporting layer).

WHY THIS EXISTS
---------------
A scanner MATCH is not a PROOF. `unix-command-injection` fires on a generic payload/matcher
and is persisted exactly like a finding whose exploitation was actually observed, so the
Technical Report presented "Unix Command Injection - Generic Detection" with the same
authority as a confirmed compromise. An analyst could not tell, from the report, which
findings had been demonstrated and which were pattern matches awaiting manual validation.

This module is the SINGLE SOURCE OF TRUTH for that distinction. Like classification.py it is
a pure classifier over metadata the scanner ALREADY produces -- no schema change, no new
column, no migration.

WHAT IT IS NOT
--------------
  * It is NOT `vulnerabilities.ai_confidence`. That column is the AI triage model's self-rated
    certainty about its own enrichment output; this is an EVIDENCE-based statement about
    whether the finding itself was demonstrated. They answer different questions, are produced
    by different subsystems, and are deliberately kept apart -- reusing ai_confidence here
    would silently let an LLM's opinion set a security report's verification status.
  * It is NOT a severity modifier. Verification NEVER changes cvss_score, final_risk_score,
    severity, or the security score. An unverified CVSS 9.8 is still a CVSS 9.8: downgrading
    unproven findings would hide real risk, which is the opposite of the intent. The report
    states both facts side by side and lets the analyst prioritise.

THE STATES
----------
Verification -- was exploitation actually demonstrated?
  * VERIFIED           -- evidence positively demonstrates the condition.
  * PARTIALLY_VERIFIED -- concrete artefacts were captured (a response excerpt, a screenshot)
                          that corroborate the match, but do not by themselves prove exploit.
  * UNVERIFIED         -- a scanner pattern matched; nothing further was captured.

Confidence -- how much weight does the signal carry, independent of verification?
  * HIGH / MEDIUM / LOW.

THE SAFE DEFAULT (requirement, not an accident)
-----------------------------------------------
A generic scanner detection is UNVERIFIED / MEDIUM. `Unverified` because a template match is
not proof; `Medium` -- not Low -- because a nuclei template firing is a real, curated signal
and calling it Low would invite dismissal of true positives.

FAILING SAFE
------------
This classifier fails toward UNVERIFIED, the exact opposite direction to classification.py
(which fails toward VULNERABILITY). Both choices are conservative for their own question:
never hide a weakness, and never overstate proof. VERIFIED is therefore reachable ONLY via an
explicit positive evidence signal -- never from a template name, a severity, or a CVSS.
"""

VERIFIED = "verified"
PARTIALLY_VERIFIED = "partially_verified"
UNVERIFIED = "unverified"

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

# Human-facing labels. Kept here so the renderer never hand-formats these strings.
_VERIFICATION_LABELS = {
    VERIFIED: "Verified",
    PARTIALLY_VERIFIED: "Partially Verified",
    UNVERIFIED: "Unverified",
}
_CONFIDENCE_LABELS = {
    CONFIDENCE_HIGH: "High",
    CONFIDENCE_MEDIUM: "Medium",
    CONFIDENCE_LOW: "Low",
}

# Matcher/template markers for INFERENCE-based detection: the tool concluded from timing or a
# blind side-channel rather than from observed output. Real data shows `time-based` as the
# matcher on 73 rows. Inference is weaker proof than a direct match, so it lowers CONFIDENCE --
# it never raises verification, and never touches severity.
_INFERENCE_MARKERS = ("time-based", "time_based", "blind", "timing", "out-of-band", "oob")

# Markers for a GENERIC template: matches a broad payload class rather than a specific,
# fingerprinted product/version condition. These are the findings §5 names explicitly
# (unix-/windows-command-injection "Generic Detection").
#
# NOT the whole story -- see _is_generic. classification.py owns a BROADER detection-template
# vocabulary (`fingerprint`, `-eol`, `-version`, and the `tech-`/`waf-` prefixes) and this list
# deliberately does not duplicate it; _is_generic defers to that module instead, so the two can
# never disagree about what counts as a detection template.
_GENERIC_MARKERS = ("generic", "-detect", "detection")


def _norm(value) -> str:
    return str(value or "").strip().lower()


# The sentinel `storage_uri` the orchestrator writes when evidence storage ITSELF failed at
# ingest time (see scanner_engine/orchestrator.py: `unavailable://evidence-storage-failed/...`,
# written with an EMPTY checksum). Object storage being down must not fail an otherwise-good
# scan, so a row is still recorded to keep the vulnerability -> evidence linkage intact -- but
# that row points at NOTHING. No bytes were ever stored and none can ever be retrieved.
_UNAVAILABLE_SCHEME = "unavailable://"


def _is_real_artefact(uri) -> bool:
    """True only for a reference to an artifact that ACTUALLY EXISTS in the evidence store.

    WHY THIS EXISTS (failure-injection finding, Prompt 32). `classify_verification` counted the
    LENGTH of `evidence_uris` to decide whether artefacts were captured. The sentinel above is
    a non-empty string, so it counted -- and a finding whose evidence upload FAILED was graded
    as though the response had been captured. With a screenshot alongside it, that reached
    VERIFIED: an infrastructure outage could upgrade a scanner match to "exploitation
    corroborated by captured evidence", which is precisely the partial-execution-promoted-to-
    VERIFIED failure this classifier's whole design is meant to prevent.

    A failed capture is the ABSENCE of evidence and must read exactly like it. This is not a
    new evidence concept -- `retention/service.py` and `evidence_integrity.py` already filter
    on the same sentinel for the same reason ("never send a non-s3 key to storage" / "no real
    object to check"); this applies that existing rule at the one place that was still missing
    it. Empty/whitespace strings are refused for the same reason.
    """
    text = str(uri or "").strip()
    return bool(text) and not text.lower().startswith(_UNAVAILABLE_SCHEME)


def _count_artefacts(values) -> int:
    """How many entries are references to artifacts that really exist.

    Accepts both shapes the report carries: `evidence_uris` (list[str]) and `screenshots`
    (list[(uri, checksum)]), taking element 0 of a tuple/list so one helper serves both."""
    total = 0
    for value in values or ():
        uri = value[0] if isinstance(value, (tuple, list)) and value else value
        if _is_real_artefact(uri):
            total += 1
    return total


def _has_inference_marker(*values) -> bool:
    joined = " ".join(_norm(v) for v in values)
    return any(m in joined for m in _INFERENCE_MARKERS)


def _is_generic(*values) -> bool:
    """True when the match is too broad to ever constitute PROOF of exploitation.

    Two sources, deliberately:
      1. `_GENERIC_MARKERS` -- broad payload-class matches ("generic", "-detect", "detection");
      2. classification.py's own detection-template vocabulary, consulted through its
         `_template_looks_like_detection`. That module is the single source of truth for "is
         this template a detection?", and it recognises markers this one does not
         (`fingerprint`, `-eol`, `-version`, and the `tech-`/`waf-` prefixes).

    (2) closes a real inconsistency: `fingerprinthub-web-fingerprints`, `nginx-version`,
    `apache-eol`, `tech-*` and `waf-*` are DETECTIONS to classification.py, but were not
    generic here -- so with both artefact kinds present they could reach VERIFIED, i.e. the
    report could state that a technology fingerprint or WAF banner was verified exploitation.
    Live reports were shielded only because gather_report_data passes `classification` first;
    this function is public and was failing OPEN for any other caller. Deferring to the
    existing classifier fixes that at the root instead of duplicating its marker list here.
    """
    joined = " ".join(_norm(v) for v in values)
    if any(m in joined for m in _GENERIC_MARKERS):
        return True
    # Imported locally for the same reason scoring.py does it: keep this module importable in
    # isolation and avoid a package-level import cycle at module-load time.
    from apps.api.modules.reports.classification import _template_looks_like_detection

    return any(_template_looks_like_detection(_norm(v)) for v in values if v)


def classify_verification(
    *,
    template_id: str | None = None,
    matcher_name: str | None = None,
    evidence_uris=None,
    screenshots=None,
    classification: str | None = None,
    cve: str | None = None,
) -> tuple[str, str]:
    """Return (verification_state, confidence) for one finding. Pure; fails toward UNVERIFIED.

    Every argument is metadata the report already loads. NOTHING here reads or returns a
    severity, a CVSS, or a risk score -- by construction this function cannot influence them.

    Evidence semantics (the only route to a stronger state):
      * screenshots -- a rendered capture of the affected page. A concrete artefact a human can
        inspect, so it corroborates the finding: PARTIALLY_VERIFIED.
      * evidence_uris -- captured tool output (evidence_type='log_excerpt' in practice). Also a
        concrete artefact: PARTIALLY_VERIFIED.
      * Neither, on its own, is proof of EXPLOITATION -- a screenshot shows a page, a log shows
        a response. So the ceiling reachable from stored artefacts alone is PARTIALLY_VERIFIED.
        VERIFIED requires BOTH kinds of artefact AND a non-generic, non-inference match, i.e.
        a specific condition corroborated from two independent directions.
    """
    # Counted with _count_artefacts, NOT len(): a failed-upload sentinel is a row pointing at
    # nothing, and counting it would let a storage outage corroborate a finding. See
    # _is_real_artefact.
    n_screens = _count_artefacts(screenshots)
    n_evidence = _count_artefacts(evidence_uris)
    has_artefacts = bool(n_screens or n_evidence)

    inference = _has_inference_marker(template_id, matcher_name)
    generic = _is_generic(template_id, matcher_name)

    # --- Verification -------------------------------------------------------------------
    # A DETECTION reports something observed, not something exploitable; "verified exploit" is
    # not a meaningful claim about it. It is reported at its artefact level, never VERIFIED.
    is_detection = _norm(classification) == "detection"

    if not has_artefacts:
        verification = UNVERIFIED
    elif is_detection or generic or inference:
        # Artefacts exist but the match itself is generic/inferred (or it is a detection):
        # corroborated, not proven.
        verification = PARTIALLY_VERIFIED
    elif n_screens and n_evidence:
        # A specific, directly-matched condition corroborated by BOTH a captured response and
        # a visual capture. This is the ONLY path to VERIFIED.
        verification = VERIFIED
    else:
        verification = PARTIALLY_VERIFIED

    # --- Confidence ---------------------------------------------------------------------
    # Independent of verification: it grades how much the SIGNAL is worth, not whether it was
    # proven. Starts at the documented safe default and moves for explicit reasons only.
    confidence = CONFIDENCE_MEDIUM
    if inference:
        # Timing/blind inference is the weakest signal class -- it is the reason `Low` exists.
        confidence = CONFIDENCE_LOW
    elif cve and not generic:
        # A specific CVE-backed template is a precise, curated signal.
        confidence = CONFIDENCE_HIGH
    elif has_artefacts and not generic:
        confidence = CONFIDENCE_HIGH

    return verification, confidence


# Stable, machine-checkable reason codes (Prompt B: "expose the reasoning behind the resulting
# verification state"). Deliberately strings, not free text, so a decision trace is
# reproducible, testable and renderable without re-deriving anything.
REASON_NO_ARTEFACTS = "no_artefacts"
REASON_GENERIC_MATCH = "generic_match"
REASON_INFERENCE_MATCH = "inference_match"
REASON_DETECTION_CLASS = "detection_class"
REASON_RESPONSE_CAPTURED = "response_captured"
REASON_SCREENSHOT_CAPTURED = "screenshot_captured"
REASON_CORROBORATED_BOTH = "corroborated_both_artefacts"
REASON_CVE_BACKED = "cve_backed"

# One human-facing sentence per code, so the renderer never hand-formats these strings (same
# convention as _VERIFICATION_LABELS above).
_REASON_NOTES = {
    REASON_NO_ARTEFACTS: "No evidence artefact was captured for this match.",
    REASON_GENERIC_MATCH: "The template matches a broad payload class rather than a specific condition.",
    REASON_INFERENCE_MATCH: "The match is inference-based (timing or out-of-band), not directly observed output.",
    REASON_DETECTION_CLASS: "This is a detection (something observed), not an exploitable condition.",
    REASON_RESPONSE_CAPTURED: "Captured tool output corroborates the match.",
    REASON_SCREENSHOT_CAPTURED: "A rendered screenshot corroborates the match.",
    REASON_CORROBORATED_BOTH: "Corroborated from two independent directions (captured response and screenshot).",
    REASON_CVE_BACKED: "The template is backed by a specific CVE identifier.",
}


def verification_reasons(
    *,
    template_id: str | None = None,
    matcher_name: str | None = None,
    evidence_uris=None,
    screenshots=None,
    classification: str | None = None,
    cve: str | None = None,
) -> list[str]:
    """The ordered reason codes explaining what `classify_verification` decided, and why.

    WHY THIS IS SEPARATE from `classify_verification`. That function returns a 2-tuple which
    call sites and tests compare by equality; widening it would break them for no benefit.
    This exposes the SAME signals it already computes internally -- it re-uses the identical
    private predicates, so the two can never disagree about whether a match is generic or
    inference-based.

    WHAT THIS IS NOT. It is not a new decision: nothing here changes a verification state, a
    confidence, a severity or a score. It is the audit trail for a decision already made, and
    it asserts NOTHING about exploitability -- `REASON_CORROBORATED_BOTH` means two artefacts
    exist, never that exploitation was demonstrated.

    Order is fixed (weakening signals first, then corroborating ones) so the output is stable
    for identical input -- a determinism requirement, not a cosmetic one.
    """
    # Same artefact-existence rule as classify_verification, so the reason trace can never
    # claim a response was captured when the capture actually failed.
    n_screens = _count_artefacts(screenshots)
    n_evidence = _count_artefacts(evidence_uris)
    reasons: list[str] = []

    if not (n_screens or n_evidence):
        reasons.append(REASON_NO_ARTEFACTS)
    if _norm(classification) == "detection":
        reasons.append(REASON_DETECTION_CLASS)
    if _is_generic(template_id, matcher_name):
        reasons.append(REASON_GENERIC_MATCH)
    if _has_inference_marker(template_id, matcher_name):
        reasons.append(REASON_INFERENCE_MATCH)
    if n_evidence:
        reasons.append(REASON_RESPONSE_CAPTURED)
    if n_screens:
        reasons.append(REASON_SCREENSHOT_CAPTURED)
    if n_screens and n_evidence:
        reasons.append(REASON_CORROBORATED_BOTH)
    if cve and not _is_generic(template_id, matcher_name):
        reasons.append(REASON_CVE_BACKED)
    return reasons


def verification_reasons_row(row) -> list[str]:
    """`verification_reasons` for a report VulnRow-like object (mirrors classify_verification_row)."""
    return verification_reasons(
        template_id=getattr(row, "template_id", None),
        matcher_name=getattr(row, "matcher_name", None),
        evidence_uris=getattr(row, "evidence_uris", None),
        screenshots=getattr(row, "screenshots", None),
        classification=getattr(row, "classification", None),
        cve=getattr(row, "cve", None),
    )


def reason_note(code: str | None) -> str:
    """One human-facing sentence for a reason code; empty string for an unknown code."""
    return _REASON_NOTES.get(_norm(code), "")


# ---------------------------------------------------------------------------------------------
# Confidence provenance + normalisation (Prompt 22)
#
# THE PROBLEM. Four subsystems in this codebase emit something called "confidence", in two
# incompatible representations:
#
#   * this module                  -- "high"/"medium"/"low", deterministic, evidence-derived;
#   * vulnerabilities.ai_confidence -- float 0..1, the AI triage model rating its OWN output;
#   * ai_agent/fp_reducer           -- "low"/"medium"/"high", the AI rating its OWN FP call;
#   * scanner_engine/attack_graph   -- float 0.7..0.95, deterministic graph provenance.
#
# Once serialised, a "high" from this module and a "high" from the AI FP reducer are the SAME
# STRING. Nothing structural stopped an AI-sourced value being written into a field a report
# renders as security confidence -- the separation was upheld by convention and by tests that
# assert the classifier happens not to read `ai_confidence`. That is a bypass waiting for its
# first careless call site.
#
# THE FIX. A confidence value that reaches the report layer must be BAND-VALUED and must carry
# its origin. `normalize_confidence` is the single admission point: it accepts only the three
# bands from a trusted origin, and REFUSES to convert a float. Refusing is the entire point --
# a numeric-to-band conversion is exactly how an AI self-rating would silently acquire the
# authority of an evidence-derived one, so there is deliberately no such conversion anywhere.
CONFIDENCE_SOURCE_EVIDENCE = "evidence"   # this module: deterministic, evidence-derived.
CONFIDENCE_SOURCE_AI = "ai"               # any model self-rating. Never security confidence.

_VALID_CONFIDENCE = (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW)


class ConfidenceProvenanceError(ValueError):
    """Raised when a confidence value is not admissible as EVIDENCE confidence.

    Deliberately an exception and not a silent downgrade: a caller trying to pass an AI rating
    or a raw float into the evidence axis has a bug, and quietly coercing it to `medium` would
    hide precisely the conflation this guard exists to prevent."""


def normalize_confidence(value, *, source: str = CONFIDENCE_SOURCE_EVIDENCE) -> str:
    """Admit `value` as an evidence-confidence band, or raise.

    The ONLY sanctioned way to put a confidence into report/API output. Rules, in order:

      * `source` must be CONFIDENCE_SOURCE_EVIDENCE. An AI-sourced rating is never security
        confidence, whatever its value -- this is the AI-bypass guard, and it fires BEFORE the
        value is even inspected so a well-formed "high" from a model cannot pass.
      * a float/int is REFUSED. The float vocabularies (ai_confidence, attack-graph, agent
        scoring) grade different questions on different scales; mapping them onto these bands
        would invent a comparison that does not exist.
      * a band string is accepted case/whitespace-insensitively (the normalisation this
        function is named for), so inconsistent spellings converge on one representation.
      * None -> the documented safe default, MEDIUM. Same default as `confidence_label`.

    Returns one of CONFIDENCE_HIGH/MEDIUM/LOW. Never returns a float, never returns None."""
    if source != CONFIDENCE_SOURCE_EVIDENCE:
        raise ConfidenceProvenanceError(
            f"confidence from source {source!r} is not evidence confidence; "
            "AI self-ratings are a separate axis and must not be rendered as security confidence"
        )
    if value is None:
        return CONFIDENCE_MEDIUM
    # bool is an int subclass -- checked with the numeric types so True cannot slip through.
    if isinstance(value, (bool, int, float)):
        raise ConfidenceProvenanceError(
            f"numeric confidence {value!r} cannot be converted to an evidence-confidence band; "
            "numeric confidences (ai_confidence, attack-graph, agent scoring) grade different "
            "questions and have no sanctioned mapping onto high/medium/low"
        )
    band = _norm(value)
    if band not in _VALID_CONFIDENCE:
        raise ConfidenceProvenanceError(f"{value!r} is not one of {_VALID_CONFIDENCE}")
    return band


def classify_verification_row(row) -> tuple[str, str]:
    """Convenience for a report VulnRow-like object.

    Reads every field with getattr defaults so any row-like object lacking them (a legacy stub,
    a hand-built test double) still classifies -- mirroring classification.classify_row."""
    return classify_verification(
        template_id=getattr(row, "template_id", None),
        matcher_name=getattr(row, "matcher_name", None),
        evidence_uris=getattr(row, "evidence_uris", None),
        screenshots=getattr(row, "screenshots", None),
        classification=getattr(row, "classification", None),
        cve=getattr(row, "cve", None),
    )


def verification_label(state: str | None) -> str:
    return _VERIFICATION_LABELS.get(_norm(state), _VERIFICATION_LABELS[UNVERIFIED])


def confidence_label(level: str | None) -> str:
    return _CONFIDENCE_LABELS.get(_norm(level), _CONFIDENCE_LABELS[CONFIDENCE_MEDIUM])


def verification_note(state: str | None) -> str:
    """One-line analyst guidance for the report, so the state is never bare jargon."""
    s = _norm(state)
    if s == VERIFIED:
        return "Exploitation corroborated by captured evidence."
    if s == PARTIALLY_VERIFIED:
        return "Supporting evidence captured; manual validation recommended."
    return "Scanner-detected condition requiring manual validation."
