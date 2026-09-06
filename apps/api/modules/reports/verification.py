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
    n_screens = len(screenshots or ())
    n_evidence = len(evidence_uris or ())
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
