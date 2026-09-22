"""Canonical vulnerability taxonomy vocabulary (Prompt A).

WHY THIS EXISTS
---------------
`VulnerabilityFinding.severity` arrives from a tool and is written straight to
`vulnerabilities.severity` by `ingest_finding`. Nuclei's runner applies `.lower()` and nothing
else, so whatever string the tool emitted becomes the persisted taxonomy value -- including
`"CRITICAL "` (trailing whitespace survives `.lower()`), or any severity word a future nuclei
release introduces.

Nothing validated that string at the ingest boundary, and the ~63 downstream consumers each
re-guessed what an unrecognised value means. They did not agree, so ONE unrecognised severity
produced TWO different wrong answers at once:

  * `reports/data.py` -- `sev = v.severity if v.severity in severity_counts else "info"`.
    A critical RCE whose severity failed the membership test was COUNTED AND RENDERED AS
    INFORMATIONAL in the customer-facing report.
  * `dashboard/service.py` -- adds every row to `active_total` but only assigns
    `by_severity` for a member of `_KNOWN_SEVERITIES`. The per-severity breakdown therefore
    did not sum to the total it was displayed beside, with no indication anything was dropped.

Both are silent. That is the actual defect: not that an odd severity can arrive (it can, and
the tool is entitled to say so), but that it was allowed past the boundary UNNORMALISED, after
which every consumer disagreed about it and the disagreement was invisible.

WHAT THIS MODULE IS
-------------------
The single source of truth for the severity vocabulary, and a pure normaliser applied ONCE at
the ingest boundary. After `normalize_severity`, `vulnerabilities.severity` is guaranteed to
hold a member of `SEVERITIES` -- so every existing downstream `in`-check, rank lookup and
`group_by` keeps working exactly as written, and their fallback branches become unreachable
rather than being reached inconsistently.

WHAT IT DOES NOT DO
-------------------
  * It does NOT invent a severity. An unrecognised value maps to the documented, conservative
    `UNKNOWN_SEVERITY_FALLBACK` and is reported by `severity_is_canonical` so the caller can
    log it -- the value is never silently upgraded to something more alarming, nor downgraded
    to `info` the way the report layer previously did.
  * It does NOT touch CWE/CVE. `category` carries the tool's CWE id and ATT&CK already
    normalises case at its own lookup (`catalog.techniques_for` -> `category.strip().lower()`),
    so there is no second vocabulary to unify here and no mapping is fabricated.
  * It does NOT change severity semantics for any value a tool already reported correctly.
    Every canonical input is returned unchanged.

THE FALLBACK CHOICE
-------------------
An unrecognised severity becomes `medium`, NOT `info`. `info` is what the report layer did, and
it is the unsafe direction: it hides a finding the tool may have considered critical. `medium`
is the same conservative default `reports/verification.py` documents for an unproven-but-real
signal -- it keeps the finding visible for analyst triage without asserting a severity the tool
did not actually state. The original string is preserved by the caller in the finding's
metadata, so nothing the tool said is lost.
"""

import re as _re

# The canonical severity vocabulary, ordered most severe first. This is the SAME set already
# hard-coded (separately) in reports/data.py `_SEVERITY_ORDER`, dashboard/service.py
# `_KNOWN_SEVERITIES` and reports/render.py `_SEVERITY_RANK`; those are deliberately left
# untouched -- normalising at ingest makes them all agree instead of rewriting 63 call sites.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

# Where an unrecognised severity lands. See "THE FALLBACK CHOICE" above for why this is
# `medium` and not `info`.
UNKNOWN_SEVERITY_FALLBACK = "medium"

# Tool spellings that mean a canonical severity but are not spelled like one. Kept
# deliberately small: only unambiguous synonyms actually emitted by scanners in this
# toolchain's ecosystem. A word not listed here is NOT guessed at -- it takes the fallback.
_SEVERITY_ALIASES: dict[str, str] = {
    "informational": "info",
    "information": "info",
    "none": "info",
    "unknown": UNKNOWN_SEVERITY_FALLBACK,
    "moderate": "medium",
    "important": "high",
    "severe": "high",
}


def normalize_severity(value: object) -> str:
    """Return a member of `SEVERITIES` for any input. Pure, total, and case/whitespace safe.

    Canonical input is returned unchanged, so this is a no-op for every severity the tools
    already report correctly -- which is the overwhelming majority of real traffic.
    """
    text = str(value or "").strip().lower()
    if text in SEVERITIES:
        return text
    if text in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[text]
    return UNKNOWN_SEVERITY_FALLBACK


def severity_is_canonical(value: object) -> bool:
    """True when `value` is already an exact canonical severity.

    Lets the ingest path tell "the tool reported a clean severity" apart from "we had to
    normalise/fall back", so the latter can be logged as the taxonomy anomaly it is instead of
    disappearing. Note this is intentionally STRICTER than `normalize_severity` succeeding: an
    alias like `"informational"` normalises cleanly but is not canonical, and a caller that
    wants to record exactly what the tool said can see that.
    """
    return str(value or "").strip().lower() in SEVERITIES and str(value) == str(value).strip().lower()


# =============================================================================================
# CANONICAL WEAKNESS IDENTIFIERS -- CWE and CVE (Prompt 23)
#
# WHAT THE AUDIT FOUND. Severity was normalised at the ingest boundary (above); the CWE that
# arrives in the SAME finding was not. `ingest_finding` writes `category=finding.category`
# verbatim, and three consumers then disagree about what that string means:
#
#   * attack/catalog.techniques_for  -- CWE_TECHNIQUE_MAP.get(category.strip().lower())
#   * compliance/catalog.controls_for_category -- CWE_CONTROL_MAP.get(category.strip().lower())
#   * reports/narrative._class_from_cwe -- a TOLERANT regex, cwe[-_ ]?(\d+)
#
# `.strip().lower()` fixes case and padding but NOT the separator. So `cwe_89`, `CWE 89` and a
# bare `89` -- all legitimate spellings of CWE-89 -- lose their ATT&CK techniques AND their
# compliance controls, while the narrative layer still resolves them to "sqli". One finding,
# two subsystems silently returning nothing, a third returning the right answer. That is the
# same class of defect the severity normaliser above was written to close, in the field it
# explicitly declined to cover.
#
# WHAT THIS ADDS. A pure canonicaliser applied at the SAME boundary, so `category` holds one
# spelling -- `cwe-<digits>` -- and every existing `.strip().lower()` lookup keeps working
# exactly as written while its miss-branch becomes unreachable instead of inconsistently hit.
#
# WHAT IT REFUSES TO DO (the non-fabrication rule, which is the point of the whole exercise):
#   * It NEVER invents a CWE. No severity->CWE guess, no title keyword->CWE guess, no default.
#     A finding without a CWE canonicalises to None and stays without one.
#   * It NEVER invents a CVE, and never derives one from a CWE or vice versa -- they are
#     independent identifiers answering different questions (a weakness CLASS vs a specific
#     published INSTANCE).
#   * It REJECTS a malformed identifier rather than coercing it. `cwe-abc`, `cwe-`, `CVE-99-1`
#     return None: an unparseable id is absence of information, and manufacturing a plausible
#     id from it would be exactly the fabrication this prompt forbids.
#   * It does NOT alter scanner-native provenance. The raw string the tool emitted stays in the
#     finding's metadata; this only governs the CANONICAL taxonomy column.

# A CWE id in any spelling a tool plausibly emits: optional `cwe` prefix with -, _ or space,
# then the numeric id. Anchored end-to-end so trailing junk cannot ride along.
_CWE_RE = _re.compile(r"^cwe[-_ ]?(\d+)$")
# A bare numeric CWE ("89"). Accepted because nuclei's cwe-id list and some feeds omit the
# prefix; canonicalised to the prefixed form so it joins the one vocabulary.
_BARE_CWE_RE = _re.compile(r"^(\d+)$")
# CVE id format: CVE-<4-digit year>-<4+ digit sequence>. Bounded exactly like
# reports/classification._CVE_RE so the two modules cannot disagree about what a CVE looks like.
_CVE_RE = _re.compile(r"^cve[-_ ]?(\d{4})[-_ ]?(\d{4,7})$")


def canonical_cwe(value: object) -> str | None:
    """Return `cwe-<id>` for any recognised CWE spelling, else None. Pure and total.

    Accepts `cwe-89`, `CWE-89`, `cwe_89`, `CWE 89`, `89` and surrounding whitespace -- every
    spelling the audit found reaching consumers -- and collapses them onto the single form the
    ATT&CK and compliance catalogues are keyed by.

    Returns None for a missing, empty or MALFORMED value. None means "this finding has no
    CWE", which is a truthful statement; it is never a stand-in for a guessed one."""
    text = str(value or "").strip().lower()
    if not text:
        return None
    match = _CWE_RE.match(text) or _BARE_CWE_RE.match(text)
    if not match:
        return None
    # Strip leading zeros ("cwe-089" -> "cwe-89") so one weakness has one key, but never
    # produce "cwe-" from "cwe-0": CWE ids are positive.
    number = match.group(1).lstrip("0")
    return f"cwe-{number}" if number else None


def cwe_is_canonical(value: object) -> bool:
    """True when `value` is ALREADY exactly `cwe-<id>` with no normalisation needed.

    The CWE counterpart of `severity_is_canonical`, and used the same way: it lets the ingest
    path log the spellings it had to correct instead of silently correcting them."""
    text = str(value or "")
    return bool(text) and text == canonical_cwe(text)


def canonical_cve(value: object) -> str | None:
    """Return `CVE-YYYY-NNNN` (upper-case, the MITRE-published form) or None.

    Accepts the separator/case variants a tool may emit. Returns None for anything that is not
    a well-formed CVE id -- including a CWE, a bare number, or a truncated id. A CVE is a claim
    that a SPECIFIC published vulnerability is present; emitting a malformed or invented one
    into a security report is precisely the fabrication this prompt prohibits, so a value that
    does not parse is reported as absent rather than repaired."""
    text = str(value or "").strip().lower()
    if not text:
        return None
    match = _CVE_RE.match(text)
    if not match:
        return None
    return f"CVE-{match.group(1)}-{match.group(2)}"


def cve_is_canonical(value: object) -> bool:
    """True when `value` is already exactly the canonical `CVE-YYYY-NNNN` form."""
    text = str(value or "")
    return bool(text) and text == canonical_cve(text)
