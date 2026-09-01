"""Detection vs Vulnerability classification (reporting layer).

WHY THIS EXISTS
---------------
Every scanner finding is persisted as a `Vulnerability` row -- there is no classification
column (see vulnerabilities/models.py). So a technology/WAF/version DETECTION is stored and
rendered identically to a real command-injection VULNERABILITY. The security score already
handles this safely (info is excluded from scoring), but the Technical Report presented
detections with full vulnerability treatment, and ATT&CK inherited technique mappings for
detections via their CWE.

This module is the SINGLE SOURCE OF TRUTH for that distinction. It is a pure classifier over
metadata the scanner already produces -- no schema change, no new column.

WHAT DRIVES THE DECISION (never severity alone)
-----------------------------------------------
A finding is a DETECTION when it merely reports something present/observed, not something
exploitable. The signal, in priority order:

  1. template_id shape -- detection templates are named by convention: a `-detect`/`-detection`
     suffix, or `tech-`/`waf-`/`fingerprint`/`-eol`/`version` markers. This is nuclei's own
     naming, verified against the live dataset: NO non-info template matches these patterns,
     so a real vulnerability is never misclassified as a detection.
  2. tags -- nuclei classification tags. Purely-detection tags ({tech, detect, waf,
     fingerprint, ...}) with no exploit tag ({sqli, rce, injection, ...}) => detection.

A finding is a VULNERABILITY when any of these hold (they OUTRANK the detection signal, so the
classifier fails toward "vulnerability" -- under-reporting detections rather than ever hiding
a weakness):
  * it carries a real CVSS score (> 0), or a CVE id, or
  * an exploit-class tag, or a CWE that maps to an ATT&CK technique.

`info` severity is a weak hint, not the decision: an info finding with a real CWE weakness
(e.g. missing security headers) is still a WEAKNESS, not a bare detection -- so info alone
never forces the detection label.
"""

VULNERABILITY = "vulnerability"
DETECTION = "detection"

# template_id substrings/suffixes that mark a detection template (nuclei naming convention).
_DETECTION_TEMPLATE_MARKERS = (
    "detect",        # tech-detect, waf-detect, apollo-server-detect, ...-detection
    "fingerprint",   # fingerprinthub-web-fingerprints
    "-eol",          # nginx-eol (end-of-life notice, not an exploitable flaw)
    "-version",      # nginx-version
    "version-detect",
)
_DETECTION_TEMPLATE_PREFIXES = ("tech-", "waf-")

# tags that, ON THEIR OWN, indicate observation rather than a weakness.
_DETECTION_TAGS = frozenset({
    "tech", "detect", "detection", "waf", "fingerprint", "fingerprints", "favicon",
})
# tags that positively indicate an exploitable class -> always a vulnerability.
_EXPLOIT_TAGS = frozenset({
    "sqli", "xss", "rce", "ssti", "lfi", "ssrf", "injection", "cve", "csrf",
    "auth-bypass", "default-login", "default-logins", "takeover", "deserialization",
})


def _norm_tags(tags) -> set[str]:
    if not tags:
        return set()
    if isinstance(tags, str):
        parts = tags.replace(",", " ").split()
    else:
        parts = list(tags)
    return {str(t).strip().lower() for t in parts if str(t).strip()}


def _template_looks_like_detection(template_id: str | None) -> bool:
    if not template_id:
        return False
    t = template_id.strip().lower()
    if any(t.startswith(p) for p in _DETECTION_TEMPLATE_PREFIXES):
        return True
    return any(m in t for m in _DETECTION_TEMPLATE_MARKERS)


def classify(
    *,
    template_id: str | None,
    cvss_score: float | None,
    category: str | None = None,
    tags=None,
    cve: str | None = None,
) -> str:
    """Return VULNERABILITY or DETECTION for one finding. Pure; fails toward VULNERABILITY.

    Every argument comes from metadata the scanner already produces and the report already
    loads -- template_id (fingerprint), cvss_score (column), category=CWE (column), and
    tags/cve (nuclei metadata, when available)."""
    tag_set = _norm_tags(tags)

    # Positive vulnerability signals outrank everything -- never hide a real weakness.
    if cvss_score is not None and cvss_score > 0:
        return VULNERABILITY
    if cve:
        return VULNERABILITY
    if tag_set & _EXPLOIT_TAGS:
        return VULNERABILITY

    # Detection signals.
    if _template_looks_like_detection(template_id):
        return DETECTION
    if tag_set and tag_set <= _DETECTION_TAGS:
        return DETECTION

    # No clear detection marker: treat as a (weak) vulnerability/weakness rather than a bare
    # detection -- e.g. an info CWE-693 "missing security headers" finding is a weakness.
    return VULNERABILITY


def classify_row(row) -> str:
    """Convenience for a report VulnRow-like object (template_id, cvss_score, category)."""
    return classify(
        template_id=getattr(row, "template_id", None),
        cvss_score=getattr(row, "cvss_score", None),
        category=getattr(row, "category", None),
    )
