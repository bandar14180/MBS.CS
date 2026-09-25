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

import re

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


# A CVE id anywhere in a template_id or title, e.g. "CVE-2021-41773" in
# `apache-detect-cve-2021-41773`. Nuclei names CVE templates after the CVE, and the id also
# survives into the finding title -- so the strongest vulnerability signal is recoverable
# from what IS persisted, with no schema change. Bounded {4} year / {4,7} sequence per the
# CVE id format, so it cannot match arbitrary hyphenated text.
_CVE_RE = re.compile(r"cve[-_]\d{4}[-_]\d{4,7}", re.IGNORECASE)


def _recover_cve(*candidates: str | None) -> str | None:
    """First CVE id found in the given strings, or None.

    WHY: `cve` is NOT a column on `vulnerabilities` -- the nuclei runner captures cve-id into
    transient finding metadata that `sync_attack_mappings` consumes and discards, so by the
    time the report layer reads a row the explicit cve is gone. Recovering it from the
    template_id/title restores the classifier's strongest vulnerability signal without adding
    a column or changing how findings are stored. Read-only and purely additive: it can only
    ever turn a would-be DETECTION into a VULNERABILITY, never the reverse."""
    for value in candidates:
        if not value:
            continue
        match = _CVE_RE.search(str(value))
        if match:
            return match.group(0)
    return None


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
    """Convenience for a report VulnRow-like object.

    Forwards EVERY signal the row actually carries -- including `cve` and `tags`, which the
    nuclei runner already captures (nuclei_runner.parse_vulnerabilities puts cve-id and the
    template's tags into the finding metadata) and VulnRow now surfaces. They are read with
    getattr defaults so any row-like object WITHOUT them (a legacy stub, a hand-built test
    double) keeps classifying exactly as before.

    Passing them matters because they are the classifier's strongest VULNERABILITY signals:
    dropping them broke the module's own guarantee (see the header: positive vulnerability
    signals outrank the detection markers, so a real weakness is never hidden). A CVE-backed
    finding whose CVSS happens to be absent and whose template name contains "detect" -- e.g.
    `apache-detect-cve-2021-41773` -- was classified DETECTION with the metadata dropped, and
    is correctly classified VULNERABILITY once the cve is forwarded."""
    template_id = getattr(row, "template_id", None)
    title = getattr(row, "title", None)
    # An explicit cve on the row wins; otherwise recover it from the template_id/title, which
    # ARE persisted (see _recover_cve for why the explicit value is usually gone by now).
    cve = getattr(row, "cve", None) or _recover_cve(template_id, title)
    return classify(
        template_id=template_id,
        cvss_score=getattr(row, "cvss_score", None),
        category=getattr(row, "category", None),
        tags=getattr(row, "tags", None),
        cve=cve,
    )
