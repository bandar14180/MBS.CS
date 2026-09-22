"""MBS-authored descriptions for reviewed Nuclei templates, keyed by template ID.

WHAT THIS MODULE IS -- AND IS NOT
---------------------------------
Every string in `_CATALOGUE` is written by MBS. None of it is scanner output. The scanner's
own words live in `vulnerabilities.description`, travel as `VulnRow.description`, reach the
renderer as the finding group's "description" key, and are attributed in the report under
"Scanning engine description:". Text from THIS module travels on a separate parameter
(`narrative.description(curated_text=...)`) and is attributed under "MBS analyst
description:". The two never merge, and this module must never be used to populate the
scanner's field: when the scanner supplied no description, that column stays NULL.

WHAT THE PROSE MAY SAY
----------------------
These descriptions explain the WEAKNESS CLASS and the behaviour of the specific template
that matched. They are written without sight of any particular finding, so they must not --
and do not -- assert that exploitation occurred, name a CVE or CWE as evidenced, or describe
a request or response as observed. Anything of that kind belongs to the finding's own
evidence, not here. Per-finding facts (where it was seen, how many locations, whether the
match was by inference, what the evidence proves) are emitted by narrative.py from data the
report already holds.

LOOKUP CONTRACT
---------------
Exact template-ID match only, after lowercasing and stripping surrounding whitespace. There
is no fuzzy matching, no prefix matching and no generic fallback: a template nobody has
reviewed returns None and the report simply carries no MBS analyst description for it. That
is deliberate. A fallback here would put unreviewed MBS prose under findings it was never
written for, which is the failure mode this module exists to prevent.

This module is pure: no imports from `reports`, no database access, no scanner execution.
"""

from __future__ import annotations

# Keys MUST be lowercase and stripped -- `curated_description` normalises its argument the
# same way, and the unit tests assert the keys already satisfy the normal form so a typo in a
# key cannot silently make an entry unreachable.
_CATALOGUE: dict[str, str] = {
    # Reflected XSS. The class-level explanation (input returned unencoded, browser parses it
    # as markup) is already emitted from narrative.Weakness; what this adds is what makes the
    # REFLECTED variant distinct: the payload is not stored, so delivery requires the victim
    # to issue the crafted request, which is what bounds its practical exploitability.
    "reflected-xss": (
        "In the reflected variant of cross-site scripting, the injected value is returned in "
        "the immediate response to the request that carried it and is not retained by the "
        "application, so each execution requires a victim to issue a request the attacker "
        "controls -- typically via a crafted link or a form submission from another origin. "
        "Delivery therefore depends on that interaction rather than on the payload persisting "
        "server-side, which distinguishes this variant from stored cross-site scripting and "
        "is the usual reason it is rated below it. It is not, however, a reason to treat the "
        "underlying encoding defect as lower priority: the missing output encoding is the same "
        "defect in either variant, the same parameter may be reachable from paths that do "
        "persist it, and a reflected payload executes under the application's own origin with "
        "whatever session the victim holds. Assessment of the real exposure depends on the "
        "context the value is written into (HTML body, attribute, URL or script), on whether "
        "the affected parameter is reachable without authentication, and on any "
        "Content-Security-Policy in force at that response."
    ),
    # Blind SSRF. The class-level SSRF text already covers "server fetches a client-supplied
    # URL". What matters for the BLIND template is that confirmation arrives out-of-band: the
    # response body does not carry the fetched content, so the evidence is an interaction
    # record, and what that evidence does and does not establish must be stated plainly.
    "blind-ssrf": (
        "In the blind variant of server-side request forgery, the application can be induced "
        "to issue a server-side request, but the response to that request is not returned to "
        "the client. Detection therefore relies on an out-of-band signal -- the target server "
        "contacting a collaborator host under the tester's control, typically over DNS or "
        "HTTP -- or on differences in timing or status code, rather than on retrieved content "
        "appearing in the response. An interaction of that kind establishes that the server "
        "was made to originate a request to an attacker-influenced destination; by itself it "
        "does not establish what the server could reach on an internal network, nor that any "
        "internal content was retrieved, and any such conclusion needs evidence of its own. "
        "The absence of a returned body limits direct data disclosure but does not make the "
        "condition low risk: the same request primitive can be used to reach internal or "
        "loopback services and cloud instance metadata endpoints that are not reachable from "
        "outside, and to perform state-changing requests against them, with the outcome "
        "inferred rather than read. Exposure depends on what the affected host can reach "
        "outbound and on whether redirects and resolved addresses are re-validated."
    ),
}


def curated_description(template_id: str | None) -> str | None:
    """MBS-authored description for `template_id`, or None if none has been reviewed.

    Lookup is exact after normalisation (lowercase, surrounding whitespace stripped). None,
    an empty string and whitespace-only input all return None, as does any template that is
    not in the catalogue -- there is no fallback text, by design.

    The returned string is MBS-authored. Callers MUST NOT present it as scanner output, write
    it to `vulnerabilities.description`, or place it on a finding group's "description" key.
    """
    if not template_id:
        return None
    return _CATALOGUE.get(template_id.strip().lower())


def catalogue_template_ids() -> tuple[str, ...]:
    """Template IDs that have a reviewed MBS description, in catalogue order."""
    return tuple(_CATALOGUE)
