"""Per-finding professional narrative for the MBS.PT security assessment report.

WHY THIS EXISTS
---------------
Before this module the Detailed Findings section could state only what the scanner itself
recorded: a title, a severity, a CVSS, and `vulnerabilities.description` -- a one-line blurb
that is absent for most rows. A reader was told THAT a condition matched, never what the
weakness is, why it exists, how it would be abused, or what the realistic impact is. That is
the difference between a scanner dump and a penetration-testing report.

This module supplies the missing prose. It is a PURE, DETERMINISTIC function of metadata the
report already loads -- no database, no clock, no network, no AI. The same finding always
produces the same narrative.

WHAT IT MUST NEVER DO (these are requirements, not preferences)
--------------------------------------------------------------
  * It never reads or returns a severity, a CVSS, a risk score or a verification state as an
    OUTPUT. It READS verification to choose its wording and nothing else. By construction it
    cannot alter any stored value, any score, or any classifier's decision.
  * It never overstates. Impact language is GATED on the finding's verification state (see
    `impact()`): only a VERIFIED finding may use confirmatory phrasing, and even then only for
    outcomes the captured evidence actually supports. PARTIALLY_VERIFIED and UNVERIFIED
    findings are described as potential and are explicitly marked as requiring manual
    validation.
  * It never claims a prerequisite it cannot support. Authentication, user interaction and
    server conditions are stated from the weakness class only, in the conditional, and the
    report says what was NOT assessed rather than implying it was.

THE KNOWLEDGE BASE
------------------
`_CLASSES` maps a weakness class to its explanation. A finding is matched to a class from
signals the report ALREADY has -- `category` (the CWE string), `template_id`, `title` and
`tags` -- by `classify_weakness()`. An unmatched finding falls back to `_GENERIC`, which is
deliberately non-committal rather than wrong.

Matching is CWE-first: the CWE is the most precise signal and is a stored column. Template and
title are consulted only when the CWE is absent or unrecognised, and are matched on whole
tokens so that (for example) a template mentioning "redirect" cannot capture an unrelated
finding whose title merely contains the substring.
"""

import re

from apps.api.modules.reports.verification import (
    PARTIALLY_VERIFIED,
    VERIFIED,
)

# --- Impact certainty labels --------------------------------------------------------------
# The three states the report must keep visibly distinct. They are derived ONLY from the
# verification state the verification.py classifier already produced.
CONFIRMED = "confirmed"
POTENTIAL = "potential"
UNVERIFIED_IMPACT = "unverified"

_IMPACT_HEADINGS = {
    CONFIRMED: "Security Impact — CONFIRMED by captured evidence",
    POTENTIAL: "Security Impact — POTENTIAL (exploitation not fully demonstrated)",
    UNVERIFIED_IMPACT: "Security Impact — POTENTIAL (unverified; requires manual validation)",
}


def impact_certainty(verification: str | None) -> str:
    """Map a verification state onto the report's impact-certainty label.

    The ONLY place the mapping is defined, so no caller can invent a fourth state or promote a
    finding's certainty. VERIFIED is the sole route to CONFIRMED."""
    state = (verification or "").strip().lower()
    if state == VERIFIED:
        return CONFIRMED
    if state == PARTIALLY_VERIFIED:
        return POTENTIAL
    return UNVERIFIED_IMPACT


def impact_heading(verification: str | None) -> str:
    return _IMPACT_HEADINGS[impact_certainty(verification)]


class Weakness:
    """One weakness class's explanation. Plain data; every field is static prose.

    `confirmed_impact` is written so it is TRUE ONLY of outcomes that captured evidence can
    actually establish, because it is emitted only for VERIFIED findings. `potential_impact`
    is written in the conditional and is what every other finding receives."""

    __slots__ = (
        "key", "name", "what_it_is", "why_it_exists", "attack_scenario",
        "confirmed_impact", "potential_impact", "prerequisites", "controls", "references",
    )

    def __init__(self, key, name, what_it_is, why_it_exists, attack_scenario,
                 confirmed_impact, potential_impact, prerequisites, controls, references=()):
        self.key = key
        self.name = name
        self.what_it_is = what_it_is
        self.why_it_exists = why_it_exists
        self.attack_scenario = attack_scenario
        self.confirmed_impact = confirmed_impact
        self.potential_impact = potential_impact
        self.prerequisites = prerequisites
        self.controls = list(controls)
        self.references = list(references)


# NOTE ON WORDING. Every `potential_impact` below is phrased with "could potentially" / "may"
# and names what was NOT demonstrated. Every `confirmed_impact` names only what evidence can
# show. No entry claims total compromise, administrator access, or exfiltration of all data:
# those outcomes require proof this pipeline does not produce.

_CLASSES: dict[str, Weakness] = {
    "sqli": Weakness(
        key="sqli",
        name="SQL Injection",
        what_it_is=(
            "User-controllable input is incorporated into an SQL statement that the "
            "application sends to its database."
        ),
        why_it_exists=(
            "The statement is assembled by concatenating or interpolating request data into "
            "SQL text rather than being sent as a parameterised query, so the database parses "
            "attacker-supplied characters as query syntax instead of as literal values."
        ),
        attack_scenario=(
            "An attacker submits input containing SQL syntax (quotes, boolean expressions, "
            "comment sequences or a time-delay function) to an affected parameter and observes "
            "a change in the response content, an error, or the response timing."
        ),
        confirmed_impact=(
            "The captured evidence establishes that attacker-supplied SQL syntax altered the "
            "query the application executed."
        ),
        potential_impact=(
            "Successful exploitation could potentially allow unauthorised database queries, "
            "disclosure of data held in the database, or modification of stored records, and "
            "in some configurations execution of database functions."
        ),
        prerequisites=(
            "Network reachability of the affected endpoint. Whether authentication is required "
            "depends on where the affected parameter is exposed."
        ),
        controls=(
            "Use parameterised queries (prepared statements) or a query builder that binds "
            "values, so request data can never be parsed as SQL syntax.",
            "Do not build SQL by string concatenation or interpolation, including for table, "
            "column and ORDER BY fragments; map those to a fixed allowlist of permitted values.",
            "Validate and canonicalise input against a strict allowlist of expected type, "
            "format and range; reject rather than attempt to sanitise.",
            "Run the application's database account with least privilege — only the objects "
            "and statements it needs, and no DDL or administrative rights.",
            "Ensure database errors are logged server-side and never returned to the client.",
        ),
        references=("CWE-89", "OWASP A03:2021 — Injection"),
    ),
    "command_injection": Weakness(
        key="command_injection",
        name="OS Command Injection",
        what_it_is=(
            "User-controllable input reaches an operating-system command that the server "
            "invokes."
        ),
        why_it_exists=(
            "The command is executed through a shell with request data embedded in the command "
            "string, and the input is neither restricted to an allowlist nor separated from the "
            "command's arguments, so shell metacharacters are interpreted as command syntax "
            "rather than as data."
        ),
        attack_scenario=(
            "An attacker submits a value containing shell metacharacters (a semicolon, pipe, "
            "backtick or command substitution) to an affected parameter and observes command "
            "output in the response or a timing difference consistent with execution."
        ),
        confirmed_impact=(
            "The captured evidence establishes that attacker-supplied input was executed as an "
            "operating-system command by the server."
        ),
        potential_impact=(
            "Successful exploitation could potentially allow execution of operating-system "
            "commands in the context of the service account, which may permit reading "
            "application files, reaching internal services, or establishing outbound "
            "connections. The realistic extent depends on the privileges of that account and "
            "on egress restrictions."
        ),
        prerequisites=(
            "Network reachability of the affected endpoint, and the ability to supply the "
            "affected parameter. No user interaction is required."
        ),
        controls=(
            "Avoid invoking a shell. Use an API that accepts an argument vector (execve-style) "
            "so input cannot be reparsed as command syntax.",
            "Where an external command is unavoidable, restrict the input to a strict allowlist "
            "of permitted values and reject anything else.",
            "Pass user data as arguments only, never as part of the command string, and never "
            "interpolate it into a shell expression.",
            "Run the service under a least-privileged account with no interactive shell.",
            "Restrict outbound network access from application hosts so that command execution "
            "cannot readily be escalated into onward access.",
        ),
        references=("CWE-78", "OWASP A03:2021 — Injection"),
    ),
    "ssrf": Weakness(
        key="ssrf",
        name="Server-Side Request Forgery (SSRF)",
        what_it_is=(
            "The application fetches a URL supplied or influenced by the client, causing the "
            "server to issue a request of the attacker's choosing."
        ),
        why_it_exists=(
            "The destination is taken from request data and used without being checked against "
            "an allowlist of permitted hosts, and the resolved address is not restricted, so "
            "the server will connect to internal addresses it can reach but the client cannot."
        ),
        attack_scenario=(
            "An attacker supplies a URL pointing at an internal address, a loopback service or "
            "a cloud metadata endpoint, and infers the outcome from the response body, the "
            "status code, or the response timing."
        ),
        confirmed_impact=(
            "The captured evidence establishes that the server issued a request to a "
            "destination controlled by the request data."
        ),
        potential_impact=(
            "Successful exploitation could potentially allow enumeration of internal network "
            "services, retrieval of content from systems that are not externally reachable, or "
            "access to instance metadata services where the environment exposes them. Retrieval "
            "of sensitive internal content was not demonstrated by this finding alone."
        ),
        prerequisites=(
            "Network reachability of the affected endpoint, and a parameter that influences the "
            "destination of a server-side request."
        ),
        controls=(
            "Validate the destination against a strict allowlist of permitted hosts, ports and "
            "schemes; reject anything not on it rather than filtering known-bad values.",
            "Resolve the hostname and block private, loopback, link-local and metadata address "
            "ranges, re-checking after resolution to prevent DNS rebinding.",
            "Disable or explicitly validate HTTP redirects, re-applying the allowlist to every "
            "redirect target.",
            "Apply egress filtering so application hosts can reach only the destinations they "
            "legitimately require.",
            "Do not return the fetched response body to the client verbatim.",
        ),
        references=("CWE-918", "OWASP A10:2021 — Server-Side Request Forgery"),
    ),
    "xss": Weakness(
        key="xss",
        name="Cross-Site Scripting (XSS)",
        what_it_is=(
            "User-controllable input is returned in an HTML response without being encoded for "
            "the context in which it appears."
        ),
        why_it_exists=(
            "The application writes request data into markup, an attribute or a script context "
            "without applying context-appropriate output encoding, so the browser parses the "
            "input as markup or script rather than as text."
        ),
        attack_scenario=(
            "An attacker crafts a request containing markup or script and induces a victim to "
            "issue it, or stores the payload where other users will retrieve it; the payload "
            "then executes in the victim's browser under the application's origin."
        ),
        confirmed_impact=(
            "The captured evidence establishes that attacker-supplied markup was returned "
            "unencoded and interpreted in the browser."
        ),
        potential_impact=(
            "Successful exploitation could potentially allow actions to be performed in the "
            "browser of an affected user under that user's session, disclosure of data rendered "
            "in the page, or presentation of attacker-controlled content within the "
            "application's origin. The scope depends on the session handling and on any "
            "content-security policy in force."
        ),
        prerequisites=(
            "For reflected variants, a victim must issue the crafted request, so user "
            "interaction is required. For stored variants, no interaction beyond viewing the "
            "affected content is required."
        ),
        controls=(
            "Apply context-aware output encoding at the point of rendering (HTML body, "
            "attribute, URL and JavaScript contexts each require different encoding).",
            "Prefer templating that escapes by default, and avoid APIs that write raw markup.",
            "Where HTML must be accepted, sanitise it with a well-maintained allowlist-based "
            "sanitiser rather than a denylist.",
            "Deploy a Content-Security-Policy that restricts script sources and forbids inline "
            "script, as defence in depth.",
            "Set HttpOnly on session cookies so they are not readable from script.",
        ),
        references=("CWE-79", "OWASP A03:2021 — Injection"),
    ),
    "path_traversal": Weakness(
        key="path_traversal",
        name="Path Traversal",
        what_it_is=(
            "User-controllable input is used to build a filesystem path that the application "
            "reads or writes."
        ),
        why_it_exists=(
            "The path is assembled from request data without canonicalising the result and "
            "confirming it remains inside the intended base directory, so traversal sequences "
            "resolve outside it."
        ),
        attack_scenario=(
            "An attacker supplies a parameter containing traversal sequences, in plain or "
            "encoded form, and requests a file outside the intended directory."
        ),
        confirmed_impact=(
            "The captured evidence establishes that a file outside the intended directory was "
            "returned by the application."
        ),
        potential_impact=(
            "Successful exploitation could potentially allow retrieval of files readable by the "
            "service account, which may include configuration files or credentials held on "
            "disk. Which files are exposed depends on the account's permissions and was not "
            "enumerated during this assessment."
        ),
        prerequisites=(
            "Network reachability of the affected endpoint and a parameter that influences a "
            "file path."
        ),
        controls=(
            "Do not build paths from request data. Map an opaque identifier to a permitted file "
            "through a server-side lookup.",
            "Where a path component is unavoidable, canonicalise the full path and verify it "
            "remains within the intended base directory before opening it.",
            "Reject traversal sequences and absolute paths after decoding, not before.",
            "Run the service under an account whose filesystem permissions are limited to the "
            "content it must serve.",
        ),
        references=("CWE-22", "OWASP A01:2021 — Broken Access Control"),
    ),
    "file_inclusion": Weakness(
        key="file_inclusion",
        name="File Inclusion",
        what_it_is=(
            "User-controllable input determines which file the application includes or "
            "executes."
        ),
        why_it_exists=(
            "The include target is taken from request data and is not constrained to a fixed "
            "set of permitted resources, so the application can be induced to load a file the "
            "developer did not intend."
        ),
        attack_scenario=(
            "An attacker supplies a path or URL to the affected parameter and observes the "
            "contents or the effects of the included resource in the response."
        ),
        confirmed_impact=(
            "The captured evidence establishes that a file selected by the request was included "
            "by the application."
        ),
        potential_impact=(
            "Successful exploitation could potentially allow disclosure of local file contents "
            "and, where a remote or attacker-writable file can be included, execution of "
            "attacker-supplied code. Code execution was not demonstrated by this finding alone."
        ),
        prerequisites=(
            "Network reachability of the affected endpoint and a parameter that selects an "
            "included resource."
        ),
        controls=(
            "Replace the dynamic include with a fixed mapping from an opaque identifier to a "
            "permitted resource.",
            "Disable remote file inclusion in the runtime configuration.",
            "Canonicalise and confirm any resolved path stays within the intended directory.",
            "Run the service with least-privileged filesystem access.",
        ),
        references=("CWE-98", "CWE-22"),
    ),
    "ssti": Weakness(
        key="ssti",
        name="Server-Side Template Injection",
        what_it_is=(
            "User-controllable input is embedded into a server-side template that is then "
            "evaluated."
        ),
        why_it_exists=(
            "Request data is concatenated into the template source rather than passed as a "
            "bound variable, so the template engine evaluates attacker-supplied expressions."
        ),
        attack_scenario=(
            "An attacker submits a template expression to an affected parameter and observes "
            "the evaluated result in the response."
        ),
        confirmed_impact=(
            "The captured evidence establishes that an attacker-supplied template expression "
            "was evaluated by the server."
        ),
        potential_impact=(
            "Successful exploitation could potentially allow disclosure of application state "
            "and, depending on the template engine and the objects it exposes, execution of "
            "code on the server. Code execution was not demonstrated by this finding alone."
        ),
        prerequisites=(
            "Network reachability of the affected endpoint and a parameter that reaches template "
            "rendering."
        ),
        controls=(
            "Pass user data to templates as bound context variables; never concatenate it into "
            "template source.",
            "Use a logic-less or sandboxed template engine for any template influenced by user "
            "input.",
            "Restrict the objects and functions exposed to the template context.",
        ),
        references=("CWE-1336", "CWE-94"),
    ),
    "deserialization": Weakness(
        key="deserialization",
        name="Insecure Deserialisation",
        what_it_is=(
            "The application deserialises data supplied by the client into application objects."
        ),
        why_it_exists=(
            "The serialised input is not integrity-protected and the deserialiser is permitted "
            "to instantiate arbitrary types, so an attacker can influence which objects are "
            "constructed and which of their methods run."
        ),
        attack_scenario=(
            "An attacker submits a crafted serialised object whose construction triggers a "
            "chain of method calls available in the application's dependencies."
        ),
        confirmed_impact=(
            "The captured evidence establishes that attacker-supplied serialised data was "
            "processed by the deserialiser."
        ),
        potential_impact=(
            "Successful exploitation could potentially allow manipulation of application logic "
            "and, where a suitable gadget chain exists in the dependencies, execution of code "
            "on the server. The presence of such a chain was not established during this "
            "assessment."
        ),
        prerequisites=(
            "The ability to supply serialised input to the affected endpoint."
        ),
        controls=(
            "Do not deserialise untrusted input. Prefer a data-only format (JSON) parsed into "
            "explicit types.",
            "Where object deserialisation is unavoidable, apply an allowlist of permitted "
            "types.",
            "Integrity-protect serialised data with a signature verified before deserialisation.",
            "Keep dependencies current to reduce the gadget chains available.",
        ),
        references=("CWE-502", "OWASP A08:2021 — Software and Data Integrity Failures"),
    ),
    "xxe": Weakness(
        key="xxe",
        name="XML External Entity (XXE) Processing",
        what_it_is=(
            "The application parses XML supplied by the client with external entity resolution "
            "enabled."
        ),
        why_it_exists=(
            "The XML parser is left at a default configuration that resolves external entities "
            "and document type definitions, so the document can instruct the parser to fetch "
            "local or remote resources."
        ),
        attack_scenario=(
            "An attacker submits an XML document declaring an external entity that references a "
            "local file or an internal URL, and observes the resolved content or a "
            "distinguishable error."
        ),
        confirmed_impact=(
            "The captured evidence establishes that the parser resolved an externally declared "
            "entity."
        ),
        potential_impact=(
            "Successful exploitation could potentially allow disclosure of files readable by "
            "the service account or the issuing of requests from the server to internal "
            "addresses. The specific resources reachable were not enumerated."
        ),
        prerequisites=(
            "An endpoint that accepts and parses XML supplied by the client."
        ),
        controls=(
            "Disable external entity and DTD processing in the XML parser.",
            "Prefer a less complex data format where XML is not required.",
            "Apply egress filtering so parser-initiated requests cannot reach internal services.",
        ),
        references=("CWE-611", "OWASP A05:2021 — Security Misconfiguration"),
    ),
    "auth_bypass": Weakness(
        key="auth_bypass",
        name="Authentication or Access-Control Bypass",
        what_it_is=(
            "A resource that is intended to be restricted can be reached without satisfying the "
            "intended authentication or authorisation check."
        ),
        why_it_exists=(
            "The check is applied inconsistently — enforced on some routes, methods or "
            "representations but not others — or it is applied in the client rather than being "
            "enforced on the server for every request."
        ),
        attack_scenario=(
            "An attacker requests the protected resource directly, varies the HTTP method or "
            "path form, or manipulates an identifier, and receives a response that should have "
            "been refused."
        ),
        confirmed_impact=(
            "The captured evidence establishes that the protected resource returned content "
            "without the intended authorisation being satisfied."
        ),
        potential_impact=(
            "Successful exploitation could potentially allow access to functionality or data "
            "intended for other users or for privileged roles. The extent of what is reachable "
            "was not enumerated during this assessment."
        ),
        prerequisites=(
            "Network reachability of the affected endpoint. No credentials are required where "
            "the check is absent."
        ),
        controls=(
            "Enforce authorisation on the server for every request, at a single choke point "
            "rather than per handler.",
            "Deny by default: a route without an explicit authorisation decision must be "
            "refused.",
            "Check ownership of the referenced object, not only that the caller is "
            "authenticated.",
            "Apply the same checks to every method and representation of a resource.",
        ),
        references=("CWE-287", "CWE-862", "OWASP A01:2021 — Broken Access Control"),
    ),
    "default_credentials": Weakness(
        key="default_credentials",
        name="Default or Weak Credentials",
        what_it_is=(
            "An account is reachable with credentials that are shipped by default or are "
            "readily guessable."
        ),
        why_it_exists=(
            "The component was deployed without changing its factory credentials, or without a "
            "policy that forces a credential change before the service is exposed."
        ),
        attack_scenario=(
            "An attacker submits the vendor's documented default credentials, or a small set of "
            "common values, to the exposed authentication interface."
        ),
        confirmed_impact=(
            "The captured evidence establishes that the submitted credentials were accepted by "
            "the service."
        ),
        potential_impact=(
            "Successful authentication could potentially allow use of whatever functionality "
            "the account holds. The privileges attached to that account were not enumerated "
            "during this assessment."
        ),
        prerequisites=(
            "Network reachability of the authentication interface."
        ),
        controls=(
            "Change all default credentials before exposing the service, and block startup "
            "while a known default is still set.",
            "Restrict administrative interfaces to trusted networks.",
            "Enforce credential strength and apply rate limiting and lockout on authentication "
            "attempts.",
            "Enable multi-factor authentication on administrative accounts.",
        ),
        references=("CWE-1392", "CWE-521", "OWASP A07:2021 — Identification and Authentication Failures"),
    ),
    "csrf": Weakness(
        key="csrf",
        name="Cross-Site Request Forgery (CSRF)",
        what_it_is=(
            "A state-changing request is accepted on the strength of the browser's ambient "
            "credentials alone."
        ),
        why_it_exists=(
            "The endpoint does not require a token or header that a third-party site cannot "
            "supply, so a request issued from another origin carries the victim's session "
            "automatically."
        ),
        attack_scenario=(
            "An attacker induces an authenticated user to visit a page that issues the "
            "state-changing request to the application."
        ),
        confirmed_impact=(
            "The captured evidence establishes that a cross-origin state-changing request was "
            "accepted."
        ),
        potential_impact=(
            "Successful exploitation could potentially allow actions to be performed with the "
            "privileges of an authenticated user without their intent. Which actions are "
            "reachable depends on the affected endpoints."
        ),
        prerequisites=(
            "The victim must be authenticated and must visit attacker-controlled content, so "
            "user interaction is required."
        ),
        controls=(
            "Require an anti-CSRF token bound to the session on every state-changing request "
            "and verify it server-side.",
            "Set SameSite on session cookies to restrict cross-site transmission.",
            "Verify the Origin header on state-changing requests.",
            "Use safe methods for operations that do not change state.",
        ),
        references=("CWE-352", "OWASP A01:2021 — Broken Access Control"),
    ),
    "open_redirect": Weakness(
        key="open_redirect",
        name="Open Redirect",
        what_it_is=(
            "The application redirects the client to a destination taken from request data."
        ),
        why_it_exists=(
            "The redirect target is not validated against a set of permitted destinations, so "
            "any absolute URL supplied in the request is honoured."
        ),
        attack_scenario=(
            "An attacker distributes a link to the application carrying an external redirect "
            "target, so the victim begins on a trusted domain and is forwarded elsewhere."
        ),
        confirmed_impact=(
            "The captured evidence establishes that the application redirected to a destination "
            "supplied in the request."
        ),
        potential_impact=(
            "The weakness could potentially be used to lend credibility to phishing, or to "
            "forward tokens carried in the URL to an external destination. Direct compromise of "
            "the application itself is not implied by this weakness alone."
        ),
        prerequisites=(
            "The victim must follow a crafted link, so user interaction is required."
        ),
        controls=(
            "Validate the redirect target against an allowlist of permitted destinations, or "
            "restrict it to a relative path.",
            "Map an opaque identifier to a permitted destination rather than accepting a URL.",
            "Where an external redirect is required, show an interstitial confirming the "
            "destination.",
        ),
        references=("CWE-601",),
    ),
    "security_headers": Weakness(
        key="security_headers",
        name="Missing or Weak Security Headers",
        what_it_is=(
            "The application's responses omit one or more HTTP headers that instruct the "
            "browser to apply protective behaviour."
        ),
        why_it_exists=(
            "The headers are not set by the application or by the fronting proxy, so the "
            "browser applies only its permissive defaults."
        ),
        attack_scenario=(
            "The absence of these headers does not itself grant access; it removes a layer that "
            "would otherwise constrain the exploitation of another weakness, such as script "
            "injection or clickjacking."
        ),
        confirmed_impact=(
            "The captured responses establish that the headers were absent."
        ),
        potential_impact=(
            "The realistic effect is reduced defence in depth: were a separate weakness such as "
            "cross-site scripting or framing to be present, its exploitation would be less "
            "constrained. This finding does not on its own indicate that such a weakness exists."
        ),
        prerequisites=(
            "None. This is an observable property of the responses rather than an exploitable "
            "condition."
        ),
        controls=(
            "Set Content-Security-Policy with a restrictive default-src and no inline script.",
            "Set Strict-Transport-Security with an appropriate max-age on HTTPS responses.",
            "Set X-Content-Type-Options: nosniff and a frame-ancestors policy (or "
            "X-Frame-Options) to prevent framing.",
            "Set Referrer-Policy to limit URL disclosure to third parties.",
            "Apply the headers centrally at the proxy or middleware so coverage is uniform.",
        ),
        references=("CWE-693", "OWASP A05:2021 — Security Misconfiguration"),
    ),
    "tls": Weakness(
        key="tls",
        name="Transport Security Weakness",
        what_it_is=(
            "The service's transport-layer configuration permits a protocol version, cipher "
            "suite or certificate condition that is no longer considered sound."
        ),
        why_it_exists=(
            "The endpoint retains a configuration kept for backward compatibility, or a "
            "certificate whose validity or trust chain is not correct for the name in use."
        ),
        attack_scenario=(
            "An attacker positioned on the network path influences the negotiated parameters or "
            "presents a certificate the client does not correctly reject."
        ),
        confirmed_impact=(
            "The captured evidence establishes the transport configuration that the service "
            "offered."
        ),
        potential_impact=(
            "Depending on the specific weakness, traffic could potentially be exposed to "
            "interception or modification by an attacker able to intercept the network path. "
            "Such a position was not established during this assessment."
        ),
        prerequisites=(
            "An attacker must be able to intercept or influence the network path between the "
            "client and the service."
        ),
        controls=(
            "Offer TLS 1.2 and above only, and disable earlier protocol versions.",
            "Restrict cipher suites to those providing forward secrecy and authenticated "
            "encryption.",
            "Ensure certificates are valid, correctly chained and issued for the names in use, "
            "and automate their renewal.",
            "Enable HTTP Strict Transport Security and redirect plaintext requests.",
        ),
        references=("CWE-326", "CWE-295"),
    ),
    "info_disclosure": Weakness(
        key="info_disclosure",
        name="Information Disclosure",
        what_it_is=(
            "The application returns content that reveals internal implementation detail to an "
            "unauthenticated client."
        ),
        why_it_exists=(
            "Diagnostic output, verbose errors, or files intended for internal use are served "
            "from a location reachable by any client, typically a debugging or deployment "
            "configuration that was not disabled for production."
        ),
        attack_scenario=(
            "An attacker requests the affected location directly and reads the returned "
            "content, using it to inform the targeting of subsequent activity."
        ),
        confirmed_impact=(
            "The captured evidence establishes that the content was returned to an "
            "unauthenticated request."
        ),
        potential_impact=(
            "The disclosed detail could potentially assist an attacker in identifying software "
            "versions, internal paths or configuration, which lowers the effort required to "
            "target other weaknesses. Whether the disclosed content includes credentials or "
            "personal data was not established."
        ),
        prerequisites=(
            "Network reachability of the affected location."
        ),
        controls=(
            "Disable debugging output and verbose error pages in production; return a generic "
            "error to the client and record detail server-side.",
            "Remove development, backup and version-control artefacts from deployed content.",
            "Restrict access to administrative and diagnostic endpoints by network policy.",
            "Review responses for internal hostnames, paths and stack traces before release.",
        ),
        references=("CWE-200", "OWASP A05:2021 — Security Misconfiguration"),
    ),
    "outdated_component": Weakness(
        key="outdated_component",
        name="Outdated or Vulnerable Component",
        what_it_is=(
            "The service exposes a software component at a version for which security defects "
            "are publicly documented."
        ),
        why_it_exists=(
            "The component has not been updated to a release in which the defects are "
            "corrected, so the deployed version retains the published weaknesses."
        ),
        attack_scenario=(
            "An attacker identifies the version from the service's own responses and applies a "
            "publicly documented technique for that version."
        ),
        confirmed_impact=(
            "The captured evidence establishes the component and version the service reported."
        ),
        potential_impact=(
            "The impact depends on which published defects apply to this version and on whether "
            "the affected functionality is reachable in this deployment. Neither was established "
            "during this assessment, so the finding indicates exposure rather than a "
            "demonstrated compromise."
        ),
        prerequisites=(
            "Reachability of the affected component. Individual published defects may carry "
            "their own preconditions."
        ),
        controls=(
            "Update the component to a supported release in which the published defects are "
            "corrected.",
            "Maintain an inventory of deployed components and their versions, and monitor "
            "vendor advisories against it.",
            "Where an immediate update is not possible, apply the vendor's documented mitigation "
            "and restrict access to the affected functionality.",
            "Suppress version detail in responses to reduce the ease of targeting.",
        ),
        references=("CWE-1035", "OWASP A06:2021 — Vulnerable and Outdated Components"),
    ),
    "exposed_panel": Weakness(
        key="exposed_panel",
        name="Exposed Administrative Interface",
        what_it_is=(
            "An administrative or management interface is reachable from the network the "
            "assessment was conducted from."
        ),
        why_it_exists=(
            "The interface is served without a network restriction limiting it to trusted "
            "sources, so its authentication is the only control standing in front of it."
        ),
        attack_scenario=(
            "An attacker locates the interface and directs credential-guessing or "
            "version-specific activity at it."
        ),
        confirmed_impact=(
            "The captured evidence establishes that the interface responded to a request from "
            "the assessment source."
        ),
        potential_impact=(
            "Exposure increases the attack surface available for credential attacks against the "
            "interface. This finding does not indicate that authentication was bypassed or that "
            "any credential was accepted."
        ),
        prerequisites=(
            "Network reachability of the interface. Use of the interface still requires valid "
            "credentials unless a separate weakness is present."
        ),
        controls=(
            "Restrict administrative interfaces to trusted networks or an authenticated proxy.",
            "Require multi-factor authentication for administrative access.",
            "Apply rate limiting and lockout to the interface's authentication.",
            "Monitor and alert on authentication failures against it.",
        ),
        references=("CWE-284", "OWASP A01:2021 — Broken Access Control"),
    ),
}


_GENERIC = Weakness(
    key="generic",
    name="Security Weakness",
    what_it_is=(
        "The scanning engine matched a condition on the target that its template library "
        "associates with a security weakness."
    ),
    why_it_exists=(
        "The underlying cause is not determined by the match alone: the engine records that "
        "the condition was present, not the implementation defect that produced it."
    ),
    attack_scenario=(
        "The technique an attacker would apply depends on the specific weakness class. "
        "Establishing it requires manual review of the affected component."
    ),
    confirmed_impact=(
        "The captured evidence establishes that the matched condition was present on the "
        "target."
    ),
    potential_impact=(
        "The realistic impact cannot be stated from the available evidence alone, and would "
        "depend on the nature of the underlying defect. Manual review is required before the "
        "impact of this finding is characterised."
    ),
    prerequisites=(
        "Network reachability of the affected location. Any further precondition is not "
        "established by the available evidence."
    ),
    controls=(
        "Review the affected component against the referenced weakness to establish the "
        "underlying cause.",
        "Apply the vendor's or framework's documented hardening guidance for the affected "
        "functionality.",
        "Re-test the affected location after remediation to confirm the condition no longer "
        "matches.",
    ),
    references=(),
)


# --- Weakness-class matching --------------------------------------------------------------
# CWE first: `vulnerabilities.category` holds the CWE and is the most precise signal we have.
_CWE_TO_CLASS = {
    "89": "sqli", "564": "sqli",
    "78": "command_injection", "77": "command_injection",
    "918": "ssrf",
    "79": "xss", "80": "xss",
    "22": "path_traversal", "23": "path_traversal", "35": "path_traversal",
    "98": "file_inclusion", "827": "file_inclusion",
    "1336": "ssti", "94": "ssti", "95": "ssti",
    "502": "deserialization",
    "611": "xxe", "827.1": "xxe",
    "287": "auth_bypass", "862": "auth_bypass", "863": "auth_bypass",
    "306": "auth_bypass", "639": "auth_bypass", "425": "auth_bypass",
    "521": "default_credentials", "1392": "default_credentials",
    "798": "default_credentials", "259": "default_credentials",
    "352": "csrf",
    "601": "open_redirect",
    "693": "security_headers", "1021": "security_headers", "16": "security_headers",
    "326": "tls", "327": "tls", "295": "tls", "319": "tls",
    "200": "info_disclosure", "213": "info_disclosure", "532": "info_disclosure",
    "538": "info_disclosure", "497": "info_disclosure", "548": "info_disclosure",
    "1035": "outdated_component", "1104": "outdated_component", "937": "outdated_component",
    "284": "exposed_panel",
}

# Whole-token markers consulted only when the CWE is absent or unrecognised. Ordered: the
# first class whose markers match wins, so more specific classes are listed before broader
# ones (e.g. `file_inclusion` before `path_traversal`).
_TOKEN_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sqli", ("sqli", "sql injection", "sql-injection", "blind sql", "error based sql")),
    ("command_injection", ("command injection", "command-injection", "rce", "os command",
                           "remote code execution", "code injection", "shell injection")),
    ("ssrf", ("ssrf", "server side request forgery", "server-side request forgery")),
    ("ssti", ("ssti", "template injection")),
    ("xxe", ("xxe", "xml external entity")),
    ("deserialization", ("deserialization", "deserialisation", "insecure deserialization")),
    ("file_inclusion", ("lfi", "rfi", "local file inclusion", "remote file inclusion",
                        "file inclusion")),
    ("path_traversal", ("path traversal", "directory traversal", "path-traversal",
                        "dir traversal", "file read", "arbitrary file read")),
    ("xss", ("xss", "cross site scripting", "cross-site scripting")),
    ("csrf", ("csrf", "cross site request forgery", "cross-site request forgery")),
    ("open_redirect", ("open redirect", "open-redirect", "unvalidated redirect")),
    ("default_credentials", ("default login", "default-login", "default credential",
                             "default password", "weak password", "weak credential")),
    ("auth_bypass", ("auth bypass", "authentication bypass", "authorization bypass",
                     "access control", "improper access", "unauthenticated access",
                     "privilege escalation")),
    ("exposed_panel", ("admin panel", "login panel", "management interface", "admin portal",
                       "exposed panel", "dashboard exposure")),
    ("security_headers", ("security header", "missing header", "csp", "content security policy",
                          "clickjacking", "x-frame-options", "hsts header")),
    ("tls", ("tls", "ssl", "certificate", "cipher", "weak crypto", "self signed",
             "self-signed", "expired cert")),
    # "eol" is matched as a standalone token (the <=4-char rule below), which is what catches
    # `nginx-eol` once hyphens have been normalised to spaces.
    ("outdated_component", ("outdated", "end of life", "eol", "obsolete",
                            "unsupported version", "vulnerable version")),
    ("info_disclosure", ("information disclosure", "info disclosure", "exposure",
                         "exposed", "disclosure", "debug", "stack trace", "phpinfo",
                         "listing", "backup file", "git config", "env file")),
)

_CWE_RE = re.compile(r"cwe[-_ ]?(\d+)", re.IGNORECASE)


def _norm(value) -> str:
    return str(value or "").strip().lower()


def _class_from_cwe(category: str | None) -> str | None:
    """Weakness-class key from a CWE string like "cwe-89", or None."""
    match = _CWE_RE.search(_norm(category))
    if not match:
        return None
    return _CWE_TO_CLASS.get(match.group(1))


def _class_from_text(*values) -> str | None:
    """Weakness-class key from template/title text, matched on whole markers.

    Hyphens and underscores in a template id are normalised to spaces first, so
    `unix-command-injection` matches the "command injection" marker. Markers are checked in
    `_TOKEN_MARKERS` order, and short markers (<= 4 chars, e.g. "xss", "rce", "lfi") must
    match as a standalone word so they cannot fire inside an unrelated identifier."""
    haystack = " ".join(_norm(v) for v in values if v)
    haystack = haystack.replace("-", " ").replace("_", " ")
    haystack = re.sub(r"\s+", " ", haystack)
    if not haystack.strip():
        return None
    for key, markers in _TOKEN_MARKERS:
        for marker in markers:
            token = marker.replace("-", " ").replace("_", " ")
            if len(token) <= 4:
                if re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", haystack):
                    return key
            elif token in haystack:
                return key
    return None


def classify_weakness(
    *,
    category: str | None = None,
    template_id: str | None = None,
    title: str | None = None,
    tags=None,
) -> Weakness:
    """Return the Weakness class for one finding. Pure; falls back to `_GENERIC`.

    CWE (the stored `category`) is authoritative when it is recognised. Template id, title and
    tags are consulted only otherwise. Falling back to `_GENERIC` is deliberate: a
    non-committal explanation is correct, whereas guessing a class would put wrong prose in a
    security report."""
    key = _class_from_cwe(category)
    if key is None:
        tag_text = " ".join(_norm(t) for t in (tags or ())) if not isinstance(tags, str) else _norm(tags)
        key = _class_from_text(template_id, title, tag_text)
    return _CLASSES.get(key or "", _GENERIC)


def classify_weakness_row(row_or_group) -> Weakness:
    """Convenience for a VulnRow or a `_finding_groups` dict.

    Accepts either shape because the renderer holds group dicts while tests and other callers
    hold rows. Every field is read with a default, so an object missing any of them still
    classifies (to `_GENERIC` at worst)."""
    def _get(name):
        if isinstance(row_or_group, dict):
            return row_or_group.get(name)
        return getattr(row_or_group, name, None)

    return classify_weakness(
        category=_get("category"),
        template_id=_get("template_id"),
        title=_get("title"),
        tags=_get("tags"),
    )


# --- Narrative assembly -------------------------------------------------------------------

def description(weakness: Weakness, *, location_count: int = 0, host_count: int = 0,
                inference: bool = False, scanner_text: str | None = None,
                curated_text: str | None = None) -> str:
    """"Vulnerability Description": what it is, why it exists, and where it was observed.

    The observation sentence is emitted ONLY from counts the report already computed, so it
    can never assert a location that is not listed in the block beneath it. `scanner_text` --
    `vulnerabilities.description` -- is appended VERBATIM when present, clearly attributed to
    the scanning engine, so the pipeline's own words are never replaced by ours.

    `curated_text` is MBS-authored prose for a reviewed template (finding_descriptions.py).
    It is a SEPARATE parameter from `scanner_text` and carries a SEPARATE attribution, because
    the report must never present our words as the engine's. The two are mutually exclusive
    and the scanner wins: when the engine described the finding, that is what the reader gets,
    and our catalogue prose is not appended alongside it. Our text appears only where the
    engine supplied none -- i.e. where `vulnerabilities.description` is NULL, which it is left
    as. Neither is emitted when both are absent."""
    parts = [weakness.what_it_is, weakness.why_it_exists]

    if location_count:
        where = f"The condition was observed at {location_count} location"
        where += "s" if location_count != 1 else ""
        if host_count > 1:
            where += f" across {host_count} hosts"
        if inference:
            where += (
                ", matched by inference (timing or an out-of-band signal) rather than by "
                "directly observed output"
            )
        parts.append(where + ".")

    text = " ".join(p for p in parts if p)
    # Explicit precedence, with the two sources kept in separate variables all the way to
    # their separate attributions: there is no code path on which curated prose can be
    # labelled "Scanning engine description", which is the guarantee this gate exists for.
    scanner_text = (scanner_text or "").strip()
    curated_text = (curated_text or "").strip()
    if scanner_text:
        text += f" Scanning engine description: {scanner_text}"
    elif curated_text:
        text += f" MBS analyst description: {curated_text}"
    return text


def impact(weakness: Weakness, verification: str | None) -> str:
    """"Security Impact", gated on verification. THIS IS THE ACCURACY BOUNDARY.

    Only a VERIFIED finding receives `confirmed_impact`, and even then the potential wording
    follows it so the report never implies that the confirmed portion is the whole story. A
    PARTIALLY_VERIFIED finding is told explicitly that exploitation was not fully
    demonstrated; an UNVERIFIED finding is told it is a potential finding requiring manual
    validation. No path lets an unproven finding be described as a confirmed compromise."""
    certainty = impact_certainty(verification)

    if certainty == CONFIRMED:
        return (
            f"{weakness.confirmed_impact} {weakness.potential_impact} "
            "Impacts beyond those established by the captured evidence remain potential "
            "rather than demonstrated."
        )
    if certainty == POTENTIAL:
        return (
            f"{weakness.potential_impact} Exploitation was NOT fully demonstrated during this "
            "assessment: supporting artefacts were captured, but they corroborate the matched "
            "condition rather than prove the outcome described above. Manual validation is "
            "recommended to establish the actual impact."
        )
    return (
        f"{weakness.potential_impact} This is a POTENTIAL finding: the condition was matched "
        "by the scanning engine and was not exploited during this assessment, and no "
        "supporting artefact was captured for it. Manual validation is required before it is "
        "treated as confirmed."
    )


def exploitation_context(weakness: Weakness, *, inference: bool = False) -> str:
    """"Exploitation Context": the attack scenario followed by the prerequisites.

    The inference note is added when the match came from timing or an out-of-band channel, so
    a reader is not left to infer from the matcher name that no output was observed."""
    text = weakness.attack_scenario
    if inference:
        text += (
            " In this instance the engine's match derives from a timing or out-of-band signal, "
            "which indicates the condition rather than showing the result of the technique."
        )
    return f"{text} Prerequisites: {weakness.prerequisites}"


def controls(weakness: Weakness) -> list[str]:
    """Standard controls for the weakness class.

    The caller MUST present these under the agreed label identifying them as standard guidance
    for the weakness class and NOT as remediation derived from scan evidence. They are used
    only when the assessment pipeline produced no remediation record for the finding."""
    return list(weakness.controls)


GENERATED_CONTROLS_LABEL = (
    "Recommended controls (standard guidance for this weakness class — not derived from "
    "scan evidence)"
)

PIPELINE_REMEDIATION_LABEL = "Remediation (from the assessment pipeline)"

EVIDENCE_STORE_NOTE = (
    "Artefacts are retained in the assessment evidence store and are referenced by object key; "
    "they are not directly retrievable from this document."
)

# Phase 3.2. States precisely what the printed digest does and does not establish. The hash is
# computed over the artefact's bytes AT CAPTURE TIME and stored with it, so it lets a recipient
# confirm a retrieved artefact is byte-identical to the one assessed. It is NOT a signature and
# proves nothing about the evidence store itself -- claiming otherwise would overstate what the
# platform actually does, which is the failure mode this whole reporting workstream exists to
# avoid.
EVIDENCE_INTEGRITY_NOTE = (
    "Each artefact is listed with the SHA-256 digest recorded when it was captured. Re-hashing "
    "a retrieved artefact and comparing it with the digest below confirms the file is "
    "byte-identical to the one this assessment examined. The digest is an integrity check, not "
    "a cryptographic signature, and does not by itself attest to the evidence store."
)

# EVIDENCE SCOPE. The pipeline stores raw tool output at TOOL-RUN granularity: one
# `log_excerpt` artefact per tool run, linked to every finding that run produced (see
# orchestrator._run_single_tool, which creates one Evidence row per run and passes its id to
# ingest_vulnerability_findings for the whole batch). That sharing is deliberate and correct --
# the artefact genuinely IS the same file for all of those findings -- but it means a reader
# who sees a raw-output artefact under a finding could reasonably, and wrongly, take it to be
# a capture made for that finding alone. Per-finding artefacts do exist (screenshots, captured
# individually and linked to one finding), so the two granularities sit side by side in the
# same list and must be distinguishable. This note is emitted only when a shared tool-run
# artefact is actually listed, and it states the scope rather than implying any conclusion.
EVIDENCE_SHARED_SCOPE_NOTE = (
    "Raw tool output is captured per tool run, not per finding: the artefact above is the "
    "complete output of the run that produced this finding and is the same artefact "
    "referenced by the other findings from that run. It corroborates that this finding came "
    "from the recorded run; it is not a capture made solely for this finding."
)

SEVERITY_CVSS_NOTE_TEMPLATE = (
    "Severity is the scanning engine's own rating; the CVSS base score of {score} bands as "
    "{band} under CVSS v3.1. Both are reported exactly as recorded, and neither is derived "
    "from the other."
)


def severity_cvss_note(severity: str | None, cvss_score, band: str | None) -> str | None:
    """The agreed clarification, emitted ONLY when the CVSS band differs from the severity.

    Returns None when they agree, when there is no CVSS, or when there is no band -- there is
    nothing to explain in those cases and an unconditional note would be noise. This is a
    STATEMENT ABOUT two values that are already displayed; it changes neither of them and
    never reclassifies a finding."""
    if cvss_score is None or not band:
        return None
    if _norm(severity) == _norm(band):
        return None
    return SEVERITY_CVSS_NOTE_TEMPLATE.format(score=cvss_score, band=band)
