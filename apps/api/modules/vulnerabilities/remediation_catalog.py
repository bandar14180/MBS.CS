"""Deterministic remediation guidance, keyed by canonical finding identity.

WHY THIS EXISTS
---------------
`remediations` had zero rows after a 698-finding scan. The model, the migration and the
report's read-side join all existed; what did not exist was a PRODUCER. The only writer was
`vulnerabilities.ai_service.generate_remediation`, which is on-demand (one HTTP call per
finding), requires a configured AI provider, and is never invoked by the scan pipeline. So a
scan could complete with hundreds of findings and produce no guidance at all.

This module is the deterministic half of the fix: a curated lookup from a finding's canonical
identity to actionable remediation. It is the same shape as `compliance/catalog.py` and
`attack/catalog.py` -- a reviewed static table, extended as finding types appear, returning
NOTHING for an identity nobody has written guidance for.

WHY TEMPLATE ID IS THE PRIMARY KEY, NOT CWE
-------------------------------------------
CWE is the obvious key and it is not sufficient here. On the reference dataset the category
column is NULL for 317 of 698 findings -- including all 166 critical SQL-injection findings,
because the nuclei templates that produced them report no `classification.cwe-id`. Keying on
CWE alone would leave the highest-severity findings on the scan without guidance, which is
precisely the population that most needs it. The template id is recoverable for every
finding (it is the first segment of the nuclei fingerprint, `template-id|matcher|matched-at`)
and is more specific than a CWE, so it is tried first and CWE is the fallback.

WHAT THE GUIDANCE MAY AND MAY NOT SAY
-------------------------------------
Every entry is written without sight of a particular finding, so it describes what to do
about the WEAKNESS CLASS. It must not assert that exploitation occurred, quote a request or
response, or name a specific affected file, parameter or host -- per-finding facts belong to
the finding's own evidence. Steps are concrete and ordered; "fix the vulnerability" is not a
step and no entry may degrade into one. A finding type with no reviewed entry produces NO
remediation row rather than generic filler, which is the same fail-closed stance the
description catalogue and the compliance map take.

This module is pure: no database access, no network, no imports from the scanner or reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from apps.api.modules.vulnerabilities.taxonomy import canonical_cwe


@dataclass(frozen=True)
class RemediationGuidance:
    """One reviewed remediation entry. Frozen so a caller cannot mutate the catalogue."""

    summary: str
    steps: tuple[str, ...]
    references: tuple[tuple[str, str], ...] = field(default=())

    def reference_dicts(self) -> list[dict[str, str]]:
        """References in the `{title, url}` shape the `remediations` column stores."""
        return [{"title": title, "url": url} for title, url in self.references]


# --- shared references ----------------------------------------------------------------------
# Deduplicated so an entry cites a canonical source rather than a re-typed URL.
_OWASP_XSS = ("OWASP Cross Site Scripting Prevention Cheat Sheet",
              "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html")
_OWASP_SQLI = ("OWASP SQL Injection Prevention Cheat Sheet",
               "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html")
_OWASP_CMDI = ("OWASP OS Command Injection Defense Cheat Sheet",
               "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html")
_OWASP_SSRF = ("OWASP SSRF Prevention Cheat Sheet",
               "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html")
_OWASP_HEADERS = ("OWASP Secure Headers Project", "https://owasp.org/www-project-secure-headers/")
_OWASP_TLS = ("OWASP Transport Layer Security Cheat Sheet",
              "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html")
_MDN_CSP = ("MDN Content-Security-Policy",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy")
_MDN_SRI = ("MDN Subresource Integrity",
            "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity")
_MDN_COOKIES = ("MDN Set-Cookie", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie")
_WP_HARDENING = ("WordPress Hardening Guide", "https://developer.wordpress.org/advanced-administration/security/hardening/")
_GCP_API_KEYS = ("Google Cloud: best practices for managing API keys",
                 "https://cloud.google.com/docs/authentication/api-keys")


# --- the catalogue, keyed by nuclei template id ----------------------------------------------
# Every key is lowercase and stripped; `guidance_for` normalises its argument the same way and
# the tests assert the keys are already in normal form, so a typo cannot make an entry
# unreachable.
_BY_TEMPLATE: dict[str, RemediationGuidance] = {
    "sqli-error-based": RemediationGuidance(
        summary=(
            "Rewrite the affected database access to use parameterised statements so that "
            "user-supplied values can never be parsed as SQL, and stop returning database "
            "error detail to clients."
        ),
        steps=(
            "Identify the query behind the affected endpoint and replace string concatenation "
            "or interpolation of request data with a parameterised/prepared statement, binding "
            "each user-supplied value as a parameter.",
            "Where an identifier must vary (table or column name, sort direction), which cannot "
            "be bound as a parameter, map the request value through a server-side allow-list of "
            "permitted identifiers rather than passing it into the statement.",
            "Validate input by type and range at the boundary as defence in depth -- not as the "
            "primary control, since validation alone does not make concatenation safe.",
            "Disable verbose database error output in production and return a generic error to "
            "the client, logging the detail server-side; the error text is what makes this class "
            "directly exploitable and it also discloses schema information.",
            "Review the database account the application connects with and reduce it to the "
            "minimum privileges the application needs, so that a future injection has a smaller "
            "blast radius.",
            "Re-test the endpoint after the change and review the rest of the codebase for the "
            "same construction pattern, which is rarely confined to one query.",
        ),
        references=(_OWASP_SQLI,),
    ),
    "time-based-sqli": RemediationGuidance(
        summary=(
            "Rewrite the affected database access to use parameterised statements. A time-based "
            "result means the injection is exploitable even though the response body shows no "
            "error, so the absence of a visible error is not mitigation."
        ),
        steps=(
            "Identify the query behind the affected endpoint and replace string concatenation or "
            "interpolation of request data with a parameterised/prepared statement.",
            "Where an identifier must vary and cannot be bound, resolve the request value through "
            "a server-side allow-list of permitted identifiers.",
            "Do not rely on suppressing error output as the fix: this variant was detected "
            "through response timing, not error text, so it remains exploitable when errors are "
            "hidden.",
            "Reduce the application's database account to least privilege to limit what a "
            "successful injection can reach.",
            "Consider statement timeouts on the database so that a deliberately slow injected "
            "query cannot also be used to exhaust connections.",
            "Re-test the endpoint and audit sibling queries built the same way.",
        ),
        references=(_OWASP_SQLI,),
    ),
    "unix-command-injection": RemediationGuidance(
        summary=(
            "Stop passing request data into a shell. Invoke the target program directly with an "
            "argument list, or replace the shell-out with a native library call."
        ),
        steps=(
            "Locate the code that builds the command and remove the shell from the path: use the "
            "language's argument-array process API (for example execve-style invocation, or "
            "subprocess with a list and shell=False) so arguments are never re-parsed by a shell.",
            "Prefer a native library over invoking an external binary where one exists, which "
            "removes the command construction entirely.",
            "Where a request value must select what runs, map it through a server-side "
            "allow-list of permitted commands or options instead of interpolating it.",
            "Validate remaining user-supplied arguments against a strict pattern, and do not "
            "attempt to sanitise by escaping shell metacharacters -- escaping is error-prone and "
            "is not a substitute for removing the shell.",
            "Run the component as an unprivileged account, and confine it (container, seccomp or "
            "equivalent) so that a residual injection cannot reach the wider host.",
            "Re-test the endpoint and audit every other shell invocation in the codebase.",
        ),
        references=(_OWASP_CMDI,),
    ),
    "windows-command-injection": RemediationGuidance(
        summary=(
            "Stop passing request data into a command interpreter. Invoke the target program "
            "directly with an argument list, or replace the shell-out with a native API call."
        ),
        steps=(
            "Locate the code that builds the command line and invoke the executable directly with "
            "an argument array rather than through cmd.exe or PowerShell, so that arguments are "
            "not re-parsed by an interpreter.",
            "Prefer a native .NET/Win32 API over spawning a process where one exists.",
            "Where a request value must select what runs, resolve it through a server-side "
            "allow-list rather than interpolating it into the command line.",
            "Do not rely on escaping metacharacters: Windows command-line quoting is parsed "
            "differently by each interpreter and escaping is not a reliable control.",
            "Run the service under a least-privilege account rather than SYSTEM or an "
            "administrator, so a residual injection is contained.",
            "Re-test the endpoint and audit other process-spawning code paths.",
        ),
        references=(_OWASP_CMDI,),
    ),
    "reflected-xss": RemediationGuidance(
        summary=(
            "Encode the reflected value for the context it is written into, and add a "
            "Content-Security-Policy so that a missed encoding does not immediately become "
            "script execution."
        ),
        steps=(
            "Apply contextual output encoding where the value is written -- HTML body, attribute, "
            "URL and JavaScript contexts each need a different encoding, and encoding for the "
            "wrong context does not protect.",
            "Prefer a template engine that encodes by default and audit every place where "
            "auto-encoding is explicitly bypassed (raw/unsafe/|safe constructs).",
            "Never write request data into a script block or an event-handler attribute; pass it "
            "as data (for example a data attribute or a JSON payload read at runtime) instead.",
            "Validate input against an expected type or pattern at the boundary as defence in "
            "depth, while keeping output encoding as the primary control.",
            "Deploy a Content-Security-Policy that avoids 'unsafe-inline' for scripts, so that a "
            "future encoding mistake does not directly yield execution.",
            "Re-test the affected parameter and check whether the same value is reachable through "
            "a path that stores it, which would make the same defect a stored XSS.",
        ),
        references=(_OWASP_XSS, _MDN_CSP),
    ),
    "blind-ssrf": RemediationGuidance(
        summary=(
            "Constrain the server-side fetch to an allow-list of permitted destinations and "
            "re-validate after DNS resolution and on every redirect."
        ),
        steps=(
            "Replace free-form URL input with a server-side allow-list of permitted hosts or, "
            "better, an indirection where the client sends an identifier and the server maps it "
            "to a fixed destination.",
            "Resolve the hostname and validate the RESOLVED IP before connecting, rejecting "
            "loopback, link-local (including the 169.254.169.254 cloud metadata address), private "
            "and other reserved ranges -- validating the hostname string alone is bypassed by DNS "
            "that resolves to an internal address.",
            "Re-apply the same validation to every redirect target rather than following "
            "redirects blindly, and cap the redirect count.",
            "Disable unnecessary URL schemes so only http/https are fetchable, blocking file://, "
            "gopher:// and similar.",
            "Egress-filter the component at the network layer so it can reach only the "
            "destinations it legitimately needs, which contains the issue even if the "
            "application check is bypassed.",
            "Require authentication on internal services rather than trusting network position, "
            "so a server-side request cannot act simply by originating internally.",
        ),
        references=(_OWASP_SSRF,),
    ),
    "http-missing-security-headers": RemediationGuidance(
        summary=(
            "Set the missing security response headers at the application or reverse proxy, so "
            "the browser enforces the protections they enable."
        ),
        steps=(
            "Set Content-Security-Policy, starting in report-only mode to find violations before "
            "enforcing, and avoid 'unsafe-inline' for scripts.",
            "Set Strict-Transport-Security with a substantial max-age on HTTPS responses so "
            "browsers refuse to fall back to cleartext.",
            "Set X-Content-Type-Options: nosniff to stop content-type sniffing, and a "
            "Referrer-Policy such as strict-origin-when-cross-origin to limit URL leakage.",
            "Set a restrictive Permissions-Policy for browser features the application does not "
            "use, and X-Frame-Options (or CSP frame-ancestors) to control framing.",
            "Apply the headers centrally -- at the reverse proxy or in shared middleware -- so "
            "new routes inherit them rather than each needing to remember.",
            "Re-test and confirm the headers are present on all responses, including error "
            "responses and redirects, which commonly bypass per-route configuration.",
        ),
        references=(_OWASP_HEADERS, _MDN_CSP),
    ),
    "weak-csp-detect": RemediationGuidance(
        summary=(
            "Tighten the Content-Security-Policy so it meaningfully constrains script sources; a "
            "policy containing 'unsafe-inline' or a wildcard script source provides little "
            "protection against injection."
        ),
        steps=(
            "Remove 'unsafe-inline' and 'unsafe-eval' from script-src, and replace wildcard or "
            "overly broad source lists with the specific origins the application loads from.",
            "Move inline scripts and inline event handlers into external files, or authorise them "
            "explicitly with a per-response nonce or a hash.",
            "Set a restrictive default-src and add object-src 'none' and base-uri 'self', which "
            "close common bypass routes.",
            "Add frame-ancestors to control who may frame the application.",
            "Roll the tightened policy out in Content-Security-Policy-Report-Only first and "
            "collect violation reports, so legitimate resources are found before enforcement.",
            "Re-test after enforcing, and treat CSP as defence in depth rather than a replacement "
            "for output encoding.",
        ),
        references=(_MDN_CSP,),
    ),
    "weak-cipher-suites": RemediationGuidance(
        summary=(
            "Reconfigure the TLS endpoint to offer only strong cipher suites and modern protocol "
            "versions, and remove the weak suites from the negotiated set."
        ),
        steps=(
            "Disable SSLv3, TLS 1.0 and TLS 1.1, and enable TLS 1.2 and TLS 1.3.",
            "Remove cipher suites using NULL, anonymous, export, DES/3DES and RC4, and those "
            "using MD5 or SHA-1 for message authentication.",
            "Prefer AEAD suites (AES-GCM, ChaCha20-Poly1305) and forward-secret key exchanges "
            "(ECDHE), ordering the server preference list accordingly.",
            "Apply the change to every TLS listener on the host, including administrative and "
            "non-production virtual hosts sharing the same service, which are commonly missed.",
            "Verify the resulting configuration with an external TLS scanner after the change.",
            "Enable HTTP Strict-Transport-Security so clients do not negotiate cleartext at all.",
        ),
        references=(_OWASP_TLS,),
    ),
    "missing-sri": RemediationGuidance(
        summary=(
            "Add Subresource Integrity attributes to externally hosted scripts and stylesheets so "
            "a modified third-party file is rejected by the browser."
        ),
        steps=(
            "Add an integrity attribute containing the SHA-384 (or stronger) hash of each "
            "externally hosted script and stylesheet, together with crossorigin=\"anonymous\".",
            "Pin third-party resources to a specific version rather than a floating 'latest' URL, "
            "since a moving target cannot be hashed.",
            "Consider self-hosting critical third-party assets, which removes the dependency on "
            "the external origin entirely.",
            "Add hash regeneration to the build or release process so an intentional dependency "
            "upgrade does not break the page and is not worked around by deleting the attribute.",
            "Re-test that the resources still load after the change, since an incorrect hash "
            "causes the browser to block the resource.",
        ),
        references=(_MDN_SRI,),
    ),
    "cookies-without-httponly": RemediationGuidance(
        summary=(
            "Set the HttpOnly attribute on session and other security-relevant cookies so they "
            "cannot be read by client-side script."
        ),
        steps=(
            "Add HttpOnly to the session cookie and any cookie holding an authentication or "
            "authorisation value.",
            "Set Secure on the same cookies so they are only ever sent over HTTPS, and set an "
            "appropriate SameSite value (Lax or Strict) to limit cross-site submission.",
            "Scope cookies with the narrowest workable Path and Domain rather than the whole site "
            "or a parent domain.",
            "Configure these attributes centrally in the session/framework configuration so every "
            "cookie the application issues inherits them.",
            "Identify any client-side code that reads the cookie via document.cookie and move that "
            "dependency server-side before enabling HttpOnly, so the change does not break it.",
        ),
        references=(_MDN_COOKIES,),
    ),
    "cookies-without-secure": RemediationGuidance(
        summary=(
            "Set the Secure attribute on cookies so they are never transmitted over a cleartext "
            "connection."
        ),
        steps=(
            "Add Secure to the session cookie and every cookie holding a security-relevant value.",
            "Add HttpOnly to the same cookies, and set an appropriate SameSite value.",
            "Serve the whole application over HTTPS and redirect cleartext requests, so that "
            "setting Secure does not simply break the site on an http:// entry point.",
            "Enable HTTP Strict-Transport-Security so the browser does not attempt cleartext at "
            "all on subsequent visits.",
            "Configure the attributes in shared session configuration rather than per-response.",
        ),
        references=(_MDN_COOKIES,),
    ),
    "tomcat-stacktraces": RemediationGuidance(
        summary=(
            "Stop returning Java stack traces to clients; return a generic error page and keep "
            "the detail in server-side logs."
        ),
        steps=(
            "Configure an application-wide error handler and custom error pages so unhandled "
            "exceptions render a generic message rather than the container's default output.",
            "Disable development or debug mode in the production deployment, which is the usual "
            "reason traces are rendered.",
            "Log the full exception server-side with a correlation identifier and show only that "
            "identifier to the client, preserving supportability without disclosure.",
            "Review what the disclosed traces revealed -- framework and library versions, internal "
            "class and file paths -- and treat those as separately actionable reconnaissance.",
            "Re-test error conditions, including malformed input and unauthenticated requests, to "
            "confirm no path still returns a trace.",
        ),
    ),
    "wp-user-enum": RemediationGuidance(
        summary=(
            "Stop the site from disclosing the list of WordPress usernames, which supplies the "
            "identifier half of a credential attack."
        ),
        steps=(
            "Restrict or disable the REST users endpoint (/wp-json/wp/v2/users) for "
            "unauthenticated requests.",
            "Block author enumeration by id (/?author=N), which redirects to the author archive "
            "and discloses the login name.",
            "Ensure the public display name differs from the login name, so an exposed author "
            "archive does not reveal credentials-relevant data.",
            "Make authentication responses uniform so a wrong username and a wrong password are "
            "indistinguishable, and apply rate limiting or lockout on the login endpoint.",
            "Enable multi-factor authentication for administrative accounts, which is what "
            "actually defeats a credential attack once usernames are known.",
        ),
        references=(_WP_HARDENING,),
    ),
    "wordpress-readme-file": RemediationGuidance(
        summary=(
            "Remove the default readme.html from the web root so the WordPress version is not "
            "disclosed, and keep the platform patched."
        ),
        steps=(
            "Delete readme.html (and any licence or install files left in the web root) from the "
            "production deployment.",
            "Add the removal to the deployment or update process, since a core update restores "
            "the file.",
            "Treat the version disclosure as secondary: confirm the installed WordPress version "
            "against current advisories and update it, which is the substantive action.",
            "Enable automatic background updates for core security releases where the deployment "
            "allows it.",
        ),
        references=(_WP_HARDENING,),
    ),
    "google-api-key": RemediationGuidance(
        summary=(
            "Verify the exposed key's restrictions in the issuing Google Cloud project; restrict "
            "or rotate it if it is unrestricted or authorises more than the page needs."
        ),
        steps=(
            "Locate the key in the Google Cloud console and review its API restrictions and "
            "application restrictions before anything else -- a properly restricted browser key "
            "is expected to be public, so the finding is only actionable once its scope is known.",
            "Apply an HTTP referrer restriction limiting the key to the application's own "
            "origins, and an API restriction limiting it to the specific APIs the page calls.",
            "Rotate the key if it is unrestricted, if it authorises APIs the page does not use, or "
            "if it was ever used server-side, and update the application to the new key.",
            "Move any key that does not need to be client-side out of client-visible content and "
            "proxy the call through the backend.",
            "Set budget alerts and quota limits on the project so unexpected use of an exposed key "
            "is noticed.",
            "Check version control history for the key, since a committed key remains retrievable "
            "after it is removed from the current files.",
        ),
        references=(_GCP_API_KEYS,),
    ),
}


# --- CWE fallback -----------------------------------------------------------------------------
# Used only when the template id has no reviewed entry. Deliberately smaller and more general
# than the template map: a CWE covers a class, so its guidance cannot be as specific.
_BY_CWE: dict[str, RemediationGuidance] = {
    "cwe-89": _BY_TEMPLATE["sqli-error-based"],
    "cwe-78": _BY_TEMPLATE["unix-command-injection"],
    "cwe-79": _BY_TEMPLATE["reflected-xss"],
    "cwe-918": _BY_TEMPLATE["blind-ssrf"],
    "cwe-693": _BY_TEMPLATE["http-missing-security-headers"],
    "cwe-1004": _BY_TEMPLATE["cookies-without-httponly"],
    "cwe-614": _BY_TEMPLATE["cookies-without-secure"],
    "cwe-209": _BY_TEMPLATE["tomcat-stacktraces"],
    "cwe-353": _BY_TEMPLATE["missing-sri"],
}


def guidance_for(template_id: str | None, category: str | None = None) -> RemediationGuidance | None:
    """Reviewed guidance for a finding, or None when nobody has written any.

    Resolution order is most-specific-first: the nuclei template id, then the canonical CWE.
    Both lookups are exact after normalisation; there is no fuzzy or prefix matching and no
    generic fallback, so an unreviewed finding type yields no remediation row rather than
    filler text attributed to guidance it was never written for.
    """
    if template_id:
        hit = _BY_TEMPLATE.get(template_id.strip().lower())
        if hit is not None:
            return hit
    cwe = canonical_cwe(category)
    if cwe:
        return _BY_CWE.get(cwe)
    return None


def catalogue_template_ids() -> tuple[str, ...]:
    """Template ids with reviewed guidance, in catalogue order."""
    return tuple(_BY_TEMPLATE)


def catalogue_cwes() -> tuple[str, ...]:
    """CWE ids with reviewed fallback guidance, in catalogue order."""
    return tuple(_BY_CWE)
