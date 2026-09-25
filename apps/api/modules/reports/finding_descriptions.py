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
    # --- Technology and version disclosure -------------------------------------------------
    # The detection templates below match banners, fingerprints, meta tags and asset paths that
    # the application serves to anyone. They report what software is present, not a flaw in it.
    # The prose therefore describes the RECONNAISSANCE value of that disclosure and is careful
    # to state what a detection does not establish -- any judgement about whether the detected
    # component is current, correctly configured or affected by a known issue. Nuclei ships
    # these templates without `info.description`, which is why the scanner's own description
    # column is empty for them.
    "tech-detect": (
        "This finding records that the application disclosed the technologies it is built on "
        "through fingerprintable indicators served to any client -- response headers, cookie "
        "names, markup patterns, script paths and similar artefacts that the Wappalyzer "
        "fingerprint set recognises. Disclosure of a technology stack is not itself a "
        "vulnerability, and this detection carries no judgement about whether any component it "
        "names is current or correctly configured; it reports presence only. "
        "Its significance is to reconnaissance: an attacker who knows the framework, server, "
        "CMS and third-party components in use can select exploits and default-credential "
        "lists that apply to that specific stack instead of probing broadly, which shortens "
        "the work of finding a real weakness and reduces the noise that probing would "
        "otherwise generate in defensive telemetry. The usual treatment is to suppress "
        "unnecessary version and product banners where the platform allows it, and to accept "
        "the residual disclosure that cannot be removed without breaking functionality, "
        "prioritising instead the patching and hardening of the components the disclosure "
        "reveals."
    ),
    "wordpress-detect": (
        "This finding records that the host is running WordPress, identified from indicators "
        "the platform serves publicly, such as generator meta tags, `wp-content` and "
        "`wp-includes` asset paths, or characteristic endpoints. The presence of WordPress is "
        "not a vulnerability and this detection makes no claim about the version in use or "
        "whether it is current. It matters because WordPress has a large, well-catalogued "
        "attack surface that is extended by every installed theme and plugin: once the "
        "platform is known, an attacker can enumerate plugins and themes, look up published "
        "vulnerabilities for the versions found, and attempt well-known administrative and "
        "authentication endpoints directly. The practical response is not to hide the "
        "platform, which is rarely achievable, but to ensure core, themes and plugins are "
        "kept patched, that unused extensions are removed rather than merely deactivated, and "
        "that administrative endpoints are protected by strong authentication and rate "
        "limiting."
    ),
    "wordpress-passive-detection": (
        "This finding records that the host was identified as running WordPress from passive "
        "indicators alone -- markup, asset paths and headers already present in responses -- "
        "without requesting WordPress-specific endpoints. It reports platform presence only, "
        "makes no claim about the version in use, and is not itself a vulnerability. Its "
        "relevance is the same as any platform disclosure: it tells an attacker which "
        "catalogue of known vulnerabilities, default paths and authentication endpoints "
        "applies to this host, allowing reconnaissance to move directly to plugin and theme "
        "enumeration. Because the indicators are passive, suppressing them generally means "
        "changing how the site serves its own assets and markup, which is usually "
        "disproportionate; the effective control is keeping the platform and its extensions "
        "patched and protecting the administrative surface."
    ),
    "spring-detect": (
        "This finding records that the application was identified as running the Java Spring "
        "framework, recognised from framework-specific response artefacts such as error page "
        "structure, headers or default endpoint paths. Framework presence is not a "
        "vulnerability and this detection asserts nothing about the Spring version or its "
        "patch level. It is reported because Spring deployments have recurring, "
        "well-documented exposure patterns that an attacker will test once the framework is "
        "known: Spring Boot Actuator management endpoints reachable without authentication, "
        "verbose error pages that disclose stack traces and internal class or path names, and "
        "a history of high-severity remote-code-execution issues in specific releases that "
        "are only exploitable against particular configurations. The appropriate follow-up is "
        "to confirm which Actuator endpoints are exposed and to whom, to disable verbose error "
        "output in production, and to verify the framework and its dependencies against "
        "current advisories."
    ),
    "roundcube-webmail-portal": (
        "This finding records that a Roundcube webmail login portal is reachable at the "
        "location shown. Exposing webmail is an intentional deployment choice for many "
        "organisations and is not in itself a vulnerability; this detection does not "
        "establish the portal's patch level or configuration, or that any account on it is "
        "accessible. It is reported because an internet-facing mail interface is a "
        "high-value, authentication-bearing entry point: it accepts credentials directly, it "
        "is a natural target for credential stuffing and password spraying using addresses "
        "harvested elsewhere, and a successful login typically yields mailbox contents and "
        "the ability to drive password resets for other systems. Roundcube has also had "
        "publicly documented vulnerabilities in specific releases, several reachable "
        "pre-authentication. Sound treatment is to confirm the deployed version against "
        "current advisories, enforce multi-factor authentication and lockout or rate "
        "limiting on the login endpoint, and restrict reachability to expected networks where "
        "the business allows."
    ),
    "wordpress-readme-file": (
        "This finding records that a WordPress `readme.html` file is served to unauthenticated "
        "clients. The file ships with the platform and is left in place by default, so its "
        "presence reflects a standard installation rather than an attacker action, and it "
        "contains no secrets. It is reported because the file commonly states the WordPress "
        "version, which converts an unversioned platform detection into a specific version "
        "an attacker can match directly against published vulnerability databases -- removing "
        "the need to probe for which issues apply and reducing the activity defenders would "
        "otherwise see. The file serves no purpose in a production deployment and is normally "
        "removed, though doing so addresses the version disclosure only: it does not patch "
        "whatever the disclosed version is exposed to, which remains the substantive work."
    ),
    # --- Credential material in client-visible content -------------------------------------
    # These templates match key formats in responses. Presence of a key is a fact; whether it
    # is SENSITIVE depends on the key type and its server-side restrictions, which the scanner
    # cannot see. The prose must therefore explain that distinction rather than assert leakage.
    "google-api-key": (
        "This finding records that a string matching the Google API key format appears in "
        "content served to the client. Not every such key is a secret: Google's browser-facing "
        "APIs, including Maps, require the key to be present in client-side code by design, "
        "and those keys are intended to be restricted server-side by HTTP referrer, IP "
        "address, application identity and the specific APIs they may call. This detection "
        "matches the key's shape and location; it does not and cannot determine which "
        "restrictions are configured, which services the key authorises, or whether it is "
        "billable. The risk is therefore conditional and needs verification against the "
        "issuing Google Cloud project: an unrestricted or over-scoped key exposed this way can "
        "be used by anyone who reads the page, resulting in quota consumption and billing "
        "charged to its owner, and, if the key authorises services beyond the intended one, "
        "access to data or functionality that was never meant to be client-reachable. The "
        "correct treatment is to confirm the key's restrictions and scope; keys that must "
        "remain client-side should be tightly restricted, and any key found to grant more "
        "than the page requires should be rotated and re-scoped."
    ),
    "google-client-id": (
        "This finding records that a Google OAuth client identifier appears in content served "
        "to the client. For web applications this identifier is public by design -- the OAuth "
        "authorisation-code flow requires the browser to present it when initiating sign-in -- "
        "so its presence is expected and is not, on its own, a disclosure of a secret. The "
        "accompanying client SECRET is the sensitive value, and it must never appear in "
        "client-visible content; this detection matches the identifier only and makes no claim "
        "that a secret was exposed. The identifier is reported because it is useful context "
        "for an assessment: it confirms which Google project the application authenticates "
        "against and provides the value an attacker would use when testing the OAuth "
        "configuration itself, where the substantive weaknesses lie -- overly permissive "
        "redirect URI patterns that allow authorisation codes to be delivered to an "
        "attacker-controlled destination, and missing state-parameter validation. Review "
        "should focus on the registered redirect URIs and the flow's state handling, and on "
        "confirming that no client secret accompanies the identifier."
    ),
    # --- WordPress extension enumeration ---------------------------------------------------
    # One shared editorial position: each of these templates identifies a specific installed
    # plugin from publicly served assets. The weakness class is identical across them, and the
    # prose says so plainly rather than inventing per-plugin risk the detection cannot support.
    # A distinct entry per template id is kept (rather than one shared string) because the
    # lookup is exact by design and each id is separately reviewed.
    **{
        _plugin_id: (
            f"This finding records that the WordPress plugin {_plugin_name} was identified on "
            "the host, detected from assets or markup the site serves publicly, such as files "
            "under `wp-content/plugins/` or plugin-specific markup. The presence of a plugin "
            "is not a vulnerability: this detection reports installation only and asserts "
            "nothing about the plugin's version, its configuration, or whether it is affected "
            "by any known issue. It is reported because plugin enumeration is a standard "
            "reconnaissance step against WordPress, where the majority of exploited "
            "vulnerabilities are in extensions rather than in core. Knowing precisely which "
            "plugins are installed lets an attacker consult public vulnerability databases "
            "for issues affecting those plugins and test only what is applicable, and plugin "
            "readme and asset files frequently disclose the installed version, which narrows "
            "that matching further. The appropriate response is to confirm the installed "
            "version against current advisories, to keep the plugin updated, and to remove "
            "plugins that are not required -- deleting rather than deactivating them, since "
            "a deactivated plugin's files remain reachable and can still be vulnerable."
        )
        for _plugin_id, _plugin_name in (
            ("wordpress-astra-sites", "Starter Templates (Astra Sites)"),
            ("wordpress-astra-widgets", "Astra Widgets"),
            ("wordpress-duplicate-page", "Duplicate Page"),
            ("wordpress-duplicator", "Duplicator (Backups & Migration)"),
            ("wordpress-elementor", "Elementor Website Builder"),
            ("wordpress-gtranslate", "GTranslate"),
            ("wordpress-header-footer-elementor", "Ultimate Addons for Elementor"),
            ("wordpress-limit-login-attempts-reloaded", "Limit Login Attempts Reloaded"),
            ("wordpress-royal-elementor-addons", "Royal Elementor Addons and Templates"),
            ("wordpress-wp-super-cache", "WP Super Cache"),
        )
    },
    # WPS Hide Login is grouped with the plugins above in kind, but its detection carries one
    # extra, specific consequence worth stating: the plugin's entire purpose is to relocate the
    # login URL, so detecting it establishes that the relocation is not, by itself, concealing
    # anything from an attacker who fingerprints the site.
    "wordpress-wps-hide-login": (
        "This finding records that the WordPress plugin WPS Hide Login was identified on the "
        "host. The plugin's function is to move the administrative login form away from the "
        "default `wp-login.php` and `wp-admin` paths so that automated attacks against those "
        "well-known URLs do not reach it. Detecting the plugin is not a vulnerability and does "
        "not disclose the relocated login path, nor does this detection assert that the "
        "relocated path was found. It is worth recording because it bears directly on what the "
        "control achieves: the measure is obscurity rather than access control, it is "
        "detectable from the outside as this finding shows, and relocated paths are commonly "
        "recoverable through other channels -- password-reset and registration flows, redirect "
        "behaviour, cached or archived links and plugin-specific quirks. The relocation "
        "remains useful for reducing untargeted automated noise against the default paths, but "
        "it should not be relied on as the protection for the administrative interface. "
        "Authentication strength at that endpoint -- multi-factor authentication, lockout or "
        "rate limiting, and network restriction where feasible -- is what actually governs the "
        "exposure."
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
