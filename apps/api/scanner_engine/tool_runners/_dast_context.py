"""Extracts the DAST-specific trigger context (parameter, HTTP method, header) from a nuclei
JSONL finding object, when nuclei actually reported it (Prompt 13, Finding #7).

WHY THIS EXISTS. Before this module, nuclei_runner.parse_vulnerabilities only ever recorded
`template_id`/`matcher_name`/`cve`/`type`/`tags` in a VulnerabilityFinding's metadata -- never
which specific parameter or header nuclei-dast actually fuzzed to trigger the finding. For a
signature (non-DAST) nuclei run this genuinely does not exist (there is nothing "injected"),
but for nuclei-dast -- which mutates request parameters/headers to fuzz an app's inputs -- the
information is real and nuclei's own JSON output can carry it; it was simply never read.

WHAT THIS EXTRACTS, and from where, ALL optional (nuclei does not guarantee any of these
fields are present, and older nuclei versions or non-HTTP templates may omit them entirely):

  * `http_method`   -- the first token of `request`'s request-line ("GET /path?q=1 HTTP/1.1"),
                        when nuclei included the raw request text (curl-command as a fallback
                        source, since it always starts with `curl -X <METHOD>` or implies GET).
  * `parameter_name` -- the query-string parameter name(s) present in `matched-at`'s URL, when
                        the finding's own location is itself a parameterised URL. This is a
                        best-effort inference from the URL nuclei matched at, NOT a claim that
                        THIS SPECIFIC parameter (vs. a sibling one on the same URL) was the
                        exact injection point -- nuclei's JSON output does not name the fuzzed
                        parameter more precisely than "this URL, this template" for a query
                        injection. Still strictly more useful than nothing, and never invents a
                        name that isn't actually in the URL.
  * `header_context` -- present only when `request` shows a header nuclei DID NOT typically
                        send with a stock GET (i.e. header-based fuzzing left a trace in the
                        raw request nuclei captured). Header VALUES are never persisted (see
                        redaction below); only header NAMES, so "X-Forwarded-For was the
                        injection point" is knowable without keeping whatever payload/session
                        material rode inside it.

REDACTION. `request`/`curl-command` text can legitimately contain a session cookie, an
Authorization bearer token, or an API key the target/tool used to reach the endpoint in the
first place (nuclei attaches whatever headers config supplied it). This module NEVER persists
raw header VALUES, and never persists the raw `request`/`curl-command` text verbatim -- only
the derived method, the header NAMES (not values) that look fuzzed, and parameter names parsed
out of the URL. `_SENSITIVE_HEADER_NAMES` is deliberately checked case-insensitively.

NEVER INVENTS VALUES. Every field returned is either a value nuclei's own output actually
contained or is absent (None / not present in the returned dict) -- there is no default,
guess, or placeholder for a field this module cannot derive from real output."""
from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

# Headers whose VALUE must never be persisted, matched case-insensitively against whatever
# header name appears in a captured request. Names themselves (e.g. "the Authorization header
# was present") are not sensitive and may still be recorded.
_SENSITIVE_HEADER_NAMES = frozenset({
    "authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "proxy-authorization",
    "x-csrf-token", "x-xsrf-token",
})

# Headers a stock nuclei GET request does not normally carry -- their PRESENCE in a captured
# request is a real signal that header-based fuzzing put something there, without needing (or
# persisting) the value itself.
_NOTABLE_HEADER_NAMES = frozenset({
    "x-forwarded-for", "x-forwarded-host", "x-original-url", "x-rewrite-url", "referer",
    "user-agent", "x-forwarded-proto", "x-real-ip",
})


def _method_from_request_text(request_text: str) -> str | None:
    """First token of the request-line in a raw HTTP request nuclei captured, e.g.
    "POST /login HTTP/1.1\\r\\n..." -> "POST". None if the text doesn't look like a request."""
    if not request_text:
        return None
    first_line = request_text.splitlines()[0] if request_text.splitlines() else ""
    parts = first_line.split()
    if len(parts) >= 2 and parts[0].isalpha() and parts[0].isupper():
        return parts[0]
    return None


def _method_from_curl_command(curl_command: str) -> str | None:
    """curl-command nuclei sometimes reports instead of/alongside `request`, e.g.
    "curl -X 'POST' -H '...' 'https://h/x'". Absence of -X means curl's (and nuclei's) default,
    GET -- reported explicitly here rather than left ambiguous, since the absence itself is a
    real, observed fact about the captured command."""
    if not curl_command:
        return None
    tokens = curl_command.split()
    for i, tok in enumerate(tokens):
        if tok == "-X" and i + 1 < len(tokens):
            return tokens[i + 1].strip("'\"").upper()
    if curl_command.strip().startswith("curl"):
        return "GET"
    return None


def _parameter_names_from_url(matched_at: str | None) -> list[str]:
    if not matched_at:
        return []
    try:
        query = urlsplit(matched_at).query
    except ValueError:
        return []
    if not query:
        return []
    return sorted(parse_qs(query, keep_blank_values=True).keys())


def _notable_header_names(request_text: str) -> list[str]:
    """Header NAMES (never values) present in a captured request that a stock GET would not
    normally carry -- see _NOTABLE_HEADER_NAMES. Sensitive names are excluded entirely (not
    even the name is reported for those -- their presence alone is expected/uninformative and
    reporting it adds no signal worth the temptation to later log the value alongside it)."""
    if not request_text:
        return []
    found: list[str] = []
    for line in request_text.splitlines()[1:]:  # skip the request-line itself
        if ":" not in line:
            continue
        name = line.split(":", 1)[0].strip().lower()
        if not name or name in _SENSITIVE_HEADER_NAMES:
            continue
        if name in _NOTABLE_HEADER_NAMES and name not in found:
            found.append(name)
    return found


def extract_dast_context(obj: dict, matched_at: str | None) -> dict:
    """Build the DAST trigger-context dict for one nuclei JSONL finding object. Every key is
    omitted (not set to None) when nuclei's output gave no basis for it, so the resulting
    metadata dict never implies false precision -- a signature-mode nuclei finding with no
    request/curl-command data contributes an empty dict, unchanged from before this module."""
    context: dict = {}

    # Prompt 24 (Requirement E): `or ""` substitutes for a MISSING value but not for a
    # WRONG-TYPED one -- a list/dict `request` passed straight through and then raised on
    # `.splitlines()`, out of the caller's whole parse loop. Both fields are free text in
    # nuclei's schema, so a non-string one carries no context to extract; treated as absent,
    # which is this module's documented "never invents a value" behaviour.
    request_text = obj.get("request")
    request_text = request_text if isinstance(request_text, str) else ""
    curl_command = obj.get("curl-command") or obj.get("curl_command")
    curl_command = curl_command if isinstance(curl_command, str) else ""

    method = _method_from_request_text(request_text) or _method_from_curl_command(curl_command)
    if method:
        context["http_method"] = method

    params = _parameter_names_from_url(matched_at)
    if params:
        context["parameter_names"] = params

    headers = _notable_header_names(request_text)
    if headers:
        context["notable_header_names"] = headers

    return context
