"""Deterministic authentication-state classification for discovered web surface (Prompt 20).

WHAT THIS ADDS, and the lines it does NOT cross. The platform scans UNAUTHENTICATED -- it
injects no credentials, and Prompt 20 is explicit that it must stay that way ("do not invent
credentials", "do not weaken authentication"). This module does NOT authenticate anything.

What it does is model the AUTHENTICATION STATE of a discovered surface from signals the
tools already observed (an httpx status_code, a login redirect), so the coverage model can
tell apart:

    unauthenticated_ok  -- reachable without credentials (a 2xx/3xx that is not a login bounce)
    protected           -- 401/403: an endpoint guarded by auth we did NOT cross
    login_redirect      -- a 30x whose Location/title points at a login/SSO flow
    server_error        -- 5xx: not a coverage statement about auth at all
    unknown             -- no usable signal

WHY IT MATTERS (Prompt 20's two assumptions to attack):

    HTTP 200 = authenticated access        -- FALSE. A 200 is unauthenticated-reachable, which
                                              says nothing about the authenticated surface behind
                                              a login. `unauthenticated_ok` names exactly that.
    login succeeded = surface fully covered -- N/A here (we never log in), but the dual holds:
                                              a `protected`/`login_redirect` endpoint is surface
                                              we did NOT cover, and must be a NAMEABLE gap, never
                                              a silent "tested, nothing found".

A `protected` endpoint that yields no finding is NOT evidence of no vulnerability -- it is
evidence we never got past the auth boundary. That distinction is the whole point.

Pure/deterministic: derived from status code + a bounded set of textual login markers. No
network, no DB, no credentials.
"""
from __future__ import annotations

# Auth-state labels. These are provenance-carrying facts about what was OBSERVED, never a
# claim about what lies behind the boundary.
AUTH_UNAUTH_OK = "unauthenticated_ok"
AUTH_PROTECTED = "protected"
AUTH_LOGIN_REDIRECT = "login_redirect"
AUTH_SERVER_ERROR = "server_error"
AUTH_UNKNOWN = "unknown"

# Auth states that represent surface we did NOT cross -- coverage the unauthenticated scan
# cannot fulfil. The coverage model treats these as a distinct, nameable gap (requires_auth),
# never as silently "covered".
UNCROSSED_AUTH_STATES = frozenset({AUTH_PROTECTED, AUTH_LOGIN_REDIRECT})

# Substrings (lowercased) in a redirect Location or page title that mark a login/SSO flow. A
# 30x alone is an ordinary redirect; only a 30x TOWARD one of these is a login bounce.
_LOGIN_MARKERS = (
    "/login", "/signin", "/sign-in", "/auth", "/sso", "/oauth", "/session/new",
    "/account/login", "/accounts/login", "/saml", "/adfs", "login.microsoftonline",
    "returnurl=", "redirect_uri=", "next=/",
)

# Title substrings that, on their own, indicate a login page even without a redirect (a 200
# that is really "please log in").
_LOGIN_TITLE_MARKERS = ("log in", "login", "sign in", "signin", "authentication required")


def _looks_like_login(*texts: str | None) -> bool:
    for t in texts:
        if not t:
            continue
        low = str(t).lower()
        if any(m in low for m in _LOGIN_MARKERS):
            return True
    return False


def classify_auth_state(
    status_code: int | str | None,
    *,
    location: str | None = None,
    title: str | None = None,
) -> str:
    """Classify the auth state of ONE observed HTTP response. Deterministic; never raises.

    `location` is the redirect target (if the tool captured it); `title` is the page title.
    A 30x is `login_redirect` only when its Location OR title looks like a login/SSO flow --
    an ordinary redirect stays `unauthenticated_ok`."""
    code = _as_int(status_code)
    if code is None:
        # No status code, but a login-looking title still tells us something.
        if _title_is_login(title):
            return AUTH_LOGIN_REDIRECT
        return AUTH_UNKNOWN

    if code in (401, 403):
        return AUTH_PROTECTED
    if 500 <= code <= 599:
        return AUTH_SERVER_ERROR
    if 300 <= code <= 399:
        return AUTH_LOGIN_REDIRECT if _looks_like_login(location, title) else AUTH_UNAUTH_OK
    if 200 <= code <= 299:
        # A 200 that is actually a login page (SPA/login form) is a login surface, not open
        # access -- attacking the "200 == accessible" assumption directly.
        if _title_is_login(title) or _looks_like_login(location):
            return AUTH_LOGIN_REDIRECT
        return AUTH_UNAUTH_OK
    return AUTH_UNKNOWN


def _title_is_login(title: str | None) -> bool:
    if not title:
        return False
    low = str(title).lower()
    return any(m in low for m in _LOGIN_TITLE_MARKERS)


def _as_int(value) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def auth_metadata(status_code, *, location: str | None = None, title: str | None = None) -> dict:
    """The metadata a finding carries for its auth state. Only a meaningful state is recorded
    (unknown adds nothing), so a signal-less finding is unchanged.

    PROVENANCE (Prompt 26). `auth_state` is INFERRED -- derived from an observed status code
    plus textual login markers, never from crossing the boundary -- and it sat in the same
    flat namespace as the OBSERVED `status_code` it was derived from. The tier is now named in
    an additive `inferred_keys` sidecar, matching api_intel.as_metadata(); every existing
    consumer (coverage.py's UNCROSSED_AUTH_STATES check) reads the same flat key unchanged.

    The distinction matters here more than anywhere: `protected` means we did NOT get past the
    auth boundary, so it is the absence of coverage, never evidence about what lies behind."""
    state = classify_auth_state(status_code, location=location, title=title)
    if state == AUTH_UNKNOWN:
        return {}
    return {"auth_state": state, "inferred_keys": ["auth_state"]}
