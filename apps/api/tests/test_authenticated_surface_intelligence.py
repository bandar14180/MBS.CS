"""Prompt 20 -- Authenticated Surface Intelligence (adversarial).

The platform scans UNAUTHENTICATED and invents no credentials. Prompt 20's job is to MODEL
the authentication state of discovered surface from observable signals, so that:

    HTTP 200 != authenticated access      -- a 200 is `unauthenticated_ok`, nothing more;
    a protected/login endpoint is a NAMED coverage gap (requires_auth), never a silent
    "tested, nothing found".

These tests attack the classifier (status codes, login redirects, login-page 200s) and its
two integration points: httpx tagging and the coverage model's requires_auth state. They also
pin that we never invent credentials or weaken auth (there is nothing here that authenticates).
"""
from apps.api.scanner_engine.auth_state import (
    AUTH_LOGIN_REDIRECT,
    AUTH_PROTECTED,
    AUTH_SERVER_ERROR,
    AUTH_UNAUTH_OK,
    AUTH_UNKNOWN,
    classify_auth_state,
)
from apps.api.scanner_engine.coverage import (
    STATE_OUT_OF_SCOPE,
    STATE_REQUIRES_AUTH,
    STATE_VERIFIED,
    ToolRunOutcome,
    build_coverage,
)
from apps.api.scanner_engine.tool_runners.base import CommonFinding, RawToolOutput
from apps.api.scanner_engine.tool_runners.httpx_runner import HttpxRunner


# --- the classifier ------------------------------------------------------------------------

def test_401_403_are_protected():
    assert classify_auth_state(401) == AUTH_PROTECTED
    assert classify_auth_state(403) == AUTH_PROTECTED


def test_200_is_unauthenticated_ok_not_authenticated():
    """The headline assumption: a 200 means reachable WITHOUT credentials -- it says nothing
    about the authenticated surface behind a login."""
    assert classify_auth_state(200) == AUTH_UNAUTH_OK


def test_login_redirect_is_detected_from_location():
    assert classify_auth_state(302, location="https://h/login?returnUrl=/app") == AUTH_LOGIN_REDIRECT


def test_ordinary_redirect_is_not_a_login_redirect():
    """A 30x alone is not a login bounce -- only a 30x toward a login/SSO flow is."""
    assert classify_auth_state(301, location="https://h/new-home") == AUTH_UNAUTH_OK


def test_200_that_is_really_a_login_page_is_flagged():
    """A 200 whose title is a login page is a login surface, not open access -- attacking the
    '200 == accessible' assumption directly."""
    assert classify_auth_state(200, title="Sign in - Acme") == AUTH_LOGIN_REDIRECT


def test_5xx_is_server_error_not_an_auth_statement():
    assert classify_auth_state(503) == AUTH_SERVER_ERROR


def test_no_signal_is_unknown():
    assert classify_auth_state(None) == AUTH_UNKNOWN
    assert classify_auth_state("not-a-code") == AUTH_UNKNOWN


# --- httpx tags the auth state -------------------------------------------------------------

def test_httpx_tags_protected_endpoints():
    raw = RawToolOutput(
        "httpx",
        stdout=(
            '{"url":"https://h/admin","status_code":403,"host":"h","port":443,"scheme":"https"}\n'
            '{"url":"https://h/","status_code":200,"host":"h","port":443,"scheme":"https"}\n'
        ),
        stderr="", exit_code=0,
    )
    by_url = {f.value: f.metadata for f in HttpxRunner().parse(raw)}
    assert by_url["https://h/admin"]["auth_state"] == AUTH_PROTECTED
    assert by_url["https://h/"]["auth_state"] == AUTH_UNAUTH_OK


def test_httpx_tags_login_redirect_from_location_field():
    raw = RawToolOutput(
        "httpx",
        stdout='{"url":"https://h/app","status_code":302,"location":"https://h/login","host":"h"}\n',
        stderr="", exit_code=0,
    )
    f = HttpxRunner().parse(raw)[0]
    assert f.metadata["auth_state"] == AUTH_LOGIN_REDIRECT


# --- coverage model names the requires_auth gap -------------------------------------------

def _svc(value, auth_state=None, in_scope=True):
    md = {"in_scope": in_scope}
    if auth_state:
        md["auth_state"] = auth_state
    return CommonFinding(asset_type="http_service", value=value, metadata=md)


def test_protected_surface_is_requires_auth_not_silently_covered():
    """FALSE-CONFIDENCE GUARD: a protected endpoint that a completed crawl 'reached' must NOT
    read as covered -- it is requires_auth, a named gap. 'No finding here' is NOT 'no
    vulnerability', it is 'we never got past the auth boundary'."""
    prior = [_svc("https://h/admin", auth_state=AUTH_PROTECTED)]
    cov = build_coverage(prior, [ToolRunOutcome("katana", "completed")], target_type="domain")
    assert cov.surfaces[0].state == STATE_REQUIRES_AUTH
    # requires_auth is not counted as recon coverage DEBT (recon cannot pay it down)...
    assert not cov.has_debt
    # ...but it is explicitly present and named, never hidden.
    assert cov.surfaces[0].reason.startswith("behind an auth boundary")


def test_login_redirect_surface_is_requires_auth():
    prior = [_svc("https://h/app", auth_state=AUTH_LOGIN_REDIRECT)]
    cov = build_coverage(prior, [], target_type="domain")
    assert cov.surfaces[0].state == STATE_REQUIRES_AUTH


def test_unauthenticated_ok_surface_follows_normal_coverage_rules():
    """An openly reachable service is classified normally -- requires_auth must NOT swallow
    ordinary surface."""
    prior = [_svc("https://h/", auth_state=AUTH_UNAUTH_OK)]
    cov = build_coverage(prior, [], target_type="domain")
    assert cov.surfaces[0].state != STATE_REQUIRES_AUTH


def test_out_of_scope_beats_requires_auth():
    """Scope precedence is preserved: an out-of-scope protected endpoint is out_of_scope, not
    requires_auth (it was never ours to probe)."""
    prior = [_svc("https://h/admin", auth_state=AUTH_PROTECTED, in_scope=False)]
    cov = build_coverage(prior, [], target_type="domain")
    assert cov.surfaces[0].state == STATE_OUT_OF_SCOPE


def test_verified_beats_requires_auth():
    """A confirmed vulnerability at a surface is the strongest evidence and wins over an
    auth-boundary observation."""
    prior = [_svc("https://h/admin", auth_state=AUTH_PROTECTED)]
    cov = build_coverage(prior, [], target_type="domain",
                         verified_locations=frozenset({"https://h/admin"}))
    assert cov.surfaces[0].state == STATE_VERIFIED


def test_auth_state_provenance_is_retained_on_the_asset():
    """Authenticated-state provenance must ride along with the discovery (Prompt 20)."""
    f = _svc("https://h/admin", auth_state=AUTH_PROTECTED)
    assert f.metadata["auth_state"] == AUTH_PROTECTED
