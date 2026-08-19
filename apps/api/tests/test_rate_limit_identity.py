"""Rate-limit IDENTITY: which bucket a request is counted against.

`X-Forwarded-For` is attacker-controlled. If it were trusted unconditionally, any anonymous
client could mint a fresh rate-limit bucket per request simply by varying the header, which
makes the limiter decorative. These tests pin the two halves of the defence:

  * `_client_ip`  -- XFF is honoured ONLY when TRUSTED_PROXY_COUNT > 0, and then the client's
    own hop is read as the Nth entry FROM THE RIGHT (the rightmost entries are appended by our
    own trusted proxies; everything to the left is caller-supplied and forgeable).
  * `_principal`  -- an authenticated request is bucketed by user id, which is stable across
    NAT/proxy IP sharing and cannot be forged without a valid token; anonymous or
    invalid-token requests fall back to the IP bucket.

No network and no Redis: the middleware helpers are pure functions of the request, so a
hand-built ASGI scope is the honest unit under test.
"""
import uuid

from starlette.requests import Request

from apps.api.core.config import get_settings
from apps.api.core.middleware import RateLimitMiddleware, _client_ip

PEER = "203.0.113.7"          # the direct socket peer (what the app actually observes)
SPOOFED = "198.51.100.66"     # what an attacker puts in X-Forwarded-For


def _request(headers: dict | None = None, client_host: str | None = PEER) -> Request:
    """A minimal real ASGI scope -- Request parses the same headers/client the server gives it."""
    return Request({
        "type": "http",
        "method": "GET",
        "path": "/api/v1/scans",
        "scheme": "http",
        "server": ("testserver", 80),
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": (client_host, 41234) if client_host else None,
    })


def _set_hops(monkeypatch, n: int) -> None:
    monkeypatch.setattr(get_settings(), "trusted_proxy_count", n)


# --- _client_ip: trusting X-Forwarded-For only when we actually sit behind proxies ---------

def test_no_trusted_proxies_ignores_x_forwarded_for(monkeypatch):
    """Default posture (TRUSTED_PROXY_COUNT=0): the header is not evidence of anything, so the
    direct peer wins no matter what the caller claims."""
    _set_hops(monkeypatch, 0)
    assert _client_ip(_request({"x-forwarded-for": SPOOFED})) == PEER
    assert _client_ip(_request({"x-forwarded-for": f"{SPOOFED}, 10.0.0.1, 10.0.0.2"})) == PEER
    assert _client_ip(_request()) == PEER          # no header at all -> same bucket


def test_one_trusted_proxy_takes_the_rightmost_entry(monkeypatch):
    """Behind ONE trusted proxy, that proxy appends the peer it saw as the LAST entry. Anything
    the client prepended is ignored."""
    _set_hops(monkeypatch, 1)
    real = "192.0.2.55"
    assert _client_ip(_request({"x-forwarded-for": f"{SPOOFED}, {real}"})) == real
    # a client stuffing many forged hops still cannot move the rightmost entry
    assert _client_ip(
        _request({"x-forwarded-for": f"{SPOOFED}, {SPOOFED}, {SPOOFED}, {real}"})
    ) == real


def test_n_trusted_proxies_take_the_nth_entry_from_the_right(monkeypatch):
    """With N trusted hops the client's own address is the Nth from the right -- the N-1
    entries to its right were added by our own proxies."""
    _set_hops(monkeypatch, 2)
    client, edge = "192.0.2.55", "10.0.0.1"
    assert _client_ip(_request({"x-forwarded-for": f"{SPOOFED}, {client}, {edge}"})) == client
    _set_hops(monkeypatch, 3)
    assert _client_ip(
        _request({"x-forwarded-for": f"{SPOOFED}, {client}, {edge}, 10.0.0.2"})
    ) == client


def test_short_forwarded_chain_falls_back_to_the_peer(monkeypatch):
    """FAIL CLOSED: if the chain is shorter than the configured hop count the header did not
    come through the expected proxies, so it is not used."""
    _set_hops(monkeypatch, 3)
    assert _client_ip(_request({"x-forwarded-for": f"{SPOOFED}, 10.0.0.1"})) == PEER
    assert _client_ip(_request({"x-forwarded-for": ""})) == PEER


def test_missing_client_is_reported_as_unknown(monkeypatch):
    """No socket peer (odd ASGI servers / test transports) must not raise."""
    _set_hops(monkeypatch, 0)
    assert _client_ip(_request(client_host=None)) == "unknown"


# --- the anti-abuse property this all exists for ------------------------------------------

def test_spoofed_forwarded_headers_cannot_mint_unlimited_anonymous_buckets(monkeypatch):
    """THE POINT. An anonymous caller varying X-Forwarded-For on every request must keep
    landing in ONE bucket, otherwise the rate limiter can be bypassed for free."""
    _set_hops(monkeypatch, 0)
    buckets = {
        RateLimitMiddleware._principal(_request({"x-forwarded-for": f"198.51.100.{i}"}))
        for i in range(50)
    }
    assert buckets == {f"ip:{PEER}"}, f"spoofing produced {len(buckets)} distinct buckets"


def test_spoofing_behind_a_trusted_proxy_still_collapses_to_one_bucket(monkeypatch):
    """Even WITH a trusted proxy configured, the entry the proxy appends is the one that
    counts -- forged prefixes cannot fan out into separate buckets."""
    _set_hops(monkeypatch, 1)
    real = "192.0.2.55"
    buckets = {
        RateLimitMiddleware._principal(
            _request({"x-forwarded-for": f"198.51.100.{i}, {real}"})
        )
        for i in range(50)
    }
    assert buckets == {f"ip:{real}"}


# --- _principal: authenticated requests are bucketed by user, not by address ---------------

def test_authenticated_request_uses_the_stable_user_principal(monkeypatch):
    """A valid bearer token buckets by user id, so one user cannot multiply their allowance by
    changing address (NAT, mobile roaming, proxy rotation)."""
    from apps.api.core.security import create_access_token

    _set_hops(monkeypatch, 0)
    user_id = uuid.uuid4()
    token = create_access_token(user_id)

    from_peer_a = RateLimitMiddleware._principal(
        _request({"authorization": f"Bearer {token}"}, client_host="203.0.113.7")
    )
    from_peer_b = RateLimitMiddleware._principal(
        _request({"authorization": f"Bearer {token}"}, client_host="198.51.100.9")
    )
    assert from_peer_a == f"user:{user_id}"
    assert from_peer_a == from_peer_b          # same user, different addresses -> one bucket


def test_absent_or_invalid_bearer_falls_back_to_the_ip_bucket(monkeypatch):
    """Anything that is not a verifiable access token degrades to the IP bucket and never
    raises -- an unauthenticated request must still be limited, not let through."""
    _set_hops(monkeypatch, 0)
    ip_bucket = f"ip:{PEER}"
    assert RateLimitMiddleware._principal(_request()) == ip_bucket
    assert RateLimitMiddleware._principal(
        _request({"authorization": "Bearer not-a-jwt"})) == ip_bucket
    assert RateLimitMiddleware._principal(
        _request({"authorization": "Basic dXNlcjpwYXNz"})) == ip_bucket
    assert RateLimitMiddleware._principal(
        _request({"authorization": "Bearer "})) == ip_bucket


def test_a_non_access_token_is_not_accepted_as_a_principal(monkeypatch):
    """Token TYPE is enforced: an MFA challenge token is a valid JWT but must not buy a user
    bucket (or, worse, be treated as authentication anywhere)."""
    from apps.api.core.security import create_mfa_challenge_token

    _set_hops(monkeypatch, 0)
    challenge = create_mfa_challenge_token(uuid.uuid4())
    assert RateLimitMiddleware._principal(
        _request({"authorization": f"Bearer {challenge}"})) == f"ip:{PEER}"
