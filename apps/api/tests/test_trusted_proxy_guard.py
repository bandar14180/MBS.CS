"""TRUSTED_PROXY_COUNT must be a DECISION in production, never an inherited default.

Production already mandates RATE_LIMIT_ENABLED=true, but a rate limiter is only as good as the
client identity it buckets on. `_client_ip` reads the caller's hop as the Nth entry from the
right of X-Forwarded-For, and the app cannot observe its own ingress chain -- so the hop count
has to come from the operator. Guessing is unsafe in both directions:

  * too LOW  -> every anonymous client collapses into one bucket (limiter is decorative);
  * too HIGH -> the Nth-from-right read reaches into caller-supplied entries, so anyone can
    forge a fresh bucket key at will.

The guard therefore refuses to start production unless the value was set EXPLICITLY. It does
not prescribe a value: 0 stays correct (and safe) when nothing fronts the app -- it simply has
to be stated. Pydantic's `model_fields_set` is what distinguishes "the operator chose 0" from
"nobody thought about it"; both produce the value 0.

These tests exercise the real `Settings.validate_production()` -- the same method main.py calls
at startup -- with no DB, network or app involved.
"""
import pytest
from pydantic import ValidationError

from apps.api.core.config import Settings

# The minimal configuration that satisfies EVERY other production check, so the only thing a
# test can trip is the control under test. Mirrors the hardened fixture in test_ai_providers.
_PROD = dict(
    environment="production",
    jwt_secret_key="a" * 48,
    s3_access_key="real-access",
    s3_secret_key="real-secret",
    database_url="mysql+aiomysql://user:strongpass@db:3306/mbs",
    cors_allow_origins=["https://mbs.example.com"],
    trusted_hosts=["mbs.example.com"],
    ai_provider="openrouter",
    rate_limit_enabled=True,
    # F-08: production requires a Secure refresh cookie.
    refresh_cookie_secure=True,
    metrics_mode="token",
    mfa_encryption_key="a-real-mfa-encryption-key",
)


def _prod(**overrides) -> Settings:
    return Settings(**{**_PROD, **overrides})


def test_production_refuses_start_when_trusted_proxy_count_not_declared():
    """The gap this guard closes: a production deployment that never considered the setting
    boots with rate limiting ON and an unconsidered identity source. It must refuse instead."""
    with pytest.raises(RuntimeError) as exc:
        _prod().validate_production()          # note: trusted_proxy_count NOT passed
    msg = str(exc.value)
    assert "TRUSTED_PROXY_COUNT" in msg
    assert "Refusing to start in production" in msg


def test_production_accepts_explicit_zero():
    """THE SAFE DEFAULT SURVIVES. 0 is the correct answer when nothing fronts the app; the
    guard only requires that it was chosen, not that it was changed."""
    s = _prod(trusted_proxy_count=0)
    s.validate_production()                    # must not raise
    assert s.trusted_proxy_count == 0
    assert "trusted_proxy_count" in s.model_fields_set


def test_production_accepts_explicit_non_zero():
    """A real proxy chain is equally acceptable -- the guard is about declaring, not about
    which number is declared."""
    s = _prod(trusted_proxy_count=2)
    s.validate_production()                    # must not raise
    assert s.trusted_proxy_count == 2


def test_development_never_requires_the_declaration():
    """Local dev, CI and the test suite must stay usable with zero configuration. The guard
    lives behind the production gate, and the default remains the safe one."""
    s = Settings(environment="development")
    s.validate_production()                    # no-op outside production
    assert s.trusted_proxy_count == 0
    assert "trusted_proxy_count" not in s.model_fields_set


def test_negative_hop_count_is_rejected():
    """A negative hop count is meaningless. It previously slipped through and behaved as 0
    because the consumer guards on `n > 0`; the field now refuses it outright."""
    with pytest.raises(ValidationError):
        Settings(trusted_proxy_count=-1)


def test_guard_message_tells_the_operator_to_determine_it_and_never_guess():
    """The message must direct the operator to the real ingress chain rather than suggest a
    value -- a prescribed number is exactly the guess this control exists to prevent."""
    with pytest.raises(RuntimeError) as exc:
        _prod().validate_production()
    msg = str(exc.value)
    assert "never guess" in msg.lower()
    assert "docs/runbooks/deployment.md" in msg
    for prescription in ("e.g. 1", "set it to 1", "should be 1", "use 1"):
        assert prescription not in msg
