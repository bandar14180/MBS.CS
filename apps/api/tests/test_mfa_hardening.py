"""MFA Sprint 1, Step 3 -- production hardening: per-user brute-force lockout, security audit
events, and last_login_at correctness. Integration via the app TestClient (+ a direct DB read for
the timestamp). Redis is the real container instance; failure counters are per-user so tests are
isolated.
"""
import asyncio
import logging
import uuid

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core.config import get_settings

_PW = "correct horse battery staple"
_MFA_KEY = "hardening-test-mfa-master-key"


def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    r = client.post("/api/v1/auth/register", json={"email": email, "password": _PW, "full_name": "H"})
    assert r.status_code == 201, r.text
    return {"email": email, **r.json()}


def _headers(t):
    return {"Authorization": f"Bearer {t['access_token']}"}


def _set_key(monkeypatch):
    monkeypatch.setattr(get_settings(), "mfa_encryption_key", _MFA_KEY)


def _enroll(client, headers):
    r = client.post("/api/v1/auth/mfa/enable", headers=headers)
    secret = r.json()["secret"]
    r2 = client.post("/api/v1/auth/mfa/verify-enable", headers=headers, json={"code": pyotp.TOTP(secret).now()})
    assert r2.status_code == 200, r2.text
    return secret, r2.json()["recovery_codes"]


async def _read_last_login(email):
    eng = create_async_engine(get_settings().database_url, poolclass=StaticPool)
    try:
        async with eng.connect() as c:
            return await c.scalar(text("SELECT last_login_at FROM users WHERE email = :e"), {"e": email})
    finally:
        await eng.dispose()


# --- brute-force lockout -------------------------------------------------------------------

def test_mfa_login_locks_user_after_max_attempts(client: TestClient, monkeypatch):
    _set_key(monkeypatch)
    monkeypatch.setattr(get_settings(), "mfa_max_attempts", 3)
    u = _register(client)
    _enroll(client, _headers(u))
    tok = client.post("/api/v1/auth/login", json={"email": u["email"], "password": _PW}).json()["mfa_token"]

    for _ in range(3):  # allowed failed attempts -> 401
        r = client.post("/api/v1/auth/mfa/login", json={"mfa_token": tok, "code": "000000"})
        assert r.status_code == 401
    locked = client.post("/api/v1/auth/mfa/login", json={"mfa_token": tok, "code": "000000"})
    assert locked.status_code == 429  # per-user lockout kicks in


def test_verify_enable_locks_user_after_max_attempts(client: TestClient, monkeypatch):
    _set_key(monkeypatch)
    monkeypatch.setattr(get_settings(), "mfa_max_attempts", 3)
    u = _register(client)
    h = _headers(u)
    client.post("/api/v1/auth/mfa/enable", headers=h)
    for _ in range(3):
        assert client.post("/api/v1/auth/mfa/verify-enable", headers=h, json={"code": "000000"}).status_code == 401
    assert client.post("/api/v1/auth/mfa/verify-enable", headers=h, json={"code": "000000"}).status_code == 429


# --- audit events --------------------------------------------------------------------------

def test_mfa_security_events_are_emitted(client: TestClient, monkeypatch, caplog):
    _set_key(monkeypatch)
    u = _register(client)
    h = _headers(u)
    with caplog.at_level(logging.INFO, logger="mbs.security"):
        secret, codes = _enroll(client, _headers(u))                       # -> mfa.enabled
        # a failed verify would re-enable-check; instead exercise a failed LOGIN for mfa.login_failed
        tok = client.post("/api/v1/auth/login", json={"email": u["email"], "password": _PW}).json()["mfa_token"]
        client.post("/api/v1/auth/mfa/login", json={"mfa_token": tok, "code": "000000"})  # -> mfa.login_failed
        client.post("/api/v1/auth/mfa/login", json={"mfa_token": tok, "code": pyotp.TOTP(secret).now()})  # -> success
        # recovery-code login
        tok2 = client.post("/api/v1/auth/login", json={"email": u["email"], "password": _PW}).json()["mfa_token"]
        client.post("/api/v1/auth/mfa/login", json={"mfa_token": tok2, "code": codes[0]})  # -> recovery_code_used
        client.post("/api/v1/auth/mfa/disable", headers=h,
                    json={"password": _PW, "code": pyotp.TOTP(secret).now()})              # -> mfa.disabled

    events = {r.getMessage() for r in caplog.records}
    for expected in ("mfa.enabled", "mfa.login_failed", "mfa.login_success", "mfa.recovery_code_used", "mfa.disabled"):
        assert expected in events, f"missing security event {expected} (got {events})"


# --- last_login_at correctness -------------------------------------------------------------

def test_last_login_set_after_second_factor(client: TestClient, monkeypatch):
    _set_key(monkeypatch)

    # (a) no-MFA user: last_login is set by a normal login
    plain = _register(client)
    assert asyncio.run(_read_last_login(plain["email"])) is None      # register does not set it
    client.post("/api/v1/auth/login", json={"email": plain["email"], "password": _PW})
    assert asyncio.run(_read_last_login(plain["email"])) is not None  # set on login

    # (b) MFA user: password step must NOT set last_login; only the second factor does
    u = _register(client)
    secret, _ = _enroll(client, _headers(u))
    assert asyncio.run(_read_last_login(u["email"])) is None          # still unset after enrollment
    tok = client.post("/api/v1/auth/login", json={"email": u["email"], "password": _PW}).json()["mfa_token"]
    assert asyncio.run(_read_last_login(u["email"])) is None          # password step did NOT set it
    client.post("/api/v1/auth/mfa/login", json={"mfa_token": tok, "code": pyotp.TOTP(secret).now()})
    assert asyncio.run(_read_last_login(u["email"])) is not None      # set only after 2FA
