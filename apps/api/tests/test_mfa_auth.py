"""MFA Sprint 1, Step 2 -- MFA wired into authentication (integration, via the app TestClient).

Verifies backward compatibility (no-MFA users unchanged) AND the MFA two-step login, enrollment,
recovery codes, and disable. The MFA encryption key is set per-test (mfa.py reads it at call time,
so monkeypatching the cached settings is enough; the app is not rebuilt).
"""
import uuid

import pyotp
from fastapi.testclient import TestClient

from apps.api.core.config import get_settings

_PW = "correct horse battery staple"
_MFA_KEY = "integration-test-mfa-master-key"


def _register(client: TestClient) -> dict:
    email = f"{uuid.uuid4()}@example.com"
    r = client.post("/api/v1/auth/register", json={"email": email, "password": _PW, "full_name": "MFA User"})
    assert r.status_code == 201, r.text
    return {"email": email, **r.json()}


def _headers(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _set_key(monkeypatch):
    monkeypatch.setattr(get_settings(), "mfa_encryption_key", _MFA_KEY)


def _enroll(client, headers):
    r = client.post("/api/v1/auth/mfa/enable", headers=headers)
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    code = pyotp.TOTP(secret).now()
    r2 = client.post("/api/v1/auth/mfa/verify-enable", headers=headers, json={"code": code})
    assert r2.status_code == 200, r2.text
    return secret, r2.json()["recovery_codes"]


# --- backward compatibility ----------------------------------------------------------------

def test_login_without_mfa_issues_tokens_unchanged(client: TestClient):
    u = _register(client)
    r = client.post("/api/v1/auth/login", json={"email": u["email"], "password": _PW})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["mfa_required"] is False
    assert body["access_token"] and body["refresh_token"]  # tokens issued exactly as before


# --- enrollment ----------------------------------------------------------------------------

def test_enable_mfa_flow_returns_recovery_codes(client: TestClient, monkeypatch):
    _set_key(monkeypatch)
    u = _register(client)
    h = _headers(u)
    r = client.post("/api/v1/auth/mfa/enable", headers=h)
    assert r.status_code == 200
    assert r.json()["provisioning_uri"].startswith("otpauth://totp/")
    secret = r.json()["secret"]
    r2 = client.post("/api/v1/auth/mfa/verify-enable", headers=h, json={"code": pyotp.TOTP(secret).now()})
    assert r2.status_code == 200
    assert len(r2.json()["recovery_codes"]) == 10
    # /users/me now reflects mfa_enabled
    me = client.get("/api/v1/users/me", headers=h)
    assert me.json()["mfa_enabled"] is True


def test_verify_enable_rejects_invalid_code(client: TestClient, monkeypatch):
    _set_key(monkeypatch)
    u = _register(client)
    h = _headers(u)
    client.post("/api/v1/auth/mfa/enable", headers=h)
    r = client.post("/api/v1/auth/mfa/verify-enable", headers=h, json={"code": "000000"})
    assert r.status_code == 401
    assert client.get("/api/v1/users/me", headers=h).json()["mfa_enabled"] is False  # not enabled


# --- MFA login (two-step) ------------------------------------------------------------------

def test_login_requires_mfa_then_completes(client: TestClient, monkeypatch):
    _set_key(monkeypatch)
    u = _register(client)
    secret, _ = _enroll(client, _headers(u))

    r = client.post("/api/v1/auth/login", json={"email": u["email"], "password": _PW})
    assert r.status_code == 200
    body = r.json()
    assert body["mfa_required"] is True
    assert body["mfa_token"] and body["access_token"] is None  # NO session token yet

    r2 = client.post("/api/v1/auth/mfa/login", json={"mfa_token": body["mfa_token"], "code": pyotp.TOTP(secret).now()})
    assert r2.status_code == 200, r2.text
    assert r2.json()["access_token"] and r2.json()["refresh_token"]


def test_mfa_login_rejects_invalid_code(client: TestClient, monkeypatch):
    _set_key(monkeypatch)
    u = _register(client)
    _enroll(client, _headers(u))
    body = client.post("/api/v1/auth/login", json={"email": u["email"], "password": _PW}).json()
    r = client.post("/api/v1/auth/mfa/login", json={"mfa_token": body["mfa_token"], "code": "000000"})
    assert r.status_code == 401


def test_mfa_challenge_token_cannot_access_protected_route(client: TestClient, monkeypatch):
    _set_key(monkeypatch)
    u = _register(client)
    _enroll(client, _headers(u))
    body = client.post("/api/v1/auth/login", json={"email": u["email"], "password": _PW}).json()
    # the mfa challenge token is type='mfa' -> rejected by the access-token decoder
    r = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {body['mfa_token']}"})
    assert r.status_code == 401


def test_recovery_code_login_is_one_time(client: TestClient, monkeypatch):
    _set_key(monkeypatch)
    u = _register(client)
    _, codes = _enroll(client, _headers(u))
    rc = codes[0]

    body = client.post("/api/v1/auth/login", json={"email": u["email"], "password": _PW}).json()
    ok = client.post("/api/v1/auth/mfa/login", json={"mfa_token": body["mfa_token"], "code": rc})
    assert ok.status_code == 200, ok.text  # recovery code works

    body2 = client.post("/api/v1/auth/login", json={"email": u["email"], "password": _PW}).json()
    reuse = client.post("/api/v1/auth/mfa/login", json={"mfa_token": body2["mfa_token"], "code": rc})
    assert reuse.status_code == 401  # already consumed


# --- disable -------------------------------------------------------------------------------

def test_disable_mfa_restores_single_factor_login(client: TestClient, monkeypatch):
    _set_key(monkeypatch)
    u = _register(client)
    secret, _ = _enroll(client, _headers(u))
    h = _headers(u)

    bad = client.post("/api/v1/auth/mfa/disable", headers=h, json={"password": "wrong", "code": pyotp.TOTP(secret).now()})
    assert bad.status_code == 401  # wrong password rejected

    ok = client.post("/api/v1/auth/mfa/disable", headers=h, json={"password": _PW, "code": pyotp.TOTP(secret).now()})
    assert ok.status_code == 204

    # login is single-factor again
    r = client.post("/api/v1/auth/login", json={"email": u["email"], "password": _PW})
    assert r.json()["mfa_required"] is False
    assert r.json()["access_token"]
