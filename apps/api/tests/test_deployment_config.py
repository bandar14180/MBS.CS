"""The SHIPPED production compose overlay must satisfy the production config guards.

PR #10 made TRUSTED_PROXY_COUNT mandatory in production: `validate_production()` refuses to
start when the value was never declared, because the app cannot observe its own ingress chain
and a rate limiter is only as good as the client identity it buckets on. The guard is correct
-- but `infra/docker-compose.prod.yml` sets `ENVIRONMENT: production` and did not supply the
setting, so the documented production API could not boot at all. Every CI gate stayed green,
because nothing asserted that the shipped deployment artifact satisfies the guards the code
enforces at startup.

That is the gap these tests close, and they close the CLASS rather than the instance: they
build a real `Settings` from the overlay's own environment and run the real
`validate_production()`. Any FUTURE production guard the shipped overlay fails to satisfy
fails here too, rather than at 3am on a deploy.

Two invariants are covered:

  1. CONFIG -- the production merge declares TRUSTED_PROXY_COUNT, and the resulting Settings
     passes `validate_production()` unchanged.
  2. TOPOLOGY -- a non-zero hop count is only meaningful if clients cannot bypass the proxy.
     No file in the production merge may publish the API on a routable interface, or the
     trusted X-Forwarded-For entries become caller-supplied.

Boundary of the fixture (deliberate): the compose file supplies everything compose is
responsible for; `_RUNTIME_SECRETS` stands in for what Docker Secrets and the operator's
`.env` deliver at runtime (JWT/MFA keys, DB DSN, object-storage credentials) and which are
therefore absent from a checked-in file. If a secret were the thing under test the fixture
would be hiding the bug, so it holds nothing the compose file is supposed to declare.
"""
import os
from pathlib import Path
from unittest import mock

import pytest
import yaml

from apps.api.core.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[3]
BASE_COMPOSE = REPO_ROOT / "infra" / "docker-compose.yml"
PROD_COMPOSE = REPO_ROOT / "infra" / "docker-compose.prod.yml"
DEV_OVERRIDE = REPO_ROOT / "infra" / "docker-compose.override.yml"

# What Docker Secrets / the operator's .env provide at runtime -- NOT the compose file's job.
# Values are placeholders that merely have to be non-default, so that the only thing these
# tests can trip is a genuine gap in the shipped compose configuration.
_RUNTIME_SECRETS = {
    "JWT_SECRET_KEY": "z" * 48,
    "MFA_ENCRYPTION_KEY": "a-real-mfa-encryption-key",
    "DATABASE_URL": "postgresql+asyncpg://mbsapp:a-real-strong-password@postgres:5432/mbs",
    "S3_ACCESS_KEY": "a-real-access-key",
    "S3_SECRET_KEY": "a-real-secret-key",
}


def _require_compose(*paths: Path) -> None:
    """Repo-root infra/ isn't bind-mounted in the dev container; skip there, assert on a
    complete checkout (CI/host). Mirrors test_monitoring_config.py."""
    for p in paths:
        if not p.is_file():
            pytest.skip(f"{p} not present in this environment (infra/ not bind-mounted)")


def _svc_env(service: dict) -> dict:
    """Normalize compose's two `environment` forms (mapping or KEY=VALUE list)."""
    env = service.get("environment", {})
    if isinstance(env, list):
        return dict(e.split("=", 1) for e in env if "=" in e)
    return env or {}


def _merged_api_environment() -> dict:
    """The api service environment as compose resolves it for the production invocation:
       docker compose -f docker-compose.yml -f docker-compose.prod.yml
    Later files win on a per-key basis; the dev override is NOT part of an explicit -f list."""
    base = yaml.safe_load(BASE_COMPOSE.read_text(encoding="utf-8"))
    prod = yaml.safe_load(PROD_COMPOSE.read_text(encoding="utf-8"))
    merged = _svc_env(base["services"]["api"])
    merged.update(_svc_env(prod["services"]["api"]))
    return {k: str(v) for k, v in merged.items()}


def _settings_from(env: dict) -> Settings:
    """Build Settings from exactly `env` and nothing else.

    `clear=True` plus `_env_file=None` is what makes this deterministic: without it the
    runner's own environment leaks in (CI exports DATABASE_URL=...mbs:mbs@..., which
    validate_production rightly rejects) and a developer's .env would shadow the file under
    test. Env vars -- rather than kwargs -- because that is how production actually loads,
    including JSON decoding of list fields like TRUSTED_HOSTS, and because pydantic records
    env-sourced values in `model_fields_set`, which is the exact mechanism the guard reads."""
    with mock.patch.dict(os.environ, env, clear=True):
        return Settings(_env_file=None)


def _api_port_publications() -> list:
    """Every host port publication for `api` in the production merge, both compose syntaxes."""
    entries = []
    for path in (BASE_COMPOSE, PROD_COMPOSE):
        cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
        for port in cfg["services"]["api"].get("ports", []) or []:
            entries.append((path.name, port))
    return entries


def _host_ip(port) -> str:
    """Host interface a publication binds to; '' means every interface."""
    if isinstance(port, dict):                    # long syntax
        return str(port.get("host_ip", "") or "")
    parts = str(port).split(":")
    return parts[0] if len(parts) >= 3 else ""    # "ip:host:container" vs "host:container"


# --- 1. Config: the shipped overlay satisfies the production guards --------------------

def test_prod_compose_declares_trusted_proxy_count():
    """THE REGRESSION. The production merge must state the hop count explicitly -- an
    inherited default is precisely what the guard exists to reject."""
    _require_compose(BASE_COMPOSE, PROD_COMPOSE)
    env = _merged_api_environment()
    assert env.get("ENVIRONMENT") == "production", "this overlay is what declares production"
    assert "TRUSTED_PROXY_COUNT" in env, (
        "docker-compose.prod.yml runs the API in production mode, so it must declare "
        "TRUSTED_PROXY_COUNT -- validate_production() refuses to start without it and the "
        "API container would crash-loop on deploy."
    )
    assert int(env["TRUSTED_PROXY_COUNT"]) >= 0


def test_prod_compose_settings_pass_validate_production():
    """The durable guarantee: the real guard, run against the real shipped configuration.
    This fails for ANY production check the overlay stops satisfying, not just this one."""
    _require_compose(BASE_COMPOSE, PROD_COMPOSE)
    settings = _settings_from({**_RUNTIME_SECRETS, **_merged_api_environment()})
    assert settings.is_production
    settings.validate_production()                        # must not raise
    # the declaration must survive as a DECLARATION, not merely as an equal value
    assert "trusted_proxy_count" in settings.model_fields_set


def test_removing_the_declaration_reproduces_the_p0():
    """NEGATIVE CASE -- proves the test above is not vacuous. Drop only TRUSTED_PROXY_COUNT
    from the shipped environment and the exact production startup failure must return; if this
    stops raising, the guard has been weakened and the assertion above proves nothing."""
    _require_compose(BASE_COMPOSE, PROD_COMPOSE)
    env = {**_RUNTIME_SECRETS, **_merged_api_environment()}
    env.pop("TRUSTED_PROXY_COUNT")
    with pytest.raises(RuntimeError) as exc:
        _settings_from(env).validate_production()
    assert "TRUSTED_PROXY_COUNT" in str(exc.value)
    assert "Refusing to start in production" in str(exc.value)


# --- 2. Topology: a trusted hop count is only as good as the bypass it forbids ----------

def test_non_zero_hop_count_forbids_a_routable_api_port():
    """The other half of the control. Trusting N appended X-Forwarded-For entries assumes
    callers must traverse those proxies; a directly reachable :8000 breaks the assumption,
    because the client then supplies the whole header and can mint a fresh rate-limit bucket
    per request -- strictly worse than having no limiter."""
    _require_compose(BASE_COMPOSE, PROD_COMPOSE)
    if int(_merged_api_environment()["TRUSTED_PROXY_COUNT"]) == 0:
        pytest.skip("hop count is 0: X-Forwarded-For is ignored, so direct access is not a forgery risk")
    for filename, port in _api_port_publications():
        assert _host_ip(port).startswith("127."), (
            f"{filename} publishes api port {port!r} on a routable interface while "
            "TRUSTED_PROXY_COUNT > 0; bind it to loopback or drop the publication so that "
            "external traffic can only arrive through the proxy chain."
        )


def test_base_compose_publishes_no_api_port():
    """Compose APPENDS `ports` across -f files rather than replacing them, so a publication in
    the base file cannot be withdrawn by the production overlay -- it would survive the merge
    on every interface. Keeping the base free of one is what makes the loopback binding above
    the ONLY api publication in production."""
    _require_compose(BASE_COMPOSE)
    base = yaml.safe_load(BASE_COMPOSE.read_text(encoding="utf-8"))
    assert not base["services"]["api"].get("ports"), (
        "the base compose must not publish the API host port; put it in "
        "docker-compose.override.yml (dev) or docker-compose.prod.yml (loopback)."
    )


def test_dev_override_keeps_the_api_reachable_locally():
    """The port moved rather than vanished. A bare `docker compose up` auto-merges the dev
    override, so local DX (http://localhost:8000, /docs) is unchanged -- while an explicit
    `-f docker-compose.yml -f docker-compose.prod.yml` excludes this file entirely."""
    _require_compose(DEV_OVERRIDE)
    dev = yaml.safe_load(DEV_OVERRIDE.read_text(encoding="utf-8"))
    assert any("8000:8000" in str(p) for p in dev["services"]["api"].get("ports", []) or []), \
        "dev override must publish 8000 so local development keeps direct API access"
