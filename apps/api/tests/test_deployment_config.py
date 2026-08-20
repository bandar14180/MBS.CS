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

The invariants covered here grew with the deployment findings that followed:

  1. CONFIG -- the production merge declares TRUSTED_PROXY_COUNT, and the resulting Settings
     passes `validate_production()` unchanged.
  2. TOPOLOGY -- a non-zero hop count is only meaningful if clients cannot bypass the proxy.
     No file in the production merge may publish the API on a routable interface, or the
     trusted X-Forwarded-For entries become caller-supplied.
  3. SECURITY BOUNDARY (B1) -- nginx:80 is the ONLY routable publication; postgres, redis,
     minio and web must not be on the host at all, and dev keeps its access via the override.
  4. REDIS AUTH (B3) -- production Redis requires a password from a Docker Secret, its
     healthcheck authenticates, and every consumer reads the same authenticated URL.
  5. CREDENTIALS (B2) -- no `mbs:mbs` / `minioadmin` default survives into production.
  6. SECRET PRECEDENCE (B4) -- a mounted `<NAME>_FILE` beats an inherited `<NAME>`, and a
     declared-but-unreadable secret file fails startup instead of falling back.
  7. NGINX ROUTING (A) -- `/api/v1/*` reaches the app with its prefix intact while
     `/api/health`, `/api/openapi.json` and `/api/docs` keep resolving to their root routes.

Tests are deterministic: they parse the shipped configuration and exercise real code. Nothing
here needs Docker, a network, or Internet access, and no secret value is ever printed.

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


def _compose(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _svc_env(service: dict) -> dict:
    """Normalize compose's two `environment` forms (mapping or KEY=VALUE list).

    A `None` value is preserved rather than coerced: in compose a key with no value means
    "inherit from the host shell", so when the host does not define it the variable ends up
    UNSET in the container. That is how the production overlay removes a base-file literal
    such as `POSTGRES_PASSWORD: mbs`, and `_prod_env()` relies on seeing the None."""
    env = service.get("environment", {})
    if isinstance(env, list):
        return dict(e.split("=", 1) for e in env if "=" in e)
    return env or {}


def _prod_env(service: str) -> dict:
    """A service's environment as the production invocation resolves it:
       docker compose -f docker-compose.yml -f docker-compose.prod.yml

    Later files win per key, and a null value in the overlay REMOVES the base literal --
    behaviour verified against the real `docker compose config` before this was relied upon.
    Values are stringified; removed keys are absent.

    Scope note: this sees only what the compose FILES declare. Variables the base file pulls
    in via `env_file: ../.env` are invisible here by design -- `.env` is operator-supplied and
    absent from CI, so asserting on it would make these tests environment-dependent. The
    guarantee that a mounted secret beats such an inherited value is covered separately by the
    `_resolve_file_secrets` precedence tests below."""
    base_env = _svc_env(_compose(BASE_COMPOSE)["services"].get(service, {}))
    prod_env = _svc_env(_compose(PROD_COMPOSE)["services"].get(service, {}))
    merged = dict(base_env)
    for key, value in prod_env.items():
        if value is None:
            merged.pop(key, None)          # null in the overlay unsets the base literal
        else:
            merged[key] = value
    return {k: str(v) for k, v in merged.items()}


def _merged_api_environment() -> dict:
    """Backwards-compatible alias for the api service (the original P0 subject)."""
    return _prod_env("api")


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


def _port_publications(service: str) -> list:
    """Every host port publication for `service` in the production merge, both compose syntaxes.

    Both files are read and their entries CONCATENATED because compose appends `ports` across
    `-f` files rather than replacing them -- which is precisely why nothing may be published
    from the base file that production would need to withdraw."""
    entries = []
    for path in (BASE_COMPOSE, PROD_COMPOSE):
        cfg = _compose(path)
        for port in (cfg["services"].get(service) or {}).get("ports", []) or []:
            entries.append((path.name, port))
    return entries


def _api_port_publications() -> list:
    return _port_publications("api")


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


# --- 3. The production security boundary (B1) -------------------------------------------

# The ONLY service allowed to publish on a routable interface in production. Everything else
# is reachable in-network by service name, so a host publication adds attack surface and buys
# nothing. Loopback bindings are permitted for host-local operations.
_PUBLIC_SERVICES = {"nginx"}
_BOUNDARY_SERVICES = (
    "nginx", "api", "postgres", "redis", "minio", "web", "prometheus", "alertmanager",
)


def _is_loopback(port) -> bool:
    ip = _host_ip(port)
    return ip.startswith("127.") or ip == "::1"


def test_production_publishes_only_nginx_on_a_routable_interface():
    """THE SECURITY BOUNDARY. Everything behind nginx must be unreachable from off-host.

    Before this was enforced the production merge published postgres 5432, redis 6379, minio
    9000/9001 and web 3000 on 0.0.0.0 -- a superuser database, an unauthenticated broker, an
    object store holding scan evidence and reports, and a Next.js dev server, all directly
    addressable. None of them needs a host port: the API and workers reach them over the
    compose network, and nginx proxies the browser."""
    _require_compose(BASE_COMPOSE, PROD_COMPOSE)
    offenders = []
    for service in _BOUNDARY_SERVICES:
        for filename, port in _port_publications(service):
            if service in _PUBLIC_SERVICES or _is_loopback(port):
                continue
            offenders.append(f"{service} publishes {port!r} in {filename}")
    assert not offenders, (
        "these services are reachable from off-host in production; bind them to loopback or "
        "drop the publication (dev access belongs in docker-compose.override.yml): "
        + "; ".join(offenders)
    )


def test_datastores_publish_no_host_port_at_all_in_production():
    """Stronger than the boundary above for the four that have no operational reason to be on
    the host: they must be absent entirely, not merely loopback-bound."""
    _require_compose(BASE_COMPOSE, PROD_COMPOSE)
    for service in ("postgres", "redis", "minio", "web"):
        assert not _port_publications(service), \
            f"{service} must publish no host port in the production merge"


def test_nginx_remains_the_public_entrypoint():
    """The boundary must not be achieved by making the stack unreachable."""
    _require_compose(BASE_COMPOSE, PROD_COMPOSE)
    published = [p for _, p in _port_publications("nginx")]
    assert any("80" in str(p) for p in published), "nginx must still serve :80 publicly"


def test_dev_override_restores_local_access_to_every_service():
    """The publications moved rather than vanished: a bare `docker compose up` auto-merges the
    dev override, so psql/redis-cli/the MinIO console and http://localhost:3000 keep working."""
    _require_compose(DEV_OVERRIDE)
    services = _compose(DEV_OVERRIDE)["services"]
    for service, expected in (
        ("postgres", "5432"), ("redis", "6379"), ("minio", "9000"), ("web", "3000"),
    ):
        ports = [str(p) for p in (services.get(service) or {}).get("ports", []) or []]
        assert any(expected in p for p in ports), \
            f"dev override must publish {expected} for {service} so local development is unchanged"


# --- 4. Redis authentication (B3) -------------------------------------------------------

_APP_SERVICES = ("api", "worker", "worker-default", "beat")


def _prod_service(name: str) -> dict:
    return _compose(PROD_COMPOSE)["services"][name]


def _redis_invocation() -> str:
    """The EFFECTIVE Redis invocation: entrypoint plus command, joined.

    Reading `command` alone would be wrong -- and silently vacuous. The startup logic lives in
    `entrypoint` precisely so the image's own docker-entrypoint.sh still performs its privilege
    drop, which leaves `command` empty; assertions scoped to `command` would then pass against
    an empty string no matter what the service actually runs."""
    svc = _prod_service("redis")
    parts = list(svc.get("entrypoint") or []) + list(svc.get("command") or [])
    return " ".join(map(str, parts))


def test_production_redis_requires_a_password():
    """Redis backs the Celery broker, the DLQ and the rate-limit / AI-budget / MFA-lockout
    counters. Unauthenticated it allows task injection and tampering with those controls, so
    production must set a password -- sourced from a Docker Secret, never a literal."""
    _require_compose(PROD_COMPOSE)
    invocation = _redis_invocation()
    assert "requirepass" in invocation, "production Redis must require authentication"
    assert "/run/secrets/redis_password" in invocation, \
        "the Redis password must come from a Docker Secret, not an inline value"
    assert "redis_password" in _prod_service("redis")["secrets"]
    # durability (R1a) must survive the entrypoint override
    assert "--appendonly yes" in invocation


def test_production_redis_healthcheck_authenticates():
    """A password without a matching healthcheck is worse than none: `redis-cli ping` returns
    NOAUTH, the service never becomes healthy, and every `depends_on: service_healthy` blocks
    the whole stack from starting."""
    _require_compose(PROD_COMPOSE)
    test = " ".join(map(str, _prod_service("redis")["healthcheck"]["test"]))
    assert "REDISCLI_AUTH" in test and "/run/secrets/redis_password" in test


def test_every_redis_consumer_uses_the_authenticated_url():
    """Consistency: each service that talks to Redis must take REDIS_URL from the same secret.
    Missing it on even one (beat, say) silently stops all periodic work once auth is on."""
    _require_compose(PROD_COMPOSE)
    for service in _APP_SERVICES:
        env = _svc_env(_prod_service(service))
        assert env.get("REDIS_URL_FILE") == "/run/secrets/redis_url", \
            f"{service} must read REDIS_URL from the redis_url secret"
        assert "redis_url" in _prod_service(service)["secrets"]


def test_redis_password_is_not_in_the_process_arguments():
    """Defence in depth: the value is written to a config file, so it never appears in the
    container's argv (visible to anything that can read /proc)."""
    _require_compose(PROD_COMPOSE)
    invocation = _redis_invocation()
    assert invocation, "the Redis invocation must not be empty (guards against a vacuous check)"
    assert "--requirepass" not in invocation, \
        "pass the password via a generated config file, not as a command-line argument"


def test_production_redis_preserves_the_image_privilege_drop():
    """THE REGRESSION. redis:7-alpine drops to the unprivileged `redis` user only when its
    entrypoint receives `redis-server` as $1 -- that single condition guards BOTH the drop
    (`setpriv --reuid redis`) and the `chown` that normalises /data ownership.

    Overriding `command:` with a bare `sh -c` made $1 = "sh", so both were skipped: the server
    ran as root and wrote root-owned 0600 AOF files into the data volume. That is not merely a
    privilege issue -- it poisons /data, because a later non-root start then fails with
    "Error moving temp append only file on the final destination: Permission denied".

    So production must hand off to the image entrypoint rather than exec redis-server itself.
    `user: redis` was rejected as the fix: it skips the chown entirely and runs the command and
    healthcheck as uid 999, which cannot read a 0600 secret file mounted from the host."""
    _require_compose(PROD_COMPOSE)
    svc = _prod_service("redis")
    entrypoint = " ".join(map(str, svc.get("entrypoint") or []))
    assert "docker-entrypoint.sh redis-server" in entrypoint, (
        "the image entrypoint must receive 'redis-server' as $1, or it silently skips the "
        "privilege drop and the /data chown"
    )
    # the dropped process must still be able to read the generated config (umask 077 as root
    # would otherwise leave it root-only and Redis would fail to start)
    assert "chown redis:redis /tmp/redis.conf" in entrypoint
    # no `user:` override -- it would defeat the entrypoint's chown and the 0600 secret read
    assert "user" not in svc, "do not set `user:`; the image entrypoint performs the drop"
    # nothing may be appended as stray positional arguments to the inline script
    assert not svc.get("command")
    # the rest of the B3 guarantees survive the restructure
    assert "--appendonly yes" in entrypoint
    assert "--requirepass" not in entrypoint


# --- 5. Datastore credentials (B2) ------------------------------------------------------

# Values shipped for local development that must never reach a production container.
_DEFAULT_CREDENTIALS = ("minioadmin", "mbs:mbs@")


def test_production_postgres_uses_a_secret_not_the_default_password():
    """The base file hardcodes POSTGRES_PASSWORD: mbs as a literal, so it cannot be overridden
    from .env. Production must unset it and read the password from a Docker Secret."""
    _require_compose(BASE_COMPOSE, PROD_COMPOSE)
    env = _prod_env("postgres")
    assert "POSTGRES_PASSWORD" not in env, \
        "the default POSTGRES_PASSWORD literal must be unset in production"
    assert env.get("POSTGRES_PASSWORD_FILE") == "/run/secrets/postgres_password"
    assert "postgres_password" in _prod_service("postgres")["secrets"]


def test_production_minio_uses_secrets_not_minioadmin():
    """MinIO holds scan evidence and generated reports; minioadmin/minioadmin is a published
    default and must not survive into production."""
    _require_compose(BASE_COMPOSE, PROD_COMPOSE)
    env = _prod_env("minio")
    for key in ("MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD"):
        assert key not in env, f"the default {key} literal must be unset in production"
        assert env.get(f"{key}_FILE", "").startswith("/run/secrets/")
    for secret in ("minio_root_user", "minio_root_password"):
        assert secret in _prod_service("minio")["secrets"]


def test_no_default_credentials_survive_into_the_production_render():
    """Whole-file sweep over what the production merge actually declares."""
    _require_compose(BASE_COMPOSE, PROD_COMPOSE)
    for service in _BOUNDARY_SERVICES + _APP_SERVICES:
        for key, value in _prod_env(service).items():
            for bad in _DEFAULT_CREDENTIALS:
                assert bad not in value, f"{service}.{key} still carries the default {bad!r}"


def test_application_services_take_db_and_storage_credentials_from_secrets():
    """The base file loads `env_file: ../.env` into every application service and a compose
    overlay cannot unset an env_file value, so the *_FILE declarations are what guarantee the
    real credentials win (see the precedence tests below). Every service that touches the
    database or object storage must declare them."""
    _require_compose(PROD_COMPOSE)
    for service in ("api", "worker", "worker-default"):
        env = _svc_env(_prod_service(service))
        assert env.get("DATABASE_URL_FILE") == "/run/secrets/database_url", \
            f"{service} must read DATABASE_URL from a secret"
        for key in ("S3_ACCESS_KEY_FILE", "S3_SECRET_KEY_FILE"):
            assert env.get(key, "").startswith("/run/secrets/"), f"{service} must set {key}"


# --- 6. Secret-file precedence (B4) -----------------------------------------------------

def test_secret_file_beats_an_inherited_value(tmp_path):
    """THE SHADOWING BUG. `<NAME>_FILE` used to be read only when `<NAME>` was absent, so a
    stale .env entry -- which a compose overlay cannot unset -- silently defeated the mounted
    Docker Secret and production ran on a development credential with no signal. The file is
    the operator's explicit delivery mechanism and must win.

    No secret value is printed: assertions compare against locally generated strings."""
    from apps.api.core import config as cfg

    secret_file = tmp_path / "database_url"
    secret_file.write_text("postgresql+asyncpg://app:from-the-secret@postgres:5432/mbs\n")
    env = {
        "DATABASE_URL": "postgresql+asyncpg://mbs:mbs@postgres:5432/mbs",   # inherited default
        "DATABASE_URL_FILE": str(secret_file),
    }
    with mock.patch.dict(os.environ, env, clear=True):
        cfg._resolve_file_secrets()
        resolved = os.environ["DATABASE_URL"]
    assert resolved.endswith("@postgres:5432/mbs")
    assert "from-the-secret" in resolved      # the file won
    assert "mbs:mbs@" not in resolved         # the inherited default did not


def test_secret_file_trailing_whitespace_is_stripped(tmp_path):
    """Secret files routinely end with a newline; it must not become part of the credential."""
    from apps.api.core import config as cfg

    secret_file = tmp_path / "token"
    secret_file.write_text("  padded-value \n")
    with mock.patch.dict(os.environ, {"METRICS_TOKEN_FILE": str(secret_file)}, clear=True):
        cfg._resolve_file_secrets()
        assert os.environ["METRICS_TOKEN"] == "padded-value"


def test_unreadable_secret_file_fails_production_instead_of_falling_back():
    """The other half of the precedence rule. If a declared secret file cannot be read, the
    inherited value must NOT quietly stand in for it -- that is the same silent substitution
    in a different disguise -- so production refuses to start."""
    from apps.api.core import config as cfg

    env = {"JWT_SECRET_KEY": "y" * 48, "JWT_SECRET_KEY_FILE": "/nonexistent/path/to/secret"}
    with mock.patch.dict(os.environ, env, clear=True):
        cfg._resolve_file_secrets()
        assert "JWT_SECRET_KEY_FILE" in cfg._UNREADABLE_FILE_SECRETS
        settings = _settings_from({**_RUNTIME_SECRETS, **_merged_api_environment()})
        with pytest.raises(RuntimeError) as exc:
            settings.validate_production()
    assert "JWT_SECRET_KEY_FILE" in str(exc.value)


def test_non_secret_configuration_is_untouched():
    """Only the declared secret names participate; ordinary configuration is never rewritten."""
    from apps.api.core import config as cfg

    env = {"TRUSTED_PROXY_COUNT": "2", "LOG_LEVEL": "DEBUG"}
    with mock.patch.dict(os.environ, env, clear=True):
        cfg._resolve_file_secrets()
        assert os.environ["TRUSTED_PROXY_COUNT"] == "2"
        assert os.environ["LOG_LEVEL"] == "DEBUG"


# --- 7. nginx routing (Finding A) -------------------------------------------------------

NGINX_CONF = REPO_ROOT / "infra" / "nginx" / "nginx.conf"


def _nginx_api_locations() -> list:
    """[(prefix, proxy_pass)] for every `location` that proxies to the API upstream."""
    text = NGINX_CONF.read_text(encoding="utf-8")
    locations, current = [], None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("location ") and line.endswith("{"):
            current = line[len("location "):-1].strip()
        elif line.startswith("proxy_pass ") and current is not None:
            target = line[len("proxy_pass "):].rstrip(";").strip()
            if "api_upstream" in target:
                locations.append((current, target))
            current = None
    return locations


def _upstream_path(request_path: str) -> str:
    """The path the API container receives for `request_path`, per nginx's rules: the LONGEST
    matching prefix wins, and a `proxy_pass` ending in `/` replaces the matched prefix with
    `/` while one without a trailing slash forwards the URI unchanged."""
    matches = [(p, t) for p, t in _nginx_api_locations() if request_path.startswith(p)]
    if not matches:
        raise AssertionError(f"no API location matches {request_path}")
    prefix, target = max(matches, key=lambda pair: len(pair[0]))
    if target.endswith("/"):
        return "/" + request_path[len(prefix):]
    return request_path


def _app_route_paths() -> set:
    """Every path the real application serves.

    Two sources, because neither alone is complete on this FastAPI version: `app.routes`
    carries the root-level Starlette routes (/docs, /openapi.json) but represents included
    routers as opaque wrappers whose `.path` is None, while the OpenAPI schema has the fully
    prefixed router paths (/api/v1/...) but omits the docs endpoints. Taking both means these
    assertions are checked against the routes the app ACTUALLY mounts rather than a
    hand-maintained list that could drift away from the nginx config."""
    from apps.api.main import app

    paths = {getattr(route, "path", None) for route in app.routes}
    paths.discard(None)
    return paths | set(app.openapi().get("paths", {}))


def test_nginx_preserves_the_api_v1_prefix():
    """FINDING A. `location /api/ { proxy_pass .../; }` stripped the prefix, so /api/v1/plans
    reached the app as /v1/plans and every browser API call 404'd. The v1 family must arrive
    unchanged, matching where the routers are actually mounted."""
    _require_compose(NGINX_CONF)
    assert _upstream_path("/api/v1/plans") == "/api/v1/plans"
    assert _upstream_path("/api/v1/auth/login") == "/api/v1/auth/login"
    prefix = Settings().api_v1_prefix
    assert any(p.startswith(prefix) for p in _app_route_paths()), \
        f"the app must actually mount routes under {prefix}"


@pytest.mark.parametrize("request_path, upstream", [
    ("/api/health", "/health"),
    ("/api/openapi.json", "/openapi.json"),
    ("/api/docs", "/docs"),
])
def test_nginx_root_level_endpoints_keep_working(request_path, upstream):
    """These three work ONLY because of the prefix strip -- they are served at the root of the
    same app. Removing the trailing slash outright would have broken all of them, so the fix
    had to add a longer-prefix location rather than change the existing one."""
    _require_compose(NGINX_CONF)
    assert _upstream_path(request_path) == upstream
    assert upstream in _app_route_paths(), f"{upstream} must be a real route on the API"


def test_nginx_api_locations_preserve_forwarding_headers():
    """TRUSTED_PROXY_COUNT=1 depends on nginx appending exactly one X-Forwarded-For entry; a
    location that forgets the headers would break the rate-limit identity for its routes."""
    _require_compose(NGINX_CONF)
    text = NGINX_CONF.read_text(encoding="utf-8")
    blocks = [b for b in text.split("location ") if b.startswith("/api")]
    assert len(blocks) >= 2, "expected both /api/v1/ and /api/ locations"
    for block in blocks:
        body = block.split("}")[0]
        for header in ("Host $host", "X-Real-IP", "X-Forwarded-For $proxy_add_x_forwarded_for",
                       "X-Forwarded-Proto"):
            assert header in body, f"an /api location is missing proxy_set_header {header}"
