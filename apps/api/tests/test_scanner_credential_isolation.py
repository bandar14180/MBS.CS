"""MBS.SC -- credential minimization for the scanner execution plane (Property B).

Two layers are asserted here:

  1. COMPOSE (the primary control): the scanner worker does not LOAD the control-plane env
     file at all, and the production overlay grants it no database/broker/object-store/AI
     secret. This is the layer that actually withholds the credentials, and it works
     because a compose overlay cannot unset an `env_file`-sourced variable -- so the only
     way to withhold one is never to load the file.

  2. RUNTIME (defence in depth): a worker started with SCANNER_EXECUTION_PLANE=true
     refuses to boot if a control-plane credential is present anyway -- catching a
     hand-edited environment or a wrong env file mount.
"""
import uuid
from pathlib import Path

import pytest
import yaml

from apps.api.celery_app.startup_security import (
    ExecutionPlaneCredentialError,
    enforce_execution_plane_credentials,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
BASE_COMPOSE = REPO_ROOT / "infra" / "docker-compose.yml"
PROD_COMPOSE = REPO_ROOT / "infra" / "docker-compose.prod.yml"

# Every credential that would make a scanner compromise a control-plane compromise.
FORBIDDEN_ON_SCANNER = {
    "DATABASE_URL", "DATABASE_URL_FILE", "DB_PASSWORD",
    "REDIS_URL", "REDIS_URL_FILE", "REDIS_PASSWORD",
    "S3_ACCESS_KEY", "S3_SECRET_KEY", "S3_ACCESS_KEY_FILE", "S3_SECRET_KEY_FILE",
    "MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD",
    "JWT_SECRET_KEY", "JWT_SECRET_KEY_FILE",
    "OPENROUTER_API_KEY", "OPENROUTER_API_KEY_FILE", "ANTHROPIC_API_KEY",
}

FORBIDDEN_SECRET_NAMES = {
    "database_url", "redis_url", "s3_access_key", "s3_secret_key",
    "jwt_secret_key", "openrouter_api_key", "minio_root_user", "minio_root_password",
    "mysql_password", "mysql_root_password", "redis_password", "metrics_token",
}


def _compose(path: Path) -> dict:
    if not path.exists():
        pytest.skip(f"{path} not present")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _env_map(service: dict) -> dict:
    env = service.get("environment") or {}
    if isinstance(env, list):  # KEY=VALUE list form
        out = {}
        for item in env:
            k, _, v = str(item).partition("=")
            out[k] = v
        return out
    return dict(env)


# ---------------------------------------------------------------------------------------
# LAYER 1 -- compose
# ---------------------------------------------------------------------------------------

def test_scanner_worker_does_not_load_the_control_plane_env_file():
    """THE load-bearing assertion. `env_file: ../.env` is how the worker previously got
    the DB DSN, the JWT secret and the MinIO credentials -- and an overlay CANNOT take an
    env_file variable away, so this must be prevented in the BASE file."""
    worker = _compose(BASE_COMPOSE)["services"]["worker"]
    env_files = worker.get("env_file") or []
    if isinstance(env_files, str):
        env_files = [env_files]
    normalized = {str(f).replace("\\", "/").split("/")[-1] for f in env_files}
    assert ".env" not in normalized, (
        "the scanner worker loads the control-plane .env; a compose overlay cannot unset "
        "those variables, so every control-plane secret is present in the scanner container"
    )
    assert ".env.scanner" in normalized


def test_production_scanner_worker_holds_no_control_plane_env_var():
    worker = _compose(PROD_COMPOSE)["services"]["worker"]
    present = FORBIDDEN_ON_SCANNER & set(_env_map(worker))
    assert not present, f"scanner worker holds control-plane credential env var(s): {sorted(present)}"


def test_production_scanner_worker_is_granted_no_control_plane_secret():
    worker = _compose(PROD_COMPOSE)["services"]["worker"]
    granted = {str(s) for s in (worker.get("secrets") or [])}
    leaked = granted & FORBIDDEN_SECRET_NAMES
    assert not leaked, f"scanner worker is granted control-plane secret(s): {sorted(leaked)}"
    # It should hold exactly its own worker credential.
    assert granted == {"scanner_worker_token"}, granted


def test_the_manager_does_hold_what_the_worker_gave_up():
    """The credentials did not vanish -- they moved to the component that legitimately
    performs persistence. Asserting this stops a future 'cleanup' from breaking the
    manager while thinking it is tightening the worker."""
    mgr = _compose(PROD_COMPOSE)["services"]["scanner-manager"]
    granted = {str(s) for s in (mgr.get("secrets") or [])}
    assert {"database_url", "redis_url", "s3_access_key", "s3_secret_key"} <= granted
    # ...but the manager does NOT get AI credentials or the JWT signing key: it authorizes
    # workers and persists results; it never mints user tokens or calls a model.
    assert "jwt_secret_key" not in granted
    assert "openrouter_api_key" not in granted


def test_worker_is_not_on_any_control_plane_network():
    """Property A, at the file level: the worker must share NO network with a datastore
    or the API, so there is no IP-layer route to them at all."""
    services = _compose(BASE_COMPOSE)["services"]
    worker_nets = set(services["worker"].get("networks") or [])
    assert worker_nets, "worker has no explicit networks (implicit default bridge = shared)"
    for name in ("mysql", "redis", "minio", "api", "ollama", "worker-default", "beat"):
        other = set(services[name].get("networks") or [])
        shared = worker_nets & other
        assert not shared, f"scanner worker shares network(s) {sorted(shared)} with {name}"


def test_worker_reaches_the_manager_and_only_the_manager():
    services = _compose(BASE_COMPOSE)["services"]
    worker_nets = set(services["worker"].get("networks") or [])
    mgr_nets = set(services["scanner-manager"].get("networks") or [])
    assert worker_nets & mgr_nets, "worker cannot reach the scanner-manager"
    # The manager is the ONLY service the worker shares a network with, apart from other
    # scanner-plane services.
    for name, svc in services.items():
        if name in {"worker", "scanner-manager"}:
            continue
        assert not (worker_nets & set(svc.get("networks") or [])), \
            f"worker unexpectedly shares a network with {name}"


def test_core_and_dispatch_networks_are_internal():
    """`internal: true` means no NAT to the outside world for the control-plane planes."""
    nets = _compose(BASE_COMPOSE)["networks"]
    assert nets["mbs-core"].get("internal") is True
    assert nets["mbs-dispatch"].get("internal") is True


def test_production_scanner_is_hardened_and_unprivileged():
    """Phase 14: no privileged container, no docker socket, caps dropped, non-root."""
    worker = _compose(PROD_COMPOSE)["services"]["worker"]
    assert worker.get("privileged") is not True
    assert "ALL" in (worker.get("cap_drop") or [])
    assert any("no-new-privileges" in str(o) for o in (worker.get("security_opt") or []))
    assert worker.get("read_only") is True
    assert str(worker.get("user", "")).startswith("10001")
    for vol in (worker.get("volumes") or []):
        assert "docker.sock" not in str(vol), "docker socket mounted into the scanner"


def test_private_site_template_grants_only_net_admin():
    """Phase 11/14: the private worker gets only the capabilities it genuinely needs.

    P7-1 UPDATE. This asserted `cap_add == ["NET_ADMIN"]` exactly. That combination could not
    actually work: alongside `user: "10001:10001"` a non-root process receives an EMPTY
    effective set (Docker leaves CapInh/CapAmb at 0, so cap_add reaches only the BOUNDING
    set), and `ip link add ... type wireguard` failed with EPERM -- the template could never
    start a private site. The fix drops from root to uid 10001 via `setpriv`, which needs
    SETUID/SETGID to perform the drop itself.

    The SECURITY CLAIM is unchanged and is still asserted below: NET_ADMIN is the only
    capability that survives into the running worker (it is the sole `--ambient-caps` entry),
    SETUID/SETGID are consumed by the drop and are not ambient, and nothing broader -- no
    SYS_ADMIN, no NET_RAW, no ALL -- is granted. The ambient-set assertions live in
    test_phase7_private_connectivity.py, which owns the P7-1 mechanism.
    """
    path = REPO_ROOT / "infra" / "docker-compose.private-site.yml"
    if not path.exists():
        pytest.skip("private-site template not present")
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    svc = next(v for k, v in doc["services"].items() if k.startswith("worker-site-"))
    assert "ALL" in (svc.get("cap_drop") or [])
    # Exactly these three, and nothing else: one for the tunnel, two consumed by the drop.
    assert set(svc.get("cap_add") or []) == {"NET_ADMIN", "SETUID", "SETGID"}, svc.get("cap_add")
    for broader in ("SYS_ADMIN", "NET_RAW", "ALL", "SYS_PTRACE", "DAC_OVERRIDE", "SYS_MODULE"):
        assert broader not in (svc.get("cap_add") or [])
    assert svc.get("privileged") is not True
    assert svc.get("read_only") is True
    # No control-plane network.
    assert "mbs-core" not in (svc.get("networks") or [])
    # The WireGuard private key directory must be tmpfs (RAM), never a persistent volume.
    assert any("/run/wireguard" in str(t) for t in (svc.get("tmpfs") or []))


# ---------------------------------------------------------------------------------------
# LAYER 2 -- runtime guard
# ---------------------------------------------------------------------------------------

def test_control_plane_worker_is_unaffected():
    """Without the execution-plane flag this is a no-op -- worker-default and beat
    legitimately hold these credentials."""
    enforce_execution_plane_credentials({"DATABASE_URL": "mysql://x", "JWT_SECRET_KEY": "s"})


def test_clean_execution_plane_starts():
    enforce_execution_plane_credentials({
        "SCANNER_EXECUTION_PLANE": "true",
        "SCANNER_WORKER_ID": "wk-1",
        "SCANNER_MANAGER_URL": "http://scanner-manager:8100",
    })


@pytest.mark.parametrize("var", sorted(FORBIDDEN_ON_SCANNER))
def test_each_control_plane_credential_blocks_startup(var):
    with pytest.raises(ExecutionPlaneCredentialError) as exc:
        enforce_execution_plane_credentials({"SCANNER_EXECUTION_PLANE": "true", var: "value"})
    assert var in str(exc.value)


def test_the_guard_reports_names_but_never_values():
    """A security check must not itself print a secret."""
    secret_value = f"s3cr3t-{uuid.uuid4().hex}"
    with pytest.raises(ExecutionPlaneCredentialError) as exc:
        enforce_execution_plane_credentials({
            "SCANNER_EXECUTION_PLANE": "true",
            "DATABASE_URL": f"mysql://user:{secret_value}@mysql/mbs",
            "JWT_SECRET_KEY": secret_value,
        })
    message = str(exc.value)
    assert "DATABASE_URL" in message and "JWT_SECRET_KEY" in message  # names, yes
    assert secret_value not in message                               # values, never
