"""Celery worker/beat must enforce the SAME production security invariants as the API.

The API validates from its FastAPI lifespan; Celery never imports `main.py`, so `worker`,
`worker-default` and `beat` previously started with no production validation whatsoever. Two
silent failure modes followed:

  * an unreadable declared `<NAME>_FILE` left the process on the inherited environment value
    -- in the shipped compose that is the `mbs` SUPERUSER DSN, because a compose overlay
    cannot unset an `env_file` variable;
  * a SUPERUSER role bypasses FORCE ROW LEVEL SECURITY, so such a worker runs every task
    with workspace isolation defeated.

HOW THESE TESTS ARE WRITTEN, AND WHY

Calling `settings.validate_production()` and declaring the worker covered is precisely the
mistake that let this gap survive -- the guard was always correct, it was simply never
invoked on that path. So these tests SPAWN THE REAL `celery` CLI against the real app module
and assert on the process outcome. If the enforcement is removed from `worker.py`, the
subprocess starts successfully and these tests fail.

`--broker=memory://` keeps them hermetic: no Redis, no network, no Internet. The DB-role
tests need a live PostgreSQL and skip cleanly without one. No secret value is ever printed;
every credential here is an obvious placeholder.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from apps.api.core.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[3]
CELERY_APP = "apps.api.celery_app.worker.celery_app"

# A configuration that satisfies every OTHER production guard, so the only thing a test can
# trip is the control under test. Placeholders only -- nothing here is a real credential.
_PROD_ENV = {
    "ENVIRONMENT": "production",
    "JWT_SECRET_KEY": "t" * 48,
    "MFA_ENCRYPTION_KEY": "a-test-mfa-encryption-key",
    "S3_ACCESS_KEY": "a-test-access-key",
    "S3_SECRET_KEY": "a-test-secret-key",
    "TRUSTED_HOSTS": '["mbs.example.com"]',
    "CORS_ALLOW_ORIGINS": '["https://mbs.example.com"]',
    "RATE_LIMIT_ENABLED": "true",
    "TRUSTED_PROXY_COUNT": "0",
    "METRICS_MODE": "token",
    "METRICS_TOKEN": "a-test-metrics-token",
    "AI_PROVIDER": "openrouter",
    "DATABASE_URL": "postgresql+asyncpg://appuser:a-test-password@postgres:5432/mbs",
}


class Outcome:
    """What actually happened to a spawned Celery process.

    `survived` is the positive signal: the process was still running when the timeout
    elapsed, i.e. it cleared every startup gate. `exited` with a non-zero code is the
    fail-closed signal. Distinguishing the two is what stops a test passing because the
    process died for an unrelated reason.
    """

    def __init__(self, returncode: int | None, output: str, survived: bool):
        self.returncode = returncode
        self.output = output
        self.survived = survived

    @property
    def refused(self) -> bool:
        return not self.survived and self.returncode not in (0, None)


def _celery(*args: str, env_overrides: dict, timeout: int) -> Outcome:
    """Run the real Celery CLI against the real app module in a clean environment.

    `env` is built from scratch rather than inherited so a developer's exported variables --
    or the repo `.env`, which pydantic reads by default -- cannot decide the outcome. PATH
    and PYTHONPATH are the only host values carried over.

    `--broker` is a GLOBAL celery option and must precede the subcommand; placed after it,
    click aborts with "No such option" and the process exits non-zero for a reason that has
    nothing to do with security -- which a careless assertion would happily accept. That
    specific misuse is asserted against below. A `Usage:` banner on its own is NOT treated as
    misuse: an import-time security refusal legitimately produces one, because celery reports
    it as "Unable to load celery application".
    """
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(REPO_ROOT),
        "PYTHONDONTWRITEBYTECODE": "1",
        "ENVIRONMENT": "production",
    }
    env.update(env_overrides)
    cmd = [sys.executable, "-m", "celery", "-A", CELERY_APP, "--broker=memory://", *args]
    try:
        proc = subprocess.run(
            cmd, cwd=str(REPO_ROOT), env=env, capture_output=True, text=True, timeout=timeout
        )
        outcome = Outcome(proc.returncode, proc.stdout + proc.stderr, survived=False)
    except subprocess.TimeoutExpired as expired:
        def _text(stream) -> str:
            if stream is None:
                return ""
            return stream.decode(errors="replace") if isinstance(stream, bytes) else stream

        outcome = Outcome(None, _text(expired.stdout) + _text(expired.stderr), survived=True)
    assert "No such option" not in outcome.output, (
        f"celery rejected the command line, so nothing was exercised: {outcome.output[:200]}"
    )
    return outcome


def _worker(env_overrides: dict, timeout: int = 30) -> Outcome:
    return _celery(
        "worker", "--pool=solo", "--concurrency=1", "--loglevel=critical",
        "--without-gossip", "--without-mingle", "--without-heartbeat",
        env_overrides=env_overrides, timeout=timeout,
    )


def _beat(tmp_path: Path, env_overrides: dict, timeout: int = 30) -> Outcome:
    return _celery(
        "beat", "--loglevel=critical", "-s", str(tmp_path / "beat-schedule"),
        env_overrides=env_overrides, timeout=timeout,
    )


# --- 1/2. Unreadable declared secret must fail the worker closed ------------------------

def test_worker_refuses_to_start_on_an_unreadable_secret_file(tmp_path):
    """THE REGRESSION. A declared DATABASE_URL_FILE that cannot be read must NOT fall back to
    the inherited DATABASE_URL. Before this fix the worker started happily on that inherited
    value -- the `mbs` superuser DSN in the shipped compose."""
    env = {**_PROD_ENV, "DATABASE_URL_FILE": str(tmp_path / "definitely-absent")}
    outcome = _worker(env)
    assert outcome.refused, (
        "worker started despite a declared-but-unreadable secret file; it would be running "
        f"on the inherited environment value (survived={outcome.survived})"
    )
    assert "DATABASE_URL_FILE" in outcome.output
    assert "could not be read" in outcome.output


def test_worker_gets_past_the_config_gate_when_the_secret_file_is_readable(tmp_path):
    """POSITIVE CONTROL, and it must be able to FAIL. The same configuration with a readable
    secret has to clear config validation and reach the DB-role bootstep.

    Proving "it got further" needs a positive marker, not just the absence of the previous
    error -- an unrelated crash would satisfy that. So the secret points at a port with
    nothing on it: the worker can only produce a CONNECTION failure if it actually reached
    the database step, which in turn proves the config gate let it through."""
    secret = tmp_path / "database_url"
    secret.write_text("postgresql+asyncpg://appuser:a-test-password@127.0.0.1:59999/mbs\n")
    outcome = _worker({**_PROD_ENV, "DATABASE_URL_FILE": str(secret)})
    assert "could not be read" not in outcome.output, "a readable secret must not be reported unreadable"
    assert "Refusing to start in production" not in outcome.output, "config validation must pass"
    assert any(m in outcome.output for m in ("Connect call failed", "Connection refused", "connect")), (
        "expected the worker to reach the database-role step and fail connecting there; "
        f"got: {outcome.output[-300:]}"
    )


# --- 5/6. Beat must be covered too ------------------------------------------------------

def test_beat_refuses_to_start_on_an_unreadable_secret_file(tmp_path):
    """Beat has no worker blueprint, so a bootstep cannot protect it -- and a Celery signal
    receiver that raises is silently swallowed. Import-time enforcement is what covers it."""
    env = {**_PROD_ENV, "DATABASE_URL_FILE": str(tmp_path / "definitely-absent")}
    outcome = _beat(tmp_path, env)
    assert outcome.refused, "beat started despite an unreadable declared secret file"
    assert "DATABASE_URL_FILE" in outcome.output and "could not be read" in outcome.output


def test_beat_refuses_to_start_on_invalid_production_config(tmp_path):
    """Beat must get the WHOLE production policy, not just the secret-file rule."""
    env = {**_PROD_ENV, "JWT_SECRET_KEY": "change-me-generate-a-real-secret"}
    outcome = _beat(tmp_path, env)
    assert outcome.refused
    assert "Refusing to start in production" in outcome.output


# --- 3/4. Database role: a SUPERUSER bypasses FORCE RLS ---------------------------------

def _database_url() -> str:
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        pytest.skip("DATABASE_URL not set; DB-role enforcement needs a live PostgreSQL")
    return url


def _role_is_superuser(url: str) -> bool:
    import psycopg2

    try:
        conn = psycopg2.connect(url.replace("+asyncpg", ""), connect_timeout=5)
    except psycopg2.OperationalError:
        pytest.skip("PostgreSQL unreachable; DB-role enforcement cannot be exercised")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            return bool(cur.fetchone()[0])
    finally:
        conn.close()


@pytest.fixture
def probe_role(request):
    """Create a real login role of the requested privilege level, yield its DSN, drop it.

    The role gets credentials of its own rather than reusing the suite's connection string:
    the shipped dev DSN (`mbs:mbs`) is itself rejected by `validate_production`, so reusing it
    would trip the CONFIG gate and the worker would never reach the DB-role step -- the test
    would then pass while proving nothing about the control under test. Distinct credentials
    isolate the database-role check as the only thing that can fail.

    The privilege level is real: a genuine SUPERUSER / NOSUPERUSER role in the live database.
    The security condition is never mocked.
    """
    import psycopg2

    url = _database_url()
    if not _role_is_superuser(url):
        pytest.skip("creating a probe role needs a superuser connection")
    superuser = request.param
    role = f"mbs_probe_{'super' if superuser else 'plain'}"
    password = "a-test-probe-password"  # placeholder; dropped at teardown
    conn = psycopg2.connect(url.replace("+asyncpg", ""), connect_timeout=5)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute(f"DROP ROLE IF EXISTS {role}")
            cur.execute(
                f"CREATE ROLE {role} LOGIN {'SUPERUSER' if superuser else 'NOSUPERUSER'} "
                "PASSWORD %s",
                (password,),
            )
        from urllib.parse import urlsplit

        parts = urlsplit(url)
        yield f"postgresql+asyncpg://{role}:{password}@{parts.hostname}:{parts.port or 5432}{parts.path}"
    finally:
        with conn.cursor() as cur:
            cur.execute(f"DROP ROLE IF EXISTS {role}")
        conn.close()


@pytest.mark.parametrize("probe_role", [True], indirect=True)
def test_worker_rejects_a_superuser_database_role_in_production(tmp_path, probe_role):
    """A SUPERUSER bypasses FORCE ROW LEVEL SECURITY, so every task it runs escapes workspace
    isolation. The API has refused this since M4.6.1; the worker -- which opens its own
    engines and executes the scans -- did not. Exercised through real worker startup, so it
    proves the bootstep is actually reached, not merely that the predicate exists."""
    secret = tmp_path / "database_url"
    secret.write_text(probe_role + "\n")
    outcome = _worker({**_PROD_ENV, "DATABASE_URL_FILE": str(secret)})
    assert outcome.refused, (
        "worker accepted a SUPERUSER database role in production; FORCE RLS would be bypassed "
        f"for every task it runs (survived={outcome.survived})"
    )
    assert "SUPERUSER" in outcome.output
    # it must be the DB-role control that refused, not an unrelated config problem
    assert "FORCE ROW LEVEL SECURITY" in outcome.output


@pytest.mark.parametrize("probe_role", [False], indirect=True)
def test_worker_accepts_a_non_superuser_database_role_in_production(tmp_path, probe_role):
    """The mirror image: a least-privileged role must be allowed through, or the control
    would simply be an outage rather than a security boundary."""
    secret = tmp_path / "database_url"
    secret.write_text(probe_role + "\n")
    outcome = _worker({**_PROD_ENV, "DATABASE_URL_FILE": str(secret)}, timeout=25)
    assert "SUPERUSER" not in outcome.output, "a non-superuser role must not be rejected"
    assert "Refusing to start in production" not in outcome.output
    # SURVIVING the timeout is the positive signal: the worker cleared config validation AND
    # the database-role step and went on serving. A test that only checked for the absence of
    # an error message would also pass if the process had crashed for some other reason.
    assert outcome.survived, (
        f"worker with a least-privileged role should keep running; it exited "
        f"{outcome.returncode}: {outcome.output[-300:]}"
    )


# --- 7/8. Existing behaviour must be intact ---------------------------------------------

def test_the_database_role_step_is_registered_on_the_worker_blueprint_only():
    """Beat opens no engine, so the DB check must not gate it -- that would trade a security
    gap for an availability one. Registration on the worker blueprint is what confines it."""
    from apps.api.celery_app.startup_security import DatabaseRoleSecurityStep
    from apps.api.celery_app.worker import celery_app

    assert DatabaseRoleSecurityStep in celery_app.steps["worker"]
    assert DatabaseRoleSecurityStep not in celery_app.steps.get("beat", set())


def test_api_startup_validation_is_unchanged():
    """The API must keep validating from its own lifespan; this fix adds enforcement to
    Celery, it does not move or weaken the API's."""
    main_src = (REPO_ROOT / "apps" / "api" / "main.py").read_text(encoding="utf-8")
    assert "settings.validate_production()" in main_src
    assert "run_startup_security_checks(" in main_src


def test_importing_the_celery_app_is_a_no_op_outside_production():
    """Development and the test suite import this module constantly; enforcement must cost
    nothing there. (That this very suite imports it and passes is the practical proof.)"""
    settings = Settings(environment="development", jwt_secret_key="change-me-in-.env")
    settings.validate_production()  # no-op outside production
    from apps.api.celery_app import startup_security

    startup_security.enforce_production_config(settings)  # must not raise
