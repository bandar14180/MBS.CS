"""Celery worker/beat must enforce the SAME production security invariants as the API.

The API validates from its FastAPI lifespan; Celery never imports `main.py`, so `worker`,
`worker-default` and `beat` previously started with no production validation whatsoever. Two
silent failure modes followed:

  * an unreadable declared `<NAME>_FILE` left the process on the inherited environment value
    -- in the shipped compose that is the `mbs` privileged DSN, because a compose overlay
    cannot unset an `env_file` variable;
  * (pre-Phase-0-MySQL-cutover) a Postgres SUPERUSER role bypassed FORCE ROW LEVEL SECURITY,
    so such a worker ran every task with workspace isolation defeated. That specific failure
    mode no longer exists: MySQL has no RLS and workspace isolation is now an application-layer
    filter (apps.api.core.tenancy) installed unconditionally at worker startup, not something a
    database role can opt out of. What the worker now MUST still verify at boot is that
    `tenancy.install()` actually ran -- see `TenancyInstalledSecurityStep` in
    `apps/api/celery_app/startup_security.py` and `assert_tenancy_installed` in
    `apps/api/core/startup_checks.py` for the successor control and its full rationale.

HOW THESE TESTS ARE WRITTEN, AND WHY

Calling `settings.validate_production()` and declaring the worker covered is precisely the
mistake that let this gap survive -- the guard was always correct, it was simply never
invoked on that path. So these tests SPAWN THE REAL `celery` CLI against the real app module
and assert on the process outcome. If the enforcement is removed from `worker.py`, the
subprocess starts successfully and these tests fail.

`--broker=memory://` keeps them hermetic: no Redis, no network, no Internet. No secret value
is ever printed; every credential here is an obvious placeholder.
"""
import os
import subprocess
import sys
from pathlib import Path

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
        # F-08: production requires the refresh cookie to be Secure.
        "REFRESH_COOKIE_SECURE": "true",
    "TRUSTED_PROXY_COUNT": "0",
    "METRICS_MODE": "token",
    "METRICS_TOKEN": "a-test-metrics-token",
    "AI_PROVIDER": "openrouter",
    "DATABASE_URL": "mysql+aiomysql://appuser:a-test-password@mysql:3306/mbs",
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
    and PYTHONPATH are the only host values carried over (plus SystemRoot on Windows, see
    below -- that one isn't a "host value that could decide the outcome", it's required for
    the child interpreter to boot at all).

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
        # Explicit, not inherited: `cwd=REPO_ROOT` below means Settings' env_file=".env" still
        # reads the REAL repo .env FILE straight off disk (an omitted env var here doesn't stop
        # that -- only an explicit one, which beats the file per pydantic-settings precedence).
        # A developer's local .env commonly sets DEV_AUTO_AUTHORIZE_TARGETS=true for manual UI
        # testing; without this, that value would leak into the "clean" child and make a
        # config-validation test's outcome depend on the developer's own untracked .env -- the
        # exact class of problem this from-scratch env exists to prevent.
        "DEV_AUTO_AUTHORIZE_TARGETS": "false",
    }
    if sys.platform == "win32":
        # Windows CPython's interpreter bootstrap (specifically hash-randomization seeding,
        # which calls into the Windows CryptoAPI) requires SystemRoot to be present in the
        # environment -- without it the child dies before main() even runs, with "Fatal
        # Python error: _Py_HashRandomization_Init: failed to get random numbers to
        # initialize Python". Every assertion below reads that crash as "the security
        # control didn't produce the expected message", which is the wrong diagnosis: the
        # child never started. Harmless everywhere else -- this branch never runs on Linux/
        # macOS, where SystemRoot doesn't exist and every other var here is untouched.
        systemroot = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT")
        if systemroot:
            env["SystemRoot"] = systemroot
        # A second, distinct Windows-only requirement, found the same way (running this
        # against real Python 3.13 on Windows): apps.api.core.db imports aiomysql, whose
        # connection.py runs `DEFAULT_USER = getpass.getuser()` at MODULE IMPORT TIME,
        # wrapped in `except KeyError` only. Python 3.13 changed getpass.getuser() to raise
        # OSError instead of KeyError when no username is resolvable (pymysql's own source,
        # a sibling dependency, has a comment acknowledging this exact CPython change) --
        # aiomysql hasn't been updated for it. With no USERNAME in this from-scratch
        # environment, importing the app crashes at that line before our own validation
        # code ever runs, and celery reports it as the same generic "Usage: ... Unable to
        # load celery application" banner as any other import-time failure -- indistinguishable
        # from the real thing without reading the full output. This is a real gap in a
        # third-party dependency, not in this codebase, and it can only ever be hit on
        # Windows + Python 3.13+ with USERNAME unset -- which never happens outside this
        # deliberately-minimal test environment (a real shell, and the Docker/Linux
        # production target, always has it).
        username = os.environ.get("USERNAME")
        if username:
            env["USERNAME"] = username
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
    secret has to clear config validation and reach the tenancy-installed bootstep.

    Proving "it got further" needs a positive marker, not just the absence of the previous
    error -- an unrelated crash would satisfy that. So the secret points at a port with
    nothing on it: the worker can only produce a CONNECTION failure if it actually reached
    the database step, which in turn proves the config gate let it through."""
    secret = tmp_path / "database_url"
    secret.write_text("mysql+aiomysql://appuser:a-test-password@127.0.0.1:59999/mbs\n")
    outcome = _worker({**_PROD_ENV, "DATABASE_URL_FILE": str(secret)})
    assert "could not be read" not in outcome.output, "a readable secret must not be reported unreadable"
    assert "Refusing to start in production" not in outcome.output, "config validation must pass"
    assert any(m in outcome.output for m in ("Connect call failed", "Connection refused", "connect")), (
        "expected the worker to reach the tenancy-installed connectivity check and fail connecting there; "
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


# --- 3/4. Database role: a SUPERUSER bypasses FORCE RLS (PRE-MIGRATION; removed) --------
#
# This section used to spawn a real worker against a genuine PostgreSQL SUPERUSER /
# NOSUPERUSER probe role and assert that the superuser one was refused (FORCE ROW LEVEL
# SECURITY bypass) while the least-privileged one was accepted. Phase 0 MySQL cutover: MySQL
# has no RLS and no role-based bypass is possible any more, because workspace isolation is no
# longer a database-enforced, privilege-gated policy at all -- it is an application-layer
# filter (apps.api.core.tenancy) that `TenancyInstalledSecurityStep` installs unconditionally
# at worker boot (see apps/api/celery_app/startup_security.py). There is no database role,
# privileged or not, that can opt a connection out of it; fabricating a "probe_role" fixture
# here would test a scenario the new architecture cannot produce.
#
# The successor invariant -- tenancy.install() actually having run before the worker serves
# any task -- IS still covered, at two levels:
#   * the pure predicate `assert_tenancy_installed` is unit-tested directly (all four
#     production x installed combinations) in `test_startup_guards.py`'s F4 section;
#   * `test_worker_gets_past_the_config_gate_when_the_secret_file_is_readable` above proves,
#     through a REAL spawned worker, that the process reaches past config validation into
#     `run_startup_security_checks` (the connectivity attempt against the dead port is what
#     that test's assertion actually observes) -- i.e. that `TenancyInstalledSecurityStep` is
#     genuinely on the path, not merely present in source.
# There is no live-process way to force `tenancy.is_installed()` false in a spawned
# subprocess (it is set unconditionally, early, by code the worker always runs), so unlike
# the old superuser fixture there is nothing a subprocess-level negative test could exercise
# that the unit-level F4 tests don't already cover more directly.


# --- 7/8. Existing behaviour must be intact ---------------------------------------------

def test_the_tenancy_installed_step_is_registered_on_the_worker_blueprint_only():
    """Beat opens no engine, so the tenancy check must not gate it -- that would trade a
    security gap for an availability one. Registration on the worker blueprint is what
    confines it (Phase 0 MySQL cutover: successor to the old DatabaseRoleSecurityStep)."""
    from apps.api.celery_app.startup_security import TenancyInstalledSecurityStep
    from apps.api.celery_app.worker import celery_app

    assert TenancyInstalledSecurityStep in celery_app.steps["worker"]
    assert TenancyInstalledSecurityStep not in celery_app.steps.get("beat", set())


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
