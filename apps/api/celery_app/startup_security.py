"""Production startup security enforcement for the Celery entrypoints.

The API enforces its production invariants from the FastAPI lifespan
(`main.py` -> `Settings.validate_production()` + `run_startup_security_checks`). Celery
never imports `main.py`, so `worker`, `worker-default` and `beat` used to start with **no**
production validation at all. Two consequences, both silent:

  * a declared `<NAME>_FILE` secret that cannot be read left the process running on the
    inherited environment value -- in the shipped compose that is the `mbs` superuser DSN
    from `.env`, because a compose overlay cannot unset an `env_file` variable;
  * [PRE-MIGRATION] a PostgreSQL SUPERUSER bypassed `FORCE ROW LEVEL SECURITY`, so such a
    worker executed every task with workspace isolation defeated. Phase 0 MySQL cutover:
    this is no longer a privilege-based bypass -- see apps/api/core/tenancy.py. The
    equivalent risk now is a worker process where `tenancy.install()` was never called
    (e.g. it's imported before models_all finishes, or a future refactor drops the call),
    which the renamed check below (`enforce_tenancy_installed`) now catches instead.

The API would refuse to boot in that state, but the workers kept running -- the loud signal
and the dangerous process were different services.

WHY THESE HOOKS (measured against celery 5.4.0, not assumed):

  Signals -- `celeryd_init`, `worker_init`, `worker_process_init`, `beat_init` -- are
  UNUSABLE for fail-closed enforcement. An exception raised inside a signal receiver is
  swallowed: the worker continues serving, and the error is not surfaced even at INFO. A
  security check wired to a signal would look correct and do nothing.

  Import time DOES abort, for both `celery worker` and `celery beat` (exit 2). It is also
  the only single mechanism that covers beat, which has no worker blueprint.

  A worker bootstep DOES abort (exit 1) and runs only in an actual worker process, which is
  what the tenancy check needs: it performs I/O, and it must not run in beat (no engine) or
  at import time in the API (which has its own lifespan check).

So: config validation runs at import in `worker.py`; the tenancy check runs as a bootstep.
Both are wired there, which is the module every Celery entrypoint must load
(`-A apps.api.celery_app.worker.celery_app`) -- a new entrypoint cannot bypass them without
deliberately building a different app.

No security policy is defined here. Both checks delegate to the same code the API uses, so
there is exactly one place where the rules live.
"""
import asyncio

from celery import bootsteps


def enforce_production_config(settings) -> None:
    """Fail closed on invalid production configuration, including an unreadable secret file.

    Pure config validation, no I/O, and a no-op outside production -- so importing the Celery
    app in development, in tests, or from the API costs nothing and changes nothing.
    Raises RuntimeError (from `validate_production`) to abort the process.
    """
    settings.validate_production()


class ExecutionPlaneCredentialError(RuntimeError):
    """A scanner execution worker was started holding control-plane credentials."""


# Credentials that must NOT be present in the scanner execution plane. Each one, in the
# hands of a process running untrusted scanner binaries, is a full compromise of something:
#   DATABASE_URL / DB_PASSWORD -> every tenant's data
#   REDIS_URL                  -> the broker (forge or steal any tenant's tasks)
#   S3_*/MINIO_*               -> all evidence and reports
#   JWT_SECRET_KEY             -> mint a valid token for any user in any workspace
#   OPENROUTER/ANTHROPIC key   -> a billable third-party credential
_FORBIDDEN_EXECUTION_PLANE_ENV = (
    "DATABASE_URL", "DATABASE_URL_FILE", "DB_PASSWORD",
    "REDIS_URL", "REDIS_URL_FILE", "REDIS_PASSWORD",
    "S3_ACCESS_KEY", "S3_SECRET_KEY", "S3_ACCESS_KEY_FILE", "S3_SECRET_KEY_FILE",
    "MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD",
    "JWT_SECRET_KEY", "JWT_SECRET_KEY_FILE",
    "OPENROUTER_API_KEY", "OPENROUTER_API_KEY_FILE", "ANTHROPIC_API_KEY",
)


def enforce_execution_plane_credentials(env=None) -> None:
    """MBS.SC Property B: refuse to start a scanner worker that holds control-plane secrets.

    Enabled by SCANNER_EXECUTION_PLANE=true, which the isolated scanner services set. This
    is a SECOND line of defence, not the primary one -- the primary is that the compose
    file never loads `.env` into these services, and compose cannot unset an env_file
    variable from an overlay. This check catches the case where someone re-adds one by
    hand, or mounts the wrong env file: the worker then fails loudly at startup instead of
    running for months quietly over-credentialled.

    Names only are reported. The VALUES are never read, logged, or included in the error --
    a security check must not itself become the thing that prints a secret.
    """
    import os

    env = os.environ if env is None else env
    if str(env.get("SCANNER_EXECUTION_PLANE", "")).strip().lower() not in {"1", "true", "yes", "on"}:
        return
    present = sorted(name for name in _FORBIDDEN_EXECUTION_PLANE_ENV if env.get(name))
    if present:
        raise ExecutionPlaneCredentialError(
            "SCANNER_EXECUTION_PLANE=true, but this process holds control-plane "
            f"credential(s): {', '.join(present)}. The scanner execution plane must reach "
            "the control plane only through the scanner-manager. Remove these from the "
            "worker's environment (they most likely arrived via `env_file: ../.env` -- use "
            "../.env.scanner instead; a compose overlay CANNOT unset an env_file variable)."
        )


async def _run_tenancy_checks(settings) -> None:
    """Open a short-lived engine and apply the API's own runtime security checks to it.

    A dedicated `StaticPool` engine, disposed straight away, mirroring how the other
    worker-side entry points obtain a connection (see `celery_app/shutdown.py`); the
    process-wide async engine in `core/db.py` is bound to whichever event loop first used
    it, so it must not be borrowed here.
    """
    from apps.api.core.db import make_worker_engine
    from apps.api.core.startup_checks import run_startup_security_checks

    engine = make_worker_engine(settings.database_url)
    try:
        await run_startup_security_checks(
            engine,
            is_production=settings.is_production,
            enforce_derived_scope=settings.scan_enforce_derived_scope,
        )
    finally:
        await engine.dispose()


def enforce_tenancy_installed(settings) -> None:
    """Refuse to start a worker where workspace isolation (apps.api.core.tenancy) isn't
    installed.

    Raises `StartupSecurityError` in production if uninstalled; warns and continues in
    development, exactly as the API does. No event loop is running at worker-bootstep time,
    so `asyncio.run` owns one for the duration of the check.
    """
    asyncio.run(_run_tenancy_checks(settings))


class TenancyInstalledSecurityStep(bootsteps.StartStopStep):
    """Worker bootstep that enforces the workspace-isolation invariant before work is
    accepted.

    Registered on the WORKER blueprint only, so it runs for `worker` and `worker-default`
    (both of which open their own engines) and never for `beat`, which schedules ticks and
    opens none -- adding a DB dependency to beat would trade a security gap for an
    availability one.

    `start()` may run again if a worker restarts its blueprint in-process. Re-checking is
    deliberate and cheap (in-process state + one `SELECT 1`), and re-validating is the safe
    direction.
    """

    def start(self, parent) -> None:
        # `parent` is the worker instance; the check needs only settings, but the bootstep
        # protocol requires the argument.
        from apps.api.core.config import get_settings

        settings = get_settings()

        # MBS.SC: the SCANNER EXECUTION PLANE has no database at all -- no DSN and, by
        # design, no network route to MySQL. This check opens a connection and runs
        # `SELECT 1`, so on an execution worker it does not measure workspace isolation,
        # it just fails to connect and crash-loops the container. (Observed exactly that:
        # once network segmentation landed, the worker restarted forever on
        # "Can't connect to MySQL server on 'mysql'".)
        #
        # Skipping it there is safe *because* of what it was protecting. The check exists
        # to catch a worker that reads tenant tables with the ORM filter uninstalled; an
        # execution worker reads NO tenant table -- it has no session and no credential,
        # and every read/write it needs goes through the scanner-manager, which binds the
        # workspace itself and runs this very check in its own process. The invariant is
        # enforced where the database actually is.
        #
        # The execution plane instead gets the check that IS meaningful for it -- that it
        # holds no control-plane credential -- at import time in worker.py.
        if settings.scanner_execution_plane:
            import logging

            logging.getLogger(__name__).info(
                "startup_security.tenancy_check_skipped reason=execution_plane "
                "(no database access by design; the scanner-manager enforces tenancy)",
                extra={"event": "startup_security.tenancy_check_skipped",
                       "reason": "execution_plane"},
            )
            return

        enforce_tenancy_installed(settings)
