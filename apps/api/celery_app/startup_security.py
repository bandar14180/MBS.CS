"""Production startup security enforcement for the Celery entrypoints.

The API enforces its production invariants from the FastAPI lifespan
(`main.py` -> `Settings.validate_production()` + `run_startup_security_checks`). Celery
never imports `main.py`, so `worker`, `worker-default` and `beat` used to start with **no**
production validation at all. Two consequences, both silent:

  * a declared `<NAME>_FILE` secret that cannot be read left the process running on the
    inherited environment value -- in the shipped compose that is the `mbs` superuser DSN
    from `.env`, because a compose overlay cannot unset an `env_file` variable;
  * a PostgreSQL SUPERUSER bypasses `FORCE ROW LEVEL SECURITY`, so such a worker executes
    every task with workspace isolation defeated.

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
  what the DB-role check needs: it performs I/O, and it must not run in beat (no engine) or
  at import time in the API (which has its own lifespan check).

So: config validation runs at import in `worker.py`; the DB-role check runs as a bootstep.
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


async def _run_database_role_checks(settings) -> None:
    """Open a short-lived engine and apply the API's own runtime security checks to it.

    A dedicated `StaticPool` engine, disposed straight away, mirroring how the other
    worker-side entry points obtain a connection (see `celery_app/shutdown.py`); the
    process-wide async engine in `core/db.py` is bound to whichever event loop first used
    it, so it must not be borrowed here.
    """
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import StaticPool

    from apps.api.core.startup_checks import run_startup_security_checks

    engine = create_async_engine(settings.database_url, poolclass=StaticPool)
    try:
        await run_startup_security_checks(
            engine,
            is_production=settings.is_production,
            enforce_derived_scope=settings.scan_enforce_derived_scope,
        )
    finally:
        await engine.dispose()


def enforce_database_role_security(settings) -> None:
    """Refuse to start a worker whose database role bypasses FORCE RLS.

    Raises `StartupSecurityError` in production on a SUPERUSER role; warns and continues in
    development, exactly as the API does. No event loop is running at worker-bootstep time,
    so `asyncio.run` owns one for the duration of the check.
    """
    asyncio.run(_run_database_role_checks(settings))


class DatabaseRoleSecurityStep(bootsteps.StartStopStep):
    """Worker bootstep that enforces the database-role invariant before work is accepted.

    Registered on the WORKER blueprint only, so it runs for `worker` and `worker-default`
    (both of which open their own engines) and never for `beat`, which schedules ticks and
    opens none -- adding a DB dependency to beat would trade a security gap for an
    availability one.

    `start()` may run again if a worker restarts its blueprint in-process. Re-checking is
    deliberate: it is a single `SELECT` against a role that could in principle have been
    altered, and re-validating is the safe direction.
    """

    def start(self, parent) -> None:
        # `parent` is the worker instance; the check needs only settings, but the bootstep
        # protocol requires the argument.
        from apps.api.core.config import get_settings

        enforce_database_role_security(get_settings())
