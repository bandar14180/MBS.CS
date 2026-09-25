"""Fail-closed guard against running the API from a STALE, BAKED-IN IMAGE.

THE FAILURE THIS EXISTS TO CATCH

`infra/docker-compose.yml` bakes the application code into the image (`COPY apps/api`), which
is what production wants. Development instead needs the code to come from the HOST tree, and
`infra/docker-compose.override.yml` supplies exactly that with `../apps/api:/srv/apps/api`.

Compose auto-merges an override file ONLY for a bare `docker compose up` issued from the
directory holding it. The instant ANY `-f` flag appears, the file list is exact and nothing is
added implicitly -- so

    docker compose -f infra/docker-compose.yml up -d api

drops the bind mount. Nothing fails. The container starts, reports healthy, and serves
whatever `apps/api` looked like the last time somebody ran `--build`. That is the whole bug:
it presents as correct behaviour, and the drift surfaces much later and far away -- in this
codebase's case as generated PDF reports rendered by a months-old `modules/reports/render.py`
while the host tree had long since moved on. Nothing in the stack could observe the gap,
because from inside the container the stale code IS the code.

WHY A SENTINEL RATHER THAN LOOKING FOR THE MOUNT

Checking "is /srv/apps/api a bind mount?" tests a symptom on one platform and answers
differently under Docker Desktop, rootless Docker, and CI. The invocation itself is the thing
that is right or wrong, so that is what is measured: the base compose file sets
`MBS_STACK_MODE=unconfigured` and BOTH real invocations replace it --

    docker-compose.override.yml -> development     docker-compose.prod.yml -> production

The sentinel therefore survives only when the `-f` list is INCOMPLETE, which is precisely the
condition that also drops the bind mount. One variable, checked once, at boot.

`${MBS_STACK_MODE:?}` interpolation in the base file would be the tidier expression of this,
and it does not work: compose interpolates each file BEFORE merging them, so a required-
variable marker aborts even a correct invocation. Verified directly against Compose v5.3.1.

SCOPE AND SAFETY

This refuses to start ONLY on the sentinel value -- the fingerprint of a known-broken
invocation. An UNSET variable is explicitly allowed, so every non-compose caller (pytest, a
bare `uvicorn`, an IDE runner, Kubernetes, an operator's own manifests) is untouched; the
guard cannot strand a deployment that never opted into the convention in the first place.
"""
from __future__ import annotations

import os

#: What the base compose file sets and each overlay is expected to replace.
SENTINEL = "unconfigured"

ENV_VAR = "MBS_STACK_MODE"

_MESSAGE = f"""\
{ENV_VAR}={SENTINEL}: this container was started from an INCOMPLETE compose -f list.

Only infra/docker-compose.yml was applied, so infra/docker-compose.override.yml -- which
bind-mounts the host's apps/api over /srv/apps/api -- was NOT merged. The API would have run
the code BAKED INTO THE IMAGE at its last build, silently serving stale behaviour rather than
the working tree.

Start a development stack with BOTH files (from the repo root):

    docker compose -f infra/docker-compose.yml -f infra/docker-compose.override.yml up -d

or with no -f at all from infra/, where compose merges the override automatically:

    cd infra && docker compose up -d

Production uses its own overlay and is unaffected:

    docker compose -f infra/docker-compose.yml -f infra/docker-compose.prod.yml up -d
"""


class StaleStackError(RuntimeError):
    """Raised when the compose invocation would have served baked-in image code in dev."""


def assert_stack_mode_configured(env: dict[str, str] | None = None) -> None:
    """Abort startup when the stack-mode sentinel survived into the container.

    `env` is injectable so the guard is testable without mutating the process environment.
    """
    value = (env if env is not None else os.environ).get(ENV_VAR)
    if value is not None and value.strip().lower() == SENTINEL:
        raise StaleStackError(_MESSAGE)
