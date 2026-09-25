"""The scanner-manager process must be able to RESOLVE every foreign key it writes through.

WHY THIS FILE EXISTS, AND WHY IT USES A SUBPROCESS

`Evidence.uploaded_by` carries `ForeignKey("users.id")`. SQLAlchemy resolves a STRING foreign
key lazily -- at flush time -- against whatever happens to be registered in `Base.metadata`.
The scanner-manager deliberately imports a NARROW slice of the models (it is a small boundary
service, not the whole app), and `users` was not in that slice. So the first INSERT of an
Evidence row died with:

    NoReferencedTableError: Foreign key associated with column 'evidence.uploaded_by'
    could not find table 'users'

POST /v1/evidence returned 500, and because vulnerability ingestion runs AFTER that flush in
the same handler, findings were never ingested either -- an entirely separate symptom with
the same single cause.

The subtle part, and the reason this file cannot be a normal test: the EXISTING suite could
not have caught it. `conftest.py` and the manager fixtures import the full model set (42
tables, `users` among them), so the FK resolves under pytest and the endpoint passes -- while
the real process, importing 9 tables, fails on the identical code path. A test that shares
the runner's import graph is testing a DIFFERENT registry than the one production uses.

So these tests spawn a SUBPROCESS with a clean interpreter, import exactly what the manager
imports, and inspect the registry that results. That is the only way to observe the
production registry from inside a test runner that has already polluted its own.

Scope: this checks REGISTRATION and RESOLUTION, not the database. The `evidence.uploaded_by`
constraint already exists in the schema (`fk_evidence_uploaded_by_users`) and the column is
nullable -- scanner evidence leaves it NULL, since the tool run is the provenance. Nothing
here implies or requires a migration.
"""
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


def _run_isolated(body: str) -> str:
    """Execute `body` in a FRESH interpreter and return its stdout.

    A fresh process is the whole point: this test module has already imported half the
    application, so `Base.metadata` in THIS process is not the registry the manager builds.
    Only a clean interpreter reproduces what the running service actually sees.
    """
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(body)],
        capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=120,
    )
    if result.returncode != 0:
        pytest.fail(
            "isolated interpreter failed:\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr[-2000:]}"
        )
    return result.stdout.strip()


def test_the_manager_process_registers_users_for_the_evidence_foreign_key():
    """THE regression test. Imports exactly what the manager imports -- nothing more -- and
    resolves the FK the way a flush() does.

    If someone drops the `users` import from scanner_manager/app.py as an unused symbol
    (it IS unused by name; it is imported for its side effect on the registry), this fails
    here instead of as a 500 on the next real scan's evidence submission.
    """
    out = _run_isolated(
        """
        import apps.api.scanner_manager.app  # the process under test
        from apps.api.core.db import Base
        from apps.api.scanner_engine.models import Evidence

        print("users_registered:", "users" in Base.metadata.tables)
        for fk in Evidence.__table__.foreign_keys:
            try:
                column = fk.column          # exactly what flush() triggers
                print(f"resolved:{fk.parent.name}->{column.table.name}.{column.name}")
            except Exception as exc:
                print(f"unresolved:{fk.parent.name}:{type(exc).__name__}")
        """
    )
    assert "users_registered: True" in out, (
        "the scanner-manager process does not register `users`; an Evidence INSERT will "
        f"fail at flush with NoReferencedTableError.\nGot:\n{out}"
    )
    assert "resolved:uploaded_by->users.id" in out, (
        f"evidence.uploaded_by does not resolve in the manager's registry.\nGot:\n{out}"
    )
    assert "unresolved:" not in out, f"an Evidence foreign key failed to resolve:\n{out}"


def test_every_foreign_key_the_manager_writes_through_resolves():
    """Generalizes past the one column that broke.

    The manager INSERTs into `tool_runs`, `evidence` and `assets`. Each carries string
    foreign keys resolved lazily, so any of them could fail the same way after an unrelated
    import change. Checking the whole write surface makes the NEXT instance of this class
    fail here rather than in production.
    """
    out = _run_isolated(
        """
        import apps.api.scanner_manager.app
        from apps.api.core.db import Base

        # The tables the manager's endpoints actually write rows into.
        for name in ("tool_runs", "evidence", "assets"):
            table = Base.metadata.tables[name]
            for fk in table.foreign_keys:
                try:
                    column = fk.column
                    print(f"ok:{name}.{fk.parent.name}->{column.table.name}")
                except Exception as exc:
                    print(f"BROKEN:{name}.{fk.parent.name}:{type(exc).__name__}")
        """
    )
    broken = [line for line in out.splitlines() if line.startswith("BROKEN:")]
    assert not broken, (
        "foreign keys the manager writes through cannot be resolved in its own process; "
        "the referenced model is not imported by scanner_manager/app.py:\n  "
        + "\n  ".join(broken)
    )


def test_the_narrow_registry_is_what_makes_this_test_necessary():
    """Pins the PREMISE, so the guard cannot quietly stop guarding.

    If the manager one day imports the whole model graph, the two tests above would pass
    for a reason that has nothing to do with the fix -- and the real defect class (a narrow
    registry that cannot resolve a lazy FK) would go unwatched. This asserts the registry is
    still materially narrower than the application's, so that a change in that assumption
    surfaces as a failure to re-examine rather than as silent false confidence.

    It deliberately asserts a LOOSE bound: the exact count is an implementation detail that
    legitimately drifts as the manager's imports evolve.
    """
    out = _run_isolated(
        """
        import apps.api.scanner_manager.app
        from apps.api.core.db import Base
        print("manager_tables:", len(Base.metadata.tables))
        """
    )
    manager_tables = int(out.split("manager_tables:")[1].strip())

    full = _run_isolated(
        """
        from apps.api.core import models_all  # noqa: F401 -- registers the app's models
        from apps.api.core.db import Base
        print("all_tables:", len(Base.metadata.tables))
        """
    )
    all_tables = int(full.split("all_tables:")[1].strip())

    assert manager_tables < all_tables, (
        f"the manager now registers {manager_tables} of {all_tables} tables. If it really "
        "imports everything, the lazy-FK failure mode above is gone -- but so is the reason "
        "these tests exist; re-check them rather than deleting this assertion."
    )
