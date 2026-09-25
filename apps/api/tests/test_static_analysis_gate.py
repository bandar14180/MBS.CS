"""AUDIT-013 -- the static-analysis gate must exist, be configured honestly, and BLOCK.

THE GAP
-------
CI's `lint` job ran exactly one command: `ruff check apps/api`.

  * NO Python type checker ran anywhere. Ruff's selected ruleset (E4/E7/E9/F/W) catches
    undefined names, unused imports and syntax errors. It cannot catch a wrong argument type,
    a None-unsafe attribute access, or a call with the wrong arity.
  * `scripts/` was outside lint coverage entirely -- even though it holds
    `scripts/raw_sql_inventory.py`, which IS the raw-SQL tenancy gate. A defect in the gate
    itself would have shipped unnoticed.

Introducing mypy immediately paid for itself: `ExportedEngagementState.approval_state` was
declared `str | None` while `EngagementState.approval_state` is a NON-NULLABLE JSON `dict`
column. Pydantic rejects a dict for a `str` field, so a GDPR tenant export for any workspace
holding an engagement_state row raised ValidationError. Nothing else in the suite covered it.

WHAT THESE TESTS ENFORCE
------------------------
1. The type checker is configured, pinned, and installed by the same requirements CI installs.
2. It is actually WIRED into CI, and the step is blocking (no continue-on-error).
3. `scripts/` is inside lint coverage.
4. The configuration is not a sham: no `ignore_errors`, and `check_untyped_defs` is on, so
   function bodies are genuinely analysed rather than skipped for want of annotations.
5. Every suppression is NARROW -- per-module `disable_error_code`, never a global blanket.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
PYPROJECT = REPO_ROOT / "pyproject.toml"
REQ_DEV = REPO_ROOT / "apps" / "api" / "requirements-dev.txt"


def _read(path: Path) -> str:
    if not path.is_file():
        pytest.skip(f"{path.name} not present (repo root not bind-mounted)")
    return path.read_text(encoding="utf-8")


def _mypy_config() -> dict:
    cfg = tomllib.loads(_read(PYPROJECT))
    mypy = cfg.get("tool", {}).get("mypy")
    assert mypy, "pyproject.toml has no [tool.mypy] section -- there is no type-check gate"
    return mypy


# --------------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------------

def test_type_checker_is_configured():
    mypy = _mypy_config()
    files = mypy.get("files") or []
    assert "apps/api" in files, "the application package must be type-checked"
    assert "scripts" in files, (
        "scripts/ must be type-checked -- it holds the raw-SQL security gate (AUDIT-013)"
    )


def test_type_check_config_is_not_a_sham():
    """A gate that skips every unannotated function body checks almost nothing in this codebase.
    `check_untyped_defs` is what makes it real."""
    mypy = _mypy_config()
    assert mypy.get("check_untyped_defs") is True, (
        "check_untyped_defs must be on, or mypy silently skips the body of every function "
        "without annotations -- which is most of this tree"
    )
    assert mypy.get("no_implicit_optional") is True
    assert mypy.get("strict_equality") is True
    assert mypy.get("warn_unused_ignores") is True, (
        "without this, stale `# type: ignore` comments accumulate and hide real errors"
    )


def test_no_blanket_error_suppression():
    """`ignore_errors` anywhere would turn the gate off for whole modules while still looking
    green. Suppressions must be per-error-code and justified."""
    cfg = tomllib.loads(_read(PYPROJECT))
    mypy = cfg["tool"]["mypy"]
    assert "ignore_errors" not in mypy, "[tool.mypy] must not set ignore_errors globally"
    for override in mypy.get("overrides", []):
        assert not override.get("ignore_errors"), (
            f"per-module ignore_errors disables the gate for {override.get('module')} -- "
            "disable specific error codes instead"
        )
        # A suppression must name the codes it suppresses.
        if "disable_error_code" in override:
            assert override["disable_error_code"], "empty disable_error_code list"


def test_overrides_are_narrow_and_named():
    """Every suppression targets NAMED modules, never a wildcard over the whole app."""
    cfg = tomllib.loads(_read(PYPROJECT))
    for override in cfg["tool"]["mypy"].get("overrides", []):
        modules = override.get("module")
        modules = [modules] if isinstance(modules, str) else (modules or [])
        for m in modules:
            assert m != "*", "a wildcard override disables the gate everywhere"
            assert not m.startswith("apps.api.*"), f"override {m!r} is too broad"
            # `apps.api.tests.*` is the one intentional package-level relaxation.
            if m.endswith(".*"):
                assert m == "apps.api.tests.*", (
                    f"package-wide override {m!r} is too broad; name the modules"
                )


def test_type_checker_is_pinned_in_dev_requirements():
    req = _read(REQ_DEV)
    assert re.search(r"^mypy==\d+\.\d+", req, re.M), (
        "mypy must be pinned in requirements-dev.txt -- CI installs the gate from there"
    )


# --------------------------------------------------------------------------------------------
# CI wiring -- a gate nobody runs is not a gate.
# --------------------------------------------------------------------------------------------

def test_ci_runs_the_type_checker():
    ci = _read(CI)
    assert re.search(r"^\s*run:\s*mypy\b", ci, re.M), (
        "CI must execute mypy; configuring it without running it changes nothing"
    )


def test_ci_lint_covers_scripts():
    ci = _read(CI)
    assert re.search(r"ruff check .*\bscripts\b", ci), (
        "CI's ruff step must include scripts/ (AUDIT-013)"
    )


def test_static_analysis_steps_are_blocking():
    """`continue-on-error: true` on these steps would make the gate advisory."""
    yaml = pytest.importorskip("yaml")
    doc = yaml.safe_load(_read(CI))
    lint = doc["jobs"]["lint"]
    assert not lint.get("continue-on-error"), "the lint job must be blocking"
    for step in lint["steps"]:
        run = str(step.get("run", ""))
        if "mypy" in run or "ruff check" in run:
            assert not step.get("continue-on-error"), (
                f"static-analysis step {step.get('name')!r} is non-blocking"
            )


# --------------------------------------------------------------------------------------------
# The gate actually passes on this tree.
# --------------------------------------------------------------------------------------------

def test_ruff_is_clean_including_scripts():
    if shutil.which("ruff") is None:
        try:
            import ruff  # noqa: F401
        except ImportError:
            pytest.skip("ruff not installed in this environment")
    proc = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "apps/api", "scripts"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0, f"ruff reported problems:\n{proc.stdout[-3000:]}"


def test_mypy_is_clean():
    """The gate must be GREEN on the current tree -- otherwise it cannot be made blocking."""
    try:
        import mypy  # noqa: F401
    except ImportError:
        pytest.skip("mypy not installed in this environment (pip install -r requirements-dev.txt)")
    proc = subprocess.run(
        [sys.executable, "-m", "mypy"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0, (
        "mypy reported errors -- the CI gate would fail:\n" + proc.stdout[-4000:]
    )


def test_the_gdpr_export_schema_bug_stays_fixed():
    """Regression lock for the real defect the type gate found on introduction:
    ExportedEngagementState.approval_state must accept the dict the model actually stores."""
    import datetime
    import uuid

    from apps.api.modules.workspaces.tenant_schemas import ExportedEngagementState

    model = ExportedEngagementState(
        id=uuid.uuid4(), scan_id=uuid.uuid4(), status="running", current_phase="recon",
        objective="obj", approval_state={"approved": True, "by": "user-1"},
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    assert model.approval_state == {"approved": True, "by": "user-1"}
    # The column default is `dict`, so the empty dict must round-trip too.
    empty = ExportedEngagementState(
        id=uuid.uuid4(), scan_id=uuid.uuid4(), status="s", current_phase="p", objective=None,
        approval_state={}, created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    assert empty.approval_state == {}
