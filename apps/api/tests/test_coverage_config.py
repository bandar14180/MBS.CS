"""Phase 1.7 -- verification tests for the coverage/CI gate configuration itself.

Asserts the coverage tooling is wired the way the pipeline depends on: the pyproject
coverage config (source, branch, fail_under=80) and the CI workflow (coverage run +
--cov-fail-under + artifact upload). Repo-root files aren't bind-mounted in the dev
container, so these skip there and assert fully on a complete checkout (CI/host).
"""
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_THRESHOLD = 80


def _load_pyproject() -> dict:
    p = REPO_ROOT / "pyproject.toml"
    if not p.is_file():
        pytest.skip("pyproject.toml not present in this environment (not bind-mounted)")
    return tomllib.loads(p.read_text(encoding="utf-8"))


def test_coverage_config_loads_and_targets_the_app():
    cfg = _load_pyproject()
    run = cfg["tool"]["coverage"]["run"]
    assert "apps/api" in run["source"]
    assert run["branch"] is True          # branch coverage -> a meaningful gate


def test_coverage_threshold_is_eighty_and_parses_as_int():
    cfg = _load_pyproject()
    fail_under = cfg["tool"]["coverage"]["report"]["fail_under"]
    assert int(fail_under) == DEFAULT_THRESHOLD   # threshold is a parseable integer == 80


def test_coverage_reports_are_configured():
    cfg = _load_pyproject()
    cov = cfg["tool"]["coverage"]
    assert cov["html"]["directory"] == "htmlcov"
    assert cov["xml"]["output"] == "coverage.xml"


def test_pytest_cov_is_a_declared_dependency():
    req = REPO_ROOT / "apps" / "api" / "requirements.txt"
    if not req.is_file():
        pytest.skip("requirements.txt not present in this environment")
    assert "pytest-cov" in req.read_text(encoding="utf-8")


def test_ci_workflow_enforces_and_uploads_coverage():
    wf = REPO_ROOT / ".github" / "workflows" / "ci.yml"
    if not wf.is_file():
        pytest.skip(".github not present in this environment (not bind-mounted)")
    text = wf.read_text(encoding="utf-8")
    assert "--cov=apps/api" in text
    assert "--cov-fail-under" in text            # the gate
    assert "coverage.xml" in text and "htmlcov" in text   # artifacts
    assert "upload-artifact" in text
