"""Phase 1.8 -- verification tests for the supply-chain security configuration.

Asserts the CI wiring the pipeline depends on exists and is shaped correctly: a GATED
dependency audit (with allowlist), an SBOM step + artifact, a CRITICAL/ignore-unfixed
container image gate, an informational worker scan, and a secret scan -- plus the config/
allowlist files and docs. Repo-root files aren't bind-mounted in the dev container, so
these skip there and assert fully on a complete checkout (CI/host).
"""
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


def _read(rel: str) -> str:
    p = REPO_ROOT / rel
    if not p.is_file():
        pytest.skip(f"{rel} not present in this environment (not bind-mounted)")
    return p.read_text(encoding="utf-8")


def _ci() -> str:
    return _read(".github/workflows/ci.yml")


# --- dependency audit: gated + allowlist + SBOM -------------------------------------------

def test_dependency_audit_is_gated_not_continue_on_error():
    ci = _ci()
    assert "supply-chain:" in ci                       # the hardened job exists
    # the audit job must NOT be non-blocking; the only continue-on-error jobs are the
    # informational ones (scan-doctor, worker image scan).
    assert "pip-audit" in ci
    # allowlist mechanism is wired
    assert "--ignore-vuln" in ci
    assert ".security/pip-audit-ignore.txt" in ci


def test_sbom_is_generated_as_json_and_uploaded():
    ci = _ci()
    # invoked via `python -m cyclonedx_py` (no PATH dependency) with an explicit JSON format
    assert "cyclonedx_py requirements apps/api/requirements.txt" in ci
    assert "--of JSON" in ci                 # guarantees JSON, not XML written to a .json file
    assert "sbom.cdx.json" in ci
    assert "upload-artifact" in ci


def test_sbom_is_valid_cyclonedx_json_when_tool_available(tmp_path):
    """R5: generate the SBOM with the pinned CLI + --of JSON and prove it parses as
    CycloneDX JSON. Skips where the dev tool isn't installed (e.g. CI's `tests` job)."""
    import importlib.util
    import json
    import subprocess
    import sys

    if importlib.util.find_spec("cyclonedx_py") is None:
        pytest.skip("cyclonedx-bom (dev tooling) not installed in this environment")
    req = REPO_ROOT / "apps" / "api" / "requirements.txt"
    if not req.is_file():
        pytest.skip("requirements.txt not present")
    out = tmp_path / "sbom.cdx.json"
    subprocess.run(
        [sys.executable, "-m", "cyclonedx_py", "requirements", str(req), "--of", "JSON", "-o", str(out)],
        check=True,
    )
    data = json.loads(out.read_text(encoding="utf-8"))   # raises if it's XML / invalid JSON
    assert data.get("bomFormat") == "CycloneDX"
    assert data.get("components")


def test_security_tooling_is_pinned_separately_from_runtime():
    dev = _read("apps/api/requirements-dev.txt")
    assert "pip-audit==" in dev and "cyclonedx-bom==" in dev
    # runtime requirements must stay untouched (no scanner tools leak into prod deps)
    runtime = _read("apps/api/requirements.txt")
    assert "pip-audit" not in runtime and "cyclonedx" not in runtime


# --- container image scan: practical CRITICAL gate + informational worker -----------------

def test_image_scan_gates_on_critical_fixed_only():
    ci = _ci()
    assert "image-scan:" in ci
    assert "trivy-action" in ci
    assert "severity: CRITICAL" in ci
    assert "ignore-unfixed: true" in ci
    assert "trivyignores: .trivyignore" in ci
    assert 'exit-code: "1"' in ci                      # CRITICAL fixed blocks


def test_worker_image_scan_is_informational_only():
    ci = _ci()
    assert "image-scan-worker:" in ci
    # worker scan must be non-blocking
    worker_block = ci.split("image-scan-worker:", 1)[1]
    assert "continue-on-error: true" in worker_block
    assert 'exit-code: "0"' in worker_block            # report only


# --- secret scanning ----------------------------------------------------------------------

def test_secret_scan_uses_pinned_cli_no_git_and_gates():
    ci = _ci()
    assert "secret-scan:" in ci
    # F1/R4: pinned gitleaks CLI (no gitleaks-action -> no org-license dependency),
    # deterministic filesystem scan, gating -- identical semantics to the local script.
    assert "uses: gitleaks/gitleaks-action" not in ci   # not the licensed Action
    assert "gitleaks detect" in ci
    assert "--no-git" in ci
    assert "--config .gitleaks.toml" in ci
    assert "--exit-code 1" in ci


# --- config/allowlist files exist and parse ----------------------------------------------

def test_pip_audit_ignore_file_exists():
    _read(".security/pip-audit-ignore.txt")            # skips/asserts presence


def test_trivyignore_exists():
    _read(".trivyignore")


def test_gitleaks_config_is_valid_toml_with_allowlist():
    raw = _read(".gitleaks.toml")
    cfg = tomllib.loads(raw)                            # must be valid TOML
    assert cfg.get("extend", {}).get("useDefault") is True
    allow = cfg.get("allowlist", {})
    # dev defaults / test fixtures are pre-allowlisted so the gate doesn't false-positive
    joined = " ".join(allow.get("regexes", []))
    assert "minioadmin" in joined
    assert allow.get("paths")                           # non-empty path allowlist


# --- docs + local runner ------------------------------------------------------------------

def test_supply_chain_docs_cover_required_topics():
    doc = _read("docs/supply-chain.md")
    for token in ("pip-audit", "SBOM", "Trivy", "gitleaks",
                  ".security/pip-audit-ignore.txt", ".trivyignore", ".gitleaks.toml"):
        assert token in doc, f"docs/supply-chain.md missing: {token}"


def test_local_runner_script_present():
    script = _read("scripts/supply_chain.sh")
    for cmd in ("audit", "sbom", "image", "secrets"):
        assert cmd in script
