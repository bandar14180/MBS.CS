"""Phase 1.8 -- verification tests for the supply-chain security configuration.

Asserts the CI wiring the pipeline depends on exists and is shaped correctly: a GATED
dependency audit (with allowlist), an SBOM step + artifact, a CRITICAL/ignore-unfixed
container image gate, an informational worker scan, and a secret scan -- plus the config/
allowlist files and docs. Repo-root files aren't bind-mounted in the dev container, so
these skip there and assert fully on a complete checkout (CI/host).
"""
import re
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


# --- F-03: the worker image gate is BLOCKING ---------------------------------------------
# These replace `test_worker_image_scan_is_informational_only`, which asserted the OPPOSITE --
# it required `continue-on-error: true` and `exit-code: "0"` to be present, so the vulnerable
# posture was locked in by the suite and the correct fix would have failed CI.


def _worker_scan_block() -> str:
    """The `image-scan-worker` job only, up to the next top-level job."""
    ci = _ci()
    assert "image-scan-worker:" in ci, "the worker image scan job is missing entirely"
    after = ci.split("image-scan-worker:", 1)[1]
    return after.split("\n  scan-doctor", 1)[0]


def _worker_gate_step() -> str:
    """Just the GATING Trivy step, excluding the informational report step that follows it.
    The distinction matters: the report step legitimately carries exit-code "0"."""
    block = _worker_scan_block()
    return block.split("- name: Trivy report", 1)[0]


def test_worker_image_scan_is_blocking():
    """F-03 CORE. The worker image runs the scanner binaries and is what `worker`,
    `worker-default` and `beat` execute in production; it must gate like the api image."""
    assert "continue-on-error" not in _worker_scan_block(), (
        "image-scan-worker must not be continue-on-error -- that neutralizes the gate "
        "regardless of Trivy's exit code"
    )


def test_worker_gate_step_uses_a_failing_exit_code():
    step = _worker_gate_step()
    assert 'exit-code: "1"' in step, "the worker gating scan must fail the job on a finding"
    assert 'exit-code: "0"' not in step, (
        "exit-code 0 on the GATING step converts every finding into a pass"
    )


def test_worker_severity_policy_matches_the_api_gate():
    """One project-wide meaning for 'blocks CI'. Both images gate on CRITICAL + fixed."""
    step = _worker_gate_step()
    assert "severity: CRITICAL" in step
    assert "severity: HIGH,CRITICAL" not in step, (
        "HIGH must not be the BLOCKING bar for the worker image (it is still reported); "
        "see the policy rationale in ci.yml"
    )
    assert "ignore-unfixed: true" in step
    assert "trivyignores: .trivyignore" in step


def test_worker_scan_has_no_escape_hatch():
    """No shell-level neutralizer may be smuggled into the worker scan job.

    Comment lines are stripped first: the rationale comments in ci.yml legitimately discuss
    `exit 0`, and matching prose would make this test fail on its own documentation."""
    executable = "\n".join(
        ln for ln in _worker_scan_block().splitlines() if not ln.strip().startswith("#")
    )
    for escape in ("|| true", "|| :", "set +e", "exit 0", "|| echo"):
        assert escape not in executable, (
            f"worker scan job contains an escape hatch: {escape!r}"
        )


def test_worker_high_findings_are_still_reported():
    """Gating on CRITICAL must not mean HIGH becomes invisible."""
    block = _worker_scan_block()
    assert "severity: HIGH,CRITICAL" in block, "HIGH must still be reported informationally"
    assert "trivy-worker-report.json" in block, "the worker report must be uploaded"


def test_scan_doctor_preflight_is_blocking_and_offline():
    """F-03: the deterministic half of the doctor gates; only the live-egress half does not."""
    ci = _ci()
    assert "scan-doctor-preflight:" in ci
    block = ci.split("scan-doctor-preflight:", 1)[1].split("\n  scan-doctor:", 1)[0]
    assert "continue-on-error" not in block, "the preflight check must block"
    assert "--preflight-only" in block
    assert "--network none" in block, (
        "preflight must run without egress, proving CI flakiness is not a reason to weaken it"
    )


def test_local_gate_scans_the_worker_image_with_ci_policy():
    """F-03: local verification must not be weaker than CI."""
    sh = _read("scripts/supply_chain.sh")
    assert "Dockerfile.worker" in sh, "the local gate must build the worker image"
    assert "mbs-worker:local" in sh, "the local gate must scan the worker image"
    worker_line = next(
        (ln for ln in sh.splitlines() if "trivy image" in ln and "mbs-worker:local" in ln), ""
    )
    assert worker_line, "no trivy invocation for the worker image"
    for required in ("--severity CRITICAL", "--ignore-unfixed", "--exit-code 1", ".trivyignore"):
        assert required in worker_line, f"local worker scan is missing {required}"


def test_trivyignore_entries_are_individually_justified():
    """A `.trivyignore` entry is an accepted RISK, so each needs a reason and a review date --
    and it must be a specific CVE, never a blanket suppression."""
    raw = _read(".trivyignore")
    entries = [ln.strip() for ln in raw.splitlines()
               if ln.strip() and not ln.strip().startswith("#")]
    for entry in entries:
        assert re.fullmatch(r"(CVE-\d{4}-\d+|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})", entry), (
            f"{entry!r} is not a specific advisory id -- blanket/wildcard suppression is not allowed"
        )
    # every id must be documented in a comment somewhere in the file
    comments = "\n".join(ln for ln in raw.splitlines() if ln.strip().startswith("#"))
    for entry in entries:
        assert entry in comments, f"{entry} is suppressed without a documented justification"
    if entries:
        assert "Review by:" in comments or "review by" in comments.lower(), (
            "suppressions must carry a review date"
        )


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


# --- F-02: scanner binaries are integrity-verified at build time --------------------------
# F-02 (HIGH, supply chain): infra/docker/Dockerfile.worker pulled katana, amass, ffuf and
# five ProjectDiscovery tools straight from GitHub release URLs and ran them, with no
# checksum or signature check anywhere. Every one of those binaries executes against
# customer infrastructure, so a replaced artifact -- a compromised release, a hijacked
# account, a MITM on the build host -- would have shipped straight into production with the
# build passing green. These tests make that failure mode impossible to reintroduce quietly.

DOCKERFILE_WORKER = "infra/docker/Dockerfile.worker"

# Every tool the worker image installs from a GitHub release archive, with the build ARG
# holding its pinned digest. Keep in lockstep with the Dockerfile.
_VERIFIED_TOOLS = {
    "naabu": "NAABU_SHA256",
    "subfinder": "SUBFINDER_SHA256",
    "httpx": "HTTPX_SHA256",
    "nuclei": "NUCLEI_SHA256",
    "dnsx": "DNSX_SHA256",
    "katana": "KATANA_SHA256",
    "amass": "AMASS_SHA256",
    "ffuf": "FFUF_SHA256",
}


def _worker_dockerfile() -> str:
    return _read(DOCKERFILE_WORKER)


def _download_lines() -> list:
    """Every line that fetches a GitHub RELEASE ARCHIVE."""
    return [
        ln for ln in _worker_dockerfile().splitlines()
        if "releases/download" in ln and "curl" in ln
    ]


def test_every_tool_pins_an_exact_version():
    """No floating tag: each tool's URL interpolates a version ARG pinned to an exact
    release, so `docker build` twice a year apart fetches the same bytes."""
    df = _worker_dockerfile()
    for tool in _VERIFIED_TOOLS:
        arg = f"{tool.upper()}_VERSION"
        m = re.search(rf"^ARG {arg}=(\S+)$", df, re.M)
        assert m, f"{tool} has no pinned {arg}"
        assert re.fullmatch(r"[0-9]+(\.[0-9]+)*", m.group(1)), \
            f"{arg}={m.group(1)!r} is not an exact version"


def test_every_tool_pins_a_sha256_digest():
    """A version pin alone is NOT integrity: a tag can be moved and a release asset can be
    re-uploaded. The digest is what actually binds the build to specific bytes."""
    df = _worker_dockerfile()
    for tool, arg in _VERIFIED_TOOLS.items():
        m = re.search(rf"^ARG {arg}=([0-9a-f]+)$", df, re.M)
        assert m, f"{tool} has no pinned {arg}"
        assert len(m.group(1)) == 64, f"{arg} is not a 64-hex-char SHA-256"


def test_every_release_download_is_verified_before_use():
    """THE CORE ASSERTION. Each downloaded archive must be checksum-verified, and the
    verification must come BEFORE the unpack/install that consumes it -- verifying after
    extraction would already have written attacker-controlled bytes to disk."""
    lines = _worker_dockerfile().splitlines()
    for idx, line in enumerate(lines):
        if "releases/download" not in line or "curl" not in line:
            continue
        m = re.search(r"-o (/tmp/\S+)", line)
        assert m, f"cannot determine output path for: {line.strip()}"
        archive = m.group(1)
        following = "\n".join(lines[idx + 1: idx + 4])
        assert "sha256sum -c" in following, \
            f"{archive} is downloaded but never checksum-verified"
        verify_at = next(i for i, ln in enumerate(lines[idx + 1: idx + 4]) if "sha256sum -c" in ln)
        consume_at = next(
            (i for i, ln in enumerate(lines[idx + 1: idx + 4])
             if ("unzip" in ln or "tar -xzf" in ln) and archive in ln),
            None,
        )
        if consume_at is not None:
            assert verify_at < consume_at, \
                f"{archive} is unpacked before it is verified"


def test_download_and_verification_counts_match():
    """A new tool added without a digest would slip through per-line checks if someone also
    removed its download; this pins the totals so the two can never diverge."""
    df = _worker_dockerfile()
    downloads = len(_download_lines())
    verifications = len([
        ln for ln in df.splitlines()
        if "sha256sum -c" in ln and not ln.strip().startswith("#")
    ])
    assert downloads == len(_VERIFIED_TOOLS), \
        f"expected {len(_VERIFIED_TOOLS)} release downloads, found {downloads}"
    assert verifications == downloads, \
        f"{downloads} downloads but {verifications} verifications -- every fetch needs one"


def test_no_unverified_fallback_path():
    """A `|| true`, `|| echo`, or `--continue-on-error` around a verification would turn the
    gate into a warning. None may exist on any checksum line."""
    for line in _worker_dockerfile().splitlines():
        if "sha256sum" in line and not line.strip().startswith("#"):
            for escape in ("|| true", "|| :", "||true", "; true", "|| echo"):
                assert escape not in line, f"verification has an escape hatch: {line.strip()}"


def test_no_floating_latest_download_urls():
    """`releases/latest` or a branch archive would make the pinned digest unsatisfiable and
    reintroduce silent drift."""
    df = _worker_dockerfile()
    for bad in ("releases/latest", "/archive/refs/heads/", "@master", "@main"):
        assert bad not in df, f"floating reference {bad!r} in the worker image"


def test_downloaded_archives_are_removed_after_install():
    """The archives are build-time only; leaving them in a layer bloats the image and keeps
    an unverified-looking copy around for later steps to pick up."""
    df = _worker_dockerfile()
    for tool in _VERIFIED_TOOLS:
        assert f"/tmp/{tool}*" in df or f"rm -f /tmp/{tool}" in df, \
            f"{tool}'s downloaded archive is never cleaned up"


def test_binary_integrity_is_documented():
    """The digest-pinning rationale and the version-bump procedure must stay documented:
    the control is only durable if the next person bumping a version knows to bump the
    digest with it."""
    doc = _read("docs/supply-chain.md")
    assert "Scanner binary integrity" in doc
    assert "sha256sum" in doc
    for tool in _VERIFIED_TOOLS:
        assert tool in doc, f"{tool} is not listed in the supply-chain doc"


# --- Raw-SQL inventory drift gate ---------------------------------------------------------
# apps/api/core/tenancy.py auto-filters every ORM query by workspace; raw SQL bypasses that
# filter, so for those statements the INVENTORY IS THE CONTROL. It used to be a prose table in
# mysql-migration-phase0.md claiming "9 sites" while the tree held 26 -- silent drift, exactly
# as that document predicted. These tests run the same scanner CI runs, so drift fails locally
# too rather than only at push time.

def _inventory_module():
    """Import scripts/raw_sql_inventory.py by path (scripts/ is not a package)."""
    import importlib.util

    script = REPO_ROOT / "scripts" / "raw_sql_inventory.py"
    if not script.is_file():
        pytest.skip("scripts/raw_sql_inventory.py not present (repo root not bind-mounted)")
    spec = importlib.util.spec_from_file_location("raw_sql_inventory", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_raw_sql_inventory_has_no_drift():
    """THE GATE. Every production raw-SQL site is registered, and every registered entry
    still exists. A new statement -- or a registered one that moved -- fails here."""
    _read("docs/architecture/raw-sql-inventory.yml")   # skips if not bind-mounted
    mod = _inventory_module()
    actual = {(s["file"], s["line"]) for s in mod.scan()}
    registered = {(f, ln) for f, lines in mod.load_inventory().items() for ln in lines}

    unregistered = sorted(actual - registered)
    missing = sorted(registered - actual)
    assert not unregistered, (
        "unregistered production raw SQL (bypasses the ORM tenancy filter) -- review it, give "
        "any tenant-scoped statement an explicit workspace predicate, then register it in "
        f"docs/architecture/raw-sql-inventory.yml: {unregistered}"
    )
    assert not missing, (
        "inventory entries point at locations that no longer hold raw SQL (removed or moved) "
        f"-- update docs/architecture/raw-sql-inventory.yml: {missing}"
    )


def test_raw_sql_scanner_excludes_schema_defaults_and_tests():
    """The scanner must not be a substring grep: `server_default=text("CURRENT_TIMESTAMP(6)")`
    is DDL, not a query, and test fixtures are not a production tenancy surface. Getting this
    wrong would bury the real statements under ~47 false positives."""
    mod = _inventory_module()
    sites = mod.scan()
    for s in sites:
        assert "server_default" not in s["snippet"], f"schema default leaked in: {s}"
        assert "/tests/" not in s["file"], f"test file leaked in: {s}"
    assert sites, "the scanner found nothing at all -- detection is broken"


def test_raw_sql_inventory_entries_are_classified():
    """An entry without a classification is an unreviewed entry. Each registered line must
    carry one of the documented categories."""
    raw = _read("docs/architecture/raw-sql-inventory.yml")
    categories = ("TENANT_SCOPED", "SYSTEM_SCOPED", "GLOBAL", "INFRASTRUCTURE")
    entry_lines = [
        ln for ln in raw.splitlines()
        if ln.strip().startswith("- ") and ln.strip()[2:].split()[0].rstrip(":").isdigit()
    ]
    assert entry_lines, "inventory has no entries"
    for ln in entry_lines:
        assert any(c in ln for c in categories), f"inventory entry is unclassified: {ln.strip()}"


def test_raw_sql_gate_is_wired_into_ci():
    ci = _ci()
    assert "raw_sql_inventory.py --check" in ci, "the raw-SQL gate must run in CI"
