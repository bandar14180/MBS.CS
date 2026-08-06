"""M4.6.3 / T3 -- runner execution boundary guard.

Security invariant: every SCAN-TIME tool execution must go through
orchestrator._run_single_tool, where SSRF (net_guard), authorization scope
(scope_guard, fail-closed) and safety-tier/RoE are enforced. The only sanctioned
exception is doctor.py -- a CLI health check that runs hardcoded, env-configured safe
hosts with empty prior findings and is never wired into the API.

This test detects any NEW `runner.run(` execution site (a potential bypass) without
depending on line numbers or exact formatting. If a new legitimate execution path is
added, it must (a) route through _run_single_tool, or (b) be added here consciously
with a security review.
"""
import re
from pathlib import Path

_API_DIR = Path(__file__).resolve().parents[1]          # apps/api
_SCANNER_DIR = _API_DIR / "scanner_engine"

# A call that INVOKES a runner instance (not a runner method *definition*).
_RUNNER_CALL = re.compile(r"\brunner\.run\(")


def _runner_execution_files() -> dict[str, int]:
    """Map {filename: count} of files under scanner_engine that invoke `runner.run(`.
    Skips comment lines and runner method definitions (`def run` / `async def run`)."""
    hits: dict[str, int] = {}
    for py in _SCANNER_DIR.rglob("*.py"):
        for raw in py.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line.startswith("#") or line.startswith(("def run", "async def run")):
                continue
            if _RUNNER_CALL.search(line):
                hits[py.name] = hits.get(py.name, 0) + 1
    return hits


def test_t3_runner_execution_sites_are_the_known_two():
    files = set(_runner_execution_files())
    assert files == {"orchestrator.py", "doctor.py"}, (
        f"Unexpected runner execution site(s): {sorted(files)}. Every scan-time "
        "runner.run() must route through orchestrator._run_single_tool (scope/SSRF/"
        "safety enforced); doctor.py is the CLI health-check exception. A new site "
        "requires a security review before this guard is updated."
    )


def test_t3_orchestrator_runner_call_is_scope_filtered():
    # The orchestrator's runner.run receives the SCOPE-FILTERED list (scoped_prior),
    # never the raw prior_findings -- the enforcement boundary is intact.
    src = (_SCANNER_DIR / "orchestrator.py").read_text(encoding="utf-8")
    assert re.search(r"runner\.run\(\s*target_value\s*,\s*config\s*,\s*scoped_prior\s*\)", src)
    assert "runner.run(target_value, config, prior_findings)" not in src  # never the unfiltered list


def test_t3_doctor_targets_are_env_constants_and_not_api_wired():
    doctor_src = (_SCANNER_DIR / "doctor.py").read_text(encoding="utf-8")
    # doctor targets come from the environment (operator-controlled), never user input.
    assert "os.environ.get(" in doctor_src
    # doctor runs with NO prior findings (no derived-asset probing).
    assert re.search(r"runner\.run\(\s*target\s*,\s*config\s*,\s*\[\]\s*\)", doctor_src)
    # doctor is not referenced by any API router or the app entrypoint.
    for router in (_API_DIR / "modules").rglob("router.py"):
        assert "doctor" not in router.read_text(encoding="utf-8"), f"doctor referenced in {router}"
    assert "run_doctor" not in (_API_DIR / "main.py").read_text(encoding="utf-8")
