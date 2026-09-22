"""Guard: the frontend's view of the scanner pipeline may not drift from TOOL_REGISTRY.

The bug this prevents actually happened. `amass`, `dnsx`, `whatweb` and `ffuf` were
registered in TOOL_REGISTRY, installed by Dockerfile.worker, and fully implemented --
but three separate hardcoded tool lists in the web app had never been updated for them:

  * ScansTab.tsx    `MODULES`      (8 of 12) -> they could not be selected for a scan
  * SchedulesPanel  `MODULES`      (5 of 12) -> they could not be scheduled
  * ScanProgress    `PHASE_ORDER`  (8 of 12) -> `stages = PHASE_ORDER.filter(...)` threw
                                                away their ToolRun rows, so even a
                                                successful run -- or a hard failure --
                                                was invisible in the pipeline widget.

The tool lists now come from GET /scan-capabilities/pipeline at runtime. What remains
in the frontend is a static FALLBACK_PIPELINE (used for the first paint / an API that
isn't up yet) and a display-label map; both are checked here so the drift cannot come
back silently. These are text assertions rather than a JS import because there is no
node toolchain in the Python test run.
"""
import json
import re
from pathlib import Path

import pytest

from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY
from apps.api.scanner_engine.tool_runners.base import BaseToolRunner

_WEB = Path(__file__).resolve().parents[3] / "apps" / "web"
_PIPELINE_TS = _WEB / "lib" / "pipeline.ts"
_SCAN_PROGRESS = _WEB / "components" / "project" / "ScanProgress.tsx"
_SCANS_TAB = _WEB / "components" / "project" / "ScansTab.tsx"
_SCHEDULES = _WEB / "components" / "project" / "SchedulesPanel.tsx"

# The API/worker images copy only `apps/api`, so these files genuinely do not exist when
# the suite is run inside one of those containers. That is not a drift failure -- skip
# rather than report one. On a full checkout (CI, and any local run) the guard is live.
pytestmark = pytest.mark.skipif(
    not _PIPELINE_TS.exists(), reason="apps/web is not present in this environment (API/worker image)"
)


def _fallback_entries() -> dict[str, int]:
    """{tool name: phase} parsed out of FALLBACK_PIPELINE's `f("name", phase, ...)` rows."""
    src = _PIPELINE_TS.read_text(encoding="utf-8")
    block = src.split("FALLBACK_PIPELINE", 1)[1].split("];", 1)[0]
    return {name: int(phase) for name, phase in re.findall(r'f\("([^"]+)",\s*(\d+)', block)}


def test_fallback_pipeline_matches_tool_registry():
    fallback = _fallback_entries()
    expected = {name: cls.phase for name, cls in TOOL_REGISTRY.items()}
    assert fallback == expected, (
        "apps/web/lib/pipeline.ts FALLBACK_PIPELINE has drifted from TOOL_REGISTRY.\n"
        f"  missing from the frontend: {sorted(set(expected) - set(fallback))}\n"
        f"  unknown to the backend:    {sorted(set(fallback) - set(expected))}\n"
        f"  phase mismatches:          "
        f"{ {k: (fallback.get(k), expected.get(k)) for k in set(fallback) & set(expected) if fallback[k] != expected[k]} }\n"
        "Registering a tool must also add it here (one line), or the UI's pre-fetch render "
        "and its offline fallback silently omit it."
    )


def test_fallback_active_testing_flags_match_the_runners():
    """`requires_active_testing` decides whether the scan form tags a tool as needing an
    authorization scope. A frontend copy that disagrees with the runner either hides a
    gate the backend enforces (a confusing 403 at scan creation) or invents one."""
    src = _PIPELINE_TS.read_text(encoding="utf-8")
    block = src.split("FALLBACK_PIPELINE", 1)[1].split("];", 1)[0]
    rows = re.findall(r'f\("([^"]+)",\s*\d+,\s*"[^"]*",\s*"[^"]*",\s*(true|false)', block)
    declared = {name: flag == "true" for name, flag in rows}
    expected = {name: cls.requires_active_testing for name, cls in TOOL_REGISTRY.items()}
    assert declared == expected


def test_fallback_vulnerability_producers_match_the_runners():
    """Only a runner that overrides parse_vulnerabilities can ever write a Vulnerability
    row; the UI uses this to explain why a recon-only scan reports zero vulnerabilities.
    Getting it wrong would tell the user the opposite of the truth."""
    src = _PIPELINE_TS.read_text(encoding="utf-8")
    block = src.split("FALLBACK_PIPELINE", 1)[1].split("];", 1)[0]
    declared = {
        name for name in _fallback_entries() if re.search(rf'f\("{re.escape(name)}",[^\n]*,\s*true\)', block)
    }
    expected = {
        name
        for name, cls in TOOL_REGISTRY.items()
        if cls.parse_vulnerabilities is not BaseToolRunner.parse_vulnerabilities
    }
    assert declared == expected


def test_scan_progress_has_a_label_for_every_registered_tool():
    """A tool with no STAGES entry still renders (it falls back to its raw name), but the
    pipeline widget is the primary place a user reads per-tool success/failure, so every
    registered tool gets a real, translated label."""
    src = _SCAN_PROGRESS.read_text(encoding="utf-8")
    block = src.split("const STAGES", 1)[1].split("};", 1)[0]
    labelled = set(re.findall(r'^\s*"?([a-z][a-z0-9-]*)"?:\s*\{\s*key:', block, re.M))
    assert set(TOOL_REGISTRY) <= labelled, (
        f"ScanProgress.tsx STAGES is missing labels for: {sorted(set(TOOL_REGISTRY) - labelled)}"
    )


def test_stage_labels_exist_in_the_english_dictionary():
    """English is the fallback for every locale, so a missing key there renders the raw
    dotted key to the user in all seven languages."""
    src = _SCAN_PROGRESS.read_text(encoding="utf-8")
    keys = set(re.findall(r'key:\s*"(scans\.[A-Za-z0-9_]+)"', src))
    en = json.loads((_WEB / "locales" / "en.json").read_text(encoding="utf-8"))
    missing = [k for k in sorted(keys) if k.split(".", 1)[1] not in en.get("scans", {})]
    assert not missing, f"stage labels missing from apps/web/locales/en.json: {missing}"


@pytest.mark.parametrize("path", [_SCANS_TAB, _SCHEDULES, _SCAN_PROGRESS])
def test_no_component_reintroduces_a_hardcoded_tool_list(path: Path):
    """The failure mode was a literal array of tool names inside a component. Selection
    defaults (DEFAULT_MODULES) are legitimately local -- a *catalogue* of every tool is
    not, because it is the thing that goes stale."""
    src = path.read_text(encoding="utf-8")
    for match in re.finditer(r"\[((?:\s*\"[a-z][a-z0-9-]*\"\s*,?)+)\]", src):
        names = set(re.findall(r'"([^"]+)"', match.group(1)))
        overlap = names & set(TOOL_REGISTRY)
        assert not (len(overlap) >= 6 and overlap != set(TOOL_REGISTRY)), (
            f"{path.name} contains a hardcoded partial tool list {sorted(names)}. "
            "Read the tool list from usePipeline() (lib/pipeline.ts) instead -- a literal "
            "list here goes stale the next time a runner is registered."
        )


def test_every_registered_runner_declares_its_binary():
    """tool_preflight resolves `binary` on PATH to tell 'not installed' apart from 'found
    nothing'. A runner that leaves it blank silently falls back to its tool name, which is
    wrong for httpx (installed as `httpx-pd`) and nuclei-dast (drives `nuclei`)."""
    missing = [name for name, cls in TOOL_REGISTRY.items() if not cls.binary]
    assert not missing, f"runners with no `binary` declared: {sorted(missing)}"


def test_doctor_covers_every_registered_tool():
    """scanner_engine.doctor is the codebase's own answer to 'did this tool actually run'.
    It covered 8 of 12 tools; a registered tool with no check must fail the run, not be
    quietly skipped."""
    from apps.api.scanner_engine.doctor import uncovered_tools

    assert uncovered_tools() == [], f"tools with no doctor check: {uncovered_tools()}"
