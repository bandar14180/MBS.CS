"""Nuclei-DAST hardening: budget validation and template provenance (Prompt 25).

Complements the existing nuclei suites rather than repeating them --
test_nuclei_execution_safety covers argv/scope/cancellation, test_nuclei_parser_robustness
covers output handling, test_nuclei_timeout covers the signature runner's timeout knobs, and
test_nuclei_detection_boundary covers the detection/verification line. What is pinned HERE is
the DAST runner's own two gaps:

  * `tool_config.dast_timeout_seconds` is key-allowlisted but its VALUE was unvalidated. A
    non-numeric value reached `run_with_timeout` and raised an opaque TypeError AFTER nuclei
    had already been spawned -- recorded as a mystery tool failure with a live subprocess on
    the error path. It is now refused BEFORE the process is created, mirroring the existing
    `nuclei_tags` contract in NucleiRunner.
  * TEMPLATE PROVENANCE. `-templates <dir>` names where templates came from but not WHICH
    set ran, so two runs that differ only because the template checkout moved were
    indistinguishable in the audit trail. The set is now reported as an OBSERVED fact read
    from the checkout, or "unknown" -- never guessed.

Both are reporting/validation changes: no finding, severity or classification is affected,
and detection never becomes verification. Fully deterministic -- the subprocess is faked, no
network and no real nuclei binary.
"""

import asyncio
import json

import pytest

from apps.api.scanner_engine.tool_runners import nuclei_dast_runner
from apps.api.scanner_engine.tool_runners.base import CommonFinding, TimedRun
from apps.api.scanner_engine.tool_runners.nuclei_dast_runner import (
    DEFAULT_TIMEOUT_SECONDS,
    NucleiDastRunner,
    _template_provenance,
)


def _crawled(*urls: str) -> list[CommonFinding]:
    """Prior findings shaped like katana's crawled URLs, so the runner has real targets."""
    return [
        CommonFinding(asset_type="url", value=u, metadata={"source": "katana"})
        for u in urls
    ]


def _fake_process(monkeypatch, *, stdout: str = "", stderr: str = "", timed_out: bool = False,
                  exit_code: int = 0) -> dict:
    """Fake the subprocess + timeout layer; record whether a process was spawned and the
    timeout the runner actually asked for."""
    seen: dict = {"spawned": False}

    class _Proc:
        returncode = 0
        stdout = None
        stderr = None
        stdin = None

        def kill(self):
            pass

        async def wait(self):
            return 0

    async def _fake_exec(*args, **_kwargs):
        seen["spawned"] = True
        seen["argv"] = list(args)
        return _Proc()

    async def _fake_run_with_timeout(proc, timeout, tool="", *, stdin=None):
        seen["timeout"] = timeout
        seen["stdin"] = stdin
        return TimedRun(stdout=stdout, stderr=stderr, timed_out=timed_out, exit_code=exit_code)

    monkeypatch.setattr(nuclei_dast_runner.asyncio, "create_subprocess_exec", _fake_exec)
    monkeypatch.setattr(nuclei_dast_runner, "run_with_timeout", _fake_run_with_timeout)
    return seen


def _run(config: dict, monkeypatch, **kwargs):
    seen = _fake_process(monkeypatch, **kwargs)
    raw = asyncio.run(
        NucleiDastRunner().run("example.com", config, _crawled("https://example.com/?q=1"))
    )
    return raw, seen


# --- Budget validation (timeout/resource governance) ------------------------------------------

def test_unconfigured_budget_uses_the_documented_default(monkeypatch):
    _raw, seen = _run({}, monkeypatch)
    assert seen["timeout"] == DEFAULT_TIMEOUT_SECONDS


def test_explicit_numeric_budget_is_honoured(monkeypatch):
    _raw, seen = _run({"dast_timeout_seconds": 30}, monkeypatch)
    assert seen["timeout"] == 30.0


def test_zero_or_negative_budget_means_no_wall_clock_cap(monkeypatch):
    """Consistent with NucleiRunner's policy: <= 0 is 'uncapped', not 'instant timeout'."""
    for value in (0, -1):
        _raw, seen = _run({"dast_timeout_seconds": value}, monkeypatch)
        assert seen["timeout"] is None, value


@pytest.mark.parametrize(
    "bad", ["600", ["600"], {"seconds": 600}, True, False, object()],
    ids=["string", "list", "dict", "true", "false", "object"],
)
def test_non_numeric_budget_is_refused_before_a_process_is_spawned(bad, monkeypatch):
    """The defect this closes: the value used to reach run_with_timeout and raise an opaque
    TypeError with nuclei ALREADY RUNNING. It must fail as a clear config error, and no
    subprocess may be created."""
    seen = _fake_process(monkeypatch)
    with pytest.raises(ValueError, match="dast_timeout_seconds"):
        asyncio.run(
            NucleiDastRunner().run(
                "example.com", {"dast_timeout_seconds": bad},
                _crawled("https://example.com/?q=1"),
            )
        )
    assert seen["spawned"] is False


def test_an_explicit_null_budget_falls_back_to_the_default(monkeypatch):
    """JSON null is 'unset', not a malformed number -- it must not raise."""
    _raw, seen = _run({"dast_timeout_seconds": None}, monkeypatch)
    assert seen["timeout"] == DEFAULT_TIMEOUT_SECONDS


def test_a_refused_budget_does_not_fall_back_to_the_default(monkeypatch):
    """Silently substituting the default would run under a budget the operator did not ask
    for while reporting success -- the same reasoning as nuclei_tags."""
    seen = _fake_process(monkeypatch)
    with pytest.raises(ValueError):
        asyncio.run(
            NucleiDastRunner().run(
                "example.com", {"dast_timeout_seconds": "abc"},
                _crawled("https://example.com/?q=1"),
            )
        )
    assert "timeout" not in seen


# --- Template / version provenance ------------------------------------------------------------

def test_provenance_is_unknown_when_no_template_dir_is_configured():
    assert _template_provenance("") == "unknown"
    assert _template_provenance(None) == "unknown"


def test_provenance_is_unknown_for_a_missing_directory(tmp_path):
    assert _template_provenance(str(tmp_path / "does-not-exist")) == "unknown"


def test_provenance_reads_the_checksum_the_checkout_actually_ships(tmp_path):
    (tmp_path / ".checksum").write_text("abc123def456\n", encoding="utf-8")
    assert _template_provenance(str(tmp_path)) == "checksum:abc123def456"


def test_provenance_falls_back_to_version_when_there_is_no_checksum(tmp_path):
    (tmp_path / ".version").write_text("v10.2.3\n", encoding="utf-8")
    assert _template_provenance(str(tmp_path)) == "version:v10.2.3"


def test_checksum_is_preferred_over_version(tmp_path):
    (tmp_path / ".checksum").write_text("digest\n", encoding="utf-8")
    (tmp_path / ".version").write_text("v10.2.3\n", encoding="utf-8")
    assert _template_provenance(str(tmp_path)) == "checksum:digest"


def test_provenance_never_fabricates_from_an_empty_marker(tmp_path):
    """An empty marker file is not a version. Absent is truthful; a placeholder is not."""
    (tmp_path / ".checksum").write_text("", encoding="utf-8")
    assert _template_provenance(str(tmp_path)) == "unknown"


def test_provenance_is_bounded_and_single_line(tmp_path):
    """This is a stderr label, not a file dump -- a huge/multi-line marker cannot flood the
    stored evidence."""
    (tmp_path / ".checksum").write_text("x" * 500 + "\nsecond line\n", encoding="utf-8")
    value = _template_provenance(str(tmp_path))
    assert "\n" not in value and len(value) <= len("checksum:") + 64


def test_provenance_degrades_to_unknown_instead_of_failing_the_run(tmp_path, monkeypatch):
    """A provenance LABEL must never be the thing that fails a scan."""
    def _boom(*_a, **_k):
        raise OSError("permission denied")

    monkeypatch.setattr("builtins.open", _boom)
    assert _template_provenance(str(tmp_path)) == "unknown"


# --- Provenance reaches the recorded run ------------------------------------------------------

def test_a_successful_run_records_coverage_and_template_provenance(monkeypatch, tmp_path):
    (tmp_path / ".version").write_text("v10.2.3\n", encoding="utf-8")
    monkeypatch.setattr(
        nuclei_dast_runner, "get_settings",
        lambda: type("S", (), {"nuclei_templates_dir": str(tmp_path)})(),
    )
    raw, _seen = _run({}, monkeypatch)
    assert "nuclei_templates=version:v10.2.3" in raw.stderr
    assert "coverage=crawled" in raw.stderr
    assert "templates=version:v10.2.3" in raw.command


def test_a_timed_out_run_still_records_provenance_and_names_the_knob(monkeypatch, tmp_path):
    """Partial-output handling is unchanged; the timeout branch must carry the same
    provenance, and name the knob an operator would raise (it previously said only
    'timed out')."""
    (tmp_path / ".version").write_text("v10.2.3\n", encoding="utf-8")
    monkeypatch.setattr(
        nuclei_dast_runner, "get_settings",
        lambda: type("S", (), {"nuclei_templates_dir": str(tmp_path)})(),
    )
    raw, _seen = _run(
        {"dast_timeout_seconds": 5}, monkeypatch,
        stdout='{"template-id":"x","matched-at":"https://example.com/"}', timed_out=True,
    )
    assert raw.timed_out is True
    assert raw.stdout, "partial output must survive a timeout"
    assert "nuclei_templates=version:v10.2.3" in raw.stderr
    assert "dast_timeout_seconds" in raw.stderr


def test_provenance_is_reported_as_unknown_rather_than_omitted(monkeypatch):
    """An unconfigured template dir must still say so explicitly -- a missing label would be
    read as 'not applicable' rather than 'we could not tell'."""
    monkeypatch.setattr(
        nuclei_dast_runner, "get_settings",
        lambda: type("S", (), {"nuclei_templates_dir": ""})(),
    )
    raw, _seen = _run({}, monkeypatch)
    assert "nuclei_templates=unknown" in raw.stderr


def test_provenance_does_not_change_findings_or_their_classification(monkeypatch, tmp_path):
    """The whole change is a label: the parser must produce exactly the same finding with and
    without template provenance, and it must carry no verification claim."""
    (tmp_path / ".version").write_text("v10.2.3\n", encoding="utf-8")
    monkeypatch.setattr(
        nuclei_dast_runner, "get_settings",
        lambda: type("S", (), {"nuclei_templates_dir": str(tmp_path)})(),
    )
    line = (
        '{"template-id":"sqli","matched-at":"https://example.com/?q=1",'
        '"info":{"name":"SQLi","severity":"high"}}'
    )
    raw, _seen = _run({}, monkeypatch, stdout=line)
    findings = NucleiDastRunner().parse_vulnerabilities(raw)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    # Detection stays detection: nothing in this change promotes a finding to VERIFIED.
    assert "verified" not in findings[0].metadata
    assert "nuclei_templates" not in findings[0].metadata


# --- Prompt 25: reproducibility and honest fuzz coverage --------------------------------------
#
# TWO CONFIRMED GAPS, both of the same family already fixed for `coverage_state` above --
# a bounded run that reports success without saying what it left out.
#
#   1. REPRODUCIBILITY. The fuzzed URLs go in on STDIN, so the recorded command could not say
#      what the run actually tested; it carried only a COUNT. `ToolRun.command_hash` is a
#      digest of that string, so two runs fuzzing entirely DIFFERENT URL sets hashed
#      identically and were indistinguishable in the audit trail. NucleiRunner already records
#      `(stdin: ...)`; the DAST runner did not.
#   2. SILENT TRUNCATION. `_target_urls` caps the list at MAX_FUZZ_URLS and said nothing. A
#      5,000-URL crawl fuzzed 200 and reported a clean DAST pass -- 96% of the discovered
#      surface untested, with nothing recording it.

def _run_with_urls(monkeypatch, urls, config=None):
    seen = _fake_process(monkeypatch)
    raw = asyncio.run(NucleiDastRunner().run("example.com", config or {}, _crawled(*urls)))
    return raw, seen


def test_the_recorded_command_names_the_urls_that_were_fuzzed(monkeypatch):
    """Reproducibility: the evidence header must say WHAT was tested, not just how many."""
    raw, _seen = _run_with_urls(
        monkeypatch, ["https://example.com/a?q=1", "https://example.com/b?z=2"])
    assert "https://example.com/a?q=1" in raw.command
    assert "https://example.com/b?z=2" in raw.command


def test_runs_over_different_urls_do_not_produce_the_same_command(monkeypatch):
    """The concrete consequence: `command_hash` is a digest of this string, so two runs that
    tested different surface must not be indistinguishable in the audit trail."""
    a, _ = _run_with_urls(monkeypatch, ["https://example.com/a?q=1"])
    b, _ = _run_with_urls(monkeypatch, ["https://example.com/b?z=2"])
    assert a.command != b.command


def test_the_recorded_url_list_is_bounded_and_states_what_it_elided(monkeypatch):
    """Evidence must stay readable, but an elision must be declared rather than silent."""
    urls = [f"https://example.com/p{i}?q=1" for i in range(nuclei_dast_runner._COMMAND_URLS_RECORDED + 10)]
    raw, _seen = _run_with_urls(monkeypatch, urls)
    assert "more)" in raw.command
    assert len(raw.command) < 4000


def test_the_fuzz_cap_and_template_provenance_are_recorded(monkeypatch):
    """Both are inputs a re-run needs in order to reproduce the same scope."""
    raw, _seen = _run_with_urls(monkeypatch, ["https://example.com/a?q=1"])
    assert f"max_fuzz_urls={nuclei_dast_runner.MAX_FUZZ_URLS}" in raw.command
    assert "templates=" in raw.command


def test_truncated_fuzzing_is_declared_not_silent(monkeypatch):
    """THE silent-truncation gap: more discovered URLs than the cap must be stated, and stated
    as UNTESTED rather than clean."""
    urls = [f"https://example.com/p{i}?q=1" for i in range(nuclei_dast_runner.MAX_FUZZ_URLS + 25)]
    raw, _seen = _run_with_urls(monkeypatch, urls)
    assert "fuzz_targets_truncated" in raw.stderr
    assert "NOT proven clean" in raw.stderr
    assert f"of {nuclei_dast_runner.MAX_FUZZ_URLS + 25}" in raw.command


def test_an_untruncated_run_makes_no_truncation_claim(monkeypatch):
    """The guard must not cry wolf on a run that fuzzed everything it found."""
    raw, _seen = _run_with_urls(monkeypatch, ["https://example.com/a?q=1"])
    assert "fuzz_targets_truncated" not in raw.stderr
    assert "(fuzzed 1 of 1 url(s)" in raw.command


def test_a_truncated_run_still_reports_its_truncation_when_it_times_out(monkeypatch):
    """A timeout must not erase the coverage caveat -- both facts are true at once."""
    seen = _fake_process(monkeypatch, timed_out=True)
    urls = [f"https://example.com/p{i}?q=1" for i in range(nuclei_dast_runner.MAX_FUZZ_URLS + 5)]
    raw = asyncio.run(NucleiDastRunner().run("example.com", {}, _crawled(*urls)))
    assert raw.timed_out is True
    assert "fuzz_targets_truncated" in raw.stderr
    assert seen["spawned"] is True


def test_truncation_reporting_never_fails_a_run_whose_selection_succeeded(monkeypatch):
    """The pre-cap count is resolved through the SSRF guard, which RAISES for a blocked
    target. That count is a REPORTING detail (how much surface the cap hid), so it must never
    fail a run whose SELECTION already succeeded -- the same rule `coverage_state` follows.

    Selection is pinned to a working list and only the accounting call is made to blow up, so
    this exercises exactly the fallback branch in `_selected_urls`."""
    calls = {"n": 0}
    real_available = NucleiDastRunner._available_urls

    def _boom_on_second_call(self, target_value, prior_findings):
        calls["n"] += 1
        if calls["n"] > 1:            # 1st call is selection; later calls are the accounting
            raise RuntimeError("ssrf guard says no")
        return real_available(self, target_value, prior_findings)

    monkeypatch.setattr(NucleiDastRunner, "_available_urls", _boom_on_second_call)
    raw, _seen = _run_with_urls(monkeypatch, ["https://example.com/a?q=1"])
    assert raw.exit_code == 0                          # the run is not failed by a label
    assert "fuzz_targets_truncated" not in raw.stderr  # and claims no truncation it cannot prove


def test_an_overridden_target_selection_is_still_honoured(monkeypatch):
    """`run()` must keep going through `_target_urls`, so a subclass or test overriding
    selection is not bypassed by the new pre-cap accounting."""
    monkeypatch.setattr(NucleiDastRunner, "_target_urls", lambda self, t, p: ["https://only.test/x"])
    _raw, seen = _run_with_urls(monkeypatch, ["https://example.com/ignored?q=1"])
    assert seen["stdin"] == b"https://only.test/x"


def test_truncation_does_not_change_findings_or_their_verification_state(monkeypatch):
    """The coverage caveat is a LABEL. It must not reclassify a detection or invent one."""
    line = json.dumps({"template-id": "dast-sqli", "matched-at": "https://example.com/p1?q=1",
                       "info": {"name": "SQLi", "severity": "high"}})
    _fake_process(monkeypatch, stdout=line)
    urls = [f"https://example.com/p{i}?q=1" for i in range(nuclei_dast_runner.MAX_FUZZ_URLS + 5)]
    raw = asyncio.run(NucleiDastRunner().run("example.com", {}, _crawled(*urls)))
    findings = NucleiDastRunner().parse_vulnerabilities(raw)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    blob = json.dumps(findings[0].metadata).lower()
    for claim in ("verified", "confirmed", "exploited"):
        assert claim not in blob


# --- Prompt 25: authenticated DAST is NOT supported by the current architecture ----------------

def test_the_platform_injects_no_credentials_into_dast():
    """Prompt 25 asks for authenticated DAST "where the current architecture already supports
    authentication". IT DOES NOT: there is no target-credential or session store anywhere in
    the platform, and `auth_state.py` is explicit that scanning is unauthenticated by design
    (Prompt 20: "do not invent credentials"). `auth_state` CLASSIFIES an observed auth boundary
    -- it never crosses one.

    This test pins that boundary so a future change to it is deliberate rather than accidental:
    no credential-bearing flag may appear in the DAST command line."""
    from apps.api.scanner_engine import auth_state

    runner = NucleiDastRunner()
    command = ["nuclei", "-dast", "-jsonl", "-silent", "-disable-update-check", "-no-color"]
    for credential_flag in ("-H", "-header", "-cookie", "-auth", "-user", "-password"):
        assert credential_flag not in command
    # An endpoint behind auth is a NAMED coverage gap, never a silent "tested, nothing found".
    assert auth_state.AUTH_PROTECTED in auth_state.UNCROSSED_AUTH_STATES
    assert auth_state.AUTH_LOGIN_REDIRECT in auth_state.UNCROSSED_AUTH_STATES
    assert runner.requires_active_testing is True
