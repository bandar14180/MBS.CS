"""Prompt 19 -- Browser / JavaScript Intelligence (adversarial).

The platform's JS intelligence is katana's `-js-crawl` (plus `-jsluice`, which is opt-in --
see JSLUICE_DEFAULT), and its browser capability is the Playwright
screenshot path. Prompt 19 requires: JS/browser discoveries actually ENTER the central
attack-surface pipeline, are deduplicated, and are NEVER treated as vulnerability proof on
their own.

The screenshot path's scope/SSRF/redirect/timeout/failure/provenance guards are already
covered by test_screenshot_evidence.py and test_worker_screenshot_capture.py -- not
duplicated here. These tests pin the JS-discovery-into-pipeline invariants, which had no
direct coverage.
"""
import asyncio
from unittest import mock

from apps.api.scanner_engine.tool_runners._web import crawled_urls, param_discovery_targets
from apps.api.scanner_engine.tool_runners.base import RawToolOutput, TimedRun
from apps.api.scanner_engine.tool_runners.katana_runner import KatanaRunner


class _FakeProc:
    returncode = 0

    async def wait(self):
        return 0


def _argv_for(config):
    """The exact argv the runner assembles for `config`, with no binary and no network."""
    captured = {}

    async def _fake_exec(*args, **kwargs):
        captured["argv"] = args
        return _FakeProc()

    async def _fake_run_with_timeout(proc, timeout, tool, stdin=None, **kwargs):
        return TimedRun(stdout="", stderr="", timed_out=False, exit_code=0)

    prior = [type("F", (), {"asset_type": "http_service", "value": "http://t.example/", "metadata": {}})()]
    with mock.patch("asyncio.create_subprocess_exec", _fake_exec),          mock.patch("apps.api.scanner_engine.tool_runners.katana_runner.run_with_timeout", _fake_run_with_timeout):
        asyncio.run(KatanaRunner().run("t.example", config, prior))
    return captured["argv"]


def test_js_crawl_flag_is_actually_passed():
    """JS intelligence is only real if the flag that follows endpoints linked from JavaScript
    is on the command line. -js-crawl is unconditional and carries the measured coverage
    (2580 URLs at a 72 MiB peak on a real target)."""
    assert "-js-crawl" in _argv_for({})


def test_jsluice_is_opt_in_not_default():
    """-jsluice is DEFAULT OFF and must be absent from argv unless explicitly enabled.

    MEASURED on three live authorized targets: with -jsluice katana allocated 3601/3838/3740
    MiB and emitted exactly ONE URL before the cgroup OOM killer took it; without it the same
    crawls peaked at 73/77/53 MiB and emitted 2465/2464/1 URLs. Leaving it on by default is
    what made whole targets burn their full per-target deadline and preserve one URL."""
    assert "-jsluice" not in _argv_for({})


def test_jsluice_can_still_be_enabled_explicitly():
    """The capability is retained, not removed: a scan that wants it can ask for it."""
    argv = _argv_for({"jsluice": True})
    assert "-jsluice" in argv
    assert "-js-crawl" in argv


def test_js_extracted_endpoints_enter_the_pipeline_as_url_assets():
    """An API endpoint jsluice pulls out of a bundle (e.g. /api/v2/files?id=) must become a
    `url` discovery asset so it flows to param discovery / DAST -- i.e. it ENTERS the central
    pipeline, not a dead-end log line."""
    raw = RawToolOutput(
        "katana",
        stdout="http://t.example/api/v2/files?id=1\nhttp://t.example/static/app.js\n",
        stderr="", exit_code=0,
    )
    findings = KatanaRunner().parse(raw)
    values = {f.value for f in findings}
    assert "http://t.example/api/v2/files?id=1" in values          # JS-derived endpoint present
    # ...and it is tagged as the API surface it is (feeds API intelligence).
    api = next(f for f in findings if f.value.startswith("http://t.example/api/v2/files"))
    assert api.metadata.get("is_api") is True and api.metadata.get("api_version") == "v2"


def test_a_js_string_alone_is_never_a_vulnerability():
    """NEVER treat a JavaScript string as proof of a vulnerability. katana is a crawler: its
    parse_vulnerabilities is empty no matter what it crawled from JS."""
    raw = RawToolOutput(
        "katana",
        stdout="http://t.example/api/admin?token=SECRET\nhttp://t.example/#/admin\n",
        stderr="", exit_code=0,
    )
    assert KatanaRunner().parse_vulnerabilities(raw) == []


def test_duplicate_js_discovery_is_suppressed():
    """A bundle referenced from many pages yields the same endpoint repeatedly -- duplicate
    discovery must collapse to one asset (and one downstream target)."""
    raw = RawToolOutput(
        "katana",
        stdout=(
            "http://t.example/api/orders\n"
            "http://T.example/api/orders\n"       # host case
            "http://t.example/api/orders#ref\n"   # fragment from a SPA route
        ),
        stderr="", exit_code=0,
    )
    findings = KatanaRunner().parse(raw)
    assert [f.value for f in findings] == ["http://t.example/api/orders"]


def test_js_discovered_endpoints_drive_downstream_testing():
    """The end-to-end Prompt-19 property: JS-discovered endpoints reach parameter discovery
    and DAST, API surfaces first."""
    raw = RawToolOutput(
        "katana",
        stdout="http://t.example/home\nhttp://t.example/graphql\nhttp://t.example/api/v1/users\n",
        stderr="", exit_code=0,
    )
    findings = KatanaRunner().parse(raw)
    param_targets = param_discovery_targets(findings, max_targets=10)
    # the two API surfaces precede the plain page
    assert param_targets.index("http://t.example/home") == len(param_targets) - 1
    # and everything discovered is available to the DAST target set
    assert set(crawled_urls(findings)) >= {
        "http://t.example/graphql", "http://t.example/api/v1/users", "http://t.example/home",
    }
