"""Unit tests for the DAST enhancement: the shared web-target helper, the katana
crawler runner, and the nuclei-dast fuzzing runner. All pure (no network)."""
from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY
from apps.api.scanner_engine.tool_runners._web import (
    crawled_urls,
    discovered_port_urls,
    param_discovery_targets,
    web_targets,
)
from apps.api.scanner_engine.tool_runners.arjun_runner import ArjunRunner
from apps.api.scanner_engine.tool_runners.base import CommonFinding, RawToolOutput
from apps.api.scanner_engine.tool_runners.katana_runner import KatanaRunner
from apps.api.scanner_engine.tool_runners.nuclei_dast_runner import NucleiDastRunner


# --- _web.web_targets: httpx services -> discovered ports -> bare host ---

def test_web_targets_prefers_httpx_confirmed_services() -> None:
    prior = [
        CommonFinding("http_service", "http://10.0.0.1", {"host": "10.0.0.1"}),
        CommonFinding("http_service", "http://10.0.0.1", {"host": "10.0.0.1"}),  # dup
        CommonFinding("service", "10.0.0.1:3000", {"ip": "10.0.0.1", "port": 3000}),
    ]
    assert web_targets("10.0.0.1", prior) == ["http://10.0.0.1"]


def test_web_targets_falls_back_to_discovered_ports() -> None:
    prior = [
        CommonFinding("port", "10.0.0.1:3300", {"ip": "10.0.0.1", "port": 3300}),
        CommonFinding("service", "10.0.0.1:3300", {"ip": "10.0.0.1", "port": 3300}),  # same endpoint
    ]
    assert web_targets("10.0.0.1", prior) == ["http://10.0.0.1:3300", "https://10.0.0.1:3300"]


def test_web_targets_rejects_an_ssrf_blocked_bare_host() -> None:
    """AUDIT-011 -- CORRECTED EXPECTATION.

    This test previously asserted that an SSRF-BLOCKED address still fell through to a
    scannable URL list:
        # 10.0.0.1 isn't allowlisted -> resolve raises -> falls back to the literal value.
        assert web_targets("10.0.0.1", []) == ["http://10.0.0.1", "https://10.0.0.1"]
    That fallback WAS the vulnerability. `web_targets` wrapped the scan-time SSRF
    revalidation in `except Exception: pass`, which swallowed TargetNotAllowed and handed
    nuclei/katana an RFC1918 target the policy had just denied. A security denial must
    propagate, so the correct expectation is that it raises.
    """
    import pytest

    from apps.api.scanner_engine.net_guard import TargetNotAllowed

    with pytest.raises(TargetNotAllowed):
        web_targets("10.0.0.1", [])


def test_web_targets_bare_host_fallback_for_an_unresolvable_host(monkeypatch) -> None:
    """The fallback itself is still correct for the case it was meant for: a host that does
    not RESOLVE (a recoverable resolver failure), as opposed to one that is FORBIDDEN."""
    import socket

    from apps.api.scanner_engine.tool_runners import _web

    monkeypatch.setattr(
        _web, "resolve_scan_host",
        lambda v: (_ for _ in ()).throw(socket.gaierror("no such host")),
    )
    assert _web.web_targets("nonexistent.invalid", []) == [
        "http://nonexistent.invalid", "https://nonexistent.invalid",
    ]


def test_discovered_port_urls_bound() -> None:
    prior = [CommonFinding("port", f"10.0.0.1:{p}", {"ip": "10.0.0.1", "port": p}) for p in range(1, 100)]
    assert len(discovered_port_urls(prior, max_endpoints=5)) == 10  # 5 endpoints x (http+https)


# --- _web.crawled_urls: parameterised URLs first ---

def test_crawled_urls_params_first_and_deduped() -> None:
    prior = [
        CommonFinding("url", "http://a/home", {}),
        CommonFinding("url", "http://a/item?id=1", {}),
        CommonFinding("url", "http://a/home", {}),  # dup
        CommonFinding("service", "a:80", {"ip": "a", "port": 80}),  # ignored (not a url)
    ]
    assert crawled_urls(prior) == ["http://a/item?id=1", "http://a/home"]


# --- katana runner ---

def test_katana_parse_extracts_urls_with_param_flag() -> None:
    raw = RawToolOutput(
        command="katana",
        stdout="http://a/\nhttp://a/search?q=x\nnot-a-url\nhttps://a/js/app.js\nhttp://a/\n",  # last is dup
        stderr="",
        exit_code=0,
    )
    findings = KatanaRunner().parse(raw)
    assert [f.value for f in findings] == ["http://a/", "http://a/search?q=x", "https://a/js/app.js"]
    assert findings[1].metadata["has_params"] is True
    assert findings[0].metadata["has_params"] is False
    assert all(f.asset_type == "url" for f in findings)
    # a crawler inventories assets, it doesn't produce vulnerabilities
    assert KatanaRunner().parse_vulnerabilities(raw) == []


def test_katana_is_passive_recon_and_web_scoped() -> None:
    assert KatanaRunner.requires_active_testing is False
    assert KatanaRunner.phase < TOOL_REGISTRY["nuclei"].phase  # crawls before the vuln scan
    assert KatanaRunner.applicable_target_types == {"domain", "ip_range"}


# --- nuclei-dast runner ---

def test_nuclei_dast_fuzzes_crawled_params_first() -> None:
    prior = [
        CommonFinding("http_service", "http://10.0.0.1:3300", {}),      # web_targets would pick this
        CommonFinding("url", "http://10.0.0.1:3300/", {}),
        CommonFinding("url", "http://10.0.0.1:3300/item?id=1", {}),
    ]
    urls = NucleiDastRunner()._target_urls("10.0.0.1", prior)
    assert urls[0] == "http://10.0.0.1:3300/item?id=1"  # parameterised URL first
    assert "http://10.0.0.1:3300/" in urls


def test_nuclei_dast_falls_back_to_web_targets_without_crawl() -> None:
    prior = [CommonFinding("port", "10.0.0.1:3300", {"ip": "10.0.0.1", "port": 3300})]
    assert NucleiDastRunner()._target_urls("10.0.0.1", prior) == [
        "http://10.0.0.1:3300",
        "https://10.0.0.1:3300",
    ]


def test_nuclei_dast_requires_active_testing_and_reuses_nuclei_parsing() -> None:
    assert NucleiDastRunner.requires_active_testing is True
    assert NucleiDastRunner.phase > TOOL_REGISTRY["katana"].phase  # runs after the crawl
    # inherits NucleiRunner.parse_vulnerabilities (identical JSONL schema)
    raw = RawToolOutput(
        command="nuclei -dast",
        stdout='{"template-id":"sqli-error-based","matcher-name":"mysql","matched-at":"http://a/item?id=1",'
        '"info":{"name":"SQL Injection","severity":"high","classification":{"cwe-id":["CWE-89"]}}}\n',
        stderr="",
        exit_code=0,
    )
    findings = NucleiDastRunner().parse_vulnerabilities(raw)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].category == "CWE-89"


def test_registry_has_dast_pipeline_in_order() -> None:
    for name in ("katana", "arjun", "nuclei-dast"):
        assert name in TOOL_REGISTRY
    order = [TOOL_REGISTRY[n].phase for n in ("httpx", "naabu", "nmap", "katana", "arjun", "nuclei", "nuclei-dast")]
    assert order == sorted(order)  # strictly ascending pipeline phases


# --- arjun parameter discovery ---

def test_param_discovery_targets_api_first_static_skipped_query_stripped() -> None:
    prior = [
        CommonFinding("url", "http://a/js/app.js", {}),          # static -> skip
        CommonFinding("url", "http://a/api/products?", {}),      # crawler's trailing '?' -> base path kept
        CommonFinding("url", "http://a/api/products?q=x", {}),   # same base -> deduped
        CommonFinding("url", "http://a/about", {}),
        CommonFinding("url", "http://a/api/files/view?file=", {}),
    ]
    targets = param_discovery_targets(prior, max_targets=10)
    # api base paths first (deduped, query stripped), then the rest
    assert targets == ["http://a/api/products", "http://a/api/files/view", "http://a/about"]


def test_arjun_parse_builds_parameterised_urls() -> None:
    raw = RawToolOutput(
        command="arjun",
        stdout=(
            '{"http://a/api/products": {"method": "GET", "params": ["q", "sort", "category"]},'
            ' "http://a/dead": {"method": "GET", "params": []}}'  # no params -> no finding
        ),
        stderr="",
        exit_code=0,
    )
    findings = ArjunRunner().parse(raw)
    assert [f.value for f in findings] == ["http://a/api/products?q=1&sort=1&category=1"]
    assert findings[0].asset_type == "url"
    assert findings[0].metadata["params"] == ["q", "sort", "category"]


def test_arjun_parse_handles_empty_or_bad_json() -> None:
    assert ArjunRunner().parse(RawToolOutput("arjun", "", "", 0)) == []
    assert ArjunRunner().parse(RawToolOutput("arjun", "not json", "", 0)) == []


def test_arjun_feeds_nuclei_dast() -> None:
    # arjun's parameterised url findings become nuclei-dast targets (params-first).
    prior = [CommonFinding("url", "http://a/api/products?q=1&sort=1", {"source": "arjun", "has_params": True})]
    assert NucleiDastRunner()._target_urls("a", prior)[0] == "http://a/api/products?q=1&sort=1"


# --- Coverage state: crawled vs root-only fallback ----------------------------------------
# Observed on a real scan: katana timed out and returned zero URLs, so DAST silently fell back
# to fuzzing the bare entry point and still reported an ordinary success in 12.3s. The run was
# not wrong -- fuzzing the root beats fuzzing nothing -- but it was INDISTINGUISHABLE from a
# full-coverage run. These pin the label that makes the difference legible. No vulnerability
# semantics change: the same URLs are fuzzed and the same findings produced.

def test_coverage_is_crawled_when_the_crawler_produced_urls():
    from apps.api.scanner_engine.tool_runners.nuclei_dast_runner import NucleiDastRunner

    prior = [
        CommonFinding("http_service", "https://t.example", {"host": "t.example"}),
        CommonFinding("url", "https://t.example/a?id=1", {"source": "katana", "has_params": True}),
    ]
    assert NucleiDastRunner().coverage_state("t.example", prior) == "crawled"


def test_coverage_is_fallback_root_only_when_the_crawl_produced_nothing():
    """THE misleading-success case: katana timed out, so only the entry point can be fuzzed."""
    from apps.api.scanner_engine.tool_runners.nuclei_dast_runner import NucleiDastRunner

    prior = [CommonFinding("http_service", "https://t.example", {"host": "t.example"})]
    assert NucleiDastRunner().coverage_state("t.example", prior) == "fallback_root_only"


def test_coverage_is_none_only_when_there_is_no_target_at_all():
    """`web_targets` synthesizes http(s)://<target> from the target name, so a named target
    always has at least the entry point to fuzz -- "none" is reachable only with no target."""
    from apps.api.scanner_engine.tool_runners.nuclei_dast_runner import NucleiDastRunner

    assert NucleiDastRunner().coverage_state("", []) == "none"
    # A named target with no crawl data is degraded, NOT empty.
    assert NucleiDastRunner().coverage_state("t.example", []) == "fallback_root_only"


def test_fallback_still_fuzzes_the_entry_point():
    """Coverage reporting must NOT reduce what gets tested -- the fallback is retained."""
    from apps.api.scanner_engine.tool_runners.nuclei_dast_runner import NucleiDastRunner

    prior = [CommonFinding("http_service", "https://t.example", {"host": "t.example"})]
    urls = NucleiDastRunner()._target_urls("t.example", prior)
    assert urls, "fallback must still provide a target to fuzz"


def test_no_targets_run_reports_coverage_none_and_does_not_claim_success(monkeypatch):
    """A run with nothing to fuzz must report failure AND state coverage=none.

    `_target_urls` is stubbed to return nothing because reaching that state for real requires
    an unresolvable target, which the SSRF guard rejects by RAISING before run() is entered --
    a pre-existing behaviour this test is not trying to change."""
    import asyncio

    from apps.api.scanner_engine.tool_runners import nuclei_dast_runner as mod
    from apps.api.scanner_engine.tool_runners.nuclei_dast_runner import NucleiDastRunner

    runner = NucleiDastRunner()
    monkeypatch.setattr(NucleiDastRunner, "_target_urls", lambda self, t, p: [])
    monkeypatch.setattr(NucleiDastRunner, "coverage_state", lambda self, t, p: "none")
    raw = asyncio.run(runner.run("t.example", {}, []))
    assert raw.exit_code != 0, "a run with nothing to fuzz must not report success"
    assert "coverage=none" in raw.stderr
    assert mod  # module imported for clarity about what is being exercised
