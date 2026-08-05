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


def test_web_targets_bare_host_fallback() -> None:
    # 10.0.0.1 isn't allowlisted -> resolve raises -> falls back to the literal value.
    assert web_targets("10.0.0.1", []) == ["http://10.0.0.1", "https://10.0.0.1"]


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
