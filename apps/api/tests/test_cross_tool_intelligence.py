"""Prompt 15 -- Cross-tool Intelligence (adversarial).

Every meaningful discovery should have a clear answer to whether it warrants another test,
and -- critically -- a FAILED upstream tool must never masquerade as a successful one to a
downstream tool. These are pure/deterministic tests of the chaining contract:

  * classify_run: a failed run yields findings the orchestrator drops (no phantom inputs);
  * downstream target selection is stable/deterministic and correctly scoped;
  * an upstream FAILURE leaves the surface as coverage DEBT, not silently "tested".

The orchestrator's own failure/ownership machinery is tested elsewhere (test_orchestrator_*).
Here we pin the cross-tool DATA-FLOW invariants that make chaining safe.
"""
from apps.api.scanner_engine.coverage import (
    STATE_ATTEMPTED_FAILED,
    STATE_COVERED,
    ToolRunOutcome,
    build_coverage,
)
from apps.api.scanner_engine.tool_runners._web import crawled_urls, web_targets
from apps.api.scanner_engine.tool_runners.base import (
    CommonFinding,
    RawToolOutput,
    classify_run,
)
from apps.api.scanner_engine.tool_runners.httpx_runner import HttpxRunner
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner


def _f(asset_type, value, **md):
    return CommonFinding(asset_type=asset_type, value=value, metadata=md)


# --- failed upstream must not become a "successfully found nothing" downstream input ------

def test_failed_run_with_empty_output_classifies_failed_not_completed():
    """A non-zero exit with NO usable output is `failed`. The orchestrator drops a failed
    run's findings (returns []), so downstream tools never receive phantom inputs from it."""
    runner = HttpxRunner()
    raw = RawToolOutput(command="httpx", stdout="", stderr="boom", exit_code=1)
    assert classify_run(runner, raw, produced_findings=False) == "failed"


def test_nonzero_exit_with_output_is_partial_not_failed():
    """A non-zero exit that STILL produced parseable output is `partial` -- its findings are
    kept (resilient pipeline), and the surface is later marked partial, still debt."""
    runner = HttpxRunner()
    raw = RawToolOutput(command="httpx", stdout="http://a/\n", stderr="warn", exit_code=1)
    assert classify_run(runner, raw, produced_findings=True) == "partial"


def test_upstream_failure_leaves_surface_as_debt_not_covered():
    """CROSS-TOOL FALSE-CONFIDENCE GUARD. httpx (web_service_discovery) failed against a
    discovered subdomain. Downstream, that subdomain is coverage DEBT (attempted_failed) --
    it must NOT read as 'covered'. Contrast with the completed case below."""
    subdomain = [_f("subdomain", "api.example.com", in_scope=True)]
    failed = build_coverage(subdomain, [ToolRunOutcome("httpx", "failed")], target_type="domain")
    assert failed.surfaces[0].state == STATE_ATTEMPTED_FAILED
    assert failed.has_debt

    covered = build_coverage(subdomain, [ToolRunOutcome("httpx", "completed")], target_type="domain")
    assert covered.surfaces[0].state == STATE_COVERED
    assert not covered.has_debt


# --- downstream scope + determinism -------------------------------------------------------

def test_downstream_web_targets_prefer_confirmed_services_over_bare_host():
    """Correlation is deterministic: given an httpx-confirmed service, the downstream tool
    targets exactly it, never the bare host -- one tool never silently scans a different
    thing than the pipeline discovered."""
    prior = [_f("http_service", "http://a:8080/")]
    assert web_targets("a", prior) == ["http://a:8080/"]
    # deterministic: identical inputs, identical output
    assert web_targets("a", prior) == web_targets("a", prior)


def test_crawled_urls_dedupe_across_tools_is_deterministic():
    """Duplicate artifacts from different tools must be handled safely: the same URL surfaced
    twice yields ONE downstream target, params-first, in a stable order."""
    prior = [
        _f("url", "http://a/x?id=1", source="katana"),
        _f("url", "http://a/x?id=1", source="arjun"),   # duplicate value, different source
        _f("url", "http://a/home"),
    ]
    out = crawled_urls(prior)
    assert out.count("http://a/x?id=1") == 1        # deduped
    assert out[0] == "http://a/x?id=1"              # arjun/param URL ranked first
    assert out == crawled_urls(prior)               # deterministic


def test_httpx_only_consumes_subdomain_findings_not_arbitrary_types():
    """A downstream tool consumes only the artifact types it is designed for -- httpx builds
    its host set from `subdomain` findings, not from `url`/`port`/noise. This is what keeps a
    misclassified upstream artifact from steering the wrong tool."""
    prior = [
        _f("subdomain", "sub.a.com"),
        _f("url", "http://a.com/should-not-be-a-host"),
        _f("port", "a.com:22", ip="a.com", port=22),
    ]
    hosts = HttpxRunner()._host_set("a.com", prior)
    assert "sub.a.com" in hosts
    assert "http://a.com/should-not-be-a-host" not in hosts


def test_nuclei_target_urls_are_bounded_and_deterministic():
    """Even a large upstream discovery cannot fan out unbounded into the vuln scanner, and the
    selection is stable run-to-run (no nondeterministic set ordering leaking into a command)."""
    prior = [_f("service", f"10.0.0.1:{p}", ip="10.0.0.1", port=p) for p in range(9000, 9100)]
    urls_a = NucleiRunner()._target_urls("10.0.0.1", prior)
    urls_b = NucleiRunner()._target_urls("10.0.0.1", prior)
    assert urls_a == urls_b                          # deterministic
    assert len(urls_a) <= 100                         # bounded (DEFAULT_MAX_ENDPOINTS * 2)
