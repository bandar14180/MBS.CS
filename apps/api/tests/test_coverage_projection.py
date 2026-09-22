"""Prompt 14 -- Coverage Gap Detection (engagement-wide coverage projection + debt).

Pure/deterministic tests (no DB, no network). These are ADVERSARIAL: several assert the
false-confidence scenarios the projection exists to make visible -- a scan that "completed"
while in-scope discovered surface never reached its expected test, and the negation
NO finding != NO vulnerability. They would pass trivially against a build that has no
coverage model (there would be nothing to assert), so each one pins a concrete state
transition the projection must produce.
"""
from apps.api.scanner_engine.coverage import (
    STATE_ATTEMPTED_FAILED,
    STATE_COVERED,
    STATE_DISCOVERED,
    STATE_OUT_OF_SCOPE,
    STATE_PARTIAL,
    STATE_UNSUPPORTED,
    STATE_VERIFIED,
    ToolRunOutcome,
    build_coverage,
)
from apps.api.scanner_engine.tool_runners.base import CommonFinding


def _f(asset_type, value, in_scope=True, **md):
    return CommonFinding(asset_type=asset_type, value=value, metadata={"in_scope": in_scope, **md})


# --- expected-capability chain model (mirrors the real pipeline) --------------------------

def test_subdomain_expects_web_service_discovery_and_is_debt_when_httpx_never_ran():
    """A discovered subdomain with NO web_service_discovery run is coverage DEBT: httpx
    should have probed it and did not."""
    cov = build_coverage([_f("subdomain", "api.example.com")], [], target_type="domain")
    s = cov.surfaces[0]
    assert s.expected_capability == "web_service_discovery"
    assert s.state == STATE_DISCOVERED
    assert cov.has_debt and cov.debt[0].value == "api.example.com"


def test_http_service_expects_web_crawling():
    cov = build_coverage([_f("http_service", "http://h/")], [], target_type="domain")
    assert cov.surfaces[0].expected_capability == "web_crawling"


def test_paramless_url_expects_parameter_discovery_but_param_url_expects_dast():
    """The real _web.py split: a url with `?` is ready to fuzz; a paramless one needs
    parameter discovery first. The projection must reproduce that or it would mis-route debt."""
    cov = build_coverage(
        [_f("url", "http://h/api/items"), _f("url", "http://h/search?q=1")],
        [],
        target_type="domain",
    )
    by_val = {s.value: s.expected_capability for s in cov.surfaces}
    assert by_val["http://h/api/items"] == "parameter_discovery"
    assert by_val["http://h/search?q=1"] == "dast_fuzzing"


# --- state transitions from real tool-run outcomes ----------------------------------------

def test_completed_run_marks_surface_covered_not_debt():
    """httpx completed -> the subdomain's web_service_discovery is COVERED, and it drops
    out of the debt set. This is the positive control for the debt logic."""
    cov = build_coverage(
        [_f("subdomain", "api.example.com")],
        [ToolRunOutcome("httpx", "completed")],
        target_type="domain",
    )
    assert cov.surfaces[0].state == STATE_COVERED
    assert not cov.has_debt


def test_failed_run_is_attempted_failed_and_still_debt():
    """FALSE-CONFIDENCE GUARD: httpx FAILED. The surface is attempted_failed, which is
    still debt -- a failed test must never read as 'tested, nothing found'."""
    cov = build_coverage(
        [_f("subdomain", "api.example.com")],
        [ToolRunOutcome("httpx", "failed")],
        target_type="domain",
    )
    assert cov.surfaces[0].state == STATE_ATTEMPTED_FAILED
    assert cov.has_debt


def test_partial_run_is_partial_and_still_debt():
    """A partial (timeout/OOM) crawl leaves the http_service under-tested -- partial is
    coverage debt too, mirroring nuclei_dast.coverage_state's 'degraded' insight but at the
    engagement level."""
    cov = build_coverage(
        [_f("http_service", "http://h/")],
        [ToolRunOutcome("katana", "partial")],
        target_type="domain",
    )
    assert cov.surfaces[0].state == STATE_PARTIAL


def test_skipped_unauthorized_does_not_count_as_covered():
    """A tool skipped for lack of authorization did NOT test anything -- the surface stays
    discovered (debt), never 'covered'. Skipping is not coverage."""
    cov = build_coverage(
        [_f("http_service", "http://h/")],
        [ToolRunOutcome("katana", "skipped_unauthorized")],
        target_type="domain",
    )
    assert cov.surfaces[0].state == STATE_DISCOVERED
    assert cov.has_debt


# --- scope and support: debt must EXCLUDE these -------------------------------------------

def test_out_of_scope_surface_is_never_debt():
    """An out-of-scope asset was intentionally not probed -- Prompt 14 requires debt to be
    distinguishable from intentionally-out-of-scope. It must not appear as debt."""
    cov = build_coverage([_f("subdomain", "evil.example.com", in_scope=False)], [], target_type="domain")
    assert cov.surfaces[0].state == STATE_OUT_OF_SCOPE
    assert not cov.has_debt


def test_in_scope_false_fails_closed_even_with_no_runs():
    cov = build_coverage([_f("subdomain", "x", in_scope=False)], [], target_type="domain")
    assert cov.surfaces[0].state == STATE_OUT_OF_SCOPE


def test_unknown_asset_type_is_unsupported_not_debt():
    """An asset type with no expected next capability (e.g. a screenshot artifact) is
    unsupported, not debt -- we never invent a test that does not exist."""
    cov = build_coverage([_f("mystery", "whatever")], [], target_type="domain")
    assert cov.surfaces[0].state == STATE_UNSUPPORTED
    assert not cov.has_debt


# --- verified is the strongest state ------------------------------------------------------

def test_verified_location_beats_covered():
    """A surface where a finding reached VERIFIED is `verified`, not merely covered, and is
    never debt -- the strongest link in the evidence chain."""
    cov = build_coverage(
        [_f("url", "http://h/search?q=1")],
        [ToolRunOutcome("nuclei-dast", "completed")],
        target_type="domain",
        verified_locations=frozenset({"http://h/search?q=1"}),
    )
    assert cov.surfaces[0].state == STATE_VERIFIED
    assert not cov.has_debt


# --- the headline false-confidence scenario -----------------------------------------------

def test_completed_scan_with_untested_api_endpoint_shows_debt():
    """THE Prompt-14 scenario: the recon tools all 'completed', but a discovered /api/
    endpoint never reached parameter discovery. The scan looks clean; the projection proves
    NO finding != NO vulnerability by reporting the endpoint as coverage debt."""
    findings = [
        _f("subdomain", "api.example.com"),
        _f("http_service", "http://api.example.com/"),
        _f("url", "http://api.example.com/api/orders"),  # paramless -> needs arjun
    ]
    outcomes = [
        ToolRunOutcome("httpx", "completed"),
        ToolRunOutcome("katana", "completed"),
        # arjun (parameter_discovery) NEVER ran.
    ]
    cov = build_coverage(findings, outcomes, target_type="domain")
    debt_vals = {s.value for s in cov.debt}
    assert "http://api.example.com/api/orders" in debt_vals
    assert "parameter_discovery" in cov.debt_summary()
    # The already-tested surfaces are NOT in debt (no false positives on debt either).
    assert "api.example.com" not in debt_vals


def test_debt_summary_empty_when_everything_covered():
    findings = [_f("subdomain", "a"), _f("http_service", "http://a/")]
    outcomes = [ToolRunOutcome("httpx", "completed"), ToolRunOutcome("katana", "completed")]
    cov = build_coverage(findings, outcomes, target_type="domain")
    assert cov.debt_summary() == "(no coverage debt)"


def test_determinism_same_inputs_same_projection():
    """Deterministic repeatability (batch requirement #13): identical evidence yields an
    identical projection, order-stable."""
    findings = [_f("subdomain", "a"), _f("url", "http://a/x?p=1")]
    outcomes = [ToolRunOutcome("httpx", "failed")]
    a = build_coverage(findings, outcomes, target_type="domain")
    b = build_coverage(findings, outcomes, target_type="domain")
    assert [(s.value, s.state) for s in a.surfaces] == [(s.value, s.state) for s in b.surfaces]
    assert [(s.value, s.state) for s in a.debt] == [(s.value, s.state) for s in b.debt]


def test_empty_and_malformed_findings_are_skipped_not_crashed():
    """Malformed evidence (empty value/type) is skipped, never guessed -- same contract as
    attack_graph.build_graph."""
    findings = [_f("subdomain", ""), _f("", "x"), _f("subdomain", "real.example.com")]
    cov = build_coverage(findings, [], target_type="domain")
    assert [s.value for s in cov.surfaces] == ["real.example.com"]
