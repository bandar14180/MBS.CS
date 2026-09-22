"""Regression coverage for apps.api.scanner_engine.location_normalize (Prompt 13, Finding #1)
and its wiring into nuclei's fingerprint formula.

Two concerns, kept deliberately separate:
  * the normalization function itself -- pure, no DB, exhaustive over the rule table in the
    module docstring;
  * that nuclei_runner.parse_vulnerabilities actually uses it, and that doing so does not
    change the fingerprint FORMAT the rest of the system already depends on
    (test_ingest_idempotency.test_dedupe_does_not_change_the_fingerprint_format pins that
    separately; this file pins the new normalization behavior on top of it).
"""
import json

from apps.api.scanner_engine.location_normalize import (
    normalize_host_port,
    normalize_location,
    normalize_url,
)
from apps.api.scanner_engine.tool_runners.base import RawToolOutput
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner


# --- normalize_url: equivalent representations collapse --------------------------------------

def test_scheme_case_is_folded():
    assert normalize_url("HTTPS://example.com/x") == "https://example.com/x"


def test_host_case_is_folded():
    assert normalize_url("https://EXAMPLE.com/login") == "https://example.com/login"


def test_default_https_port_is_stripped():
    assert normalize_url("https://example.com:443/foo") == "https://example.com/foo"


def test_default_http_port_is_stripped():
    assert normalize_url("http://example.com:80/foo") == "http://example.com/foo"


def test_non_default_port_is_preserved():
    assert normalize_url("https://example.com:8443/foo") == "https://example.com:8443/foo"


def test_empty_path_becomes_root():
    assert normalize_url("https://example.com") == "https://example.com/"


def test_fragment_is_stripped():
    assert normalize_url("https://example.com/x#section") == "https://example.com/x"


def test_percent_encoding_case_is_folded():
    assert normalize_url("https://example.com/%2Fx") == normalize_url("https://example.com/%2fx")


def test_ipv6_host_with_default_port_is_stripped():
    assert normalize_url("https://[::1]:443/x") == "https://[::1]/x"


def test_ipv6_host_case_is_folded():
    assert normalize_url("https://[::FFFF:1]/x") == "https://[::ffff:1]/x"


def test_four_equivalent_urls_all_normalize_identically():
    variants = [
        "https://example.com/login",
        "https://EXAMPLE.com/login",
        "https://example.com:443/login",
        "HTTPS://example.com:443/login",
    ]
    normalized = {normalize_url(v) for v in variants}
    assert len(normalized) == 1, f"expected one canonical form, got {normalized}"


def test_idempotent():
    for value in ("https://EXAMPLE.com:443/Foo%2Fbar#frag", "http://h:80/", "https://h"):
        once = normalize_url(value)
        assert normalize_url(once) == once


# --- normalize_url: genuinely different locations must NOT collapse --------------------------

def test_different_paths_are_not_merged():
    assert normalize_url("https://example.com/login?id=1") != normalize_url("https://example.com/search?q=1")


def test_trailing_slash_on_non_root_path_is_preserved():
    # Deliberately NOT normalized -- see the module docstring's rule table. A server can treat
    # "/foo" and "/foo/" as different resources.
    assert normalize_url("https://example.com/foo") != normalize_url("https://example.com/foo/")


def test_different_non_default_ports_are_not_merged():
    assert normalize_url("https://example.com:8443/x") != normalize_url("https://example.com:9443/x")


def test_query_value_content_is_not_altered():
    # Casing/content inside a query value can be the injected payload itself -- must survive
    # verbatim (only percent-encoding hex-digit case folds, never the decoded meaning).
    assert "SELECT" in normalize_url("https://example.com/x?q=SELECT+1")


def test_malformed_url_falls_back_unchanged():
    weird = "not a url at all"
    assert normalize_url(weird) == weird


# --- normalize_host_port (nmap/naabu-style bare network locations) ---------------------------

def test_host_port_case_is_folded():
    assert normalize_host_port("Host.example:8080") == "host.example:8080"


def test_host_port_without_port_is_folded():
    assert normalize_host_port("Host.example") == "host.example"


def test_host_port_preserves_the_port_value():
    assert normalize_host_port("host.example:22") != normalize_host_port("host.example:23")


# --- normalize_location dispatch --------------------------------------------------------------

def test_dispatches_url_vs_bare_host():
    assert normalize_location("https://EX.com/x") == "https://ex.com/x"
    assert normalize_location("EX.com:22") == "ex.com:22"


def test_none_and_empty_pass_through():
    assert normalize_location(None) is None
    assert normalize_location("") == ""


# --- wiring into nuclei's fingerprint formula --------------------------------------------------

def _line(matched_at: str, template="tpl", matcher="m"):
    return json.dumps({
        "template-id": template, "matcher-name": matcher, "matched-at": matched_at,
        "info": {"name": "X", "severity": "high"},
    })


def test_nuclei_fingerprint_normalizes_matched_at():
    raw = RawToolOutput(command="nuclei", stdout=_line("https://EXAMPLE.com:443/login"), stderr="", exit_code=0)
    findings = NucleiRunner().parse_vulnerabilities(raw)
    assert findings[0].fingerprint == "tpl|m|https://example.com/login"


def test_nuclei_fingerprint_still_pipe_delimited_three_parts_minimum():
    """Format contract unchanged: template_id|matcher|matched_at. Regression-pinned already by
    test_ingest_idempotency.test_dedupe_does_not_change_the_fingerprint_format for an
    already-normalized-looking URL; this asserts the same shape survives normalization."""
    raw = RawToolOutput(command="nuclei", stdout=_line("HTTPS://Ex.test:443/z"), stderr="", exit_code=0)
    findings = NucleiRunner().parse_vulnerabilities(raw)
    assert findings[0].fingerprint == "tpl|m|https://ex.test/z"


def test_nuclei_two_equivalent_urls_now_produce_the_same_fingerprint():
    """The concrete Finding #1 scenario: two scans reporting cosmetically different but
    equivalent matched_at values for the same real endpoint must now dedupe to one fingerprint,
    where before they would not have."""
    raw_a = RawToolOutput(command="nuclei", stdout=_line("https://example.com/login"), stderr="", exit_code=0)
    raw_b = RawToolOutput(command="nuclei", stdout=_line("https://EXAMPLE.com:443/login"), stderr="", exit_code=0)
    fp_a = NucleiRunner().parse_vulnerabilities(raw_a)[0].fingerprint
    fp_b = NucleiRunner().parse_vulnerabilities(raw_b)[0].fingerprint
    assert fp_a == fp_b


def test_nuclei_matched_at_field_itself_is_left_raw_for_display():
    """The fingerprint's location component is normalized, but VulnerabilityFinding.matched_at
    (used for evidence/report display) keeps the exact string nuclei reported."""
    raw = RawToolOutput(command="nuclei", stdout=_line("https://EXAMPLE.com:443/login"), stderr="", exit_code=0)
    finding = NucleiRunner().parse_vulnerabilities(raw)[0]
    assert finding.matched_at == "https://EXAMPLE.com:443/login"
    assert finding.fingerprint == "tpl|m|https://example.com/login"


def test_nuclei_genuinely_different_locations_still_distinct():
    raw = RawToolOutput(
        command="nuclei",
        stdout="\n".join([_line("https://example.com/login?id=1"), _line("https://example.com/search?q=1")]),
        stderr="", exit_code=0,
    )
    findings = NucleiRunner().parse_vulnerabilities(raw)
    fps = {f.fingerprint for f in findings}
    assert len(fps) == 2
